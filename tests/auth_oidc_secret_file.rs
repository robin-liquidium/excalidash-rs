//! Port of backend/src/__tests__/oidc-secret-file.integration.ts: OIDC_CLIENT_SECRET_FILE
//! is resolved by the production configuration, conflicts and bad files fail closed,
//! and no secret is ever logged.
mod common;
#[path = "auth_oidc_support/mod.rs"]
mod support;

use common::*;
use std::{
    io::Read,
    process::{Command, Stdio},
    time::{Duration, Instant},
};
use support::*;

const SECRET: &str = "test-only-oidc-secret";

fn base_env(idp_issuer: &str) -> Vec<(&'static str, String)> {
    vec![
        ("NODE_ENV", "production".into()),
        ("AUTH_MODE", "hybrid".into()),
        ("JWT_SECRET", "test-jwt-secret-with-at-least-thirty-two-characters".into()),
        ("API_KEY_HASH_PEPPER", "oidc-test-pepper".into()),
        ("OIDC_ISSUER_URL", idp_issuer.into()),
        ("OIDC_CLIENT_ID", CLIENT_ID.into()),
        ("OIDC_REDIRECT_URI", REDIRECT_URI.into()),
        ("OIDC_ID_TOKEN_SIGNED_RESPONSE_ALG", "HS256".into()),
    ]
}

/// Run the binary until it exits (config failure) or 5s pass; returns (exit code, output).
fn run_expect_exit(extra: &[(&str, String)]) -> (Option<i32>, String) {
    let dir = tempfile::tempdir().unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_excalidash-rs"));
    cmd.env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("EXCALIDASH_BACKEND_ROOT", dir.path())
        .env("DATABASE_URL", format!("file:{}", dir.path().join("dev.db").display()))
        .env("PORT", "0")
        .env("BACKEND_HOST", "127.0.0.1")
        .current_dir(dir.path())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in base_env("https://id.example.test").into_iter().chain(extra.iter().map(|(k, v)| (*k, v.clone()))) {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break s.code();
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let mut out = String::new();
    child.stdout.take().unwrap().read_to_string(&mut out).ok();
    child.stderr.take().unwrap().read_to_string(&mut out).ok();
    (status, out)
}

fn secret_dir() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("client-secret");
    std::fs::write(&file, format!("{SECRET}\r\n")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    (dir, file)
}

fn start_with(idp: &MockIdp, extra: &[(&str, String)]) -> TestServer {
    let mut env: Vec<(&str, String)> = base_env(&idp.issuer);
    env.extend(extra.iter().cloned());
    let pairs: Vec<(&str, &str)> = env.iter().map(|(k, v)| (*k, v.as_str())).collect();
    TestServer::start(&pairs)
}

#[test]
fn loads_a_mounted_secret_through_the_production_configuration() {
    let (_dir, file) = secret_dir();
    let idp = MockIdp::start();
    idp.state.lock().unwrap().hs_secret = Some(SECRET.into());
    let s = start_with(&idp, &[("OIDC_CLIENT_SECRET_FILE", file.display().to_string())]);
    // The resolved secret both authenticates the client and verifies HS256 ID tokens.
    let r = oidc_login(&s.client(), &idp, serde_json::json!({"sub": "s", "email": "s@example.test", "email_verified": true}));
    assert_eq!(r.header("location").as_deref(), Some("/dashboard"), "{}", s.output());
    use base64::Engine;
    let basic = base64::engine::general_purpose::STANDARD.encode(format!("{CLIENT_ID}:{SECRET}"));
    assert_eq!(
        idp.state.lock().unwrap().token_requests.last().unwrap().0.get("authorization"),
        Some(&format!("Basic {basic}"))
    );
    assert!(!s.output().contains(SECRET));
}

#[test]
fn keeps_environment_secret_startup_compatible() {
    let idp = MockIdp::start();
    let s = start_with(&idp, &[("OIDC_CLIENT_SECRET", SECRET.into())]);
    assert!(s.output().contains("Configuration validated successfully"));
}

#[test]
fn fails_closed_on_conflicting_sources_without_logging_either_secret() {
    let (_dir, file) = secret_dir();
    let (status, out) = run_expect_exit(&[
        ("OIDC_CLIENT_SECRET_FILE", file.display().to_string()),
        ("OIDC_CLIENT_SECRET", "other-test-secret".into()),
    ]);
    assert!(matches!(status, Some(c) if c != 0), "status {status:?}: {out}");
    assert!(out.contains("Use only one"), "{out}");
    assert!(!out.contains("other-test-secret"));
    assert!(!out.contains(SECRET));
}

#[test]
fn fails_closed_on_missing_or_empty_files() {
    let (dir, _file) = secret_dir();
    let empty = dir.path().join("empty");
    std::fs::write(&empty, "\r\n").unwrap();
    for (path, reason) in [(dir.path().join("missing"), "not readable"), (empty, "empty")] {
        let (status, out) = run_expect_exit(&[("OIDC_CLIENT_SECRET_FILE", path.display().to_string())]);
        assert!(matches!(status, Some(c) if c != 0), "status {status:?}: {out}");
        assert!(out.contains(&format!("OIDC_CLIENT_SECRET_FILE is {reason}")), "{out}");
    }
}
