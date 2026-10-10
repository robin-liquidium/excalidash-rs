//! password-reset-delivery.integration.ts (SMTP) plus the Resend transport
//! against a fake HTTP endpoint (RESEND_BASE_URL, honoured like the Resend SDK).
mod common;

use common::*;
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

fn hex_sha256(s: &str) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(s.as_bytes()))
}

fn poll<T>(what: &str, mut f: impl FnMut() -> Option<T>) -> T {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Some(v) = f() {
            return v;
        }
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// Minimal SMTP sink, same protocol as the upstream test's net.Server.
fn fake_smtp() -> (u16, Arc<Mutex<Option<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let delivered = Arc::new(Mutex::new(None));
    let out = delivered.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let out = out.clone();
            std::thread::spawn(move || {
                let _ = stream.write_all(b"220 localhost test mail\r\n");
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut message: Option<Vec<String>> = None;
                loop {
                    let mut line = String::new();
                    match reader.read_line(&mut line) {
                        Ok(0) | Err(_) => return,
                        Ok(_) => {}
                    }
                    let line = line.trim_end_matches(['\r', '\n']).to_string();
                    if let Some(m) = message.as_mut() {
                        if line == "." {
                            *out.lock().unwrap() = Some(m.join("\r\n"));
                            message = None;
                            let _ = stream.write_all(b"250 accepted\r\n");
                        } else {
                            m.push(line.strip_prefix("..").map(|r| format!(".{r}")).unwrap_or(line));
                        }
                    } else if line.eq_ignore_ascii_case("DATA") {
                        message = Some(vec![]);
                        let _ = stream.write_all(b"354 send message\r\n");
                    } else if line.eq_ignore_ascii_case("QUIT") {
                        let _ = stream.write_all(b"221 bye\r\n");
                        return;
                    } else {
                        let _ = stream.write_all(b"250 localhost\r\n");
                    }
                }
            });
        }
    });
    (port, delivered)
}

#[test]
fn delivers_reset_link_over_smtp_without_exposing_raw_token() {
    let (smtp_port, delivered) = fake_smtp();
    let port = smtp_port.to_string();
    let server = TestServer::start(&[
        ("MAIL_TRANSPORT", "smtp"),
        ("MAIL_FROM", "ExcaliDash <no-reply@example.test>"),
        ("SMTP_HOST", "127.0.0.1"),
        ("SMTP_PORT", &port),
        ("SMTP_SECURE", "false"),
        ("ENABLE_PASSWORD_RESET", "true"),
    ]);
    enable_auth(&server);
    let email = "reset-delivery@example.test";
    let uid = seed_user(&server, email, "Reset User", "USER");
    let mut c = server.client();
    c.fetch_csrf();
    assert_eq!(c.get("/auth/password-reset-capability").json(), json!({ "enabled": true }));

    let r = c.post("/auth/password-reset-request", json!({ "email": email }));
    assert_eq!(r.status, 200);
    assert!(r.json().get("token").is_none());

    let raw = poll("smtp delivery", || delivered.lock().unwrap().clone());
    let decoded = raw.replace("=\r\n", "").replace("=3D", "=");
    let re = regex::Regex::new(r"reset-password-confirm#token=([a-f0-9]{64})").unwrap();
    let token = re.captures(&decoded).expect("token in mail")[1].to_string();
    assert!(decoded.contains(email));
    assert!(decoded.contains("Subject: Reset your ExcaliDash password"));
    assert!(decoded.contains("From: ExcaliDash <no-reply@example.test>"));
    assert!(decoded.contains("multipart/alternative"));
    assert!(decoded.contains("The link is valid for 60 minutes and can be used once."));
    assert!(decoded.contains("https://first.example.test/reset-password-confirm#token="));

    let stored: String = server
        .db()
        .query_row(r#"SELECT "token" FROM "PasswordResetToken" WHERE "userId" = ?1"#, [&uid], |r| r.get(0))
        .unwrap();
    assert_eq!(stored, hex_sha256(&token));
    assert_ne!(stored, token);

    let password = "New-Password-789!";
    let r = c.post("/auth/password-reset-confirm", json!({ "token": token, "password": password }));
    assert_eq!(r.status, 200, "{}", r.text());
    // Upstream checks /auth/login with old/new passwords; verify the stored hash directly.
    let hash: String =
        server.db().query_row(r#"SELECT "passwordHash" FROM "User" WHERE "id" = ?1"#, [&uid], |r| r.get(0)).unwrap();
    assert!(!bcrypt::verify(STRONG_PASSWORD, &hash).unwrap());
    assert!(bcrypt::verify(password, &hash).unwrap());
    let r = c.post("/auth/password-reset-confirm", json!({ "token": token, "password": password }));
    assert_eq!(r.status, 400);
}

struct Captured {
    request_line: String,
    headers: Vec<(String, String)>,
    body: String,
}

/// One-shot HTTP endpoint answering every request with `status` + `body`.
fn fake_http(status: u16, body: &'static str) -> (u16, Arc<Mutex<Vec<Captured>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(vec![]));
    let out = seen.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut request_line = String::new();
            reader.read_line(&mut request_line).unwrap();
            let mut headers = vec![];
            let mut len = 0usize;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                let line = line.trim_end().to_string();
                if line.is_empty() {
                    break;
                }
                let (k, v) = line.split_once(':').unwrap();
                let (k, v) = (k.trim().to_ascii_lowercase(), v.trim().to_string());
                if k == "content-length" {
                    len = v.parse().unwrap();
                }
                headers.push((k, v));
            }
            let mut buf = vec![0u8; len];
            reader.read_exact(&mut buf).unwrap();
            out.lock().unwrap().push(Captured {
                request_line: request_line.trim_end().to_string(),
                headers,
                body: String::from_utf8(buf).unwrap(),
            });
            let reason = if status == 200 { "OK" } else { "Unprocessable Entity" };
            let resp = format!(
                "HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(resp.as_bytes());
        }
    });
    (port, seen)
}

#[test]
fn delivers_reset_link_via_resend_api() {
    let (port, seen) = fake_http(200, r#"{"id":"email_123"}"#);
    let base = format!("http://127.0.0.1:{port}");
    let server = TestServer::start(&[
        ("MAIL_TRANSPORT", "resend"),
        ("RESEND_API_KEY", "re_test_key"),
        ("RESEND_BASE_URL", &base),
        ("MAIL_FROM", "ExcaliDash <no-reply@example.test>"),
        ("MAIL_REPLY_TO", "support@example.test"),
        ("ENABLE_PASSWORD_RESET", "true"),
    ]);
    enable_auth(&server);
    let email = "resend-user@example.test";
    seed_user(&server, email, "Resend User", "USER");
    let c = server.client();
    assert_eq!(c.get("/auth/password-reset-capability").json(), json!({ "enabled": true }));
    let r = c.post("/auth/password-reset-request", json!({ "email": email }));
    assert_eq!(r.status, 200);

    poll("resend request", || (!seen.lock().unwrap().is_empty()).then_some(()));
    let seen = seen.lock().unwrap();
    let req = &seen[0];
    assert_eq!(req.request_line, "POST /emails HTTP/1.1");
    let header = |k: &str| req.headers.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
    assert_eq!(header("authorization").as_deref(), Some("Bearer re_test_key"));
    assert_eq!(header("user-agent").as_deref(), Some("resend-node:6.22.0"));
    assert_eq!(header("content-type").as_deref(), Some("application/json"));
    assert!(header("idempotency-key").is_none(), "upstream passes the key in the payload, so the SDK never sends it");
    let body: Value = serde_json::from_str(&req.body).unwrap();
    let keys: Vec<&str> = body.as_object().unwrap().keys().map(String::as_str).collect();
    assert_eq!(keys, ["from", "html", "reply_to", "subject", "text", "to"]);
    assert_eq!(body["from"], "ExcaliDash <no-reply@example.test>");
    assert_eq!(body["reply_to"], "support@example.test");
    assert_eq!(body["to"], json!([email]));
    assert_eq!(body["subject"], "Reset your ExcaliDash password");
    let text = body["text"].as_str().unwrap();
    assert!(text.starts_with("Reset your ExcaliDash password\n\nOpen this link to choose a new password:\nhttps://first.example.test/reset-password-confirm#token="));
    assert!(body["html"].as_str().unwrap().starts_with("<!doctype html>"));
    assert!(!server.output().contains("was not delivered"));
}

#[test]
fn logs_resend_delivery_failures() {
    let (port, _seen) = fake_http(422, r#"{"statusCode":422,"name":"validation_error","message":"Invalid `from` field."}"#);
    let base = format!("http://127.0.0.1:{port}");
    let server = TestServer::start(&[
        ("MAIL_TRANSPORT", "resend"),
        ("RESEND_API_KEY", "re_test_key"),
        ("RESEND_BASE_URL", &base),
        ("MAIL_FROM", "bad"),
        ("ENABLE_PASSWORD_RESET", "true"),
    ]);
    enable_auth(&server);
    seed_user(&server, "fail@example.test", "Fail", "USER");
    let r = server.client().post("/auth/password-reset-request", json!({ "email": "fail@example.test" }));
    assert_eq!(r.status, 200, "the response stays neutral");
    poll("delivery failure log", || {
        server
            .output()
            .contains("[mail] Password reset email was not delivered: validation_error: Invalid `from` field.")
            .then_some(())
    });
}
