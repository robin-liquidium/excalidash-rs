//! Black-box test harness: spawns the real binary (like upstream's
//! `startRuntimeServer`) against a temp SQLite DB and talks HTTP to it.
#![allow(dead_code)]

use reqwest::blocking::{Client as HttpClient, Response};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    io::Read,
    net::TcpListener,
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

pub const ORIGIN: &str = "https://first.example.test";
pub const STRONG_PASSWORD: &str = "Str0ng!Passw0rd#1";

pub struct TestServer {
    pub url: String,
    pub port: u16,
    pub dir: tempfile::TempDir,
    pub db_path: PathBuf,
    child: Option<Child>,
    output: Arc<Mutex<String>>,
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

pub fn default_env() -> Vec<(&'static str, String)> {
    vec![
        ("NODE_ENV", "production".into()),
        ("AUTH_MODE", "local".into()),
        ("BACKEND_HOST", "127.0.0.1".into()),
        ("FRONTEND_URL", "https://first.example.test,https://second.example.test".into()),
        ("JWT_SECRET", "test-jwt-secret-0123456789abcdef0123456789abcdef".into()),
        ("CSRF_SECRET", "test-csrf-secret-0123456789abcdef".into()),
        ("API_KEY_HASH_PEPPER", "runtime-test-pepper".into()),
        ("UPDATE_CHECK_OUTBOUND", "false".into()),
        ("MAIL_TRANSPORT", "none".into()),
        ("ENFORCE_HTTPS_REDIRECT", "false".into()),
        ("RATE_LIMIT_MAX_REQUESTS", "100000".into()),
        ("CSRF_MAX_REQUESTS", "100000".into()),
    ]
}

impl TestServer {
    /// Start with defaults overridden by `overrides` (use value "" to unset a default).
    pub fn start(overrides: &[(&str, &str)]) -> TestServer {
        Self::start_in(tempfile::tempdir().unwrap(), overrides)
    }

    /// Start using an existing directory (e.g. a pre-seeded database).
    pub fn start_in(dir: tempfile::TempDir, overrides: &[(&str, &str)]) -> TestServer {
        install_crypto();
        let port = free_port();
        let db_path = dir.path().join("prisma").join("dev.db");
        let mut env: HashMap<String, String> =
            default_env().into_iter().map(|(k, v)| (k.to_string(), v)).collect();
        env.insert("PORT".into(), port.to_string());
        env.insert("EXCALIDASH_BACKEND_ROOT".into(), dir.path().display().to_string());
        env.insert("DATABASE_URL".into(), format!("file:{}", db_path.display()));
        for (k, v) in overrides {
            if v.is_empty() {
                env.remove(*k);
            } else {
                env.insert(k.to_string(), v.to_string());
            }
        }
        let mut child = Command::new(env!("CARGO_BIN_EXE_excalidash-rs"))
            .env_clear()
            .envs(&env)
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .current_dir(dir.path())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn server");
        let output = Arc::new(Mutex::new(String::new()));
        for stream in [child.stdout.take().map(|s| Box::new(s) as Box<dyn Read + Send>), child.stderr.take().map(|s| Box::new(s) as Box<dyn Read + Send>)].into_iter().flatten() {
            let out = output.clone();
            std::thread::spawn(move || {
                let mut stream = stream;
                let mut buf = [0u8; 4096];
                while let Ok(n) = stream.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    let mut o = out.lock().unwrap();
                    o.push_str(&String::from_utf8_lossy(&buf[..n]));
                    if o.len() > 200_000 {
                        let cut = o.len() - 100_000;
                        o.drain(..cut);
                    }
                }
            });
        }
        let url = format!("http://127.0.0.1:{port}");
        let mut server = TestServer { url, port, dir, db_path, child: Some(child), output };
        let deadline = Instant::now() + Duration::from_secs(20);
        let probe = HttpClient::builder().timeout(Duration::from_millis(500)).build().unwrap();
        loop {
            if let Some(status) = server.child.as_mut().unwrap().try_wait().unwrap() {
                panic!("server exited early ({status}): {}", server.output());
            }
            if let Ok(r) = probe.get(format!("{}/health", server.url)).send() {
                if r.status() == 200 || r.status() == 503 {
                    break;
                }
            }
            if Instant::now() > deadline {
                panic!("server did not become healthy: {}", server.output());
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        server
    }

    pub fn output(&self) -> String {
        self.output.lock().unwrap().clone()
    }

    /// Direct DB handle (WAL lets tests read/write alongside the server).
    pub fn db(&self) -> rusqlite::Connection {
        let c = rusqlite::Connection::open(&self.db_path).unwrap();
        c.busy_timeout(Duration::from_secs(10)).unwrap();
        c.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
        c
    }

    pub fn client(&self) -> TestClient {
        TestClient::new(&self.url)
    }

    pub fn stop(&mut self) {
        if let Some(mut c) = self.child.take() {
            unsafe {
                libc_kill(c.id() as i32, 15);
            }
            let deadline = Instant::now() + Duration::from_secs(5);
            while Instant::now() < deadline {
                if c.try_wait().ok().flatten().is_some() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

unsafe extern "C" {
    #[link_name = "kill"]
    fn libc_kill(pid: i32, sig: i32) -> i32;
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.stop();
    }
}

/// A browser-like client: cookie jar, Origin header, CSRF token handling.
pub struct TestClient {
    pub base: String,
    pub http: HttpClient,
    pub origin: Option<String>,
    pub csrf: Option<String>,
    pub bearer: Option<String>,
    pub extra: HeaderMap,
}

#[derive(Debug)]
pub struct Resp {
    pub status: u16,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

impl Resp {
    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
    pub fn header(&self, name: &str) -> Option<String> {
        self.headers.get(name).and_then(|v| v.to_str().ok()).map(str::to_string)
    }
    pub fn header_all(&self, name: &str) -> Vec<String> {
        self.headers.get_all(name).iter().filter_map(|v| v.to_str().ok()).map(str::to_string).collect()
    }
}

impl TestClient {
    pub fn new(base: &str) -> TestClient {
        install_crypto();
        TestClient {
            base: base.to_string(),
            http: HttpClient::builder()
                .cookie_store(true)
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(60))
                .build()
                .unwrap(),
            origin: Some(ORIGIN.to_string()),
            csrf: None,
            bearer: None,
            extra: HeaderMap::new(),
        }
    }

    /// GET /csrf-token and remember the token (cookie jar keeps the client cookie).
    pub fn fetch_csrf(&mut self) -> String {
        let r = self.get("/csrf-token");
        assert_eq!(r.status, 200, "csrf-token: {}", r.text());
        let token = r.json()["token"].as_str().unwrap().to_string();
        self.csrf = Some(token.clone());
        token
    }

    pub fn with_header(mut self, k: &str, v: &str) -> Self {
        self.extra.insert(HeaderName::from_bytes(k.as_bytes()).unwrap(), HeaderValue::from_str(v).unwrap());
        self
    }

    pub fn send(&self, method: &str, path: &str, body: Option<&Value>) -> Resp {
        self.send_raw(method, path, body.map(|b| ("application/json".to_string(), serde_json::to_vec(b).unwrap())))
    }

    pub fn send_raw(&self, method: &str, path: &str, body: Option<(String, Vec<u8>)>) -> Resp {
        let m = reqwest::Method::from_bytes(method.as_bytes()).unwrap();
        let mut rb = self.http.request(m, format!("{}{}", self.base, path));
        if let Some(o) = &self.origin {
            rb = rb.header("Origin", o);
        }
        if let Some(t) = &self.csrf {
            rb = rb.header("x-csrf-token", t);
        }
        if let Some(b) = &self.bearer {
            rb = rb.header("Authorization", format!("Bearer {b}"));
        }
        for (k, v) in &self.extra {
            rb = rb.header(k, v);
        }
        if let Some((ct, bytes)) = body {
            rb = rb.header("Content-Type", ct).body(bytes);
        }
        let r: Response = rb.send().expect("request");
        let status = r.status().as_u16();
        let headers = r.headers().clone();
        let body = r.bytes().map(|b| b.to_vec()).unwrap_or_default();
        Resp { status, headers, body }
    }

    pub fn get(&self, path: &str) -> Resp {
        self.send("GET", path, None)
    }
    pub fn delete(&self, path: &str) -> Resp {
        self.send("DELETE", path, None)
    }
    pub fn post(&self, path: &str, body: Value) -> Resp {
        self.send("POST", path, Some(&body))
    }
    pub fn put(&self, path: &str, body: Value) -> Resp {
        self.send("PUT", path, Some(&body))
    }
    pub fn patch(&self, path: &str, body: Value) -> Resp {
        self.send("PATCH", path, Some(&body))
    }
}

/// Fresh install → enable auth via onboarding → register the bootstrap admin
/// (reading the setup code from the server log) → logged-in client.
/// Returns (client, user json).
pub fn bootstrap_admin(server: &TestServer, email: &str) -> (TestClient, Value) {
    let mut c = server.client();
    c.fetch_csrf();
    let r = c.post("/auth/onboarding-choice", json!({"enableAuth": true}));
    assert!(r.status < 300, "onboarding-choice: {} {}", r.status, r.text());
    let code = wait_for_setup_code(server);
    let r = c.post(
        "/auth/register",
        json!({"email": email, "password": STRONG_PASSWORD, "name": "Admin User", "setupCode": code}),
    );
    assert!(r.status < 300, "register admin: {} {}", r.status, r.text());
    let user = r.json()["user"].clone();
    c.fetch_csrf();
    (c, user)
}

pub fn wait_for_setup_code(server: &TestServer) -> String {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let out = server.output();
        if let Some(line) = out.lines().rev().find(|l| l.contains("[BOOTSTRAP SETUP]")) {
            let code = line.split("): ").nth(1).unwrap().split(' ').next().unwrap().to_string();
            return code;
        }
        if Instant::now() > deadline {
            panic!("no setup code in log: {out}");
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// Log in an existing user with a fresh client.
pub fn login(server: &TestServer, email: &str, password: &str) -> TestClient {
    let mut c = server.client();
    c.fetch_csrf();
    let r = c.post("/auth/login", json!({"email": email, "password": password}));
    assert_eq!(r.status, 200, "login: {}", r.text());
    c.fetch_csrf();
    c
}

pub fn install_crypto() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}
