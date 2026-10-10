//! Port of upstream csrf.integration.ts (stateless HMAC tokens, horizontal
//! scaling, referer parsing), exercised over HTTP via the auth routes' requireCsrf.
mod common;
use base64::Engine;
use common::*;
use hmac::{Hmac, KeyInit, Mac};
use serde_json::json;

const CSRF_SECRET: &str = "test-csrf-secret-0123456789abcdef";
const CLIENT_COOKIE: &str = "csrf-client-test-0123456789";

fn b64url(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

/// security.ts createCsrfToken with an explicit timestamp.
fn craft_token(client_id: &str, ts: i64) -> String {
    let nonce = b64url(&[7u8; 16]);
    let payload = format!("{{\"ts\":{ts},\"nonce\":\"{nonce}\"}}");
    let mut mac = <Hmac<sha2::Sha256> as KeyInit>::new_from_slice(CSRF_SECRET.as_bytes()).unwrap();
    mac.update(format!("{client_id}|{ts}|{nonce}").as_bytes());
    format!("{}.{}", b64url(payload.as_bytes()), b64url(&mac.finalize().into_bytes()))
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// Client with a fixed csrf client cookie (no jar involvement) and a given token.
fn client_with(s: &TestServer, cookie: &str, token: Option<&str>) -> TestClient {
    let mut c = s.client().with_header("Cookie", &format!("excalidash-csrf-client={cookie}"));
    c.csrf = token.map(str::to_string);
    c
}

/// POST /auth/logout (auth enabled): 200 when CSRF passes, 403 otherwise.
fn csrf_probe(c: &TestClient) -> Resp {
    c.post("/auth/logout", json!({}))
}

fn server() -> TestServer {
    let s = TestServer::start(&[]);
    enable_auth(&s);
    s
}

#[test]
fn creates_payload_signature_tokens_that_validate_for_the_same_client() {
    let s = server();
    let mut c = s.client();
    let token = c.fetch_csrf();
    assert!(regex::Regex::new(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$").unwrap().is_match(&token), "{token}");
    let r = csrf_probe(&c);
    assert_eq!(r.status, 200, "{}", r.text());
}

#[test]
fn rejects_validation_for_a_different_client_id() {
    let s = server();
    let a = s.client().with_header("Cookie", "excalidash-csrf-client=client-a-0123456789abcdef");
    let token = a.get("/csrf-token").json()["token"].as_str().unwrap().to_string();
    assert_eq!(csrf_probe(&client_with(&s, "client-a-0123456789abcdef", Some(&token))).status, 200);
    let r = csrf_probe(&client_with(&s, "client-b-0123456789abcdef", Some(&token)));
    assert_eq!(r.status, 403);
    assert_eq!(
        r.json(),
        json!({"error": "CSRF token invalid", "message": "Invalid or expired CSRF token. Please refresh and try again."})
    );
}

#[test]
fn rejects_malformed_tokens() {
    let s = server();
    for bad in ["not-a-token", "a.b.c"] {
        let r = csrf_probe(&client_with(&s, CLIENT_COOKIE, Some(bad)));
        assert_eq!(r.status, 403);
        assert_eq!(r.json()["error"], "CSRF token invalid");
    }
    let r = csrf_probe(&client_with(&s, CLIENT_COOKIE, Some("")));
    assert_eq!(r.status, 403);
    assert_eq!(r.json(), json!({"error": "CSRF token missing", "message": "Missing x-csrf-token header"}));
}

#[test]
fn tokens_are_stateless_and_survive_repeated_use() {
    // revokeCsrfToken is a no-op upstream: a token stays valid across requests.
    let s = server();
    let mut c = s.client();
    c.fetch_csrf();
    for _ in 0..3 {
        assert_eq!(csrf_probe(&c).status, 200);
    }
}

#[test]
fn expires_tokens_after_24_hours() {
    let s = server();
    let client_id = format!("cookie:{CLIENT_COOKIE}");
    let day = 24 * 60 * 60 * 1000;
    let fresh = craft_token(&client_id, now_ms());
    assert_eq!(csrf_probe(&client_with(&s, CLIENT_COOKIE, Some(&fresh))).status, 200);
    let almost = craft_token(&client_id, now_ms() - day + 60_000);
    assert_eq!(csrf_probe(&client_with(&s, CLIENT_COOKIE, Some(&almost))).status, 200);
    let expired = craft_token(&client_id, now_ms() - day - 1);
    assert_eq!(csrf_probe(&client_with(&s, CLIENT_COOKIE, Some(&expired))).status, 403);
    let future = craft_token(&client_id, now_ms() + 6 * 60 * 1000);
    assert_eq!(csrf_probe(&client_with(&s, CLIENT_COOKIE, Some(&future))).status, 403);
}

#[test]
fn validates_across_instances_sharing_the_secret() {
    // Simulated pods: separate processes and databases, same CSRF_SECRET.
    let pods: Vec<TestServer> = (0..3).map(|_| server()).collect();
    let issuer = pods[0].client().with_header("Cookie", &format!("excalidash-csrf-client={CLIENT_COOKIE}"));
    let token = issuer.get("/csrf-token").json()["token"].as_str().unwrap().to_string();
    let mut failures = 0;
    for i in 0..60 {
        if csrf_probe(&client_with(&pods[i % 3], CLIENT_COOKIE, Some(&token))).status != 200 {
            failures += 1;
        }
    }
    assert_eq!(failures, 0);
    // A pod with a different secret rejects it.
    let other = TestServer::start(&[("CSRF_SECRET", "a-completely-different-secret-value")]);
    enable_auth(&other);
    assert_eq!(csrf_probe(&client_with(&other, CLIENT_COOKIE, Some(&token))).status, 403);
}

#[test]
fn referer_origin_parsing() {
    use excalidash_rs::http::csrf::get_origin_from_referer as origin;
    assert_eq!(origin("https://example.com/path?x=1").as_deref(), Some("https://example.com"));
    assert_eq!(origin("http://localhost:5173/some/page").as_deref(), Some("http://localhost:5173"));
    assert_eq!(origin("https://example.com.evil.com/anything").as_deref(), Some("https://example.com.evil.com"));
    assert_eq!(origin("https://example.com@evil.com/anything").as_deref(), Some("https://evil.com"));
    assert_eq!(origin(""), None);
    assert_eq!(origin("not a url"), None);
    assert_eq!(origin("file:///etc/passwd"), None);
}

#[test]
fn referer_checks_on_auth_routes() {
    let s = server();
    let mut c = TestClient { origin: None, ..s.client() };
    c.fetch_csrf();
    let with_referer = |referer: &str| {
        let mut cl = TestClient { origin: None, ..s.client() };
        cl.http = c.http.clone();
        cl.csrf = c.csrf.clone();
        cl.with_header("Referer", referer).post("/auth/logout", json!({}))
    };
    assert_eq!(with_referer("https://first.example.test/path?x=1").status, 200);
    for bad in ["https://first.example.test.evil.com/anything", "https://first.example.test@evil.com/anything", "not a url", "file:///etc/passwd"] {
        let r = with_referer(bad);
        assert_eq!(r.status, 403, "{bad}");
        assert_eq!(r.json(), json!({"error": "CSRF referer mismatch", "message": "Referer not allowed"}));
    }
    let evil = TestClient { origin: Some("https://evil.example".into()), http: c.http.clone(), csrf: c.csrf.clone(), ..s.client() };
    let r = evil.post("/auth/logout", json!({}));
    assert_eq!(r.json(), json!({"error": "CSRF origin mismatch", "message": "Origin not allowed"}));
}
