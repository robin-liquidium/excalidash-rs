//! Core pipeline parity: health, helmet/CORS headers, onboarding gate, CSRF, body parsing, 404.
mod common;
use common::*;
use serde_json::json;

#[test]
fn health_and_core_headers() {
    let s = TestServer::start(&[]);
    let c = s.client();
    let r = c.get("/health");
    assert_eq!(r.status, 200);
    assert_eq!(r.json(), json!({"status": "ok", "database": "ok"}));
    assert_eq!(r.header("x-frame-options").as_deref(), Some("SAMEORIGIN"));
    assert_eq!(r.header("access-control-allow-origin").as_deref(), Some(ORIGIN));
    assert_eq!(r.header("access-control-allow-credentials").as_deref(), Some("true"));
    assert_eq!(r.header("ratelimit-policy").as_deref(), Some("100000;w=900"));
    assert!(r.header("etag").unwrap().starts_with("W/\"1f-"));
    assert!(r.header("x-request-id").is_some());
}

#[test]
fn onboarding_gate_blocks_app_routes_until_setup() {
    let s = TestServer::start(&[]);
    let c = s.client();
    let r = c.get("/drawings");
    assert_eq!(r.status, 409);
    assert_eq!(r.json()["code"], "AUTH_ONBOARDING_REQUIRED");
    assert_eq!(r.header("clear-site-data").as_deref(), Some("\"cache\""));
}

#[test]
fn csrf_required_for_mutations() {
    let s = TestServer::start(&[("DISABLE_ONBOARDING_GATE", "true")]);
    let mut c = s.client();
    let r = c.post("/drawings", json!({}));
    assert_eq!(r.status, 403);
    assert_eq!(r.json()["error"], "CSRF token missing");
    c.fetch_csrf();
    let evil = TestClient { origin: Some("https://evil.example".into()), ..s.client() };
    let r = evil.post("/drawings", json!({}));
    assert_eq!(r.json()["error"], "CSRF origin mismatch");
    c.csrf = Some("garbage.token".into());
    let r = c.post("/drawings", json!({}));
    assert_eq!(r.json()["error"], "CSRF token invalid");
}

#[test]
fn malformed_json_is_400_and_unknown_route_404() {
    let s = TestServer::start(&[("DISABLE_ONBOARDING_GATE", "true")]);
    let c = s.client();
    let r = c.send_raw("POST", "/drawings", Some(("application/json".into(), b"{bad".to_vec())));
    assert_eq!(r.status, 400);
    assert_eq!(r.json(), json!({"error": "Request error", "message": "Invalid request"}));
    let r = c.get("/definitely-not-a-route");
    assert_eq!(r.status, 404);
    assert!(r.text().contains("<pre>Cannot GET /definitely-not-a-route</pre>"));
    assert_eq!(r.header("content-security-policy").as_deref(), Some("default-src 'none'"));
}

#[test]
fn preflight_and_disallowed_origin() {
    let s = TestServer::start(&[]);
    let c = s.client();
    let r = c.send("OPTIONS", "/drawings", None);
    assert_eq!(r.status, 204);
    assert_eq!(r.header("access-control-allow-methods").as_deref(), Some("GET,HEAD,PUT,PATCH,POST,DELETE"));
    let evil = TestClient { origin: Some("https://evil.example".into()), ..s.client() };
    let r = evil.get("/health");
    assert!(r.header("access-control-allow-origin").is_none());
    assert!(r.header("vary").is_none());
}
