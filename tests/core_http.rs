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

/// Express routing semantics: automatic OPTIONS reply and case-insensitive literal segments.
#[test]
fn express_options_reply_and_case_insensitive_paths() {
    let s = TestServer::start(&[("DISABLE_ONBOARDING_GATE", "true")]);
    let evil = TestClient { origin: Some("https://evil.example".into()), ..s.client() };
    let r = evil.send("OPTIONS", "/drawings/abc", None);
    assert_eq!(r.status, 200);
    assert_eq!(r.header("allow").as_deref(), Some("DELETE, GET, HEAD, PUT"));
    assert_eq!(r.header("content-type").as_deref(), Some("text/plain"));
    assert_eq!(r.text(), "DELETE, GET, HEAD, PUT");
    assert!(r.header("etag").is_none());
    let r = evil.send("OPTIONS", "/nope", None);
    assert_eq!(r.status, 404);
    assert!(r.text().contains("Cannot OPTIONS /nope"));
    let c = s.client();
    assert_eq!(c.get("/HEALTH").status, 200);
    assert_eq!(c.get("/Csrf-Token").status, 200);
    let r = c.get("/Auth/Status");
    assert_eq!(r.status, 200, "{}", r.text());
    assert!(r.json().get("authEnabled").is_some());
}

/// The WebSocket upgrade must keep `Connection: Upgrade` (browsers reject anything else).
#[test]
fn websocket_upgrade_handshake_is_untouched() {
    use std::io::{Read, Write};
    let s = TestServer::start(&[("AUTH_MODE", "disabled")]);
    let mut tcp = std::net::TcpStream::connect(("127.0.0.1", s.port)).unwrap();
    tcp.set_read_timeout(Some(std::time::Duration::from_secs(5))).unwrap();
    tcp.write_all(
        b"GET /socket.io/?EIO=4&transport=websocket HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
    )
    .unwrap();
    let mut buf = vec![0u8; 2048];
    let n = tcp.read(&mut buf).unwrap();
    let head = String::from_utf8_lossy(&buf[..n]);
    let head = head.split("\r\n\r\n").next().unwrap();
    assert!(head.starts_with("HTTP/1.1 101 Switching Protocols\r\n"), "{head}");
    assert!(head.contains("\r\nConnection: Upgrade") || head.contains("\r\nConnection: upgrade"), "{head}");
    assert!(head.contains("\r\nUpgrade: websocket"), "{head}");
    assert!(head.contains("\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo="), "{head}");
    assert!(!head.to_ascii_lowercase().contains("keep-alive"), "{head}");
}

/// Rust-only EXCALIDASH_THEME_FOLLOW_SYSTEM: index.html gets the theme script, the script is
/// served, and GET/PUT /auth/preferences answer with the OS theme cookie. Off by default.
#[test]
fn theme_follow_system_injects_script_and_overrides_preference() {
    let dist = tempfile::tempdir().unwrap();
    std::fs::write(dist.path().join("index.html"), "<!doctype html>\n<html><head><title>x</title></head><body></body></html>\n").unwrap();
    let dir = dist.path().to_str().unwrap();

    let off = TestServer::start(&[("FRONTEND_DIST_DIR", dir)]);
    let page = off.client().get("/").text();
    assert!(!page.contains("excalidash-rs-theme.js"), "{page}");
    assert_eq!(off.client().get("/excalidash-rs-theme.js").status, 404, "nginx asset 404 when off");

    let on = TestServer::start(&[("FRONTEND_DIST_DIR", dir), ("EXCALIDASH_THEME_FOLLOW_SYSTEM", "true")]);
    let r = on.client().get("/");
    assert!(r.text().contains("<head>\n    <script src=\"/excalidash-rs-theme.js\"></script><title>"), "{}", r.text());
    let s = on.client().get("/editor/abc");
    assert!(s.text().contains("excalidash-rs-theme.js"), "SPA fallback is injected too");
    let js = on.client().get("/excalidash-rs-theme.js");
    assert_eq!(js.status, 200);
    assert_eq!(js.header("content-type").as_deref(), Some("application/javascript; charset=utf-8"));
    assert!(js.text().contains("prefers-color-scheme: dark"));

    // The preference override does not depend on the bundled frontend.
    let api = TestServer::start(&[("EXCALIDASH_THEME_FOLLOW_SYSTEM", "true")]);
    let (mut c, _) = user_session(&api, "theme@example.test", "USER");
    let r = c.put("/auth/preferences", json!({"theme": "light", "language": "de"}));
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(c.get("/auth/preferences").json()["preferences"], json!({"theme": "light", "language": "de"}));
    let cookie = c.extra.get("cookie").unwrap().to_str().unwrap().to_string();
    c.extra.insert("cookie", format!("{cookie}; excalidash-system-theme=dark").parse().unwrap());
    assert_eq!(c.get("/auth/preferences").json()["preferences"], json!({"theme": "dark", "language": "de"}));
}
