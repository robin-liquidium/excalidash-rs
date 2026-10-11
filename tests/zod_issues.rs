//! Dev-mode (`NODE_ENV=development`) validation bodies for drawing create/update:
//! zod 4 issue arrays captured from upstream 0.6.5 (tests/fixtures/zod_issues.*).
mod common;
use common::*;
use serde_json::Value;

#[test]
fn drawing_validation_issues_match_upstream_zod() {
    let fx = |n: &str| -> Value {
        serde_json::from_str(&std::fs::read_to_string(format!("{}/tests/fixtures/{n}", env!("CARGO_MANIFEST_DIR"))).unwrap()).unwrap()
    };
    let (input, expected) = (fx("zod_issues.input.json"), fx("zod_issues.expected.json"));
    let s = TestServer::start(&[("NODE_ENV", "development"), ("AUTH_MODE", "disabled")]);
    let mut c = s.client();
    c.fetch_csrf();
    let created = c.post("/drawings", serde_json::json!({"name": "t", "elements": [], "appState": {}}));
    let id = created.json()["id"].as_str().unwrap().to_string();
    let mut bad = vec![];
    for (kind, method, path) in [("creates", "POST", "/drawings".to_string()), ("updates", "PUT", format!("/drawings/{id}"))] {
        for (i, body) in input[kind].as_array().unwrap().iter().enumerate() {
            let r = c.send(method, &path, Some(body));
            let got = if r.status < 300 { serde_json::json!([r.status, null]) } else { serde_json::json!([r.status, r.json()]) };
            if got != expected[kind][i] {
                bad.push(format!("{kind}[{i}] {body}\n  upstream {}\n  rust     {got}", expected[kind][i]));
            }
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}
