//! Port of link-sharing-expiry.integration.ts and link-sharing-public.integration.ts.
mod common;
#[path = "dashboard_support/mod.rs"]
mod support;

use common::*;
use serde_json::{json, Value};
use support::*;

const HOUR_MS: i64 = 60 * 60 * 1000;
const DAY_MS: i64 = 24 * HOUR_MS;

struct Owner {
    s: TestServer,
    c: TestClient,
    id: String,
}

fn owner() -> Owner {
    let s = auth_server();
    let (c, id) = user(&s, "owner-user@test.local", "Owner User");
    Owner { s, c, id }
}

impl Owner {
    fn drawing(&self) -> String {
        simple_drawing(&self.s, &self.id, "Shared Drawing")
    }
    fn post_link(&self, drawing: &str, permission: &str, expires: Option<Value>) -> Resp {
        let mut body = json!({"permission": permission});
        if let Some(e) = expires {
            body["expiresAt"] = e;
        }
        self.c.post(&format!("/drawings/{drawing}/link-shares"), body)
    }
    fn link(&self, drawing: &str, permission: &str, expires: Option<Value>) -> Value {
        let r = self.post_link(drawing, permission, expires);
        assert_eq!(r.status, 200, "{}", r.text());
        r.json()
    }
}

fn stored_ms(body: &Value) -> i64 {
    excalidash_rs::util::parse_date_ms(body["share"]["expiresAt"].as_str().unwrap()).unwrap()
}

fn iso(ms: i64) -> String {
    excalidash_rs::util::iso_from_ms(ms)
}

// ---------------------------------------------------------------------------
// link-sharing-expiry.integration.ts

#[test]
fn stores_null_expiry_when_view_expires_at_is_explicitly_null() {
    let o = owner();
    let d = o.drawing();
    let b = o.link(&d, "view", Some(Value::Null));
    assert_eq!(b["share"]["expiresAt"], Value::Null);
    let keys: Vec<&String> = b["share"].as_object().unwrap().keys().collect();
    assert_eq!(keys, ["id", "permission", "expiresAt", "revokedAt", "createdAt"]);
}

#[test]
fn uses_the_default_expiry_when_view_expires_at_is_omitted() {
    let o = owner();
    let d = o.drawing();
    let stored = stored_ms(&o.link(&d, "view", None));
    assert!(stored > now_ms() + 29 * DAY_MS);
    assert!(stored < now_ms() + 31 * DAY_MS);
}

#[test]
fn stores_null_expiry_for_edit_links_and_keeps_them_valid() {
    let o = owner();
    let d = o.drawing();
    let b = o.link(&d, "edit", Some(Value::Null));
    assert_eq!(b["share"]["expiresAt"], Value::Null);
    let (exp, rev): (Option<i64>, Option<i64>) = o
        .s
        .db()
        .query_row(r#"SELECT "expiresAt","revokedAt" FROM "DrawingLinkShare" WHERE "id" = ?1"#, [b["share"]["id"].as_str().unwrap()], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    assert_eq!((exp, rev), (None, None));
}

#[test]
fn still_uses_the_default_expiry_when_edit_expires_at_is_omitted() {
    let o = owner();
    let d = o.drawing();
    let stored = stored_ms(&o.link(&d, "edit", None));
    assert!(stored > now_ms() + 6 * DAY_MS);
    assert!(stored < now_ms() + 8 * DAY_MS);
}

#[test]
fn honors_explicit_far_future_view_dates_without_the_edit_link_cap() {
    let o = owner();
    let d = o.drawing();
    let one_year = now_ms() + 365 * DAY_MS;
    let stored = stored_ms(&o.link(&d, "view", Some(json!(iso(one_year)))));
    assert!(stored > now_ms() + 180 * DAY_MS);
    assert!((stored - one_year).abs() < 5 * 60_000);
}

#[test]
fn caps_explicit_far_future_edit_dates_to_max_ttl() {
    let o = owner();
    let d = o.drawing();
    let stored = stored_ms(&o.link(&d, "edit", Some(json!(iso(now_ms() + 365 * DAY_MS)))));
    assert!(stored > now_ms() + 89 * DAY_MS);
    assert!(stored < now_ms() + 91 * DAY_MS);
}

#[test]
fn rejects_explicit_past_and_invalid_expiry_values() {
    let o = owner();
    let d = o.drawing();
    let past = o.post_link(&d, "view", Some(json!(iso(now_ms() - HOUR_MS))));
    assert_eq!(past.status, 400);
    assert_eq!(past.json()["message"], "Expiry must be at least 1 minute in the future");
    let invalid = o.post_link(&d, "view", Some(json!("not-a-date")));
    assert_eq!(invalid.status, 400);
    assert_eq!(invalid.json()["message"], "Invalid expiry");
    // Non-string non-null values and blank strings are invalid too.
    assert_eq!(o.post_link(&d, "view", Some(json!(12345))).json()["message"], "Invalid expiry");
    assert_eq!(o.post_link(&d, "view", Some(json!("   "))).json()["message"], "Invalid expiry");
    assert_eq!(
        o.post_link(&d, "owner", None).json(),
        json!({"error": "Validation error", "message": "Invalid permission"})
    );
}

// ---------------------------------------------------------------------------
// link-sharing-public.integration.ts

#[test]
fn allows_anonymous_get_when_link_share_policy_is_view() {
    let o = owner();
    let d = o.drawing();
    o.link(&d, "view", None);
    let r = o.s.client().get(&format!("/drawings/{d}"));
    assert_eq!(r.status, 200);
    assert_eq!(r.json()["id"], json!(d));
    assert_eq!(r.json()["accessLevel"], "view");
    assert_eq!(r.json()["collectionId"], Value::Null);
    let r = anon(&o.s).put(&format!("/drawings/{d}"), json!({"name": "Should Not Save"}));
    assert_eq!(r.status, 404);
}

#[test]
fn still_allows_anonymous_get_with_stale_or_refresh_cookies() {
    let o = owner();
    let d = o.drawing();
    o.link(&d, "view", None);
    let token = refresh_like_token(&o.id, "owner-user@test.local");
    for cookie in [format!("excalidash-access-token={token}"), format!("excalidash-refresh-token={token}")] {
        let r = o.s.client().with_header("Cookie", &cookie).get(&format!("/drawings/{d}"));
        assert_eq!(r.status, 200, "{cookie}");
        assert_eq!(r.json()["accessLevel"], "view");
    }
}

#[test]
fn allows_anonymous_put_when_link_share_policy_is_edit() {
    let o = owner();
    let d = o.drawing();
    o.link(&d, "edit", None);
    let r = anon(&o.s).put(&format!("/drawings/{d}"), json!({"name": "Renamed By Anonymous"}));
    assert_eq!(r.status, 200);
    assert_eq!(r.json()["id"], json!(d));
    assert_eq!(r.json()["name"], "Renamed By Anonymous");
    assert_eq!(r.json()["accessLevel"], "edit");
}

#[test]
fn still_allows_anonymous_put_with_stale_or_refresh_cookies() {
    let o = owner();
    let d = o.drawing();
    o.link(&d, "edit", None);
    let token = refresh_like_token(&o.id, "owner-user@test.local");
    for (i, name) in ["excalidash-access-token", "excalidash-refresh-token"].iter().enumerate() {
        let mut c = o.s.client().with_header("Cookie", &format!("{name}={token}"));
        c.fetch_csrf_with_cookie_header();
        let r = c.put(&format!("/drawings/{d}"), json!({"name": format!("Edited {i}")}));
        assert_eq!(r.status, 200, "{name}: {}", r.text());
        assert_eq!(r.json()["name"], json!(format!("Edited {i}")));
    }
}

#[test]
fn returns_401_for_a_private_drawing_with_stale_credentials() {
    let o = owner();
    let d = o.drawing();
    let token = refresh_like_token(&o.id, "owner-user@test.local");
    for name in ["excalidash-access-token", "excalidash-refresh-token"] {
        let r = o.s.client().with_header("Cookie", &format!("{name}={token}")).get(&format!("/drawings/{d}"));
        assert_eq!(r.status, 401, "{name}");
        assert_eq!(r.json(), json!({"error": "Unauthorized", "message": "Invalid or expired token"}));
        // Preview and history use the same optional-auth error path.
        let r = o.s.client().with_header("Cookie", &format!("{name}={token}")).get(&format!("/drawings/{d}/preview"));
        assert_eq!(r.status, 401);
    }
    let mut c = o.s.client().with_header("Cookie", &format!("excalidash-access-token={token}"));
    c.fetch_csrf_with_cookie_header();
    let r = c.put(&format!("/drawings/{d}"), json!({"name": "Should Fail"}));
    assert_eq!(r.status, 401);
    assert_eq!(r.json()["message"], "Invalid or expired token");
}

#[test]
fn revokes_previous_active_link_share_when_creating_a_new_one() {
    let o = owner();
    let d = o.drawing();
    let first = o.link(&d, "view", None);
    let first_id = first["share"]["id"].as_str().unwrap().to_string();
    o.link(&d, "edit", None);
    let revoked: Option<i64> =
        o.s.db().query_row(r#"SELECT "revokedAt" FROM "DrawingLinkShare" WHERE "id" = ?1"#, [&first_id], |r| r.get(0)).unwrap();
    assert!(revoked.is_some());
    assert_eq!(count(&o.s, r#"SELECT COUNT(*) FROM "DrawingLinkShare" WHERE "drawingId" = ?1 AND "revokedAt" IS NULL"#, &d), 1);
}

#[test]
fn revoking_a_link_share_removes_public_access() {
    let o = owner();
    let d = o.drawing();
    let share = o.link(&d, "view", None);
    let sid = share["share"]["id"].as_str().unwrap();
    assert_eq!(o.s.client().get(&format!("/drawings/{d}")).status, 200);
    let (other, _) = user(&o.s, "intruder@test.local", "Intruder");
    assert_eq!(other.delete(&format!("/drawings/{d}/link-shares/{sid}")).json(), json!({"error": "Drawing not found"}));
    assert_eq!(other.post(&format!("/drawings/{d}/link-shares"), json!({"permission": "view"})).status, 404);
    assert_eq!(o.c.delete(&format!("/drawings/{d}/link-shares/{sid}")).json(), json!({"success": true}));
    assert_eq!(o.s.client().get(&format!("/drawings/{d}")).status, 404);
    // Expired shares grant nothing either.
    let share = o.link(&d, "view", None);
    o.s.db()
        .execute(r#"UPDATE "DrawingLinkShare" SET "expiresAt" = ?1 WHERE "id" = ?2"#, excalidash_rs::sql::params![now_ms() - 1000, share["share"]["id"].as_str().unwrap()])
        .unwrap();
    assert_eq!(o.s.client().get(&format!("/drawings/{d}")).status, 404);
}
