//! Port of drawings-shared.integration.ts and drawings-shared-hidden.integration.ts,
//! plus the owner-only sharing routes (share-resolve, sharing, permissions).
mod common;
#[path = "dashboard_support/mod.rs"]
mod support;

use common::*;
use serde_json::{json, Value};
use support::*;

#[test]
fn shared_list_excludes_own_drawings_with_self_permission_rows() {
    let s = auth_server();
    let a_id = seed_user(&s, "user-a@test.local", "User A", "USER");
    let b_id = seed_user(&s, "user-b@test.local", "User B", "USER");
    let owned_by_a = simple_drawing(&s, &a_id, "Owned by A");
    let owned_by_b = simple_drawing(&s, &b_id, "Owned by B");
    insert_permission(&s, &owned_by_a, &a_id, "edit", &a_id);
    insert_permission(&s, &owned_by_b, &a_id, "view", &b_id);

    let mut c = s.client();
    c.bearer = Some(mint_access_token(&a_id, "user-a@test.local"));
    let r = c.get("/drawings/shared");
    assert_eq!(r.status, 200);
    let got = ids(&r.json());
    assert!(got.contains(&owned_by_b));
    assert!(!got.contains(&owned_by_a));
}

#[test]
fn shared_list_shape_and_collection_exclusion() {
    let s = auth_server();
    let (owner, owner_id) = user(&s, "owner-s@test.local", "Owner");
    let (rec, rec_id) = user(&s, "rec-s@test.local", "Recipient");
    let col = insert_collection(&s, &owner_id, "Col");
    let loose = insert_drawing(&s, &owner_id, NewDrawing { name: "Loose", elements: Some(r#"[{"id":"a"}]"#), ..Default::default() });
    let in_col = insert_drawing(&s, &owner_id, NewDrawing { name: "InCol", collection_id: Some(&col), ..Default::default() });
    insert_permission(&s, &loose, &rec_id, "edit", &owner_id);
    insert_permission(&s, &in_col, &rec_id, "view", &owner_id);

    let b = rec.get("/drawings/shared").json();
    assert_eq!(b["totalCount"], 2);
    let first = b["drawings"].as_array().unwrap().iter().find(|d| d["id"] == json!(loose)).unwrap();
    let keys: Vec<&String> = first.as_object().unwrap().keys().collect();
    assert_eq!(keys, ["id", "name", "collectionId", "version", "createdAt", "updatedAt", "userId", "accessLevel", "creatorName"]);
    assert_eq!(first["accessLevel"], "edit");
    assert_eq!(first["creatorName"], "Owner");
    assert_eq!(first["collectionId"], Value::Null);

    // includeData: full model; upstream does not select permissions there → "view".
    let full = rec.get("/drawings/shared?includeData=1&search=loo").json();
    assert_eq!(ids(&full), vec![loose.clone()]);
    let d = &full["drawings"][0];
    assert_eq!(d["elements"], json!([{"id": "a"}]));
    assert_eq!(d["accessLevel"], "view");

    // Once the collection itself is shared, drawings visible through it (and, like
    // Prisma's SQL `NOT IN`, drawings without a collection) drop out of the list.
    let r = owner.post(&format!("/collections/{col}/shares"), json!({"identifier": "rec-s@test.local", "role": "view"}));
    assert_eq!(r.status, 200);
    assert_eq!(rec.get("/drawings/shared").json()["totalCount"], 0);

    // Pagination params are clamped like /drawings.
    let p = rec.get("/drawings/shared?limit=500&offset=-1").json();
    assert_eq!((p["limit"].clone(), p["offset"].clone()), (json!(200), json!(0)));
    assert_eq!(s.client().get("/drawings/shared").status, 401);
}

#[test]
fn hides_and_unhides_a_shared_drawing() {
    let s = auth_server();
    let owner_id = seed_user(&s, "owner-h@test.local", "Owner", "USER");
    let (rec, rec_id) = user(&s, "recipient-h@test.local", "Recipient");
    let drawing = simple_drawing(&s, &owner_id, "Shared drawing");
    insert_permission(&s, &drawing, &rec_id, "view", &owner_id);

    assert!(ids(&rec.get("/drawings/shared").json()).contains(&drawing));
    let r = rec.patch(&format!("/drawings/{drawing}/shared-visibility"), json!({"hidden": true}));
    assert_eq!(r.status, 200);
    assert_eq!(r.json(), json!({"success": true, "hidden": true}));
    let after = rec.get("/drawings/shared").json();
    assert!(!ids(&after).contains(&drawing));
    assert_eq!(after["totalCount"], 0);
    // Hidden drawings stay accessible by id.
    assert_eq!(rec.get(&format!("/drawings/{drawing}")).status, 200);

    let r = rec.patch(&format!("/drawings/{drawing}/shared-visibility"), json!({"hidden": false}));
    assert_eq!(r.status, 200);
    assert!(ids(&rec.get("/drawings/shared").json()).contains(&drawing));
}

#[test]
fn shared_visibility_rejects_non_recipients_and_non_booleans() {
    let s = auth_server();
    let owner_id = seed_user(&s, "owner-h2@test.local", "Owner 2", "USER");
    let (stranger, _) = user(&s, "stranger-h@test.local", "Stranger");
    let drawing = simple_drawing(&s, &owner_id, "Not shared with stranger");
    let r = stranger.patch(&format!("/drawings/{drawing}/shared-visibility"), json!({"hidden": true}));
    assert_eq!((r.status, r.json()), (404, json!({"error": "Shared drawing not found"})));
    let r = stranger.patch(&format!("/drawings/{drawing}/shared-visibility"), json!({"hidden": "yes"}));
    assert_eq!((r.status, r.json()), (400, json!({"error": "Validation error", "message": "`hidden` must be a boolean"})));
}

#[test]
fn owner_sharing_routes() {
    let s = auth_server_with(&[("ENABLE_AUDIT_LOGGING", "true")]);
    let (owner, owner_id) = user(&s, "owner-p@test.local", "Owner Person");
    let (other, other_id) = user(&s, "bob@test.local", "Bob Builder");
    let inactive = seed_user(&s, "zed@test.local", "Zed Inactive", "USER");
    s.db().execute(r#"UPDATE "User" SET "isActive" = 0 WHERE "id" = ?1"#, [&inactive]).unwrap();
    let d = simple_drawing(&s, &owner_id, "Mine");

    // share-resolve: short queries return empty before the ownership check.
    assert_eq!(other.get("/drawings/missing/share-resolve?q=ab").json(), json!({"users": []}));
    assert_eq!(other.get(&format!("/drawings/{d}/share-resolve?q=bob")).json(), json!({"error": "Drawing not found"}));
    let r = owner.get(&format!("/drawings/{d}/share-resolve?q=%20BOB%20"));
    assert_eq!(r.json(), json!({"users": [{"id": other_id, "name": "Bob Builder", "email": "bob@test.local"}]}));
    assert_eq!(owner.get(&format!("/drawings/{d}/share-resolve?q=zed")).json(), json!({"users": []}));
    assert_eq!(owner.get(&format!("/drawings/{d}/share-resolve?q=owner")).json(), json!({"users": []}));

    // permissions
    let p = format!("/drawings/{d}/permissions");
    let invalid = json!({"error": "Validation error", "message": "Invalid grantee or permission"});
    assert_eq!(owner.post(&p, json!({"granteeUserId": other_id, "permission": "admin"})).json(), invalid);
    assert_eq!(owner.post(&p, json!({"granteeUserId": 5, "permission": "view"})).json(), invalid);
    assert_eq!(
        owner.post(&p, json!({"granteeUserId": owner_id, "permission": "view"})).json(),
        json!({"error": "Validation error", "message": "Cannot share with yourself"})
    );
    assert_eq!(owner.post(&p, json!({"granteeUserId": inactive, "permission": "view"})).json(), json!({"error": "User not found"}));
    assert_eq!(other.post(&p, json!({"granteeUserId": owner_id, "permission": "view"})).json(), json!({"error": "Drawing not found"}));
    let r = owner.post(&p, json!({"granteeUserId": other_id, "permission": "view"}));
    assert_eq!(r.status, 200);
    let perm = r.json()["permission"].clone();
    let keys: Vec<&String> = perm.as_object().unwrap().keys().collect();
    assert_eq!(keys, ["id", "granteeUserId", "permission", "createdAt", "updatedAt", "granteeUser"]);
    assert_eq!(perm["granteeUser"], json!({"id": other_id, "name": "Bob Builder", "email": "bob@test.local"}));
    // Upsert keeps the id.
    let r2 = owner.post(&p, json!({"granteeUserId": other_id, "permission": "edit"}));
    assert_eq!(r2.json()["permission"]["id"], perm["id"]);
    assert_eq!(r2.json()["permission"]["permission"], "edit");
    assert_eq!(other.get(&format!("/drawings/{d}")).json()["accessLevel"], "edit");

    // sharing overview
    owner.post(&format!("/drawings/{d}/link-shares"), json!({"permission": "view"}));
    let ov = owner.get(&format!("/drawings/{d}/sharing")).json();
    assert_eq!(ov["permissions"].as_array().unwrap().len(), 1);
    let link = &ov["linkShares"][0];
    let keys: Vec<&String> = link.as_object().unwrap().keys().collect();
    assert_eq!(keys, ["id", "permission", "expiresAt", "revokedAt", "createdAt", "updatedAt", "lastUsedAt"]);
    assert_eq!(other.get(&format!("/drawings/{d}/sharing")).json(), json!({"error": "Drawing not found"}));

    // revoke
    let perm_id = perm["id"].as_str().unwrap();
    assert_eq!(other.delete(&format!("/drawings/{d}/permissions/{perm_id}")).status, 404);
    assert_eq!(owner.delete(&format!("/drawings/{d}/permissions/{perm_id}")).json(), json!({"success": true}));
    assert_eq!(owner.delete(&format!("/drawings/{d}/permissions/{perm_id}")).json(), json!({"success": true}));
    assert_eq!(count(&s, r#"SELECT COUNT(*) FROM "DrawingPermission" WHERE "drawingId" = ?1"#, &d), 0);
    for action in ["drawing_shared_user_upsert", "drawing_shared_user_revoke", "drawing_link_share_created"] {
        assert!(count(&s, r#"SELECT COUNT(*) FROM "AuditLog" WHERE "action" = ?1"#, action) >= 1, "{action}");
    }
}
