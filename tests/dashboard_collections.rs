//! Port of collection-sharing.integration.ts plus collections CRUD/share-route
//! branches and the library routes.
mod common;
#[path = "dashboard_support/mod.rs"]
mod support;

use common::*;
use serde_json::{json, Value};
use support::*;

struct World {
    s: TestServer,
    owner: TestClient,
    owner_id: String,
    viewer: TestClient,
    viewer_id: String,
    editor: TestClient,
    editor_id: String,
}

fn world() -> World {
    let s = auth_server();
    let (owner, owner_id) = user(&s, "owner-collections@test.local", "Owner User");
    let (viewer, viewer_id) = user(&s, "viewer-collections@test.local", "Viewer User");
    let (editor, editor_id) = user(&s, "editor-collections@test.local", "Editor User");
    World { s, owner, owner_id, viewer, viewer_id, editor, editor_id }
}

impl World {
    fn collection(&self) -> String {
        insert_collection(&self.s, &self.owner_id, "Shared Collection")
    }
    fn drawing_in(&self, col: &str) -> String {
        insert_drawing(&self.s, &self.owner_id, NewDrawing { name: "Owner Drawing", collection_id: Some(col), ..Default::default() })
    }
    fn share(&self, col: &str, email: &str, role: &str) -> Value {
        let r = self.owner.post(&format!("/collections/{col}/shares"), json!({"identifier": email, "role": role}));
        assert_eq!(r.status, 200, "{}", r.text());
        r.json()
    }
}

#[test]
fn adds_a_viewer_share_and_returns_collection_metadata_for_the_recipient() {
    let w = world();
    let col = w.collection();
    let body = w.share(&col, "viewer-collections@test.local", "view");
    assert_eq!(body["share"]["role"], "view");
    assert_eq!(body["share"]["granteeUserId"], json!(w.viewer_id));
    let keys: Vec<&String> = body["share"].as_object().unwrap().keys().collect();
    assert_eq!(keys, ["id", "collectionId", "granteeUserId", "role", "createdByUserId", "createdAt", "updatedAt", "granteeUser"]);

    let r = w.viewer.get("/collections");
    assert_eq!(r.status, 200);
    let list = r.json();
    let shared = list.as_array().unwrap().iter().find(|c| c["id"] == json!(col)).unwrap();
    assert_eq!(shared["isOwner"], false);
    assert_eq!(shared["sharedRole"], "view");
    assert_eq!(shared["user"], json!({"id": w.owner_id, "name": "Owner User", "email": "owner-collections@test.local"}));
    let keys: Vec<&String> = shared.as_object().unwrap().keys().collect();
    assert_eq!(keys, ["id", "name", "userId", "createdAt", "updatedAt", "user", "sharedRole", "isOwner"]);
    // Owner sees it flagged as shared, plus the trash pseudo-collection.
    let mine = w.owner.get("/collections").json();
    let own = mine.as_array().unwrap().iter().find(|c| c["id"] == json!(col)).unwrap();
    assert_eq!((own["isShared"].clone(), own["isOwner"].clone(), own["sharedRole"].clone()), (json!(true), json!(true), Value::Null));
    let trash = mine.as_array().unwrap().iter().find(|c| c["id"] == "trash").unwrap();
    assert_eq!(trash["name"], "Trash");
    assert_eq!(trash["isShared"], false);
}

#[test]
fn allows_view_access_to_drawings_in_shared_collection_but_blocks_creating_for_view_only_share() {
    let w = world();
    let col = w.collection();
    w.drawing_in(&col);
    w.share(&col, "viewer-collections@test.local", "view");
    let r = w.viewer.get(&format!("/drawings?collectionId={col}"));
    assert_eq!(r.status, 200);
    assert_eq!(r.json()["drawings"].as_array().unwrap().len(), 1);
    let r = w.viewer.post(
        "/drawings",
        json!({"name": "Viewer Cannot Create Here", "elements": [], "appState": {}, "files": {}, "collectionId": col}),
    );
    assert_eq!(r.status, 403);
    assert!(r.json()["error"].as_str().unwrap().contains("No edit access"));
}

#[test]
fn allows_creating_drawings_in_shared_collection_for_editor_role() {
    let w = world();
    let col = w.collection();
    w.share(&col, "editor-collections@test.local", "edit");
    let r = w.editor.post(
        "/drawings",
        json!({"name": "Editor Can Create Here", "elements": [], "appState": {}, "files": {}, "collectionId": col}),
    );
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(r.json()["collectionId"], json!(col));
    assert_eq!(r.json()["userId"], json!(w.editor_id));
}

#[test]
fn uses_the_stronger_collection_role_when_a_direct_drawing_grant_is_weaker() {
    let w = world();
    let col = w.collection();
    let d = w.drawing_in(&col);
    insert_collection_share(&w.s, &col, &w.editor_id, "edit", &w.owner_id);
    insert_permission(&w.s, &d, &w.editor_id, "view", &w.owner_id);
    let r = w.editor.put(&format!("/drawings/{d}"), json!({"name": "Edited through collection role"}));
    assert_eq!(r.status, 200);
    assert_eq!(r.json()["name"], "Edited through collection role");
    assert_eq!(r.json()["accessLevel"], "edit");
}

#[test]
fn revokes_access_after_removing_collection_share() {
    let w = world();
    let col = w.collection();
    w.drawing_in(&col);
    w.share(&col, "viewer-collections@test.local", "view");
    let before = w.viewer.get(&format!("/drawings?collectionId={col}"));
    assert_eq!(before.status, 200);
    assert_eq!(before.header("x-cache").as_deref(), Some("MISS"));
    let r = w.owner.delete(&format!("/collections/{col}/shares/{}", w.viewer_id));
    assert_eq!((r.status, r.json()["success"].clone()), (200, json!(true)));
    assert_eq!(w.viewer.get(&format!("/drawings?collectionId={col}")).status, 404);
}

#[test]
fn hides_a_previously_shared_collection_from_the_recipient_after_the_owner_deletes_it() {
    let w = world();
    let col = w.collection();
    let d = w.drawing_in(&col);
    w.share(&col, "viewer-collections@test.local", "view");
    let has = |c: &TestClient| c.get("/collections").json().as_array().unwrap().iter().any(|c| c["id"] == json!(col));
    assert!(has(&w.viewer));
    let r = w.owner.delete(&format!("/collections/{col}"));
    assert_eq!((r.status, r.json()), (200, json!({"success": true})));
    assert!(!has(&w.viewer));
    // Drawings are unfiled, not deleted.
    assert_eq!(drawing_row(&w.s, &d).unwrap().6, None);
}

#[test]
fn prevents_a_view_only_invited_user_from_renaming_editing_or_deleting_drawings() {
    let w = world();
    let col = w.collection();
    let d = w.drawing_in(&col);
    w.share(&col, "viewer-collections@test.local", "view");
    assert_eq!(w.viewer.put(&format!("/drawings/{d}"), json!({"name": "Viewer Rename Attempt"})).status, 404);
    let r = w.viewer.put(
        &format!("/drawings/{d}"),
        json!({"elements": [{"id": "v1", "type": "rectangle", "x": 0, "y": 0, "width": 10, "height": 10}], "appState": {}, "files": {}}),
    );
    assert_eq!(r.status, 404);
    assert_eq!(w.viewer.delete(&format!("/drawings/{d}")).status, 404);
    assert_eq!(w.viewer.get(&format!("/drawings/{d}")).json()["accessLevel"], "view");
}

#[test]
fn prevents_a_view_only_invited_user_from_creating_or_importing_into_a_shared_collection() {
    let w = world();
    let col = w.collection();
    w.share(&col, "viewer-collections@test.local", "view");
    let r = w.viewer.post(
        "/drawings",
        json!({"name": "Viewer Cannot Create Here", "elements": [], "appState": {}, "files": {}, "collectionId": col}),
    );
    assert_eq!(r.status, 403);
    assert!(r.json()["error"].as_str().unwrap().contains("No edit access"));
    let r = w.viewer.clone_with_header("x-imported-file", "true").post(
        "/drawings",
        json!({"name": "Imported by Viewer", "elements": [], "appState": {}, "files": {}, "preview": null, "collectionId": col}),
    );
    assert_eq!(r.status, 403);
    assert!(r.json()["error"].as_str().unwrap().contains("No edit access"));
}

#[test]
fn allows_an_editor_to_move_their_own_drawing_into_a_shared_collection() {
    let w = world();
    let col = w.collection();
    insert_collection_share(&w.s, &col, &w.editor_id, "edit", &w.owner_id);
    let d = simple_drawing(&w.s, &w.editor_id, "Editor Drawing");
    let r = w.editor.put(&format!("/drawings/{d}"), json!({"collectionId": col}));
    assert_eq!(r.status, 200);
    assert_eq!(r.json()["collectionId"], json!(col));
    assert!(ids(&w.editor.get(&format!("/drawings?collectionId={col}")).json()).contains(&d));
    assert_eq!(w.editor.put(&format!("/drawings/{d}"), json!({"collectionId": null})).status, 200);
    let after = w.editor.get(&format!("/drawings?collectionId={col}"));
    assert_eq!(after.status, 200);
    assert_eq!(after.json()["drawings"], json!([]));
}

#[test]
fn prevents_a_viewer_from_moving_their_own_drawing_into_a_shared_collection() {
    let w = world();
    let col = w.collection();
    insert_collection_share(&w.s, &col, &w.viewer_id, "view", &w.owner_id);
    let d = simple_drawing(&w.s, &w.viewer_id, "Viewer Drawing");
    let r = w.viewer.put(&format!("/drawings/{d}"), json!({"collectionId": col}));
    assert_eq!(r.status, 404);
    assert_eq!(r.json()["error"], "Collection not found");
    assert_eq!(drawing_row(&w.s, &d).unwrap().6, None);
}

// ---------------------------------------------------------------------------
// Collections CRUD and share-route branches

#[test]
fn collections_crud_branches() {
    let w = world();
    let c = &w.owner;
    let r = c.post("/collections", json!({"name": "  <b>Bold</b> Name  "}));
    assert_eq!(r.status, 200);
    let b = r.json();
    let keys: Vec<&String> = b.as_object().unwrap().keys().collect();
    assert_eq!(keys, ["id", "name", "userId", "createdAt", "updatedAt", "sharedRole", "isOwner"]);
    assert_eq!(b["name"], "<b>Bold</b> Name");
    let id = b["id"].as_str().unwrap().to_string();

    let name_err = json!({"error": "Validation error", "message": "Collection name must be between 1 and 100 characters"});
    assert_eq!(c.post("/collections", json!({"name": "   "})).json(), name_err);
    assert_eq!(c.post("/collections", json!({"name": "x".repeat(101)})).json(), name_err);
    assert_eq!(c.post("/collections", json!({})).json(), name_err);
    // `req.body.name` with no JSON body throws → 500.
    let r = c.send("POST", "/collections", None);
    assert_eq!(r.status, 500);

    let r = c.put(&format!("/collections/{id}"), json!({"name": "Renamed"}));
    assert_eq!(r.status, 200);
    let keys: Vec<String> = r.json().as_object().unwrap().keys().cloned().collect();
    assert_eq!(keys, ["id", "name", "userId", "createdAt", "updatedAt"]);
    assert_eq!(r.json()["name"], "Renamed");
    assert_eq!(c.put(&format!("/collections/{id}"), json!({"name": ""})).json(), name_err);
    assert_eq!(c.put("/collections/missing", json!({"name": "x"})).json(), json!({"error": "Collection not found"}));
    assert_eq!(
        c.put("/collections/trash", json!({"name": "x"})).json(),
        json!({"error": "Validation error", "message": "Trash collection cannot be renamed"})
    );
    assert_eq!(
        c.delete(&format!("/collections/trash:{}", w.owner_id)).json(),
        json!({"error": "Validation error", "message": "Trash collection cannot be deleted"})
    );
    assert_eq!(c.delete("/collections/missing").json(), json!({"error": "Collection not found"}));
    assert_eq!(c.delete(&format!("/collections/{id}")).json(), json!({"success": true}));
    assert_eq!(w.s.client().get("/collections").status, 401);
}

#[test]
fn legacy_trash_drawings_are_migrated_by_collections_listing() {
    let w = world();
    // Legacy rows referenced a shared "trash" collection id.
    w.s.db().execute(r#"INSERT INTO "Collection" ("id","name","userId","createdAt","updatedAt") VALUES ('trash','Trash',?1,0,0)"#, [&w.owner_id]).unwrap();
    let d = insert_drawing(&w.s, &w.owner_id, NewDrawing { name: "Old", collection_id: Some("trash"), ..Default::default() });
    let list = w.owner.get("/collections").json();
    let trash: Vec<&Value> = list.as_array().unwrap().iter().filter(|c| c["id"] == "trash").collect();
    assert_eq!(trash.len(), 1, "legacy row hidden once the per-user trash exists: {list}");
    assert_eq!(drawing_row(&w.s, &d).unwrap().6, Some(format!("trash:{}", w.owner_id)));
    assert_eq!(ids(&w.owner.get("/drawings?collectionId=trash").json()), vec![d]);
}

#[test]
fn collection_share_route_branches() {
    let w = world();
    let col = w.collection();
    let c = &w.owner;
    let base = format!("/collections/{col}/shares");
    let required = json!({"error": "identifier and role (view|edit) are required"});
    assert_eq!(c.post(&base, json!({"identifier": "", "role": "view"})).json(), required);
    assert_eq!(c.post(&base, json!({"identifier": "x", "role": "owner"})).json(), required);
    assert_eq!(c.post("/collections/missing/shares", json!({"identifier": "x", "role": "view"})).json(), json!({"error": "Collection not found"}));
    assert_eq!(c.post(&base, json!({"identifier": "nobody@test.local", "role": "view"})).json(), json!({"error": "User not found"}));
    assert_eq!(c.post(&base, json!({"identifier": "OWNER-collections@test.local", "role": "view"})).json(), json!({"error": "Cannot share with yourself"}));
    // identifier.toLowerCase on a non-string throws → 500.
    assert_eq!(c.post(&base, json!({"identifier": 7, "role": "view"})).status, 500);
    // Lookup by exact name works too.
    let r = c.post(&base, json!({"identifier": "Viewer User", "role": "view"}));
    assert_eq!(r.json()["share"]["granteeUserId"], json!(w.viewer_id));
    let first_id = r.json()["share"]["id"].clone();
    // Upsert updates the role in place.
    let r = c.post(&base, json!({"identifier": "viewer-collections@test.local", "role": "edit"}));
    assert_eq!((r.json()["share"]["id"].clone(), r.json()["share"]["role"].clone()), (first_id, json!("edit")));

    let shares = c.get(&base).json();
    assert_eq!(shares["shares"].as_array().unwrap().len(), 1);
    assert_eq!(shares["shares"][0]["granteeUser"]["email"], "viewer-collections@test.local");
    assert_eq!(w.viewer.get(&base).json(), json!({"error": "Collection not found"}));

    let p = format!("{base}/{}", w.viewer_id);
    assert_eq!(c.patch(&p, json!({"role": "x"})).json(), json!({"error": "role must be view or edit"}));
    assert_eq!(c.patch(&format!("{base}/nobody"), json!({"role": "view"})).json(), json!({"error": "Share not found"}));
    assert_eq!(c.patch(&p, json!({"role": "view"})).json(), json!({"success": true}));
    assert_eq!(c.get(&base).json()["shares"][0]["role"], "view");
    assert_eq!(c.send("PATCH", &p, None).status, 500);
    assert_eq!(w.viewer.delete(&p).json(), json!({"error": "Collection not found"}));
    assert_eq!(c.delete(&p).json(), json!({"success": true}));
    assert_eq!(c.get(&base).json(), json!({"shares": []}));

    // share-resolve: excludes owner and existing grantees, needs >= 2 chars.
    let sr = format!("/collections/{col}/share-resolve");
    assert_eq!(c.get(&format!("{sr}?q=e")).json(), json!({"users": []}));
    assert_eq!(c.get("/collections/missing/share-resolve?q=ed").json(), json!({"error": "Collection not found"}));
    let found = c.get(&format!("{sr}?q=collections")).json();
    let emails: Vec<&str> = found["users"].as_array().unwrap().iter().map(|u| u["email"].as_str().unwrap()).collect();
    assert_eq!(emails.len(), 2);
    assert!(!emails.contains(&"owner-collections@test.local"));
    c.post(&base, json!({"identifier": "editor-collections@test.local", "role": "edit"}));
    let found = c.get(&format!("{sr}?q=EDITOR")).json();
    assert_eq!(found, json!({"users": []}));
}

#[test]
fn library_routes() {
    let s = auth_server();
    let (c, uid) = user(&s, "lib@test.local", "Lib");
    assert_eq!(c.get("/library").json(), json!({"items": []}));
    assert_eq!(c.put("/library", json!({"items": "nope"})).json(), json!({"error": "Items must be an array"}));
    assert_eq!(c.send("PUT", "/library", None).status, 500);
    let items = json!([{"id": "lib1", "elements": []}]);
    assert_eq!(c.put("/library", json!({"items": items})).json(), json!({"items": items}));
    assert_eq!(c.get("/library").json(), json!({"items": items}));
    let stored: String = s.db().query_row(r#"SELECT "items" FROM "Library" WHERE "id" = ?1"#, [format!("user_{uid}")], |r| r.get(0)).unwrap();
    assert_eq!(stored, items.to_string());
    assert_eq!(c.put("/library", json!({"items": []})).json(), json!({"items": []}));
    assert_eq!(s.client().get("/library").status, 401);
}
