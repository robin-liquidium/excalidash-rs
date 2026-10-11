//! Port of drawings.integration.ts and user-sandboxing.integration.ts, plus the
//! main success/error branches of the drawing CRUD routes.
mod common;
#[path = "dashboard_support/mod.rs"]
mod support;

#[allow(unused_imports)]
use common::*;
use excalidash_rs::security::{
    configure_max_data_url_size, max_data_url_size, reset_security_settings, sanitize_drawing_data,
    validate_imported_drawing, SanitizeFailure,
};
use serde_json::{json, Value};
use std::sync::Mutex;
use support::*;

// ---------------------------------------------------------------------------
// drawings.integration.ts — "Security Sanitization - Image Data URLs"
// (pure sanitizer behaviour; security settings are process-global, so serialize)

static SECURITY_LOCK: Mutex<()> = Mutex::new(());

const SMALL_PNG: &str =
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8DwHwAFBQIAX8jx0gAAAABJRU5ErkJggg==";

fn large_image_data_url() -> String {
    format!("data:image/png;base64,{}", SMALL_PNG.repeat(500))
}

fn sample_files(count: usize, large: bool) -> Value {
    let mut m = serde_json::Map::new();
    for i in 0..count {
        let id = format!("file-{i}-1700000000000");
        let url = if large { format!("data:image/png;base64,{}", SMALL_PNG.repeat(10000)) } else { format!("data:image/png;base64,{SMALL_PNG}") };
        m.insert(id.clone(), json!({"id": id, "mimeType": "image/png", "dataURL": url, "created": 1, "lastRetrieved": 1}));
    }
    Value::Object(m)
}

fn sanitize_files_only(files: &Value) -> Result<Value, SanitizeFailure> {
    sanitize_drawing_data(&json!([]), &json!({"viewBackgroundColor": "#ffffff"}), Some(files), None)
        .map(|s| s.files.unwrap_or(Value::Null))
}

fn sanitize_preview(preview: &str) -> String {
    sanitize_drawing_data(&json!([]), &json!({"viewBackgroundColor": "#ffffff"}), Some(&json!({})), Some(&json!(preview)))
        .unwrap()
        .preview
        .unwrap()
        .as_str()
        .unwrap()
        .to_string()
}

#[test]
fn sanitizer_size_limits_are_configurable() {
    let _g = SECURITY_LOCK.lock().unwrap();
    reset_security_settings();
    assert_eq!(max_data_url_size(), 10 * 1024 * 1024);
    configure_max_data_url_size(5 * 1024 * 1024);
    assert_eq!(max_data_url_size(), 5 * 1024 * 1024);

    configure_max_data_url_size(1000);
    let big = json!({"file-1": {"id": "file-1", "mimeType": "image/png", "dataURL": format!("data:image/png;base64,{}", "A".repeat(2000)), "created": 1}});
    match sanitize_files_only(&big) {
        Err(SanitizeFailure::Drawing(e)) => {
            assert_eq!(e.status, 413);
            assert_eq!(e.file_id, "file-1");
        }
        other => panic!("expected 413, got {other:?}"),
    }

    configure_max_data_url_size(5000);
    let small_url = format!("data:image/png;base64,{}", "A".repeat(100));
    let out = sanitize_files_only(&json!({"file-1": {"id": "file-1", "dataURL": small_url}})).unwrap();
    assert_eq!(out["file-1"]["dataURL"], json!(small_url));

    configure_max_data_url_size(100);
    assert_eq!(max_data_url_size(), 100);
    reset_security_settings();
    assert_eq!(max_data_url_size(), 10 * 1024 * 1024);
}

#[test]
fn sanitizer_preserves_image_data_urls() {
    let _g = SECURITY_LOCK.lock().unwrap();
    reset_security_settings();
    // small
    let files = sample_files(1, false);
    let out = sanitize_files_only(&files).unwrap();
    assert_eq!(out, Value::Object(files.as_object().unwrap().iter().map(|(k, v)| {
        let mut v = v.clone();
        v["created"] = json!("");
        v["lastRetrieved"] = json!("");
        (k.clone(), v)
    }).collect()));
    // svg
    let svg = format!(
        "data:image/svg+xml;base64,{}",
        excalidash_rs::util::b64_std(b"<svg xmlns='http://www.w3.org/2000/svg' width='120' height='80'><rect width='120' height='80' fill='#4f46e5'/></svg>")
    );
    let out = sanitize_files_only(&json!({"file-1": {"id": "file-1", "mimeType": "image/svg+xml", "dataURL": svg}})).unwrap();
    assert_eq!(out["file-1"]["dataURL"], json!(svg));
    // large (issue #17) and multiple large
    let files = sample_files(3, true);
    let out = sanitize_files_only(&files).unwrap();
    for (id, f) in files.as_object().unwrap() {
        assert!(f["dataURL"].as_str().unwrap().len() > 10000);
        assert_eq!(out[id]["dataURL"], f["dataURL"]);
    }
    // case-insensitive MIME
    let upper = format!("data:IMAGE/PNG;base64,{SMALL_PNG}");
    let out = sanitize_files_only(&json!({"file-1": {"id": "file-1", "mimeType": "IMAGE/PNG", "dataURL": upper}})).unwrap();
    assert_eq!(out["file-1"]["dataURL"], json!(upper));
    // exactly 10000 / 10001 chars
    for n in [10000usize, 10001] {
        let base = "data:image/png;base64,";
        let url = format!("{base}{}", "A".repeat(n - base.len()));
        let out = sanitize_drawing_data(&json!([]), &json!({}), Some(&json!({"b": {"id": "b", "dataURL": url}})), None).unwrap();
        assert_eq!(out.files.unwrap()["b"]["dataURL"].as_str().unwrap().len(), n);
    }
}

#[test]
fn sanitizer_rejects_malicious_data_urls_and_cleans_metadata() {
    let _g = SECURITY_LOCK.lock().unwrap();
    reset_security_settings();
    for bad in ["data:image/png;base64,<script>alert('xss')</script>AAAA", "javascript:alert('xss')"] {
        match sanitize_files_only(&json!({"file-1": {"id": "file-1", "mimeType": "image/png", "dataURL": bad}})) {
            Err(SanitizeFailure::Drawing(e)) => {
                assert_eq!(e.status, 400);
                assert_eq!(e.file_id, "file-1");
            }
            other => panic!("expected 400 for {bad}, got {other:?}"),
        }
    }
    assert_eq!(sanitize_files_only(&Value::Null).unwrap(), Value::Null);
    assert_eq!(sanitize_files_only(&json!({})).unwrap(), json!({}));
    let ok_url = format!("data:image/png;base64,{SMALL_PNG}");
    let out = sanitize_files_only(&json!({"file-1": {"id": "<script>alert('xss')</script>", "mimeType": "image/png<script>", "dataURL": ok_url}})).unwrap();
    assert!(!out["file-1"]["id"].as_str().unwrap().contains("<script>"));
    assert!(!out["file-1"]["mimeType"].as_str().unwrap().contains("<script>"));
    assert_eq!(out["file-1"]["dataURL"], json!(ok_url));
}

#[test]
fn sanitizer_preview_svg_handling() {
    let _g = SECURITY_LOCK.lock().unwrap();
    let p = sanitize_preview(concat!(
        r#"<svg version="1.1" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 728.39453125 606.908203125" width="1456.7890625" height="1213.81640625" preserveAspectRatio="xMidYMid meet">"#,
        r##"<rect x="0" y="0" width="728.39453125" height="606.908203125" fill="#ffffff"></rect>"##,
        r##"<path d="M0 0 L20 20" stroke="#000" stroke-linecap="round"></path>"##,
        "</svg>"
    ));
    assert!(p.contains(r#"viewBox="0 0 728.39453125 606.908203125""#), "{p}");
    assert!(p.contains(r#"preserveAspectRatio="xMidYMid meet""#), "{p}");
    assert!(p.contains(r#"stroke-linecap="round""#), "{p}");
    assert!(p.contains(r#"xmlns="http://www.w3.org/2000/svg""#), "{p}");

    let p = sanitize_preview(r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 40 40"><image x="0" y="0" width="40" height="40" href="data:image/png;base64,AAAA"></image></svg>"#);
    assert!(p.contains("<image"), "{p}");
    assert!(p.contains(r#"href="data:image/png;base64,AAAA""#), "{p}");

    let p = sanitize_preview(r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 40 40"><image x="0" y="0" width="40" height="40" href="javascript:alert(1)"></image><rect x="0" y="0" width="10" height="10" fill="#000"></rect></svg>"##);
    assert!(!p.contains("<image"), "{p}");
    assert!(p.contains("<rect"), "{p}");

    let p = sanitize_preview(concat!(
        r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">"#,
        r#"<defs><pattern id="p1" width="1" height="1" patternUnits="objectBoundingBox">"#,
        r#"<image href="data:image/png;base64,AAAA" width="100" height="100"></image>"#,
        "</pattern></defs>",
        r#"<rect x="0" y="0" width="100" height="100" fill="url(#p1)"></rect>"#,
        "</svg>"
    ));
    for needle in ["<defs>", "<pattern", r#"id="p1""#, "<image", r#"fill="url(#p1)""#] {
        assert!(p.contains(needle), "{needle} missing in {p}");
    }
}

#[test]
fn validate_imported_drawing_with_files() {
    let _g = SECURITY_LOCK.lock().unwrap();
    reset_security_settings();
    let files = sample_files(2, true);
    let first = files.as_object().unwrap().keys().next().unwrap().clone();
    let drawing = json!({
        "elements": [{"id": "img-1", "type": "image", "fileId": first, "x": 0, "y": 0, "width": 100, "height": 100, "angle": 0, "version": 1, "versionNonce": 1}],
        "appState": {"viewBackgroundColor": "#ffffff"},
        "files": files,
    });
    assert!(validate_imported_drawing(&drawing));
    let bad = json!({"elements": [], "appState": {"viewBackgroundColor": "#ffffff"}, "files": {"file-1": {"id": "file-1", "dataURL": "javascript:alert('xss')"}}});
    assert!(!validate_imported_drawing(&bad));
}

#[test]
fn issue_17_regression_large_image_preserved() {
    let _g = SECURITY_LOCK.lock().unwrap();
    reset_security_settings();
    let url = large_image_data_url();
    assert!(url.len() > 10000);
    let out = sanitize_drawing_data(
        &json!([{"id": "image-element", "type": "image", "fileId": "user-uploaded-image", "x": 0, "y": 0, "width": 400, "height": 300, "angle": 0, "version": 1, "versionNonce": 1}]),
        &json!({"viewBackgroundColor": "#ffffff"}),
        Some(&json!({"user-uploaded-image": {"id": "user-uploaded-image", "mimeType": "image/png", "dataURL": url, "created": 1, "lastRetrieved": 1}})),
        Some(&Value::Null),
    )
    .unwrap();
    assert_eq!(out.files.unwrap()["user-uploaded-image"]["dataURL"], json!(url));
}

// ---------------------------------------------------------------------------
// drawings.integration.ts — "Drawing API - Database Round-Trip" (through the HTTP API)

#[test]
fn image_data_urls_survive_db_round_trip_through_api() {
    let s = auth_server();
    let (c, uid) = user(&s, "roundtrip@test.local", "Round Trip");
    let large = large_image_data_url();
    let small = format!("data:image/png;base64,{SMALL_PNG}");
    let files = json!({
        "small-image": {"id": "small-image", "mimeType": "image/png", "dataURL": small},
        "large-image": {"id": "large-image", "mimeType": "image/png", "dataURL": large},
    })
    .to_string();
    let id = insert_drawing(&s, &uid, NewDrawing { name: "Multi-Image Test", files: Some(&files), ..Default::default() });
    let r = c.get(&format!("/drawings/{id}"));
    assert_eq!(r.status, 200, "{}", r.text());
    let body = r.json();
    assert_eq!(body["files"]["small-image"]["dataURL"], json!(small));
    assert_eq!(body["files"]["large-image"]["dataURL"].as_str().unwrap().len(), large.len());
    assert_eq!(body["files"]["large-image"]["dataURL"], json!(large));

    // Update cycle (direct DB update like upstream), then read back.
    let files2 = json!({"file-x": {"id": "file-x", "mimeType": "image/png", "dataURL": large}}).to_string();
    s.db().execute(r#"UPDATE "Drawing" SET "files" = ?1 WHERE "id" = ?2"#, [&files2, &id]).unwrap();
    let r = c.get(&format!("/drawings/{id}"));
    assert_eq!(r.json()["files"]["file-x"]["dataURL"], json!(large));
}

// ---------------------------------------------------------------------------
// user-sandboxing.integration.ts (through the HTTP API)

#[test]
fn users_cannot_see_or_touch_each_others_drawings_and_collections() {
    let s = auth_server();
    let (a, a_id) = user(&s, "usera@test.com", "User A");
    let (b, b_id) = user(&s, "userb@test.com", "User B");
    let da = simple_drawing(&s, &a_id, "User A Drawing");
    let db = simple_drawing(&s, &b_id, "User B Drawing");

    let la = a.get("/drawings").json();
    let lb = b.get("/drawings").json();
    assert_eq!(ids(&la), vec![da.clone()]);
    assert_eq!(la["drawings"][0]["name"], "User A Drawing");
    assert_eq!(ids(&lb), vec![db.clone()]);
    assert_eq!(lb["drawings"][0]["name"], "User B Drawing");

    // B cannot read/update/delete/duplicate A's drawing by id.
    assert_eq!(b.get(&format!("/drawings/{da}")).status, 404);
    assert_eq!(b.put(&format!("/drawings/{da}"), json!({"name": "x"})).status, 404);
    assert_eq!(b.delete(&format!("/drawings/{da}")).status, 404);
    assert_eq!(b.post(&format!("/drawings/{da}/duplicate"), json!({})).status, 404);
    assert_eq!(b.get(&format!("/drawings/{da}/preview")).status, 404);
    assert_eq!(drawing_row(&s, &da).unwrap().0, "User A Drawing");

    // Collections are isolated too.
    let ca = insert_collection(&s, &a_id, "User A Collection");
    let cols: Vec<String> = b.get("/collections").json().as_array().unwrap().iter().map(|c| c["id"].as_str().unwrap().to_string()).collect();
    assert!(!cols.contains(&ca));
    assert_eq!(b.put(&format!("/collections/{ca}"), json!({"name": "hijack"})).status, 404);
    assert_eq!(b.delete(&format!("/collections/{ca}")).status, 404);
    assert_eq!(b.get(&format!("/drawings?collectionId={ca}")).status, 404);
}

#[test]
fn drawings_cache_keys_are_user_scoped() {
    use excalidash_rs::drawings_cache::{CacheKeyParts, DrawingsCache};
    let k = |user_id, search_term, include_data| {
        DrawingsCache::build_key(&CacheKeyParts {
            user_id,
            search_term,
            collection_filter: "default",
            include_data,
            sort_field: "updatedAt",
            sort_direction: "desc",
        })
    };
    assert_ne!(k("user-a-id", "", false), k("user-b-id", "", false));
    assert_eq!(k("same-user", "test", true), k("same-user", "test", true));
}

// ---------------------------------------------------------------------------
// Route behaviour: list / read / create / update / delete / duplicate / preview

#[test]
fn list_drawings_filters_sorts_paginates_and_caches() {
    let s = auth_server();
    let (c, uid) = user(&s, "lister@test.local", "Lister");
    let col = insert_collection(&s, &uid, "Col");
    let d1 = insert_drawing(&s, &uid, NewDrawing { name: "Alpha", ..Default::default() });
    std::thread::sleep(std::time::Duration::from_millis(5));
    let d2 = insert_drawing(&s, &uid, NewDrawing { name: "beta", collection_id: Some(&col), ..Default::default() });
    std::thread::sleep(std::time::Duration::from_millis(5));
    // Legacy trash id is migrated by /collections, but the list filter accepts both forms.
    s.db().execute(r#"INSERT INTO "Collection" ("id","name","userId","createdAt","updatedAt") VALUES (?1,'Trash',?2,0,0)"#, [format!("trash:{uid}"), uid.clone()]).unwrap();
    let d3 = insert_drawing(&s, &uid, NewDrawing { name: "Gamma", collection_id: Some(&format!("trash:{uid}")), ..Default::default() });

    let r = c.get("/drawings");
    assert_eq!(r.status, 200);
    assert_eq!(r.header("x-cache").as_deref(), Some("MISS"));
    assert_eq!(r.header("content-type").as_deref(), Some("application/json"));
    let body = r.json();
    assert_eq!(ids(&body), vec![d2.clone(), d1.clone()]);
    assert_eq!(body["totalCount"], 2);
    assert_eq!(body["limit"], 50);
    assert_eq!(body["offset"], 0);
    let keys: Vec<&String> = body["drawings"][0].as_object().unwrap().keys().collect();
    assert_eq!(keys, ["id", "name", "collectionId", "version", "createdAt", "updatedAt", "userId", "creatorName"]);
    assert_eq!(body["drawings"][0]["creatorName"], "Lister");
    // Second identical request is served from the cache with the same body.
    let r2 = c.get("/drawings");
    assert_eq!(r2.header("x-cache").as_deref(), Some("HIT"));
    assert_eq!(r2.body, r.body);
    assert_eq!(r2.header("etag"), r.header("etag"));

    // Trash view maps the internal id to "trash".
    let t = c.get("/drawings?collectionId=trash").json();
    assert_eq!(ids(&t), vec![d3.clone()]);
    assert_eq!(t["drawings"][0]["collectionId"], "trash");
    // Unfiled.
    assert_eq!(ids(&c.get("/drawings?collectionId=null").json()), vec![d1.clone()]);
    // Specific collection.
    assert_eq!(ids(&c.get(&format!("/drawings?collectionId={col}")).json()), vec![d2.clone()]);
    assert_eq!(c.get("/drawings?collectionId=missing").json(), json!({"error": "Collection not found"}));
    // Search is LIKE without wildcard escaping (Prisma `contains`): case-insensitive on
    // SQLite, case-sensitive on PostgreSQL.
    if is_pg() {
        assert!(ids(&c.get("/drawings?search=ALP").json()).is_empty());
        assert_eq!(ids(&c.get("/drawings?search=Alp").json()), vec![d1.clone()]);
    } else {
        assert_eq!(ids(&c.get("/drawings?search=ALP").json()), vec![d1.clone()]);
    }
    assert_eq!(ids(&c.get("/drawings?search=%25").json()).len(), 2);
    assert_eq!(ids(&c.get("/drawings?search=b_ta").json()), vec![d2.clone()]);
    // Sorting by name defaults to asc (binary collation: uppercase first).
    assert_eq!(ids(&c.get("/drawings?sortField=name").json()), vec![d1.clone(), d2.clone()]);
    assert_eq!(ids(&c.get("/drawings?sortField=name&sortDirection=desc").json()), vec![d2.clone(), d1.clone()]);
    // Pagination clamps.
    let p = c.get("/drawings?limit=1&offset=1").json();
    assert_eq!(ids(&p), vec![d1.clone()]);
    assert_eq!((p["limit"].clone(), p["offset"].clone(), p["totalCount"].clone()), (json!(1), json!(1), json!(2)));
    let p = c.get("/drawings?limit=0&offset=-4").json();
    assert_eq!((p["limit"].clone(), p["offset"].clone()), (json!(1), json!(0)));
    let p = c.get("/drawings?limit=9999&offset=abc").json();
    assert_eq!((p["limit"].clone(), p["offset"].clone()), (json!(200), json!(0)));
    // includeData returns parsed scene fields + full model keys.
    let full = c.get("/drawings?includeData=TRUE&collectionId=null").json();
    let keys: Vec<&String> = full["drawings"][0].as_object().unwrap().keys().collect();
    assert_eq!(
        keys,
        ["id", "name", "elements", "appState", "files", "preview", "version", "userId", "collectionId", "createdAt", "updatedAt", "creatorName"]
    );
    assert_eq!(full["drawings"][0]["elements"], json!([]));
    // Writes invalidate the cache.
    c.post("/drawings", json!({"name": "New"}));
    assert_eq!(c.get("/drawings").header("x-cache").as_deref(), Some("MISS"));
    // Unauthenticated.
    assert_eq!(s.client().get("/drawings").status, 401);
}

#[test]
fn get_drawing_owner_view_and_errors() {
    let s = auth_server();
    let (c, uid) = user(&s, "reader@test.local", "Reader");
    let id = insert_drawing(
        &s,
        &uid,
        NewDrawing { name: "R", elements: Some(r#"[{"id":"a"}]"#), app_state: Some("not-json"), files: Some(""), ..Default::default() },
    );
    let r = c.get(&format!("/drawings/{id}"));
    assert_eq!(r.status, 200);
    let b = r.json();
    let keys: Vec<&String> = b.as_object().unwrap().keys().collect();
    assert_eq!(
        keys,
        ["id", "name", "elements", "appState", "files", "preview", "version", "userId", "collectionId", "createdAt", "updatedAt", "accessLevel"]
    );
    assert_eq!(b["elements"], json!([{"id": "a"}]));
    assert_eq!(b["appState"], json!({})); // parseJsonField fallback
    assert_eq!(b["files"], json!({}));
    assert_eq!(b["accessLevel"], "owner");
    assert_eq!(c.get("/drawings/nope").json(), json!({"error": "Drawing not found", "message": "Drawing does not exist"}));
    // Anonymous on a private drawing: 404 (no stale credentials).
    assert_eq!(s.client().get(&format!("/drawings/{id}")).status, 404);
}

#[test]
fn create_drawing_validation_and_collections() {
    let s = auth_server();
    let (c, uid) = user(&s, "creator@test.local", "Creator");
    let (_o, other) = user(&s, "other@test.local", "Other");

    let r = c.post("/drawings", json!({"elements": [{"id": "e1", "type": "text", "text": "a<b", "x": 1}], "appState": {"viewBackgroundColor": "#fff"}, "preview": "<svg><script>x</script></svg>"}));
    assert_eq!(r.status, 200, "{}", r.text());
    let b = r.json();
    assert_eq!(b["name"], "Untitled Drawing");
    assert_eq!(b["version"], 1);
    assert_eq!(b["preview"], "<svg></svg>");
    assert_eq!(b["files"], json!({}));
    assert_eq!(b["collectionId"], Value::Null);
    assert_eq!(b["userId"], json!(uid));
    assert!(b.get("accessLevel").is_none());
    let keys: Vec<&String> = b.as_object().unwrap().keys().collect();
    assert_eq!(keys, ["id", "name", "elements", "appState", "files", "preview", "version", "userId", "collectionId", "createdAt", "updatedAt"]);

    // Trash target creates the per-user trash collection.
    let r = c.post("/drawings", json!({"name": " Trashed ", "collectionId": "trash"}));
    assert_eq!(r.status, 200);
    assert_eq!(r.json()["collectionId"], "trash");
    assert_eq!(r.json()["name"], "Trashed");
    let id = r.json()["id"].as_str().unwrap().to_string();
    assert_eq!(drawing_row(&s, &id).unwrap().6, Some(format!("trash:{uid}")));

    // Validation errors (production body).
    let invalid = json!({"error": "Validation error", "message": "Invalid request data"});
    for bad in [json!({"name": ""}), json!({"name": 5}), json!({"elements": "x"}), json!({"collectionId": "  "}), json!({"appState": {"gridSize": 5000}}), json!([])] {
        let r = c.post("/drawings", bad.clone());
        assert_eq!((r.status, r.json()), (400, invalid.clone()), "{bad}");
    }
    // Non-JSON body → req.body undefined → validation error.
    let r = c.send_raw("POST", "/drawings", Some(("text/plain".into(), b"hi".to_vec())));
    assert_eq!(r.status, 400);
    // Bad image → DrawingSanitizationError through the error handler.
    let r = c.post("/drawings", json!({"files": {"f": {"dataURL": "javascript:alert(1)"}}}));
    assert_eq!(r.status, 400);
    assert_eq!(r.json(), json!({"error": "Request error", "message": "Image file \"f\" has an invalid image reference and was rejected."}));
    // Imported-file validation.
    let r = c.clone_with_header("x-imported-file", "true").post("/drawings", json!({"name": "x"}));
    assert_eq!(r.json(), json!({"error": "Invalid imported drawing file", "message": "The imported file contains potentially malicious content or invalid structure"}));
    // Collections: missing / other user's without share.
    assert_eq!(c.post("/drawings", json!({"collectionId": "missing"})).json(), json!({"error": "Collection not found"}));
    let foreign = insert_collection(&s, &other, "Theirs");
    let r = c.post("/drawings", json!({"collectionId": foreign}));
    assert_eq!((r.status, r.json()), (403, json!({"error": "No edit access to this collection"})));
    let mine = insert_collection(&s, &uid, "Mine");
    assert_eq!(c.post("/drawings", json!({"collectionId": mine})).json()["collectionId"], json!(mine));
    assert_eq!(s.client().post("/drawings", json!({})).status, 403); // CSRF first
    let mut anon = s.client();
    anon.fetch_csrf();
    assert_eq!(anon.post("/drawings", json!({})).status, 401);
}

#[test]
fn update_drawing_branches() {
    let s = auth_server();
    let (c, uid) = user(&s, "updater@test.local", "Updater");
    let (o, other) = user(&s, "viewer@test.local", "Viewer");
    let id = simple_drawing(&s, &uid, "Orig");

    // Metadata-only update (no version bump, no snapshot).
    let r = c.put(&format!("/drawings/{id}"), json!({"name": "  Renamed  ", "preview": "<svg><script>x</script></svg>"}));
    assert_eq!(r.status, 200, "{}", r.text());
    let b = r.json();
    assert_eq!((b["name"].clone(), b["preview"].clone(), b["version"].clone(), b["accessLevel"].clone()), (json!("Renamed"), json!("<svg></svg>"), json!(1), json!("owner")));
    assert_eq!(count(&s, r#"SELECT COUNT(*) FROM "DrawingSnapshot" WHERE "drawingId" = ?1"#, &id), 0);
    // Empty update → Prisma updateMany count 0 → 404.
    assert_eq!(c.put(&format!("/drawings/{id}"), json!({})).json(), json!({"error": "Drawing not found"}));
    // Scene update bumps version and snapshots the previous state.
    let r = c.put(&format!("/drawings/{id}"), json!({"elements": [{"id": "x", "type": "rectangle"}], "version": 1}));
    assert_eq!(r.json()["version"], 2);
    assert_eq!(count(&s, r#"SELECT COUNT(*) FROM "DrawingSnapshot" WHERE "drawingId" = ?1"#, &id), 1);
    // Stale version → 409.
    let r = c.put(&format!("/drawings/{id}"), json!({"appState": {}, "version": 1}));
    assert_eq!(
        (r.status, r.json()),
        (409, json!({"error": "Conflict", "code": "VERSION_CONFLICT", "message": "Drawing has changed since this editor state was loaded.", "currentVersion": 2}))
    );
    // Versionless scene save retries optimistically.
    assert_eq!(c.put(&format!("/drawings/{id}"), json!({"appState": {"viewBackgroundColor": "#000"}})).json()["version"], 3);
    // Validation.
    assert_eq!(c.put(&format!("/drawings/{id}"), json!({"version": 0, "elements": []})).status, 400);
    assert_eq!(c.put(&format!("/drawings/{id}"), json!({"name": ""})).json(), json!({"error": "Validation error", "message": "Invalid request data"}));
    // Collection moves.
    assert_eq!(c.put(&format!("/drawings/{id}"), json!({"collectionId": "nope"})).json(), json!({"error": "Collection not found"}));
    let r = c.put(&format!("/drawings/{id}"), json!({"collectionId": "trash"}));
    assert_eq!(r.json()["collectionId"], "trash");
    assert_eq!(drawing_row(&s, &id).unwrap().6, Some(format!("trash:{uid}")));
    assert_eq!(c.put(&format!("/drawings/{id}"), json!({"collectionId": null})).json()["collectionId"], Value::Null);
    // Editors (non-owners) cannot move drawings.
    insert_permission(&s, &id, &other, "edit", &uid);
    let r = o.put(&format!("/drawings/{id}"), json!({"collectionId": null}));
    assert_eq!((r.status, r.json()), (403, json!({"error": "Forbidden", "message": "Only the owner can move drawings between collections"})));
    let r = o.put(&format!("/drawings/{id}"), json!({"name": "By editor"}));
    assert_eq!((r.status, r.json()["accessLevel"].clone()), (200, json!("edit")));
    // Missing drawing.
    assert_eq!(c.put("/drawings/missing", json!({"name": "x"})).json(), json!({"error": "Drawing not found", "message": "Drawing does not exist"}));
}

#[test]
fn delete_and_duplicate_drawing() {
    let s = auth_server_with(&[("ENABLE_AUDIT_LOGGING", "true")]);
    let (c, uid) = user(&s, "dup@test.local", "Dup");
    let files = json!({"img": {"id": "img", "dataURL": "/api/files/SRC/img"}}).to_string();
    let id = insert_drawing(&s, &uid, NewDrawing { name: "Source", files: Some(&files), preview: Some("<svg>/api/files/SRC/img</svg>"), version: Some(4), ..Default::default() });
    s.db().execute(r#"UPDATE "Drawing" SET "files" = replace("files",'SRC',"id"), "preview" = replace("preview",'SRC',"id")"#, []).unwrap();
    insert_db_file(&s, &id, "img", &[1, 2, 3]);

    let r = c.post(&format!("/drawings/{id}/duplicate"), json!({}));
    assert_eq!(r.status, 200, "{}", r.text());
    let b = r.json();
    let new_id = b["id"].as_str().unwrap().to_string();
    assert_ne!(new_id, id);
    assert_eq!(b["name"], "Source (Copy)");
    assert_eq!(b["version"], 1);
    assert_eq!(b["files"]["img"]["dataURL"], json!(format!("/api/files/{new_id}/img")));
    assert_eq!(b["preview"], json!(format!("<svg>/api/files/{new_id}/img</svg>")));
    let copied: Vec<u8> = s.db().query_row(r#"SELECT "data" FROM "DrawingFile" WHERE "drawingId" = ?1 AND "fileId" = 'img'"#, [&new_id], |r| r.get(0)).unwrap();
    assert_eq!(copied, vec![1, 2, 3]);
    assert_eq!(c.post("/drawings/missing/duplicate", json!({})).json(), json!({"error": "Original drawing not found"}));

    let r = c.delete(&format!("/drawings/{id}"));
    assert_eq!((r.status, r.json()), (200, json!({"success": true})));
    assert!(drawing_row(&s, &id).is_none());
    assert_eq!(count(&s, r#"SELECT COUNT(*) FROM "DrawingFile" WHERE "drawingId" = ?1"#, &id), 0);
    assert_eq!(count(&s, r#"SELECT COUNT(*) FROM "AuditLog" WHERE "action" = ?1"#, "drawing_deleted"), 1);
    assert_eq!(c.delete(&format!("/drawings/{id}")).json(), json!({"error": "Drawing not found"}));
}

#[test]
fn preview_route_etag_and_access() {
    let s = auth_server();
    let (c, uid) = user(&s, "preview@test.local", "Preview");
    let id = insert_drawing(&s, &uid, NewDrawing { name: "P", preview: Some("<svg/>"), ..Default::default() });
    let updated = drawing_row(&s, &id).unwrap().7;
    let r = c.get(&format!("/drawings/{id}/preview"));
    assert_eq!(r.status, 200);
    assert_eq!(r.json(), json!({"preview": "<svg/>", "updatedAt": updated}));
    let etag = format!("W/\"preview-{id}-{updated}\"");
    assert_eq!(r.header("etag"), Some(etag.clone()));
    assert_eq!(r.header("cache-control").as_deref(), Some("private, max-age=0, must-revalidate"));
    let r = c.clone_with_header("if-none-match", &etag).get(&format!("/drawings/{id}/preview"));
    assert_eq!(r.status, 304);
    assert!(r.body.is_empty());
    assert_eq!(s.client().get(&format!("/drawings/{id}/preview")).json(), json!({"error": "Drawing not found", "message": "Drawing does not exist"}));
}

#[test]
fn unknown_methods_fall_through_to_express_404() {
    let s = auth_server();
    let (c, _) = user(&s, "methods@test.local", "Methods");
    let r = c.send("PATCH", "/drawings/abc", Some(&json!({})));
    assert_eq!(r.status, 404);
    assert!(r.text().contains("Cannot PATCH /drawings/abc"), "{}", r.text());
}
