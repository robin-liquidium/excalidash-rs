//! drawing-file-store.integration.ts (database-bytes mode) + files routes parity.
//! Scene-PUT/duplicate/export cases live with the dashboard/import-export ports;
//! the interning logic itself is unit-tested in src/files.rs.
mod common;
use common::*;
use serde_json::{json, Value};

const TINY_PNG_B64: &str =
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8/58BAwAI/AL+hc2rNAAAAABJRU5ErkJggg==";

fn png_bytes() -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(TINY_PNG_B64).unwrap()
}

struct Ctx {
    s: TestServer,
    owner: TestClient,
    owner_id: String,
    other: TestClient,
    other_id: String,
}

fn setup(env: &[(&str, &str)]) -> Ctx {
    let s = TestServer::start(env);
    enable_auth(&s);
    let owner_id = seed_user(&s, "owner@test.local", "Owner", "USER");
    let other_id = seed_user(&s, "other@test.local", "Other", "USER");
    let owner = session_client(&s, &owner_id, "owner@test.local");
    let other = session_client(&s, &other_id, "other@test.local");
    Ctx { s, owner, owner_id, other, other_id }
}

pub fn create_drawing(s: &TestServer, user_id: &str, name: &str, elements: &Value, files: &Value, version: i64) -> String {
    let id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().timestamp_millis();
    s.db()
        .execute(
            r#"INSERT INTO "Drawing" ("id","name","elements","appState","files","userId","version","createdAt","updatedAt")
               VALUES (?1,?2,?3,'{}',?4,?5,?6,?7,?7)"#,
            excalidash_rs::sql::params![id, name, elements.to_string(), files.to_string(), user_id, version, now],
        )
        .unwrap();
    id
}

fn upload(c: &TestClient, drawing: &str, file: &str, body: Vec<u8>, ct: &str) -> Resp {
    c.send_raw("PUT", &format!("/drawings/{drawing}/files/{file}"), Some((ct.to_string(), body)))
}

fn row(s: &TestServer, drawing: &str, file: &str) -> Option<(String, String, i64, Option<Vec<u8>>)> {
    s.db()
        .query_row(
            r#"SELECT "storage","mimeType","sizeBytes","data" FROM "DrawingFile" WHERE "drawingId"=?1 AND "fileId"=?2"#,
            [drawing, file],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .ok()
}

fn count(s: &TestServer, drawing: &str) -> i64 {
    s.db()
        .query_row(r#"SELECT COUNT(*) FROM "DrawingFile" WHERE "drawingId"=?1"#, [drawing], |r| r.get(0))
        .unwrap()
}

#[test]
fn stores_raw_bytes_and_serves_them_with_immutable_etag() {
    let t = setup(&[]);
    let d = create_drawing(&t.s, &t.owner_id, "Store Test", &json!([]), &json!({}), 1);
    let put = upload(&t.owner, &d, "img-1", png_bytes(), "image/png");
    assert_eq!(put.status, 200, "{}", put.text());
    assert_eq!(put.json(), json!({"url": format!("/api/files/{d}/img-1"), "fileId": "img-1"}));
    let (storage, mime, size, data) = row(&t.s, &d, "img-1").unwrap();
    assert_eq!((storage.as_str(), mime.as_str(), size), ("db", "image/png", png_bytes().len() as i64));
    assert_eq!(data.unwrap(), png_bytes());

    let get = t.owner.get(&format!("/files/{d}/img-1"));
    assert_eq!(get.status, 200);
    assert!(get.header("content-type").unwrap().contains("image/png"));
    assert_eq!(get.header("cache-control").as_deref(), Some("private, max-age=31536000, immutable"));
    assert_eq!(get.header("etag").as_deref(), Some("\"img-1\""));
    assert_eq!(get.header("content-length").as_deref(), Some(png_bytes().len().to_string().as_str()));
    assert_eq!(get.body, png_bytes());
}

#[test]
fn returns_304_when_if_none_match_matches() {
    let t = setup(&[]);
    let d = create_drawing(&t.s, &t.owner_id, "Store Test", &json!([]), &json!({}), 1);
    upload(&t.owner, &d, "img-1", png_bytes(), "image/png");
    let c = session_client(&t.s, &t.owner_id, "owner@test.local").with_header("If-None-Match", "\"img-1\"");
    let r = c.get(&format!("/files/{d}/img-1"));
    assert_eq!(r.status, 304);
    assert_eq!(r.header("etag").as_deref(), Some("\"img-1\""));
    assert!(r.body.is_empty());
}

#[test]
fn reupload_is_idempotent_noop() {
    let t = setup(&[]);
    let d = create_drawing(&t.s, &t.owner_id, "Store Test", &json!([]), &json!({}), 1);
    upload(&t.owner, &d, "img-1", png_bytes(), "image/png");
    let second = upload(&t.owner, &d, "img-1", vec![9, 9, 9], "image/jpeg");
    assert_eq!(second.status, 200);
    assert_eq!(second.json(), json!({"url": format!("/api/files/{d}/img-1"), "fileId": "img-1"}));
    assert_eq!(count(&t.s, &d), 1);
    assert_eq!(row(&t.s, &d, "img-1").unwrap().3.unwrap(), png_bytes());
}

#[test]
fn rejects_unsupported_content_type_with_415() {
    let t = setup(&[]);
    let d = create_drawing(&t.s, &t.owner_id, "Store Test", &json!([]), &json!({}), 1);
    let r = upload(&t.owner, &d, "img-1", vec![1, 2, 3], "application/pdf");
    assert_eq!(r.status, 415);
    assert_eq!(
        r.json(),
        json!({
            "error": "Unsupported media type",
            "message": "Content-Type must be one of: image/png, image/jpeg, image/gif, image/webp, image/avif, image/bmp, image/svg+xml",
        })
    );
}

#[test]
fn non_editor_upload_is_404_and_viewer_too() {
    let t = setup(&[]);
    let d = create_drawing(&t.s, &t.owner_id, "Store Test", &json!([]), &json!({}), 1);
    let r = upload(&t.other, &d, "img-1", png_bytes(), "image/png");
    assert_eq!(r.status, 404);
    assert_eq!(r.json(), json!({"error": "Drawing not found"}));
    assert_eq!(count(&t.s, &d), 0);
    // A view-only collaborator can read but not upload.
    let now = chrono::Utc::now().timestamp_millis();
    t.s.db()
        .execute(
            r#"INSERT INTO "DrawingPermission" ("id","drawingId","granteeUserId","permission","createdByUserId","createdAt","updatedAt")
               VALUES (?1,?2,?3,'view',?4,?5,?5)"#,
            excalidash_rs::sql::params![uuid::Uuid::new_v4().to_string(), d, t.other_id, t.owner_id, now],
        )
        .unwrap();
    assert_eq!(upload(&t.other, &d, "img-1", png_bytes(), "image/png").status, 404);
    upload(&t.owner, &d, "img-1", png_bytes(), "image/png");
    assert_eq!(t.other.get(&format!("/files/{d}/img-1")).status, 200);
}

#[test]
fn upload_validation_errors() {
    let t = setup(&[("FILE_UPLOAD_MAX_MB", "0.001")]);
    let d = create_drawing(&t.s, &t.owner_id, "Store Test", &json!([]), &json!({}), 1);
    // Empty body.
    let r = upload(&t.owner, &d, "img-1", vec![], "image/png");
    assert_eq!(r.status, 400);
    assert_eq!(r.json(), json!({"error": "Empty request body", "message": "Send the raw image bytes as the request body."}));
    // Too large (limit applies before id/access validation).
    let r = upload(&t.owner, "bad.id", "img-1", vec![0u8; 2000], "image/png");
    assert_eq!(r.status, 413);
    assert_eq!(
        r.json(),
        json!({"error": "File too large", "message": "Uploaded file exceeds the 0.001MB limit. Raise FILE_UPLOAD_MAX_MB to accept larger images."})
    );
    // Invalid id segment.
    let r = upload(&t.owner, &d, "a.b", vec![1], "image/png");
    assert_eq!(r.status, 400);
    assert_eq!(r.json(), json!({"error": "Invalid id segment"}));
    // Unauthenticated.
    let anon = t.s.client();
    let mut anon = anon;
    anon.fetch_csrf();
    let r = upload(&anon, &d, "img-1", vec![1], "image/png");
    assert_eq!(r.status, 401);
}

#[test]
fn get_access_rules_and_not_found() {
    let t = setup(&[]);
    let d = create_drawing(&t.s, &t.owner_id, "Store Test", &json!([]), &json!({}), 1);
    upload(&t.owner, &d, "img-1", png_bytes(), "image/png");
    // Other user / anonymous: 404 "File not found".
    let r = t.other.get(&format!("/files/{d}/img-1"));
    assert_eq!((r.status, r.json()), (404, json!({"error": "File not found"})));
    let anon = t.s.client();
    assert_eq!(anon.get(&format!("/files/{d}/img-1")).status, 404);
    assert_eq!(t.owner.get(&format!("/files/{d}/missing")).json(), json!({"error": "File not found"}));
    assert_eq!(t.owner.get(&format!("/files/{d}/a.b")).json(), json!({"error": "Invalid id segment"}));
    // An active link share opens it to anonymous viewers; expired/revoked ones do not.
    let now = chrono::Utc::now().timestamp_millis();
    let share = uuid::Uuid::new_v4().to_string();
    t.s.db()
        .execute(
            r#"INSERT INTO "DrawingLinkShare" ("id","drawingId","tokenHash","permission","createdByUserId","expiresAt","revokedAt","createdAt","updatedAt")
               VALUES (?1,?2,?3,'view',?4,?5,NULL,?6,?6)"#,
            excalidash_rs::sql::params![share, d, uuid::Uuid::new_v4().to_string(), t.owner_id, now + 60_000, now],
        )
        .unwrap();
    let r = anon.get(&format!("/files/{d}/img-1"));
    assert_eq!(r.status, 200);
    assert_eq!(r.body, png_bytes());
    t.s.db().execute(r#"UPDATE "DrawingLinkShare" SET "expiresAt" = ?1"#, [now - 1]).unwrap();
    assert_eq!(anon.get(&format!("/files/{d}/img-1")).status, 404);
    // A legacy empty db row is "not found".
    t.s.db()
        .execute(
            r#"INSERT INTO "DrawingFile" ("drawingId","fileId","mimeType","sizeBytes","storage","s3Key","data","createdAt")
               VALUES (?1,'empty','image/png',0,'db',NULL,NULL,?2)"#,
            excalidash_rs::sql::params![d, now],
        )
        .unwrap();
    assert_eq!(t.owner.get(&format!("/files/{d}/empty")).status, 404);
    // An s3 row while S3 is disabled is "not found".
    t.s.db()
        .execute(
            r#"INSERT INTO "DrawingFile" ("drawingId","fileId","mimeType","sizeBytes","storage","s3Key","data","createdAt")
               VALUES (?1,'remote','image/png',3,'s3','k/remote.png',NULL,?2)"#,
            excalidash_rs::sql::params![d, now],
        )
        .unwrap();
    assert_eq!(t.owner.get(&format!("/files/{d}/remote")).status, 404);
}

#[test]
fn empty_legacy_row_is_repaired_by_upload() {
    let t = setup(&[]);
    let d = create_drawing(&t.s, &t.owner_id, "Store Test", &json!([]), &json!({}), 1);
    let now = chrono::Utc::now().timestamp_millis();
    t.s.db()
        .execute(
            r#"INSERT INTO "DrawingFile" ("drawingId","fileId","mimeType","sizeBytes","storage","s3Key","data","createdAt")
               VALUES (?1,'image','image/png',0,'db',NULL,NULL,?2)"#,
            excalidash_rs::sql::params![d, now],
        )
        .unwrap();
    assert_eq!(upload(&t.owner, &d, "image", vec![1, 2, 3], "image/gif").status, 200);
    let (_, mime, size, data) = row(&t.s, &d, "image").unwrap();
    assert_eq!((mime.as_str(), size, data.unwrap()), ("image/gif", 3, vec![1, 2, 3]));
}

#[test]
fn files_config_requires_auth() {
    let t = setup(&[]);
    let r = t.owner.get("/files/config");
    assert_eq!((r.status, r.json()), (200, json!({"s3Enabled": false})));
    assert_eq!(t.s.client().get("/files/config").status, 401);
}
