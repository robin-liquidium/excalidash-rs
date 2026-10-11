//! storage.integration.ts + the storage-route parts of file-retention.integration.ts
//! (database-bytes mode; S3 variants live in files_s3.rs behind EXRS_TEST_S3=1).
mod common;
use common::*;
use serde_json::{json, Value};

struct Ctx {
    s: TestServer,
    owner: TestClient,
    owner_id: String,
    other: TestClient,
}

fn setup() -> Ctx {
    let s = TestServer::start(&[]);
    enable_auth(&s);
    let owner_id = seed_user(&s, "owner@test.local", "Owner", "USER");
    let other_id = seed_user(&s, "other@test.local", "Other", "USER");
    let owner = session_client(&s, &owner_id, "owner@test.local");
    let other = session_client(&s, &other_id, "other@test.local");
    Ctx { s, owner, owner_id, other }
}

fn create_drawing(s: &TestServer, user_id: &str, name: &str, elements: Value, files: Value, version: i64) -> String {
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

fn file_entry(id: &str) -> Value {
    json!({"id": id, "mimeType": "image/png", "dataURL": "data:image/png;base64,AAAA", "created": 1700000000000i64})
}

fn image_element(el: &str, file: &str, deleted: bool) -> Value {
    json!({"id": el, "type": "image", "x": 0, "y": 0, "width": 100, "height": 100, "isDeleted": deleted, "fileId": file})
}

fn insert_db_file(s: &TestServer, drawing: &str, file: &str, bytes: &[u8]) {
    s.db()
        .execute(
            r#"INSERT INTO "DrawingFile" ("drawingId","fileId","mimeType","sizeBytes","storage","s3Key","data","createdAt")
               VALUES (?1,?2,'image/png',?3,'db',NULL,?4,?5)"#,
            excalidash_rs::sql::params![drawing, file, bytes.len() as i64, bytes, chrono::Utc::now().timestamp_millis()],
        )
        .unwrap();
}

fn insert_snapshot(s: &TestServer, drawing: &str, elements: &str, files: &str) -> String {
    let id = uuid::Uuid::new_v4().to_string();
    s.db()
        .execute(
            r#"INSERT INTO "DrawingSnapshot" ("id","drawingId","version","elements","appState","files","createdAt")
               VALUES (?1,?2,1,?3,'{}',?4,?5)"#,
            excalidash_rs::sql::params![id, drawing, elements, files, chrono::Utc::now().timestamp_millis()],
        )
        .unwrap();
    id
}

/// Node-compatible `encodeSnapshotField` (brotli "br1:" when it is smaller).
fn encode(value: &str, compressed: bool) -> String {
    excalidash_rs::snapshots::encode_field(value, compressed)
}

fn file_count(s: &TestServer, drawing: &str, file: Option<&str>) -> i64 {
    match file {
        Some(f) => s.db().query_row(
            r#"SELECT COUNT(*) FROM "DrawingFile" WHERE "drawingId"=?1 AND "fileId"=?2"#,
            [drawing, f],
            |r| r.get(0),
        ),
        None => s.db().query_row(r#"SELECT COUNT(*) FROM "DrawingFile" WHERE "drawingId"=?1"#, [drawing], |r| r.get(0)),
    }
    .unwrap()
}

fn drawing_state(s: &TestServer, drawing: &str) -> (Value, Value, i64) {
    s.db()
        .query_row(r#"SELECT "elements","files","version" FROM "Drawing" WHERE "id"=?1"#, [drawing], |r| {
            Ok((
                serde_json::from_str::<Value>(&r.get::<_, String>(0)?).unwrap(),
                serde_json::from_str::<Value>(&r.get::<_, String>(1)?).unwrap(),
                r.get(2)?,
            ))
        })
        .unwrap()
}

fn ids(v: &Value) -> Vec<String> {
    v.as_array().unwrap().iter().map(|e| e["id"].as_str().unwrap().to_string()).collect()
}

fn keys(v: &Value) -> Vec<String> {
    v.as_object().unwrap().keys().cloned().collect()
}

#[test]
fn trim_keeps_historical_image_bytes() {
    for compressed in [false, true] {
        let t = setup();
        let d = create_drawing(
            &t.s,
            &t.owner_id,
            "Historical Image",
            json!([image_element("deleted", "historical", true)]),
            json!({"historical": file_entry("historical")}),
            1,
        );
        let bytes = [1u8, 2, 3, 4];
        insert_db_file(&t.s, &d, "historical", &bytes);
        insert_db_file(&t.s, &d, "unreferenced", &bytes);
        let mut hist = file_entry("historical");
        hist["dataURL"] = json!(format!("/api/files/{d}/historical"));
        hist["description"] = json!("x".repeat(1000));
        let files = encode(&json!({"historical": hist}).to_string(), compressed);
        if compressed {
            assert!(files.starts_with("br1:"));
        }
        insert_snapshot(&t.s, &d, &encode(&json!([image_element("old", "historical", false)]).to_string(), compressed), &files);
        let r = t.owner.post(&format!("/drawings/{d}/trim"), json!({"confirmName": "Historical Image"}));
        assert_eq!(r.status, 200, "{}", r.text());
        assert_eq!(file_count(&t.s, &d, Some("unreferenced")), 0);
        let image = t.owner.get(&format!("/files/{d}/historical"));
        assert_eq!(image.status, 200);
        assert_eq!(image.body, bytes);
        // (History restore is covered by the history route port.)
    }
}

#[test]
fn trim_removes_deleted_elements_and_orphan_entries_and_bumps_version() {
    let t = setup();
    let d = create_drawing(
        &t.s,
        &t.owner_id,
        "Trim Me",
        json!([image_element("el-keep", "file-keep", false), image_element("el-drop", "file-drop", true)]),
        json!({
            "file-keep": file_entry("file-keep"),
            "file-drop": file_entry("file-drop"),
            "file-unreferenced": file_entry("file-unreferenced"),
        }),
        7,
    );
    let r = t.owner.post(&format!("/drawings/{d}/trim"), json!({"confirmName": "Trim Me"}));
    assert_eq!(r.status, 200);
    assert_eq!(
        r.json(),
        json!({"trimmed": {"elementsRemoved": 1, "filesRemoved": 2, "s3ObjectsDeleted": 0, "s3DeleteErrors": 0}})
    );
    let (elements, files, version) = drawing_state(&t.s, &d);
    assert_eq!(ids(&elements), vec!["el-keep"]);
    assert_eq!(keys(&files), vec!["file-keep"]);
    assert_eq!(version, 8);
}

#[test]
fn trim_rejects_wrong_confirm_name_and_non_owner() {
    let t = setup();
    let d = create_drawing(&t.s, &t.owner_id, "My Drawing", json!([]), json!({}), 1);
    let r = t.owner.post(&format!("/drawings/{d}/trim"), json!({"confirmName": "Wrong Name"}));
    assert_eq!((r.status, r.json()), (403, json!({"error": "confirmName does not match drawing name"})));
    let r = t.owner.post(&format!("/drawings/{d}/trim"), json!({}));
    assert_eq!(r.status, 403);
    let r = t.other.post(&format!("/drawings/{d}/trim"), json!({"confirmName": "My Drawing"}));
    assert_eq!((r.status, r.json()), (404, json!({"error": "Drawing not found"})));
}

#[test]
fn orphans_remove_scene_entries_but_keep_bytes_needed_by_history() {
    let t = setup();
    let d = create_drawing(&t.s, &t.owner_id, "History Cleanup", json!([]), json!({"historical": file_entry("historical")}), 1);
    let bytes = [1u8, 2, 3, 4];
    insert_db_file(&t.s, &d, "historical", &bytes);
    let mut hist = file_entry("historical");
    hist["dataURL"] = json!(format!("/api/files/{d}/historical"));
    hist["description"] = json!("x".repeat(1000));
    insert_snapshot(&t.s, &d, "[]", &encode(&json!({"historical": hist}).to_string(), true));
    let r = t.owner.send(
        "DELETE",
        &format!("/drawings/{d}/files/orphans"),
        Some(&json!({"confirmName": "History Cleanup", "fileIds": ["historical"]})),
    );
    assert_eq!(r.status, 200);
    assert_eq!(drawing_state(&t.s, &d).1, json!({}));
    let image = t.owner.get(&format!("/files/{d}/historical"));
    assert_eq!(image.status, 200);
    assert_eq!(image.body, bytes);
}

#[test]
fn orphans_remove_requested_ids_and_their_soft_deleted_elements() {
    let t = setup();
    let d = create_drawing(
        &t.s,
        &t.owner_id,
        "Orphan Cleanup",
        json!([image_element("el-active", "file-active", false), image_element("el-deleted", "file-orphan", true)]),
        json!({"file-active": file_entry("file-active"), "file-orphan": file_entry("file-orphan")}),
        3,
    );
    insert_db_file(&t.s, &d, "file-orphan", &[1]);
    let r = t.owner.send(
        "DELETE",
        &format!("/drawings/{d}/files/orphans"),
        Some(&json!({"confirmName": "Orphan Cleanup", "fileIds": ["file-orphan"]})),
    );
    assert_eq!(r.status, 200);
    assert_eq!(r.json(), json!({"deleted": 1, "errors": 0}));
    let (elements, files, version) = drawing_state(&t.s, &d);
    assert_eq!(keys(&files), vec!["file-active"]);
    assert_eq!(ids(&elements), vec!["el-active"]);
    assert_eq!(version, 4);
    assert_eq!(file_count(&t.s, &d, Some("file-orphan")), 0);
}

#[test]
fn orphans_validation() {
    let t = setup();
    let d = create_drawing(
        &t.s,
        &t.owner_id,
        "Active Refs",
        json!([image_element("el-active", "file-active", false)]),
        json!({"file-active": file_entry("file-active"), "file-x": file_entry("file-x")}),
        1,
    );
    let del = |body: Value| t.owner.send("DELETE", &format!("/drawings/{d}/files/orphans"), Some(&body));
    let r = del(json!({"confirmName": "Active Refs", "fileIds": ["file-active"]}));
    assert_eq!(
        (r.status, r.json()),
        (400, json!({"error": "Cannot delete files referenced by active elements", "blockedFileIds": ["file-active"]}))
    );
    let r = del(json!({"confirmName": "Active Refs", "fileIds": []}));
    assert_eq!((r.status, r.json()), (400, json!({"error": "fileIds must be a non-empty array"})));
    let r = del(json!({"confirmName": "Active Refs", "fileIds": ["ok", "../x", 5]}));
    assert_eq!(
        (r.status, r.json()),
        (400, json!({"error": "fileIds contains invalid entries", "invalidFileIds": ["../x", 5]}))
    );
    let r = del(json!({"confirmName": "Wrong", "fileIds": ["file-x"]}));
    assert_eq!(r.status, 403);
    let r = t.other.send("DELETE", &format!("/drawings/{d}/files/orphans"), Some(&json!({"confirmName": "Active Refs", "fileIds": ["file-x"]})));
    assert_eq!(r.status, 404);
}

#[test]
fn diff_reports_canvas_vs_sqlite_presence() {
    let t = setup();
    let d = create_drawing(
        &t.s,
        &t.owner_id,
        "Diff Me",
        json!([image_element("el-a", "file-a", false), image_element("el-b", "file-b", true)]),
        json!({"file-a": file_entry("file-a"), "file-b": file_entry("file-b"), "file-c": file_entry("file-c")}),
        1,
    );
    insert_db_file(&t.s, &d, "file-c", &[1, 2]);
    let r = t.owner.get(&format!("/drawings/{d}/files/diff"));
    assert_eq!(r.status, 200);
    let body = r.json();
    assert_eq!(body["summary"], json!({"totalCanvasRefs": 2, "totalSqliteFiles": 3, "totalS3Files": 1}));
    let rows = body["files"].as_array().unwrap();
    let by = |id: &str| rows.iter().find(|r| r["fileId"] == id).unwrap().clone();
    assert_eq!(
        by("file-a"),
        json!({"fileId": "file-a", "inCanvas": true, "inCanvasActive": true, "inSqlite": true, "inS3": false,
               "inS3Record": false, "s3Key": null, "mimeType": null, "s3SizeBytes": null})
    );
    assert_eq!((by("file-b")["inCanvas"].clone(), by("file-b")["inCanvasActive"].clone()), (json!(true), json!(false)));
    assert_eq!(
        by("file-c"),
        json!({"fileId": "file-c", "inCanvas": false, "inCanvasActive": false, "inSqlite": true, "inS3": true,
               "inS3Record": true, "s3Key": null, "mimeType": "image/png", "s3SizeBytes": 2})
    );
    assert_eq!(t.other.get(&format!("/drawings/{d}/files/diff")).status, 404);
}

/// file-retention: "protects S3 history references during %s and deletes unrelated objects" (db rows).
#[test]
fn trim_and_orphans_protect_history_references() {
    for op in ["trim", "orphans"] {
        let t = setup();
        let d = create_drawing(&t.s, &t.owner_id, "Retention", json!([]), json!({}), 1);
        insert_db_file(&t.s, &d, "historical", &[1, 2, 3]);
        insert_db_file(&t.s, &d, "orphan", &[1, 2, 3]);
        let files = json!({"historical": {"dataURL": format!("/api/files/{d}/historical"), "description": "x".repeat(1000)}});
        insert_snapshot(&t.s, &d, "[]", &encode(&files.to_string(), true));
        let r = if op == "trim" {
            t.owner.post(&format!("/drawings/{d}/trim"), json!({"confirmName": "Retention"}))
        } else {
            t.owner.send(
                "DELETE",
                &format!("/drawings/{d}/files/orphans"),
                Some(&json!({"confirmName": "Retention", "fileIds": ["historical", "orphan"]})),
            )
        };
        assert_eq!(r.status, 200, "{op}: {}", r.text());
        let rows: Vec<String> = {
            let db = t.s.db();
            let mut st = db.prepare(r#"SELECT "fileId" FROM "DrawingFile" WHERE "drawingId"=?1"#).unwrap();
            st.query_map([&d], |r| r.get(0)).unwrap().map(Result::unwrap).collect()
        };
        assert_eq!(rows, vec!["historical"], "{op}");
    }
}

/// file-retention: "keeps all bytes when snapshot files cannot establish references".
#[test]
fn unreadable_history_keeps_all_bytes() {
    for files in ["br1:broken", "not-json", "[]"] {
        let t = setup();
        let d = create_drawing(&t.s, &t.owner_id, "Retention", json!([]), json!({}), 1);
        insert_db_file(&t.s, &d, "unknown", &[1]);
        insert_snapshot(&t.s, &d, "[]", files);
        let r = t.owner.post(&format!("/drawings/{d}/trim"), json!({"confirmName": "Retention"}));
        assert_eq!(r.status, 200, "{files}");
        assert_eq!(file_count(&t.s, &d, None), 1, "{files}");
    }
}

/// file-retention: tracked rows that no scene references are reclaimed by a guarded trim.
#[test]
fn trim_reclaims_untracked_rows() {
    let t = setup();
    let d = create_drawing(&t.s, &t.owner_id, "Retention", json!([]), json!({}), 1);
    insert_db_file(&t.s, &d, "image", &[1, 2, 3]);
    let r = t.owner.post(&format!("/drawings/{d}/trim"), json!({"confirmName": "Retention"}));
    assert_eq!(r.status, 200);
    assert_eq!(file_count(&t.s, &d, None), 0);
}
