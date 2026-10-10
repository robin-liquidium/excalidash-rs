//! Port of upstream imports-compat.integration.ts (+ importsCompatFixtures.ts),
//! plus multer upload semantics of the import routes.
mod common;

use common::*;
use rusqlite::types::Value as Sql;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Fixtures (importsCompatFixtures.ts)

struct LegacyOpts {
    plural_lower: bool,
    include_collections: bool,
    include_migrations_table: bool,
    include_trash_drawing: bool,
}

fn legacy_db(dir: &Path, opts: LegacyOpts) -> PathBuf {
    let path = dir.join(format!("legacy-export-{}.db", uuid::Uuid::new_v4()));
    let db = rusqlite::Connection::open(&path).unwrap();
    let (td, tc) = if opts.plural_lower { ("drawings", "collections") } else { ("Drawing", "Collection") };
    if opts.include_collections {
        db.execute_batch(&format!(
            r#"CREATE TABLE "{tc}" (id TEXT PRIMARY KEY NOT NULL, name TEXT NOT NULL, createdAt TEXT, updatedAt TEXT);"#
        ))
        .unwrap();
        db.execute(
            &format!(r#"INSERT INTO "{tc}" (id, name, createdAt, updatedAt) VALUES (?, ?, ?, ?)"#),
            ["legacy-collection-1", "Legacy Collection", "2024-01-01T00:00:00.000Z", "2024-01-02T00:00:00.000Z"],
        )
        .unwrap();
    }
    db.execute_batch(&format!(
        r#"CREATE TABLE "{td}" (id TEXT PRIMARY KEY NOT NULL, name TEXT NOT NULL, elements TEXT NOT NULL, appState TEXT NOT NULL,
           files TEXT, preview TEXT, version INTEGER, collectionId TEXT, collectionName TEXT, createdAt TEXT, updatedAt TEXT);"#
    ))
    .unwrap();
    let now = "2024-01-03T00:00:00.000Z";
    let insert = format!(
        r#"INSERT INTO "{td}" (id, name, elements, appState, files, preview, version, collectionId, collectionName, createdAt, updatedAt)
           VALUES (?, ?, '[]', '{{}}', '{{}}', NULL, ?, ?, ?, ?, ?)"#
    );
    let (cid, cname) = if opts.include_collections { (Some("legacy-collection-1"), Some("Legacy Collection")) } else { (None, None) };
    db.execute(&insert, rusqlite::params!["legacy-drawing-1", "Legacy Drawing 1", 1, cid, cname, now, now]).unwrap();
    db.execute(&insert, rusqlite::params!["legacy-drawing-2", "Legacy Drawing 2 (unorganized)", 2, None::<&str>, None::<&str>, now, now])
        .unwrap();
    if opts.include_trash_drawing {
        db.execute(&insert, rusqlite::params!["legacy-drawing-trash", "Legacy Trash Drawing", 1, "trash", "Trash", now, now]).unwrap();
    }
    if opts.include_migrations_table {
        db.execute_batch(
            r#"CREATE TABLE "_prisma_migrations" (id TEXT PRIMARY KEY NOT NULL, checksum TEXT NOT NULL, finished_at TEXT,
               migration_name TEXT NOT NULL, logs TEXT, rolled_back_at TEXT, started_at TEXT NOT NULL, applied_steps_count INTEGER NOT NULL DEFAULT 0);"#,
        )
        .unwrap();
        db.execute(
            r#"INSERT INTO "_prisma_migrations" VALUES ('m1','checksum','2024-01-04T00:00:00.000Z','20240104000000_initial',NULL,NULL,'2024-01-04T00:00:00.000Z',1)"#,
            [],
        )
        .unwrap();
    }
    path
}

fn prisma_legacy(dir: &Path) -> PathBuf {
    legacy_db(dir, LegacyOpts { plural_lower: false, include_collections: true, include_migrations_table: false, include_trash_drawing: false })
}

fn legacy_db_with_duplicate_ids(dir: &Path) -> PathBuf {
    let path = dir.join("legacy-duplicate-ids.db");
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute_batch(
        r#"CREATE TABLE "Drawing" (id TEXT, name TEXT NOT NULL, elements TEXT NOT NULL, appState TEXT NOT NULL, files TEXT, preview TEXT,
           version INTEGER, collectionId TEXT, collectionName TEXT, createdAt TEXT, updatedAt TEXT);
           INSERT INTO "Drawing" VALUES ('legacy-duplicate-id','Legacy Drawing A','[]','{}','{}',NULL,1,NULL,NULL,'x','x');
           INSERT INTO "Drawing" VALUES ('legacy-duplicate-id','Legacy Drawing B','[]','{}','{}',NULL,1,NULL,NULL,'x','x');"#,
    )
    .unwrap();
    path
}

fn zip_bytes(entries: &[(&str, String)]) -> Vec<u8> {
    let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let opts = zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
    for (name, content) in entries {
        w.start_file(*name, opts).unwrap();
        w.write_all(content.as_bytes()).unwrap();
    }
    w.finish().unwrap().into_inner()
}

fn manifest(drawings: Value, collections: Value) -> String {
    json!({
        "format": "excalidash",
        "formatVersion": 1,
        "exportedAt": "2026-10-10T00:00:00.000Z",
        "unorganizedFolder": "Unorganized",
        "collections": collections,
        "drawings": drawings,
    })
    .to_string()
}

fn scene(elements: Value, files: Value) -> String {
    json!({"type": "excalidraw", "version": 2, "source": "test", "elements": elements, "appState": {}, "files": files}).to_string()
}

fn duplicate_id_archive() -> Vec<u8> {
    zip_bytes(&[
        (
            "excalidash.manifest.json",
            manifest(
                json!([
                    {"id": "duplicate-drawing-id", "name": "Drawing One", "filePath": "Unorganized/drawing-1.excalidraw", "collectionId": null},
                    {"id": "duplicate-drawing-id", "name": "Drawing Two", "filePath": "Unorganized/drawing-2.excalidraw", "collectionId": null},
                ]),
                json!([]),
            ),
        ),
        ("Unorganized/drawing-1.excalidraw", scene(json!([]), json!({}))),
        ("Unorganized/drawing-2.excalidraw", scene(json!([]), json!({}))),
    ])
}

fn large_drawing_archive() -> Vec<u8> {
    let data_url = format!("data:image/png;base64,{}", "A".repeat(5 * 1024 * 1024));
    zip_bytes(&[
        (
            "excalidash.manifest.json",
            manifest(
                json!([{"id": "large-backup-drawing", "name": "Large backup drawing",
                        "filePath": "Unorganized/large-backup-drawing.excalidraw", "collectionId": null}]),
                json!([]),
            ),
        ),
        (
            "Unorganized/large-backup-drawing.excalidraw",
            scene(json!([]), json!({"large-image": {"id": "large-image", "mimeType": "image/png", "dataURL": data_url, "created": 1}})),
        ),
    ])
}

// ---------------------------------------------------------------------------
// HTTP helpers

fn multipart(field: &str, filename: &str, bytes: &[u8]) -> (String, Vec<u8>) {
    let boundary = "----excalidash-test-boundary-7MA4YWxkTrZu0gW";
    let mut body = Vec::new();
    write!(
        body,
        "--{boundary}\r\nContent-Disposition: form-data; name=\"{field}\"; filename=\"{filename}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
    )
    .unwrap();
    body.extend_from_slice(bytes);
    write!(body, "\r\n--{boundary}--\r\n").unwrap();
    (format!("multipart/form-data; boundary={boundary}"), body)
}

fn upload(c: &TestClient, path: &str, field: &str, filename: &str, bytes: &[u8]) -> Resp {
    c.send_raw("POST", path, Some(multipart(field, filename, bytes)))
}

fn upload_file(c: &TestClient, path: &str, field: &str, file: &Path) -> Resp {
    let name = file.file_name().unwrap().to_string_lossy().into_owned();
    upload(c, path, field, &name, &std::fs::read(file).unwrap())
}

struct Env {
    server: TestServer,
    client: TestClient,
    user: String,
    tmp: tempfile::TempDir,
}

fn env() -> Env {
    let server = TestServer::start(&[]);
    let (client, user) = user_session(&server, "importer@example.test", "USER");
    Env { server, client, user, tmp: tempfile::tempdir().unwrap() }
}

fn row(db: &rusqlite::Connection, sql: &str, id: &str) -> Option<Vec<Sql>> {
    let mut st = db.prepare(sql).unwrap();
    let n = st.column_count();
    let mut rows = st.query([id]).unwrap();
    rows.next().unwrap().map(|r| (0..n).map(|i| r.get::<_, Sql>(i).unwrap()).collect())
}

fn drawing(db: &rusqlite::Connection, id: &str) -> Option<Vec<Sql>> {
    row(db, r#"SELECT * FROM "Drawing" WHERE "id" = ?1"#, id)
}

fn snapshots(db: &rusqlite::Connection, id: &str) -> Vec<Vec<Sql>> {
    let mut st = db.prepare(r#"SELECT * FROM "DrawingSnapshot" WHERE "drawingId" = ?1 ORDER BY "id""#).unwrap();
    let n = st.column_count();
    st.query_map([id], |r| Ok((0..n).map(|i| r.get::<_, Sql>(i).unwrap()).collect::<Vec<_>>())).unwrap().map(Result::unwrap).collect()
}

fn file_data(db: &rusqlite::Connection, drawing_id: &str, file_id: &str) -> Option<Vec<u8>> {
    db.query_row(
        r#"SELECT "data" FROM "DrawingFile" WHERE "drawingId" = ?1 AND "fileId" = ?2"#,
        [drawing_id, file_id],
        |r| r.get(0),
    )
    .ok()
}

fn count(db: &rusqlite::Connection, sql: &str) -> i64 {
    db.query_row(sql, [], |r| r.get(0)).unwrap()
}

fn now() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

fn insert_drawing(db: &rusqlite::Connection, id: &str, user: &str, name: &str, elements: &str, files: &str, version: i64) {
    db.execute(
        r#"INSERT INTO "Drawing" ("id","name","elements","appState","files","version","userId","createdAt","updatedAt")
           VALUES (?1,?2,?3,'{}',?4,?5,?6,?7,?7)"#,
        rusqlite::params![id, name, elements, files, version, user, now()],
    )
    .unwrap();
}

fn insert_file(db: &rusqlite::Connection, drawing_id: &str, file_id: &str, storage: &str, s3_key: Option<&str>, data: Option<&[u8]>, size: i64) {
    db.execute(
        r#"INSERT INTO "DrawingFile" ("drawingId","fileId","mimeType","sizeBytes","storage","s3Key","data","createdAt")
           VALUES (?1,?2,'image/png',?3,?4,?5,?6,?7)"#,
        rusqlite::params![drawing_id, file_id, size, storage, s3_key, data, now()],
    )
    .unwrap();
}

/// seedDrawingBeforeInvalidImport
fn seed_existing(env: &Env, id: &str) {
    let db = env.server.db();
    db.execute(
        r#"INSERT INTO "Drawing" ("id","name","elements","appState","files","version","userId","createdAt","updatedAt")
           VALUES (?1,'Keep this drawing',?2,?3,?4,7,?5,?6,?6)"#,
        rusqlite::params![
            id,
            json!([{"id": "saved-element", "type": "rectangle", "x": 1, "y": 2, "width": 3, "height": 4}]).to_string(),
            json!({"viewBackgroundColor": "#fedcba"}).to_string(),
            json!({"saved-image": {"id": "saved-image", "mimeType": "image/png", "created": 123, "dataURL": format!("/api/files/{id}/saved-image")}})
                .to_string(),
            env.user,
            now()
        ],
    )
    .unwrap();
    insert_file(&db, id, "saved-image", "db", None, Some(b"keep saved bytes"), 16);
    db.execute(
        r#"INSERT INTO "DrawingSnapshot" ("id","drawingId","version","elements","appState","files","createdAt") VALUES (?1,?2,6,'[]','{}','{}',?3)"#,
        rusqlite::params![uuid::Uuid::new_v4().to_string(), id, now()],
    )
    .unwrap();
}

fn download_export(c: &TestClient) -> Vec<u8> {
    let r = c.get("/export/excalidash");
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(r.header("content-type").as_deref(), Some("application/zip"));
    r.body
}

fn read_zip(bytes: &[u8]) -> std::collections::BTreeMap<String, String> {
    let mut z = zip::ZipArchive::new(std::io::Cursor::new(bytes.to_vec())).unwrap();
    let mut out = std::collections::BTreeMap::new();
    for i in 0..z.len() {
        let mut f = z.by_index(i).unwrap();
        let mut s = String::new();
        f.read_to_string(&mut s).unwrap();
        out.insert(f.name().unwrap().to_string(), s);
    }
    out
}

// ---------------------------------------------------------------------------
// Tests

#[test]
fn verifies_prisma_style_legacy_export_with_migration_info() {
    let e = env();
    let db = legacy_db(e.tmp.path(), LegacyOpts {
        plural_lower: false,
        include_collections: true,
        include_migrations_table: true,
        include_trash_drawing: false,
    });
    let r = upload_file(&e.client, "/import/sqlite/legacy/verify", "db", &db);
    assert_eq!(r.status, 200, "{}", r.text());
    let b = r.json();
    assert_eq!(b["valid"], true);
    assert_eq!(b["drawings"], 2);
    assert_eq!(b["collections"], 1);
    assert_eq!(b["latestMigration"], "20240104000000_initial");
    let cur = b["currentLatestMigration"].as_str().unwrap();
    assert!(cur.len() > 15 && cur[..14].bytes().all(|c| c.is_ascii_digit()) && &cur[14..15] == "_", "{cur}");
    // Staged uploads are removed afterwards.
    assert_eq!(std::fs::read_dir(e.server.dir.path().join("uploads")).unwrap().count(), 0);
}

#[test]
fn merge_imports_legacy_export_into_current_account() {
    let e = env();
    let db = legacy_db(e.tmp.path(), LegacyOpts {
        plural_lower: false,
        include_collections: true,
        include_migrations_table: false,
        include_trash_drawing: true,
    });
    let r = upload_file(&e.client, "/import/sqlite/legacy", "db", &db);
    assert_eq!(r.status, 200, "{}", r.text());
    let b = r.json();
    assert_eq!(b["success"], true);
    assert!(b["collections"]["created"].as_i64().unwrap() >= 1);
    assert!(b["drawings"]["created"].as_i64().unwrap() >= 3);
    let sdb = e.server.db();
    let mut st = sdb.prepare(r#"SELECT "id","userId","collectionId" FROM "Drawing" ORDER BY "name""#).unwrap();
    let rows: Vec<(String, String, Option<String>)> =
        st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap().map(Result::unwrap).collect();
    assert!(rows.iter().all(|r| r.1 == e.user));
    let ids: Vec<&str> = rows.iter().map(|r| r.0.as_str()).collect();
    for id in ["legacy-drawing-1", "legacy-drawing-2", "legacy-drawing-trash"] {
        assert!(ids.contains(&id), "{ids:?}");
    }
    let trash = format!("trash:{}", e.user);
    assert_eq!(count(&sdb, &format!(r#"SELECT COUNT(*) FROM "Collection" WHERE "id" = '{trash}'"#)), 1);
    let trash_drawing = rows.iter().find(|r| r.0 == "legacy-drawing-trash").unwrap();
    assert_eq!(trash_drawing.2.as_deref(), Some(trash.as_str()));
    let d1 = rows.iter().find(|r| r.0 == "legacy-drawing-1").unwrap();
    assert_eq!(d1.2.as_deref(), Some("legacy-collection-1"));
}

#[test]
fn supports_plural_lowercase_table_names() {
    let e = env();
    let db = legacy_db(e.tmp.path(), LegacyOpts {
        plural_lower: true,
        include_collections: true,
        include_migrations_table: false,
        include_trash_drawing: false,
    });
    let v = upload_file(&e.client, "/import/sqlite/legacy/verify", "db", &db);
    assert_eq!(v.status, 200, "{}", v.text());
    assert_eq!(v.json()["drawings"], 2);
    assert_eq!(v.json()["collections"], 1);
    assert_eq!(v.json()["latestMigration"], Value::Null);
    let r = upload_file(&e.client, "/import/sqlite/legacy", "db", &db);
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(r.json()["success"], true);
}

#[test]
fn verify_fails_without_drawing_table() {
    let e = env();
    let path = e.tmp.path().join("invalid.db");
    rusqlite::Connection::open(&path).unwrap().execute_batch(r#"CREATE TABLE "NotDrawing" (id TEXT PRIMARY KEY NOT NULL);"#).unwrap();
    let r = upload_file(&e.client, "/import/sqlite/legacy/verify", "db", &path);
    assert_eq!(r.status, 400);
    assert_eq!(r.json(), json!({"error": "Invalid legacy DB", "message": "Missing Drawing table"}));
}

#[test]
fn excalidash_verify_and_import_reject_duplicate_drawing_ids() {
    let e = env();
    for path in ["/import/excalidash/verify", "/import/excalidash"] {
        let r = upload(&e.client, path, "archive", "duplicate-drawing-ids.excalidash", &duplicate_id_archive());
        assert_eq!(r.status, 400, "{path}");
        assert_eq!(
            r.json(),
            json!({"error": "Invalid backup manifest", "message": "Duplicate drawing id in manifest: duplicate-drawing-id"})
        );
    }
}

#[test]
fn imports_backup_drawing_larger_than_former_5mib_limit() {
    let e = env();
    let r = upload(&e.client, "/import/excalidash", "archive", "large-backup.excalidash", &large_drawing_archive());
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(r.json()["success"], true);
    let files: String = e
        .server
        .db()
        .query_row(r#"SELECT "files" FROM "Drawing" WHERE "id" = 'large-backup-drawing'"#, [], |r| r.get(0))
        .unwrap();
    assert!(serde_json::from_str::<Value>(&files).unwrap().get("large-image").is_some());
}

#[test]
fn legacy_verify_and_import_reject_duplicate_drawing_ids() {
    let e = env();
    let db = legacy_db_with_duplicate_ids(e.tmp.path());
    for path in ["/import/sqlite/legacy/verify", "/import/sqlite/legacy"] {
        let r = upload_file(&e.client, path, "db", &db);
        assert_eq!(r.status, 400, "{path}");
        assert_eq!(r.json(), json!({"error": "Invalid legacy DB", "message": "Duplicate drawing id in legacy DB: legacy-duplicate-id"}));
    }
}

#[test]
fn rejects_backup_with_invalid_scene_without_overwriting() {
    let e = env();
    seed_existing(&e, "invalid-backup-existing");
    let db = e.server.db();
    let before = drawing(&db, "invalid-backup-existing").unwrap();
    let history = snapshots(&db, "invalid-backup-existing");
    let cases = [
        ("missing elements", json!({"appState": {}, "files": {}})),
        ("object elements", json!({"elements": {}, "appState": {}, "files": {}})),
        ("null elements", json!({"elements": null, "appState": {}, "files": {}})),
        ("string appState", json!({"elements": [], "appState": "corrupt", "files": {}})),
        ("array files", json!({"elements": [], "appState": {}, "files": []})),
    ];
    for (label, scene) in cases {
        let archive = zip_bytes(&[
            (
                "excalidash.manifest.json",
                manifest(
                    json!([{"id": "invalid-backup-existing", "name": "Overwrite", "collectionId": null, "filePath": "Unorganized/invalid.excalidraw"}]),
                    json!([{"id": "must-not-create", "name": "Rejected collection", "folder": "Rejected"}]),
                ),
            ),
            ("Unorganized/invalid.excalidraw", scene.to_string()),
        ]);
        let r = upload(&e.client, "/import/excalidash", "archive", "invalid.excalidash", &archive);
        assert_eq!(r.status, 400, "{label}");
        assert_eq!(
            r.json(),
            json!({"error": "Invalid backup", "message": "Drawing contains invalid scene fields"}),
            "{label}"
        );
        assert_eq!(drawing(&db, "invalid-backup-existing").unwrap(), before, "{label}");
        assert_eq!(count(&db, r#"SELECT COUNT(*) FROM "Collection" WHERE "id" = 'must-not-create'"#), 0);
        assert_eq!(snapshots(&db, "invalid-backup-existing"), history);
        assert_eq!(file_data(&db, "invalid-backup-existing", "saved-image").unwrap(), b"keep saved bytes");
    }
}

#[test]
fn rejects_malformed_legacy_json_before_overwriting() {
    for field in ["elements", "appState", "files"] {
        let e = env();
        seed_existing(&e, "legacy-drawing-1");
        let db = e.server.db();
        let before = drawing(&db, "legacy-drawing-1").unwrap();
        let history = snapshots(&db, "legacy-drawing-1");
        let legacy = prisma_legacy(e.tmp.path());
        rusqlite::Connection::open(&legacy)
            .unwrap()
            .execute(&format!(r#"UPDATE "Drawing" SET "{field}" = ?1 WHERE id = ?2"#), ["{broken", "legacy-drawing-1"])
            .unwrap();
        let r = upload_file(&e.client, "/import/sqlite/legacy", "db", &legacy);
        assert_eq!(r.status, 400, "{field}: {}", r.text());
        assert_eq!(r.json(), json!({"error": "Invalid imported drawing", "message": "Legacy drawing contains invalid JSON"}));
        assert_eq!(drawing(&db, "legacy-drawing-1").unwrap(), before);
        assert_eq!(count(&db, r#"SELECT COUNT(*) FROM "Drawing""#), 1);
        assert_eq!(snapshots(&db, "legacy-drawing-1"), history);
        assert_eq!(file_data(&db, "legacy-drawing-1", "saved-image").unwrap(), b"keep saved bytes");
        assert_eq!(count(&db, r#"SELECT COUNT(*) FROM "Collection" WHERE "id" = 'legacy-collection-1'"#), 0);
    }
}

fn decode_snapshot(v: &str) -> String {
    // snapshotCodec: "br1:" + base64(brotli(value)).
    match v.strip_prefix("br1:") {
        None => v.to_string(),
        Some(b64) => {
            use base64::Engine;
            let raw = base64::engine::general_purpose::STANDARD.decode(b64).unwrap();
            let mut out = String::new();
            brotli::Decompressor::new(&raw[..], 4096).read_to_string(&mut out).unwrap();
            out
        }
    }
}

#[test]
fn same_id_import_preserves_recoverable_history_and_advances_version() {
    for format in ["excalidash", "legacy"] {
        let e = env();
        let id = if format == "legacy" { "legacy-drawing-1" } else { "import-existing" };
        seed_existing(&e, id);
        let db = e.server.db();
        let (elements, app_state, files): (String, String, String) = db
            .query_row(r#"SELECT "elements","appState","files" FROM "Drawing" WHERE "id" = ?1"#, [id], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .unwrap();
        let r = if format == "legacy" {
            upload_file(&e.client, "/import/sqlite/legacy", "db", &prisma_legacy(e.tmp.path()))
        } else {
            let archive = zip_bytes(&[
                (
                    "excalidash.manifest.json",
                    manifest(
                        json!([{"id": id, "name": "Restored backup", "version": 1, "collectionId": null, "filePath": "Unorganized/drawing.excalidraw"}]),
                        json!([]),
                    ),
                ),
                ("Unorganized/drawing.excalidraw", json!({"elements": [], "appState": {}, "files": {}}).to_string()),
            ]);
            upload(&e.client, "/import/excalidash", "archive", "valid.excalidash", &archive)
        };
        assert_eq!(r.status, 200, "{format}: {}", r.text());
        let (version, new_elements): (i64, String) = db
            .query_row(r#"SELECT "version","elements" FROM "Drawing" WHERE "id" = ?1"#, [id], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap();
        assert_eq!(version, 8, "{format}");
        assert_eq!(serde_json::from_str::<Value>(&new_elements).unwrap(), json!([]));
        let mut st = db.prepare(r#"SELECT "version","elements","appState","files" FROM "DrawingSnapshot" WHERE "drawingId" = ?1"#).unwrap();
        let snaps: Vec<(i64, String, String, String)> =
            st.query_map([id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))).unwrap().map(Result::unwrap).collect();
        assert_eq!(snaps.len(), 2);
        let backup = snaps.iter().find(|s| s.0 == 7).expect("safety snapshot of version 7");
        assert_eq!(decode_snapshot(&backup.1), elements);
        assert_eq!(decode_snapshot(&backup.2), app_state);
        assert_eq!(decode_snapshot(&backup.3), files);
        assert_eq!(file_data(&db, id, "saved-image").unwrap(), b"keep saved bytes");
        if format == "excalidash" {
            assert_eq!(r.json()["drawings"], json!({"created": 0, "updated": 1, "idConflicts": 0}));
            assert_eq!(r.json()["message"], "Backup imported successfully");
        }
    }
}

#[test]
fn excalidraw_drawings_round_trip_through_export_and_reimport() {
    let e = env();
    let elements = json!([{"id": "el1", "type": "rectangle", "x": 0, "y": 0, "width": 5, "height": 5}]);
    insert_drawing(&e.server.db(), "excalidraw-roundtrip-1", &e.user, "Sketch", &elements.to_string(), "{}", 1);
    let buffer = download_export(&e.client);
    let entries = read_zip(&buffer);
    let manifest: Value = serde_json::from_str(&entries["excalidash.manifest.json"]).unwrap();
    let entry = manifest["drawings"].as_array().unwrap().iter().find(|d| d["id"] == "excalidraw-roundtrip-1").unwrap();
    assert!(entry["filePath"].as_str().unwrap().ends_with(".excalidraw"));
    let r = upload(&e.client, "/import/excalidash", "archive", "backup.excalidash", &buffer);
    assert_eq!(r.status, 200, "{}", r.text());
    let stored: String = e
        .server
        .db()
        .query_row(r#"SELECT "elements" FROM "Drawing" WHERE "id" = 'excalidraw-roundtrip-1'"#, [], |r| r.get(0))
        .unwrap();
    assert_eq!(serde_json::from_str::<Value>(&stored).unwrap(), elements);
}

#[test]
fn export_archive_layout_matches_upstream() {
    let e = env();
    let db = e.server.db();
    db.execute(
        r#"INSERT INTO "Collection" ("id","name","userId","createdAt","updatedAt") VALUES ('c1','My: Coll',?1,1000,2000)"#,
        [&e.user],
    )
    .unwrap();
    insert_drawing(&db, "abcdef0123456789", &e.user, "Drawing / One", "[]", "{}", 3);
    db.execute(r#"UPDATE "Drawing" SET "collectionId" = 'c1' WHERE "id" = 'abcdef0123456789'"#, []).unwrap();
    insert_drawing(&db, "loose-drawing", &e.user, "  ", "[]", "{}", 1);
    let r = e.client.get("/export/excalidash?ext=zip");
    assert_eq!(r.status, 200);
    let cd = r.header("content-disposition").unwrap();
    assert!(cd.starts_with("attachment; filename=\"excalidash-backup-") && cd.ends_with(".excalidash.zip\""), "{cd}");
    let entries = read_zip(&r.body);
    let names: Vec<&String> = entries.keys().collect();
    assert!(names.contains(&&"README.txt".to_string()));
    let m: Value = serde_json::from_str(&entries["excalidash.manifest.json"]).unwrap();
    assert!(entries["excalidash.manifest.json"].starts_with("{\n  \"format\": \"excalidash\",\n  \"formatVersion\": 1,"));
    assert_eq!(m["userId"], e.user.as_str());
    assert_eq!(m["unorganizedFolder"], "Unorganized");
    assert_eq!(m["excalidashBackendVersion"], include_str!("../VERSION").trim());
    assert_eq!(
        m["collections"],
        json!([{"id": "c1", "name": "My: Coll", "folder": "My_ Coll", "createdAt": "1970-01-01T00:00:01.000Z", "updatedAt": "1970-01-01T00:00:02.000Z"}])
    );
    let d = m["drawings"].as_array().unwrap();
    let one = d.iter().find(|d| d["id"] == "abcdef0123456789").unwrap();
    assert_eq!(one["filePath"], "My_ Coll/Drawing _ One__abcdef01.excalidraw");
    assert_eq!(one["collectionId"], "c1");
    assert_eq!(one["version"], 3);
    let loose = d.iter().find(|d| d["id"] == "loose-drawing").unwrap();
    assert_eq!(loose["filePath"], "Unorganized/Untitled__loose-dr.excalidraw");
    let data: Value = serde_json::from_str(&entries["My_ Coll/Drawing _ One__abcdef01.excalidraw"]).unwrap();
    assert_eq!(data["type"], "excalidraw");
    assert_eq!(data["version"], 2);
    assert!(data["source"].as_str().unwrap().starts_with("http://127.0.0.1:"));
    assert_eq!(data["excalidash"]["drawingId"], "abcdef0123456789");
    assert_eq!(data["excalidash"]["collectionId"], "c1");
    assert!(entries["README.txt"].contains("Collections: 1\nDrawings: 2\n"));
}

#[test]
fn exports_managed_image_references_as_inline_data_urls() {
    let e = env();
    let db = e.server.db();
    let bytes = b"portable backup image";
    insert_drawing(
        &db,
        "portable-image-export",
        &e.user,
        "Portable image",
        "[]",
        &json!({"image": {"id": "image", "mimeType": "image/png", "dataURL": "/api/files/portable-image-export/image", "created": 123}}).to_string(),
        1,
    );
    insert_file(&db, "portable-image-export", "image", "db", None, Some(bytes), bytes.len() as i64);
    let entries = read_zip(&download_export(&e.client));
    let m: Value = serde_json::from_str(&entries["excalidash.manifest.json"]).unwrap();
    let path = m["drawings"][0]["filePath"].as_str().unwrap();
    let exported: Value = serde_json::from_str(&entries[path]).unwrap();
    use base64::Engine;
    assert_eq!(
        exported["files"]["image"],
        json!({"id": "image", "mimeType": "image/png",
               "dataURL": format!("data:image/png;base64,{}", base64::engine::general_purpose::STANDARD.encode(bytes)), "created": 123})
    );
}

fn backup_image_drawing(e: &Env, files: Value) {
    insert_drawing(
        &e.server.db(),
        "backup-images",
        &e.user,
        "Backup images",
        &json!([{"id": "external-element", "type": "image", "fileId": "external"}, {"id": "managed-element", "type": "image", "fileId": "managed"}])
            .to_string(),
        &files.to_string(),
        1,
    );
}

fn external_files() -> Value {
    json!({
        "external": {"id": "external", "mimeType": "image/png", "dataURL": "https://external.example/imported.png?version=1", "created": 123},
        "legacy": {"id": "legacy", "mimeType": "image/png", "dataURL": "http://legacy.example/image.png", "created": 123},
    })
}

/// First half of "round-trips unmanaged HTTP(S) references alongside bundled managed images".
#[test]
fn exports_unmanaged_references_alongside_bundled_managed_images() {
    let e = env();
    let bytes = b"round-trip managed image";
    let mut files = external_files();
    files["managed"] = json!({"id": "managed", "mimeType": "image/png", "dataURL": "https://cdn.example/managed.png"});
    backup_image_drawing(&e, files);
    insert_file(&e.server.db(), "backup-images", "managed", "db", None, Some(bytes), bytes.len() as i64);
    let entries = read_zip(&download_export(&e.client));
    let m: Value = serde_json::from_str(&entries["excalidash.manifest.json"]).unwrap();
    let exported: Value = serde_json::from_str(&entries[m["drawings"][0]["filePath"].as_str().unwrap()]).unwrap();
    for (k, v) in external_files().as_object().unwrap() {
        assert_eq!(&exported["files"][k], v);
    }
    use base64::Engine;
    assert_eq!(
        exported["files"]["managed"]["dataURL"],
        format!("data:image/png;base64,{}", base64::engine::general_purpose::STANDARD.encode(bytes))
    );
    assert_eq!(exported["elements"][1]["fileId"], "managed");
}

/// Second half: restoring into an empty account interns the bundled image.
/// Needs the real `files::intern_drawing_files` (implemented in parallel).
#[test]
fn reimport_interns_bundled_images_and_keeps_external_references() {
    let e = env();
    let bytes = b"round-trip managed image";
    let mut files = external_files();
    files["managed"] = json!({"id": "managed", "mimeType": "image/png", "dataURL": "https://cdn.example/managed.png"});
    backup_image_drawing(&e, files);
    insert_file(&e.server.db(), "backup-images", "managed", "db", None, Some(bytes), bytes.len() as i64);
    let buffer = download_export(&e.client);
    let db = e.server.db();
    db.execute_batch(r#"DELETE FROM "DrawingFile"; DELETE FROM "Drawing";"#).unwrap();
    let r = upload(&e.client, "/import/excalidash", "archive", "backup.excalidash", &buffer);
    assert_eq!(r.status, 200, "{}", r.text());
    let stored: String = db.query_row(r#"SELECT "files" FROM "Drawing" WHERE "id" = 'backup-images'"#, [], |r| r.get(0)).unwrap();
    let stored: Value = serde_json::from_str(&stored).unwrap();
    for (k, v) in external_files().as_object().unwrap() {
        assert_eq!(stored[k]["dataURL"], v["dataURL"]);
    }
    assert_eq!(stored["managed"]["dataURL"], "/api/files/backup-images/managed");
    assert_eq!(file_data(&db, "backup-images", "managed").unwrap(), bytes);
    assert_eq!(count(&db, r#"SELECT COUNT(*) FROM "DrawingFile""#), 1);
    assert_eq!(e.client.get("/export/excalidash").status, 200);
}

#[test]
fn returns_complete_500_before_streaming_when_managed_storage_fails() {
    for failure in ["missing row", "missing db bytes", "missing s3 key", "s3 missing", "s3 error"] {
        let e = env();
        let managed_url = if failure == "missing row" { "/api/files/backup-images/managed" } else { "https://cdn.example/managed.png" };
        backup_image_drawing(
            &e,
            json!({
                "managed": {"id": "managed", "mimeType": "image/png", "dataURL": managed_url},
                "external": {"id": "external", "mimeType": "image/png", "dataURL": "https://external.example/image.png"},
            }),
        );
        if failure != "missing row" {
            let storage = if failure == "missing db bytes" { "db" } else { "s3" };
            let key = if failure.starts_with("s3 ") { Some("managed/image.png") } else { None };
            insert_file(&e.server.db(), "backup-images", "managed", storage, key, None, 42);
        }
        let r = e.client.get("/export/excalidash");
        assert_eq!(r.status, 500, "{failure}");
        assert!(r.header("content-type").unwrap().contains("application/json"));
        assert!(r.header("content-disposition").is_none());
        assert_eq!(r.json()["error"], "Internal server error");
    }
}

// ---------------------------------------------------------------------------
// multer / route semantics

#[test]
fn upload_semantics_match_multer() {
    let e = env();
    // Not multipart → no req.file.
    let r = e.client.post("/import/excalidash", json!({}));
    assert_eq!((r.status, r.json()), (400, json!({"error": "No file uploaded"})));
    let r = e.client.send_raw("POST", "/import/sqlite/legacy/verify", None);
    assert_eq!((r.status, r.json()), (400, json!({"error": "No file uploaded"})));
    // Wrong field name → MulterError (500).
    let r = upload(&e.client, "/import/excalidash/verify", "file", "a.excalidash", b"x");
    assert_eq!(r.status, 500);
    assert_eq!(r.json()["error"], "Internal server error");
    // fileFilter for the "db" field.
    let r = upload(&e.client, "/import/sqlite/legacy/verify", "db", "legacy.txt", b"x");
    assert_eq!(r.status, 500);
    // Not a SQLite file.
    let r = upload(&e.client, "/import/sqlite/legacy/verify", "db", "legacy.db", b"definitely not sqlite at all");
    assert_eq!((r.status, r.json()), (400, json!({"error": "Invalid database format"})));
    // Not a zip → JSZip throws.
    let r = upload(&e.client, "/import/excalidash/verify", "archive", "a.excalidash", b"not a zip");
    assert_eq!(r.status, 500);
    // Unauthenticated.
    let mut anon = e.server.client();
    anon.fetch_csrf();
    let r = upload(&anon, "/import/excalidash", "archive", "a.excalidash", b"x");
    assert_eq!(r.status, 401);
    assert_eq!(std::fs::read_dir(e.server.dir.path().join("uploads")).unwrap().count(), 0);
}

#[test]
fn excalidash_verify_reports_manifest_summary_and_errors() {
    let e = env();
    let good = zip_bytes(&[
        (
            "excalidash.manifest.json",
            json!({"format": "excalidash", "formatVersion": 1, "exportedAt": "2026-01-01T00:00:00.000Z", "excalidashBackendVersion": "0.6.5",
                   "unorganizedFolder": "Unorganized", "collections": [{"id": "c", "name": "C", "folder": "C"}],
                   "drawings": [{"id": "d", "name": "D", "filePath": "C/d.excalidraw", "collectionId": "c"}]})
            .to_string(),
        ),
        ("C/d.excalidraw", scene(json!([]), json!({}))),
    ]);
    let r = upload(&e.client, "/import/excalidash/verify", "archive", "b.excalidash", &good);
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(
        r.json(),
        json!({"valid": true, "formatVersion": 1, "exportedAt": "2026-01-01T00:00:00.000Z", "excalidashBackendVersion": "0.6.5", "collections": 1, "drawings": 1})
    );
    let cases: Vec<(Vec<u8>, Value)> = vec![
        (zip_bytes(&[("x.txt", "x".into())]), json!({"error": "Invalid backup", "message": "Missing excalidash.manifest.json"})),
        (
            zip_bytes(&[("excalidash.manifest.json", "{nope".into())]),
            json!({"error": "Invalid backup manifest", "message": "excalidash.manifest.json is not valid JSON"}),
        ),
        (
            zip_bytes(&[("excalidash.manifest.json", json!({"format": "excalidash", "formatVersion": 2}).to_string())]),
            json!({"error": "Invalid backup manifest", "message": "Malformed excalidash.manifest.json"}),
        ),
        (
            zip_bytes(&[("excalidash.manifest.json", manifest(json!([{"id": "d", "name": "D", "filePath": "U/d.excalidraw", "collectionId": null}]), json!([])))]),
            json!({"error": "Invalid backup", "message": "Missing drawing file: U/d.excalidraw"}),
        ),
        (
            zip_bytes(&[("excalidash.manifest.json", manifest(json!([]), json!([]))), ("/abs.txt", "x".into())]),
            json!({"error": "Invalid backup", "message": "Unsafe archive path: /abs.txt"}),
        ),
    ];
    for (archive, expected) in cases {
        let r = upload(&e.client, "/import/excalidash/verify", "archive", "b.excalidash", &archive);
        assert_eq!((r.status, r.json()), (400, expected));
    }
}

#[test]
fn excalidash_import_resolves_collections_trash_and_foreign_ids() {
    let e = env();
    let db = e.server.db();
    let other = seed_user(&e.server, "other@example.test", "Other", "USER");
    db.execute(r#"INSERT INTO "Collection" ("id","name","userId","createdAt","updatedAt") VALUES ('foreign-col','F',?1,1,1)"#, [&other])
        .unwrap();
    insert_drawing(&db, "foreign-drawing", &other, "Theirs", "[]", "{}", 1);
    let archive = zip_bytes(&[
        (
            "excalidash.manifest.json",
            manifest(
                json!([
                    {"id": "foreign-drawing", "name": "Mine now", "filePath": "F/a.excalidraw", "collectionId": "foreign-col", "version": 4},
                    {"id": "trashed", "name": "<b>Trashed</b><script>x</script>", "filePath": "Trash/b.excalidraw", "collectionId": "trash"},
                ]),
                json!([{"id": "foreign-col", "name": "F", "folder": "F"}, {"id": "trash", "name": "Trash", "folder": "Trash"}]),
            ),
        ),
        ("F/a.excalidraw", scene(json!([]), json!({}))),
        ("Trash/b.excalidraw", scene(json!([]), json!({}))),
    ]);
    let r = upload(&e.client, "/import/excalidash", "archive", "b.excalidash", &archive);
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(
        r.json(),
        json!({"success": true, "message": "Backup imported successfully",
               "collections": {"created": 1, "updated": 0, "idConflicts": 1},
               "drawings": {"created": 2, "updated": 0, "idConflicts": 1}})
    );
    // The foreign drawing is untouched; a copy exists under a new id in a new collection.
    let theirs: (String, String) =
        db.query_row(r#"SELECT "name","userId" FROM "Drawing" WHERE "id" = 'foreign-drawing'"#, [], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
    assert_eq!(theirs, ("Theirs".to_string(), other.clone()));
    let (copy_id, copy_col, version): (String, String, i64) = db
        .query_row(r#"SELECT "id","collectionId","version" FROM "Drawing" WHERE "name" = 'Mine now'"#, [], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })
        .unwrap();
    assert_ne!(copy_id, "foreign-drawing");
    assert_ne!(copy_col, "foreign-col");
    assert_eq!(version, 4);
    let (name, col): (String, String) =
        db.query_row(r#"SELECT "name","collectionId" FROM "Drawing" WHERE "id" = 'trashed'"#, [], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
    assert_eq!(name, "<b>Trashed</b>");
    assert_eq!(col, format!("trash:{}", e.user));
}
