//! Ports of release-updates.integration.ts (against a local fake GitHub API)
//! and release-upgrade.integration.ts (Prisma 0.6.2 baseline → current).
mod common;

use common::*;
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

const VERSION: &str = include_str!("../VERSION");

fn version() -> &'static str {
    VERSION.trim()
}

/// Minimal fake of api.github.com: records request lines + headers and
/// answers with the configured (status, body).
struct FakeGithub {
    url: String,
    requests: Arc<Mutex<Vec<(String, Vec<String>)>>>,
    response: Arc<Mutex<(u16, String)>>,
}

impl FakeGithub {
    fn start(status: u16, body: Value) -> FakeGithub {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let response = Arc::new(Mutex::new((status, body.to_string())));
        let (reqs, resp) = (requests.clone(), response.clone());
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                if reader.read_line(&mut line).is_err() {
                    continue;
                }
                let mut headers = Vec::new();
                loop {
                    let mut h = String::new();
                    if reader.read_line(&mut h).is_err() || h == "\r\n" || h.is_empty() {
                        break;
                    }
                    headers.push(h.trim_end().to_lowercase());
                }
                reqs.lock().unwrap().push((line.trim_end().to_string(), headers));
                let (status, body) = resp.lock().unwrap().clone();
                let _ = write!(
                    stream,
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nETag: \"fixture\"\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let mut sink = Vec::new();
                let _ = stream.flush();
                let _ = reader.get_mut().read_to_end(&mut sink);
            }
        });
        FakeGithub { url, requests, response }
    }

    fn paths(&self) -> Vec<String> {
        self.requests.lock().unwrap().iter().map(|(l, _)| l.split(' ').nth(1).unwrap_or("").to_string()).collect()
    }
}

fn release(tag: &str, published: &str, prerelease: bool) -> Value {
    json!({"tag_name": format!("v{tag}"), "published_at": published, "prerelease": prerelease, "draft": false,
           "html_url": format!("https://github.com/ZimengXiong/ExcaliDash/releases/tag/v{tag}")})
}

fn current() -> String {
    format!("{}-dev.1234567", version())
}

fn server_for(gh: &FakeGithub, extra: &[(&str, &str)]) -> TestServer {
    let cur = current();
    let mut env = vec![
        ("AUTH_MODE", "disabled"),
        ("APP_BUILD_LABEL", cur.as_str()),
        ("UPDATE_CHECK_OUTBOUND", "true"),
        ("EXCALIDASH_GITHUB_API_URL", gh.url.as_str()),
    ];
    env.extend_from_slice(extra);
    TestServer::start(&env)
}

#[test]
fn queries_the_stable_endpoint() {
    let gh = FakeGithub::start(200, release(version(), "2026-10-02T12:00:00Z", false));
    let server = server_for(&gh, &[("UPDATE_CHECK_GITHUB_TOKEN", "fixture-token")]);
    let r = server.client().get("/system/update?channel=stable");
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(
        r.json(),
        json!({
            "channel": "stable",
            "outboundEnabled": true,
            "latestVersion": version(),
            "latestUrl": format!("https://github.com/ZimengXiong/ExcaliDash/releases/tag/v{}", version()),
            "publishedAt": "2026-10-02T12:00:00Z",
            "isUpdateAvailable": true,
            "currentVersion": current(),
        })
    );
    // Key order matches `{ ...latest, currentVersion, isUpdateAvailable }`.
    assert!(r.text().starts_with(r#"{"channel":"stable","outboundEnabled":true,"latestVersion":"#));
    assert!(r.text().ends_with(&format!(r#""isUpdateAvailable":true,"currentVersion":"{}"}}"#, current())));
    assert_eq!(gh.paths(), vec!["/repos/ZimengXiong/ExcaliDash/releases/latest"]);
    let headers = &gh.requests.lock().unwrap()[0].1;
    assert!(headers.contains(&"accept: application/vnd.github+json".to_string()));
    assert!(headers.contains(&"user-agent: excalidash-updatecheck".to_string()));
    assert!(headers.contains(&"authorization: bearer fixture-token".to_string()));
}

#[test]
fn selects_dev_builds_by_publication_time() {
    let v = version();
    let gh = FakeGithub::start(
        200,
        json!([release(&format!("{v}-dev.fffffff"), "2026-10-01T12:00:00Z", true), release(&format!("{v}-dev.0000000"), "2026-10-02T12:00:00Z", true)]),
    );
    let server = server_for(&gh, &[]);
    let r = server.client().get("/system/update?channel=prerelease");
    assert_eq!(r.status, 200);
    let b = r.json();
    assert_eq!(b["currentVersion"], current());
    assert_eq!(b["latestVersion"], format!("{v}-dev.0000000"));
    assert_eq!(b["isUpdateAvailable"], true);
    assert_eq!(gh.paths(), vec!["/repos/ZimengXiong/ExcaliDash/releases?per_page=100"]);
}

#[test]
fn does_not_advertise_installed_dev_build() {
    let gh = FakeGithub::start(200, json!([release(&current(), "2026-10-02T12:00:00Z", true)]));
    let server = server_for(&gh, &[]);
    let r = server.client().get("/system/update?channel=prerelease");
    assert_eq!(r.status, 200);
    assert_eq!(r.json()["isUpdateAvailable"], false);
}

#[test]
fn prefers_stable_release_over_same_version_dev_builds() {
    let v = version();
    let gh = FakeGithub::start(
        200,
        json!([release(v, "2026-10-01T12:00:00Z", false), release(&format!("{v}-dev.fffffff"), "2026-10-02T12:00:00Z", true)]),
    );
    let server = server_for(&gh, &[]);
    let b = server.client().get("/system/update?channel=prerelease").json();
    assert_eq!(b["latestVersion"], v);
    assert_eq!(b["isUpdateAvailable"], true);
}

#[test]
fn caches_checks_without_mixing_channels() {
    let gh = FakeGithub::start(200, release(version(), "2026-10-02T12:00:00Z", false));
    let server = server_for(&gh, &[]);
    let c = server.client();
    assert_eq!(c.get("/system/update?channel=stable").status, 200);
    assert_eq!(c.get("/system/update?channel=stable").status, 200);
    assert_eq!(gh.paths().len(), 1);
    *gh.response.lock().unwrap() = (200, json!([release(&current(), "2026-10-02T12:00:00Z", true)]).to_string());
    let r = c.get("/system/update?channel=prerelease");
    assert_eq!(r.status, 200);
    assert_eq!(r.json()["latestVersion"], current());
    assert_eq!(gh.paths().len(), 2);
}

#[test]
fn reports_github_errors() {
    let gh = FakeGithub::start(403, json!({"message": "rate limited"}));
    let server = server_for(&gh, &[]);
    let r = server.client().get("/system/update");
    assert_eq!(r.status, 200);
    assert_eq!(
        r.json(),
        json!({"channel": "stable", "outboundEnabled": true, "latestVersion": null, "latestUrl": null, "publishedAt": null,
               "isUpdateAvailable": null, "error": "GitHub API error: HTTP 403", "currentVersion": current()})
    );
}

#[test]
fn outbound_disabled_skips_github() {
    let server = TestServer::start(&[("AUTH_MODE", "disabled")]);
    let r = server.client().get("/system/update?channel=prerelease");
    assert_eq!(r.status, 200);
    assert_eq!(
        r.json(),
        json!({"channel": "prerelease", "outboundEnabled": false, "latestVersion": null, "latestUrl": null, "publishedAt": null,
               "isUpdateAvailable": null, "currentVersion": version()})
    );
}

#[test]
fn retains_version_for_foreign_build_labels() {
    for label in ["", "0.9.9-dev.fffffff", "ci-1234567"] {
        let server = TestServer::start(&[("AUTH_MODE", "disabled"), ("APP_BUILD_LABEL", label), ("ENFORCE_HTTPS_REDIRECT", "false")]);
        let r = server.client().get("/system/update");
        assert_eq!(r.status, 200);
        assert_eq!(r.json()["currentVersion"], version(), "{label:?}");
    }
}

// ---------------------------------------------------------------------------
// release-upgrade.integration.ts

const BASELINE: &str = "20260822050000_drop_ai_tldraw";

fn table_snapshot(db: &excalidash_rs::sql::Connection, table: &str) -> (String, Vec<Vec<excalidash_rs::sql::types::Value>>) {
    let cols: Vec<String> = db
        .prepare(&format!(r#"PRAGMA table_info("{table}")"#))
        .unwrap()
        .query_map([], |r| r.get::<_, String>(1))
        .unwrap()
        .map(|c| format!("\"{}\"", c.unwrap()))
        .collect();
    let query = format!(r#"SELECT {} FROM "{table}" ORDER BY rowid"#, cols.join(", "));
    (query.clone(), rows(db, &query))
}

fn rows(db: &excalidash_rs::sql::Connection, query: &str) -> Vec<Vec<excalidash_rs::sql::types::Value>> {
    let mut st = db.prepare(query).unwrap();
    st.query_map([], |r| Ok((0..r.column_count()).map(|i| r.get(i).unwrap()).collect())).unwrap().map(Result::unwrap).collect()
}

#[test]
fn upgrade_preserves_accounts_scenes_images_history_and_access() {
    use excalidash_rs::db::{migrate_deploy, MIGRATIONS};
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("prisma")).unwrap();
    let db_path = dir.path().join("prisma").join("dev.db");
    let names: Vec<&str> = MIGRATIONS.iter().map(|(n, _)| *n).collect();
    assert!(names.contains(&BASELINE));
    assert!(names.iter().any(|n| *n > BASELINE));
    {
        // What `prisma migrate deploy` of the 0.6.2 baseline leaves behind.
        let db = excalidash_rs::sql::Connection::open(&db_path).unwrap();
        db.execute_batch(
            r#"CREATE TABLE "_prisma_migrations" ("id" TEXT PRIMARY KEY NOT NULL, "checksum" TEXT NOT NULL, "finished_at" DATETIME,
               "migration_name" TEXT NOT NULL, "logs" TEXT, "rolled_back_at" DATETIME, "started_at" DATETIME NOT NULL DEFAULT current_timestamp,
               "applied_steps_count" INTEGER UNSIGNED NOT NULL DEFAULT 0);"#,
        )
        .unwrap();
        for (name, sql) in MIGRATIONS.iter().filter(|(n, _)| *n <= BASELINE) {
            db.execute_batch(sql).unwrap();
            use sha2::Digest;
            let checksum = hex::encode(sha2::Sha256::digest(sql.as_bytes()));
            db.execute(
                r#"INSERT INTO "_prisma_migrations" VALUES (?1, ?2, 1760000000000, ?3, NULL, NULL, 1760000000000, 1)"#,
                excalidash_rs::sql::params![uuid::Uuid::new_v4().to_string(), checksum, name],
            )
            .unwrap();
        }
    }
    let db = excalidash_rs::sql::Connection::open(&db_path).unwrap();
    db.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
    db.execute_batch(
        r##"
        INSERT INTO User (id, email, passwordHash, name, preferences, createdAt, updatedAt)
          VALUES ('owner', 'owner@example.test', 'fixture-hash', 'Owner', '{"language":"en"}', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
                 ('viewer', 'viewer@example.test', 'fixture-hash', 'Viewer', '{}', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);
        INSERT INTO Collection (id, name, userId, createdAt, updatedAt)
          VALUES ('collection', 'Existing collection', 'owner', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);
        INSERT INTO Drawing (id, name, elements, appState, files, preview, version, userId, collectionId, createdAt, updatedAt)
          VALUES ('drawing', 'Existing drawing', '[{"id":"shape","type":"rectangle"}]', '{"viewBackgroundColor":"#ffffff"}', '{}', '<svg></svg>', 7, 'owner', 'collection', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);
        INSERT INTO DrawingSnapshot (id, drawingId, version, elements, appState, files)
          VALUES ('snapshot', 'drawing', 6, '[{"id":"earlier"}]', '{}', '{}');
        INSERT INTO DrawingPermission (id, drawingId, granteeUserId, permission, createdByUserId, createdAt, updatedAt)
          VALUES ('permission', 'drawing', 'viewer', 'view', 'owner', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);
        INSERT INTO CollectionShare (id, collectionId, granteeUserId, role, createdByUserId, createdAt, updatedAt)
          VALUES ('share', 'collection', 'viewer', 'view', 'owner', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);
        INSERT INTO Library (id, items, createdAt, updatedAt)
          VALUES ('user_owner', '[{"id":"library-item"}]', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);
        INSERT INTO ApiKey (id, userId, name, keyId, tokenHash, prefix, createdAt, updatedAt)
          VALUES ('key', 'owner', 'Existing key', 'key-id', 'fixture-token-hash', 'test', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);
        "##,
    )
    .unwrap();
    db.execute(
        "INSERT INTO DrawingFile (drawingId, fileId, mimeType, sizeBytes, storage, data) VALUES (?, ?, ?, ?, ?, ?)",
        excalidash_rs::sql::params!["drawing", "image", "image/png", 4, "db", vec![0u8, 1, 2, 255]],
    )
    .unwrap();
    let tables = [
        "User", "Collection", "Drawing", "DrawingSnapshot", "DrawingPermission", "CollectionShare", "Library", "DrawingFile", "ApiKey", "SystemConfig",
    ];
    let snapshots: Vec<_> = tables.iter().map(|t| table_snapshot(&db, t)).collect();

    // Two deploys: a second container start must not replay or corrupt migrations.
    for expected in [names.iter().filter(|n| **n > BASELINE).count(), 0] {
        let mut c = excalidash_rs::sql::Connection::open(&db_path).unwrap();
        c.execute_batch("PRAGMA foreign_keys = OFF;").unwrap();
        assert_eq!(migrate_deploy(&mut c).unwrap(), expected);
    }
    for (query, before) in &snapshots {
        assert_eq!(&rows(&db, query), before, "{query}");
    }
    assert!(rows(&db, "PRAGMA foreign_key_check").is_empty());
    let ok: String = db.query_row("PRAGMA integrity_check", [], |r| r.get(0)).unwrap();
    assert_eq!(ok, "ok");
    let (version, snap_version, grantee): (i64, i64, String) = db
        .query_row(
            r#"SELECT d."version", s."version", p."granteeUserId" FROM "Drawing" d JOIN "DrawingSnapshot" s ON s."drawingId" = d."id"
               JOIN "DrawingPermission" p ON p."drawingId" = d."id" WHERE d."id" = 'drawing'"#,
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!((version, snap_version, grantee.as_str()), (7, 6, "viewer"));
    let scoped: Option<String> = db.query_row(r#"SELECT "drawingId" FROM "ApiKey" WHERE "id" = 'key'"#, [], |r| r.get(0)).unwrap();
    assert!(scoped.is_none());
    db.execute(r#"UPDATE "SystemConfig" SET "aiProvider" = 'disabled', "updatedAt" = 1 WHERE "id" = 'default'"#, []).unwrap();
    db.execute(
        r#"INSERT INTO "ApiKey" ("id","userId","drawingId","name","keyId","tokenHash","prefix","createdAt","updatedAt")
           VALUES ('scoped-id','owner','drawing','Scoped key','scoped','scoped-fixture-hash','test',1,1)"#,
        [],
    )
    .unwrap();
    drop(db);

    // Restart the real server on the upgraded database: no migrations, healthy.
    let server = TestServer::start_in(dir, &[]);
    assert!(server.output().contains("No pending migrations to apply."), "{}", server.output());
    let r = server.client().get("/health");
    assert_eq!(r.json(), json!({"status": "ok", "database": "ok"}));
    let mode: i64 = server.db().query_row("PRAGMA auto_vacuum", [], |r| r.get(0)).unwrap();
    assert_eq!(mode, 2);
}
