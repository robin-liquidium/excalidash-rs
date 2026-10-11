//! S3-mode parity (file-retention.integration.ts S3 cases, routes/files.ts redirect,
//! s3.ts client ops). Needs an S3-compatible server; opt in with EXRS_TEST_S3=1:
//!   docker run -d --rm --name exrs-files-minio -p 127.0.0.1:19000:9000 \
//!     -e MINIO_ROOT_USER=minio -e MINIO_ROOT_PASSWORD=minio12345 minio/minio server /data
//! (any S3 server works; override with EXRS_TEST_S3_ENDPOINT / _ACCESS_KEY / _SECRET_KEY).
mod common;
use common::*;
use excalidash_rs::config::S3Config;
use excalidash_rs::s3::S3Client;
use serde_json::{json, Value};

fn enabled() -> bool {
    if std::env::var("EXRS_TEST_S3").as_deref() == Ok("1") {
        return true;
    }
    eprintln!("skipping S3 test (set EXRS_TEST_S3=1)");
    false
}

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}

fn endpoint() -> String {
    env_or("EXRS_TEST_S3_ENDPOINT", "http://127.0.0.1:19000")
}

fn s3_config(bucket: &str) -> S3Config {
    S3Config {
        bucket: Some(bucket.to_string()),
        region: "us-east-1".into(),
        endpoint: Some(endpoint()),
        public_url: None,
        force_path_style: true,
        key_prefix: "excalidash".into(),
        access_key_id: Some(env_or("EXRS_TEST_S3_ACCESS_KEY", "minio")),
        secret_access_key: Some(env_or("EXRS_TEST_S3_SECRET_KEY", "minio12345")),
    }
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap()
}

fn http() -> reqwest::Client {
    install_crypto();
    reqwest::Client::new()
}

/// Fresh bucket per test.
fn create_bucket() -> String {
    install_crypto();
    let name = format!("exrs-{}", &uuid::Uuid::new_v4().simple().to_string()[..16]);
    let bucket = rusty_s3::Bucket::new(endpoint().parse().unwrap(), rusty_s3::UrlStyle::Path, name.clone(), "us-east-1").unwrap();
    let creds = rusty_s3::Credentials::new(env_or("EXRS_TEST_S3_ACCESS_KEY", "minio"), env_or("EXRS_TEST_S3_SECRET_KEY", "minio12345"));
    use rusty_s3::S3Action;
    let url = bucket.create_bucket(&creds).sign(std::time::Duration::from_secs(60));
    let r = reqwest::blocking::Client::new().put(url.as_str()).send().unwrap();
    assert!(r.status().is_success(), "create bucket: {} {}", r.status(), r.text().unwrap_or_default());
    name
}

fn start(bucket: &str) -> TestServer {
    let cfg = s3_config(bucket);
    let ak = cfg.access_key_id.clone().unwrap();
    let sk = cfg.secret_access_key.clone().unwrap();
    let ep = endpoint();
    TestServer::start(&[
        ("S3_BUCKET", bucket),
        ("S3_REGION", "us-east-1"),
        ("S3_ENDPOINT", &ep),
        ("S3_FORCE_PATH_STYLE", "true"),
        ("AWS_ACCESS_KEY_ID", &ak),
        ("AWS_SECRET_ACCESS_KEY", &sk),
    ])
}

fn create_drawing(s: &TestServer, user_id: &str, name: &str) -> String {
    let id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().timestamp_millis();
    s.db()
        .execute(
            r#"INSERT INTO "Drawing" ("id","name","elements","appState","files","userId","version","createdAt","updatedAt")
               VALUES (?1,?2,'[]','{}','{}',?3,1,?4,?4)"#,
            excalidash_rs::sql::params![id, name, user_id, now],
        )
        .unwrap();
    id
}

fn s3_row(s: &TestServer, drawing: &str, file: &str) -> Option<(String, Option<String>, String)> {
    s.db()
        .query_row(
            r#"SELECT "storage","s3Key","mimeType" FROM "DrawingFile" WHERE "drawingId"=?1 AND "fileId"=?2"#,
            [drawing, file],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .ok()
}

fn upload(c: &TestClient, drawing: &str, file: &str, body: Vec<u8>, ct: &str) -> Resp {
    c.send_raw("PUT", &format!("/drawings/{drawing}/files/{file}"), Some((ct.to_string(), body)))
}

/// file-retention: "lists a collaborator's first raw S3 upload in the drawing owner's storage namespace".
#[test]
fn collaborator_raw_upload_lands_in_owner_namespace() {
    if !enabled() {
        return;
    }
    let bucket = create_bucket();
    let s = start(&bucket);
    enable_auth(&s);
    let owner_id = seed_user(&s, "owner@test.local", "Owner", "USER");
    let peer_id = seed_user(&s, "peer@test.local", "Peer", "USER");
    let owner = session_client(&s, &owner_id, "owner@test.local");
    let peer = session_client(&s, &peer_id, "peer@test.local");
    let d = create_drawing(&s, &owner_id, "Retention");
    let now = chrono::Utc::now().timestamp_millis();
    s.db()
        .execute(
            r#"INSERT INTO "DrawingPermission" ("id","drawingId","granteeUserId","permission","createdByUserId","createdAt","updatedAt")
               VALUES (?1,?2,?3,'edit',?4,?5,?5)"#,
            excalidash_rs::sql::params![uuid::Uuid::new_v4().to_string(), d, peer_id, owner_id, now],
        )
        .unwrap();
    assert_eq!(owner.get("/files/config").json(), json!({"s3Enabled": true}));

    let bytes = vec![1u8, 2, 3];
    let up = upload(&peer, &d, "peer-first", bytes.clone(), "image/png");
    assert_eq!(up.status, 200, "{}", up.text());
    assert_eq!(up.json(), json!({"url": format!("/api/files/{d}/peer-first"), "fileId": "peer-first"}));

    let got = peer.get(&format!("/files/{d}/peer-first"));
    assert_eq!(got.status, 302);
    assert!(got.text().starts_with("Found. Redirecting to "));
    let location = got.header("location").unwrap();
    let fetched = reqwest::blocking::get(&location).unwrap();
    assert_eq!(fetched.status(), 200);
    assert_eq!(fetched.headers()["content-type"], "image/png");
    assert_eq!(fetched.headers()["content-disposition"], "inline; filename=\"peer-first\"");
    assert_eq!(fetched.headers()["cache-control"], "public, max-age=31536000, immutable");
    assert_eq!(fetched.bytes().unwrap().to_vec(), bytes);

    let diff = owner.get(&format!("/drawings/{d}/files/diff"));
    assert_eq!(diff.status, 200);
    let rows = diff.json()["files"].clone();
    assert_eq!(rows.as_array().unwrap().len(), 1);
    assert_eq!(rows[0]["fileId"], "peer-first");
    assert_eq!(rows[0]["inS3"], true);
    assert_eq!(rows[0]["inS3Record"], true);
    assert_eq!(diff.json()["summary"]["totalS3Files"], 1);

    let (storage, key, _) = s3_row(&s, &d, "peer-first").unwrap();
    let key = key.unwrap();
    assert_eq!(storage, "s3");
    assert!(key.starts_with(&format!("excalidash/{owner_id}/{d}/")), "{key}");
    assert!(key.ends_with("/peer-first.png"));

    let retried = upload(&owner, &d, "peer-first", vec![9, 9, 9], "image/png");
    assert_eq!(retried.status, 200);
    let client = S3Client::new(&s3_config(&bucket)).unwrap();
    let rt = rt();
    let objects = rt.block_on(client.list_objects(&http(), &format!("excalidash/{owner_id}/{d}/"))).unwrap();
    assert_eq!(objects.len(), 1);
    assert_eq!(rt.block_on(client.download_buffer(&http(), &key)).unwrap(), bytes);
}

#[test]
fn scriptable_types_are_forced_to_download() {
    if !enabled() {
        return;
    }
    let bucket = create_bucket();
    let s = start(&bucket);
    let (owner, owner_id) = user_session(&s, "owner@test.local", "USER");
    let d = create_drawing(&s, &owner_id, "Svg");
    let svg = b"<svg xmlns=\"http://www.w3.org/2000/svg\"/>".to_vec();
    assert_eq!(upload(&owner, &d, "vector", svg.clone(), "image/svg+xml; charset=utf-8").status, 200);
    let got = owner.get(&format!("/files/{d}/vector"));
    assert_eq!(got.status, 302);
    let fetched = reqwest::blocking::get(got.header("location").unwrap()).unwrap();
    assert_eq!(fetched.headers()["content-type"], "image/svg+xml");
    assert_eq!(fetched.headers()["content-disposition"], "attachment");
    assert_eq!(fetched.bytes().unwrap().to_vec(), svg);
    // Browsers asking for HTML get the html redirect body.
    let html = session_client(&s, &owner_id, "owner@test.local").with_header("Accept", "text/html");
    let r = html.get(&format!("/files/{d}/vector"));
    assert_eq!(r.status, 302);
    assert!(r.text().starts_with("<p>Found. Redirecting to "));
    assert_eq!(r.header("vary").as_deref(), Some("Accept"));
}

/// file-retention: "protects S3 history references during %s and deletes unrelated objects".
#[test]
fn trim_and_orphans_delete_only_unreferenced_objects() {
    if !enabled() {
        return;
    }
    for op in ["trim", "orphans"] {
        let bucket = create_bucket();
        let s = start(&bucket);
        let (owner, owner_id) = user_session(&s, "owner@test.local", "USER");
        let d = create_drawing(&s, &owner_id, "Retention");
        let client = S3Client::new(&s3_config(&bucket)).unwrap();
        let rt = rt();
        let protected_key = client.build_key(&owner_id, &d, "historical", "png", None);
        let orphan_key = client.build_key(&owner_id, &d, "orphan", "png", Some("gen"));
        let untracked_key = client.build_key(&owner_id, &d, "untracked", "png", Some("gen2"));
        for k in [&protected_key, &orphan_key, &untracked_key] {
            rt.block_on(client.upload_buffer(&http(), k, vec![1, 2, 3], "image/png")).unwrap();
        }
        let now = chrono::Utc::now().timestamp_millis();
        for (fid, key) in [("historical", &protected_key), ("orphan", &orphan_key)] {
            s.db()
                .execute(
                    r#"INSERT INTO "DrawingFile" ("drawingId","fileId","mimeType","sizeBytes","storage","s3Key","data","createdAt")
                       VALUES (?1,?2,'image/png',3,'s3',?3,NULL,?4)"#,
                    excalidash_rs::sql::params![d, fid, key, now],
                )
                .unwrap();
        }
        let files = json!({"historical": {"dataURL": format!("/api/files/{d}/historical"), "description": "x".repeat(1000)}});
        s.db()
            .execute(
                r#"INSERT INTO "DrawingSnapshot" ("id","drawingId","version","elements","appState","files","createdAt")
                   VALUES (?1,?2,1,'[]','{}',?3,?4)"#,
                excalidash_rs::sql::params![uuid::Uuid::new_v4().to_string(), d, excalidash_rs::snapshots::encode_field(&files.to_string(), true), now],
            )
            .unwrap();
        let r = if op == "trim" {
            owner.post(&format!("/drawings/{d}/trim"), json!({"confirmName": "Retention"}))
        } else {
            owner.send(
                "DELETE",
                &format!("/drawings/{d}/files/orphans"),
                Some(&json!({"confirmName": "Retention", "fileIds": ["historical", "orphan"]})),
            )
        };
        assert_eq!(r.status, 200, "{op}: {}", r.text());
        if op == "trim" {
            assert_eq!(r.json()["trimmed"]["s3ObjectsDeleted"], 1);
        } else {
            assert_eq!(r.json(), json!({"deleted": 2, "errors": 0}));
        }
        let mut keys: Vec<String> = rt
            .block_on(client.list_objects(&http(), &client.drawing_prefix(&owner_id, &d)))
            .unwrap()
            .into_iter()
            .map(|o| o.key)
            .collect();
        keys.sort();
        let mut expected = vec![protected_key.clone(), untracked_key.clone()];
        expected.sort();
        // Untracked objects may be in-flight uploads: never reclaimed by trim/orphans.
        assert_eq!(keys, expected, "{op}");
        assert!(s3_row(&s, &d, "historical").is_some());
        assert!(s3_row(&s, &d, "orphan").is_none());
        // Diff lists the untracked object as S3-only.
        let diff = owner.get(&format!("/drawings/{d}/files/diff")).json();
        let rows: Vec<Value> = diff["files"].as_array().unwrap().clone();
        let untracked = rows.iter().find(|r| r["fileId"] == "untracked").unwrap();
        assert_eq!(untracked["inS3"], true);
        assert_eq!(untracked["inS3Record"], false);
        assert_eq!(untracked["s3Key"], json!(untracked_key));
        assert_eq!(untracked["s3SizeBytes"], 3);
    }
}

/// s3.ts client operations used by duplicate/export/storage doctor.
#[test]
fn client_operations() {
    if !enabled() {
        return;
    }
    let bucket = create_bucket();
    let client = S3Client::new(&s3_config(&bucket)).unwrap();
    let h = http();
    let rt = rt();
    rt.block_on(async {
        assert_eq!(client.check_bucket_reachable(&h, 3000).await, Ok(()));
        let src = client.build_key("owner", "drawing", "image", "png", Some("generation"));
        client.upload_buffer(&h, &src, vec![7, 7, 7], "image/png").await.unwrap();
        let dest = client.build_key("owner", "copy", "image", "png", None);
        client.copy_object(&h, &src, &dest, Some("image/webp")).await.unwrap();
        assert_eq!(client.download_buffer(&h, &dest).await.unwrap(), vec![7, 7, 7]);
        let url = client.presigned_download_url(&h, &dest, 60, None, None).await.unwrap();
        let r = h.get(&url).send().await.unwrap();
        assert_eq!(r.headers()["content-type"], "image/webp");
        // Pagination-independent listing by prefix.
        for i in 0..3 {
            client.upload_buffer(&h, &format!("excalidash/owner/many/f{i}.png"), vec![i], "image/png").await.unwrap();
        }
        let listed = client.list_objects(&h, "excalidash/owner/many/").await.unwrap();
        assert_eq!(listed.len(), 3);
        assert_eq!(listed[2].size, 1);
        client.delete_object(&h, &dest).await.unwrap();
        assert!(client.download_buffer(&h, &dest).await.is_err());
        assert!(client.copy_object(&h, "missing/key.png", "x/y.png", None).await.is_err());
        let missing = S3Client::new(&s3_config("exrs-does-not-exist-bucket")).unwrap();
        assert!(missing.check_bucket_reachable(&h, 3000).await.is_err());
    });
    let unreachable = S3Client::new(&S3Config { endpoint: Some("http://10.255.255.1:9".into()), ..s3_config(&bucket) }).unwrap();
    let err = rt.block_on(unreachable.check_bucket_reachable(&h, 300)).unwrap_err();
    assert_eq!(err, "timed out after 300ms");
}

/// drawingDeleteDuplicateRoutes: duplicate copies S3 objects into the new drawing's prefix;
/// delete removes every object under the drawing prefix plus recorded keys.
#[test]
fn duplicate_copies_and_delete_removes_s3_objects() {
    if !enabled() {
        return;
    }
    let bucket = create_bucket();
    let s = start(&bucket);
    let (owner, owner_id) = user_session(&s, "owner@test.local", "USER");
    let d = create_drawing(&s, &owner_id, "Source");
    assert_eq!(upload(&owner, &d, "img-a", vec![7u8, 7, 7], "image/png").status, 200);
    s.db()
        .execute(
            r#"UPDATE "Drawing" SET "files" = ?1 WHERE "id" = ?2"#,
            excalidash_rs::sql::params![json!({"img-a": {"id": "img-a", "mimeType": "image/png", "dataURL": format!("/api/files/{d}/img-a")}}).to_string(), d],
        )
        .unwrap();

    let dup = owner.post(&format!("/drawings/{d}/duplicate"), json!({}));
    assert_eq!(dup.status, 200, "{}", dup.text());
    let new_id = dup.json()["id"].as_str().unwrap().to_string();
    assert_eq!(dup.json()["name"], "Source (Copy)");
    assert_eq!(dup.json()["files"]["img-a"]["dataURL"], Value::String(format!("/api/files/{new_id}/img-a")));
    let (storage, key, mime) = s3_row(&s, &new_id, "img-a").unwrap();
    let key = key.unwrap();
    assert_eq!((storage.as_str(), mime.as_str()), ("s3", "image/png"));
    assert_eq!(key, format!("excalidash/{owner_id}/{new_id}/img-a.png"));
    let client = S3Client::new(&s3_config(&bucket)).unwrap();
    let rt = rt();
    assert_eq!(rt.block_on(client.download_buffer(&http(), &key)).unwrap(), vec![7u8, 7, 7]);

    // Delete the source: its objects go, the copy's stay.
    let del = owner.delete(&format!("/drawings/{d}"));
    assert_eq!(del.status, 200, "{}", del.text());
    let src_objects = rt.block_on(client.list_objects(&http(), &format!("excalidash/{owner_id}/{d}/"))).unwrap();
    assert!(src_objects.is_empty(), "{src_objects:?}");
    assert!(s3_row(&s, &d, "img-a").is_none());
    assert_eq!(rt.block_on(client.download_buffer(&http(), &key)).unwrap(), vec![7u8, 7, 7]);
    let got = owner.get(&format!("/files/{new_id}/img-a"));
    assert_eq!(got.status, 302);
}

/// No explicit keys: the AWS default chain supplies credentials (upstream leaves
/// `credentials` unset and the SDK resolves them). Covers a shared credentials
/// profile and an ECS-style container credentials endpoint.
#[test]
fn default_credential_chain_profile_and_container() {
    if !enabled() {
        return;
    }
    let bucket = create_bucket();
    let ep = endpoint();
    let (ak, sk) = (env_or("EXRS_TEST_S3_ACCESS_KEY", "minio"), env_or("EXRS_TEST_S3_SECRET_KEY", "minio12345"));

    // 1) shared credentials file selected via AWS_PROFILE
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join(".aws")).unwrap();
    std::fs::write(
        home.path().join(".aws/credentials"),
        format!("[default]\naws_access_key_id = wrong\naws_secret_access_key = wrong\n\n[exrs]\naws_access_key_id = {ak}\naws_secret_access_key = {sk}\n"),
    )
    .unwrap();
    let home_s = home.path().display().to_string();
    let s = TestServer::start(&[
        ("S3_BUCKET", &bucket), ("S3_REGION", "us-east-1"), ("S3_ENDPOINT", &ep), ("S3_FORCE_PATH_STYLE", "true"),
        ("HOME", &home_s), ("AWS_PROFILE", "exrs"), ("AWS_EC2_METADATA_DISABLED", "true"),
    ]);
    let (owner, owner_id) = user_session(&s, "owner@test.local", "USER");
    let d = create_drawing(&s, &owner_id, "Profile");
    let up = upload(&owner, &d, "via-profile", vec![1, 2, 3], "image/png");
    assert_eq!(up.status, 200, "{}\n{}", up.text(), s.output());
    let got = owner.get(&format!("/files/{d}/via-profile"));
    assert_eq!(got.status, 302);
    assert_eq!(reqwest::blocking::get(got.header("location").unwrap()).unwrap().bytes().unwrap().to_vec(), vec![1, 2, 3]);
    drop(s);

    // 2) container credentials endpoint (AWS_CONTAINER_CREDENTIALS_FULL_URI + auth token)
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let body = format!(r#"{{"AccessKeyId":"{ak}","SecretAccessKey":"{sk}","Expiration":"2099-01-01T00:00:00Z"}}"#);
    let seen_auth = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    let seen = seen_auth.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            use std::io::{BufRead, Write};
            let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            loop {
                line.clear();
                if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" { break; }
                if line.to_lowercase().starts_with("authorization:") { *seen.lock().unwrap() = line.trim().to_string(); }
            }
            let mut s = stream;
            let _ = write!(s, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body);
        }
    });
    let uri = format!("http://127.0.0.1:{port}/creds");
    let s = TestServer::start(&[
        ("S3_BUCKET", &bucket), ("S3_REGION", "us-east-1"), ("S3_ENDPOINT", &ep), ("S3_FORCE_PATH_STYLE", "true"),
        ("AWS_CONTAINER_CREDENTIALS_FULL_URI", &uri), ("AWS_CONTAINER_AUTHORIZATION_TOKEN", "secret-token"),
        ("AWS_EC2_METADATA_DISABLED", "true"),
    ]);
    let (owner, owner_id) = user_session(&s, "owner@test.local", "USER");
    let d = create_drawing(&s, &owner_id, "Container");
    let up = upload(&owner, &d, "via-container", vec![4, 5], "image/png");
    assert_eq!(up.status, 200, "{}\n{}", up.text(), s.output());
    assert_eq!(seen_auth.lock().unwrap().to_lowercase(), "authorization: secret-token");
    drop(s);

    // 3) nothing available: upload fails like the SDK ("Could not load credentials from any providers")
    let s = TestServer::start(&[
        ("S3_BUCKET", &bucket), ("S3_REGION", "us-east-1"), ("S3_ENDPOINT", &ep), ("S3_FORCE_PATH_STYLE", "true"),
        ("HOME", "/nonexistent"), ("AWS_EC2_METADATA_DISABLED", "true"),
    ]);
    let (owner, owner_id) = user_session(&s, "owner@test.local", "USER");
    let d = create_drawing(&s, &owner_id, "None");
    let up = upload(&owner, &d, "nope", vec![1], "image/png");
    assert_eq!(up.status, 500, "{}", up.text());
    assert!(s.output().contains("Could not load credentials from any providers"), "{}", s.output());
}
