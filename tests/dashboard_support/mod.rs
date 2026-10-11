//! Shared helpers for the dashboard_* tests (included via `#[path]`).
#![allow(dead_code)]

use crate::common::*;
use serde_json::{json, Value};

/// Server with auth enabled + onboarding completed.
pub fn auth_server() -> TestServer {
    let s = TestServer::start(&[]);
    enable_auth(&s);
    s
}

pub fn auth_server_with(env: &[(&str, &str)]) -> TestServer {
    let s = TestServer::start(env);
    enable_auth(&s);
    s
}

/// Seed a user and return a cookie-authenticated client with CSRF.
pub fn user(s: &TestServer, email: &str, name: &str) -> (TestClient, String) {
    let id = seed_user(s, email, name, "USER");
    (session_client(s, &id, &email.to_lowercase()), id)
}

/// Anonymous browser-like client with a CSRF token.
pub fn anon(s: &TestServer) -> TestClient {
    let mut c = s.client();
    c.fetch_csrf();
    c
}

pub fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

#[derive(Default)]
pub struct NewDrawing<'a> {
    pub name: &'a str,
    pub elements: Option<&'a str>,
    pub app_state: Option<&'a str>,
    pub files: Option<&'a str>,
    pub preview: Option<&'a str>,
    pub version: Option<i64>,
    pub collection_id: Option<&'a str>,
}

pub fn insert_drawing(s: &TestServer, user_id: &str, d: NewDrawing<'_>) -> String {
    let id = uuid::Uuid::new_v4().to_string();
    let now = now_ms();
    s.db()
        .execute(
            r#"INSERT INTO "Drawing" ("id","name","elements","appState","files","preview","version","userId","collectionId","createdAt","updatedAt")
               VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?10)"#,
            excalidash_rs::sql::params![
                id,
                if d.name.is_empty() { "Drawing" } else { d.name },
                d.elements.unwrap_or("[]"),
                d.app_state.unwrap_or("{}"),
                d.files.unwrap_or("{}"),
                d.preview,
                d.version.unwrap_or(1),
                user_id,
                d.collection_id,
                now
            ],
        )
        .unwrap();
    id
}

pub fn simple_drawing(s: &TestServer, user_id: &str, name: &str) -> String {
    insert_drawing(s, user_id, NewDrawing { name, ..Default::default() })
}

pub fn insert_collection(s: &TestServer, user_id: &str, name: &str) -> String {
    let id = uuid::Uuid::new_v4().to_string();
    let now = now_ms();
    s.db()
        .execute(
            r#"INSERT INTO "Collection" ("id","name","userId","createdAt","updatedAt") VALUES (?1,?2,?3,?4,?4)"#,
            excalidash_rs::sql::params![id, name, user_id, now],
        )
        .unwrap();
    id
}

pub fn insert_permission(s: &TestServer, drawing_id: &str, grantee: &str, permission: &str, created_by: &str) -> String {
    let id = uuid::Uuid::new_v4().to_string();
    let now = now_ms();
    s.db()
        .execute(
            r#"INSERT INTO "DrawingPermission" ("id","drawingId","granteeUserId","permission","hidden","createdByUserId","createdAt","updatedAt")
               VALUES (?1,?2,?3,?4,0,?5,?6,?6)"#,
            excalidash_rs::sql::params![id, drawing_id, grantee, permission, created_by, now],
        )
        .unwrap();
    id
}

pub fn insert_collection_share(s: &TestServer, collection_id: &str, grantee: &str, role: &str, created_by: &str) {
    let now = now_ms();
    s.db()
        .execute(
            r#"INSERT INTO "CollectionShare" ("id","collectionId","granteeUserId","role","createdByUserId","createdAt","updatedAt")
               VALUES (?1,?2,?3,?4,?5,?6,?6)"#,
            excalidash_rs::sql::params![uuid::Uuid::new_v4().to_string(), collection_id, grantee, role, created_by, now],
        )
        .unwrap();
}

pub fn insert_snapshot(s: &TestServer, drawing_id: &str, version: i64, elements: &str, app_state: &str, files: &str) -> String {
    let id = uuid::Uuid::new_v4().to_string();
    s.db()
        .execute(
            r#"INSERT INTO "DrawingSnapshot" ("id","drawingId","version","elements","appState","files","createdAt") VALUES (?1,?2,?3,?4,?5,?6,?7)"#,
            excalidash_rs::sql::params![id, drawing_id, version, elements, app_state, files, now_ms()],
        )
        .unwrap();
    id
}

pub fn insert_db_file(s: &TestServer, drawing_id: &str, file_id: &str, bytes: &[u8]) {
    s.db()
        .execute(
            r#"INSERT INTO "DrawingFile" ("drawingId","fileId","mimeType","sizeBytes","storage","s3Key","data","createdAt") VALUES (?1,?2,'image/png',?3,'db',NULL,?4,?5)"#,
            excalidash_rs::sql::params![drawing_id, file_id, bytes.len() as i64, bytes, now_ms()],
        )
        .unwrap();
}

/// Full Drawing row as (name, elements, appState, files, preview, version, collectionId, updatedAt).
pub fn drawing_row(s: &TestServer, id: &str) -> Option<(String, String, String, String, Option<String>, i64, Option<String>, i64)> {
    use excalidash_rs::sql::OptionalExtension;
    s.db()
        .query_row(
            r#"SELECT "name","elements","appState","files","preview","version","collectionId","updatedAt" FROM "Drawing" WHERE "id" = ?1"#,
            [id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?)),
        )
        .optional()
        .unwrap()
}

pub fn drawing_files(s: &TestServer, id: &str) -> Value {
    serde_json::from_str(&drawing_row(s, id).unwrap().3).unwrap()
}

pub fn count(s: &TestServer, sql: &str, p: &str) -> i64 {
    s.db().query_row(sql, [p], |r| r.get(0)).unwrap()
}

pub fn ids(body: &Value) -> Vec<String> {
    body["drawings"].as_array().unwrap().iter().map(|d| d["id"].as_str().unwrap().to_string()).collect()
}

pub fn file_entry(id: &str, data_url: &str) -> Value {
    json!({"id": id, "mimeType": "image/png", "dataURL": data_url, "created": 1})
}

/// JWT signed like a refresh token (type=refresh) — invalid as an access token.
pub fn refresh_like_token(user_id: &str, email: &str) -> String {
    let now = chrono::Utc::now().timestamp();
    let claims = json!({"userId": user_id, "email": email, "type": "refresh", "iat": now, "exp": now + 3600});
    jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
        &claims,
        &jsonwebtoken::EncodingKey::from_secret(TEST_JWT_SECRET.as_bytes()),
    )
    .unwrap()
}

/// Client with a Bearer token (no cookies) plus CSRF.
pub fn bearer_client(s: &TestServer, user_id: &str, email: &str) -> TestClient {
    let mut c = s.client();
    c.bearer = Some(mint_access_token(user_id, email));
    c.fetch_csrf();
    c
}

pub trait ClientExt {
    fn clone_client(&self) -> TestClient;
    fn clone_with_header(&self, k: &str, v: &str) -> TestClient;
}

impl ClientExt for TestClient {
    fn clone_client(&self) -> TestClient {
        TestClient {
            base: self.base.clone(),
            http: self.http.clone(),
            origin: self.origin.clone(),
            csrf: self.csrf.clone(),
            bearer: self.bearer.clone(),
            extra: self.extra.clone(),
        }
    }
    fn clone_with_header(&self, k: &str, v: &str) -> TestClient {
        self.clone_client().with_header(k, v)
    }
}
