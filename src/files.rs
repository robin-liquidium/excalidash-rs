//! fileProcessing.ts + drawingFileStore.ts — image blob interning and the
//! immutable DrawingFile store (S3 objects or inline database bytes).
use base64::Engine;
use rusqlite::{Connection, OptionalExtension};
use serde_json::{Map, Value};

use crate::db::{Db, DbError};
use crate::http::error::ApiError;
use crate::s3::{self, S3Client};
use crate::state::AppState;

/// `MIME_TO_EXT` (insertion order matters for the 415 message).
pub const MIME_TO_EXT: [(&str, &str); 7] = [
    ("image/png", "png"),
    ("image/jpeg", "jpg"),
    ("image/gif", "gif"),
    ("image/webp", "webp"),
    ("image/avif", "avif"),
    ("image/bmp", "bmp"),
    ("image/svg+xml", "svg"),
];

pub fn mime_ext(mime: &str) -> Option<&'static str> {
    MIME_TO_EXT.iter().find(|(m, _)| *m == mime).map(|(_, e)| *e)
}

/// `/^[\w-]{1,200}$/` (ASCII word chars, as in JS without the `u` flag).
pub fn is_valid_file_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 200 && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

const UPLOAD_CONCURRENCY: usize = 8;

/// `decodeDataURL`: `^data:([^;]+);base64,(.+)$` (dotall), Node's lenient base64.
pub fn decode_data_url(data_url: &str) -> Option<(Vec<u8>, String)> {
    let rest = data_url.strip_prefix("data:")?;
    let semi = rest.find(';')?;
    let mime = &rest[..semi];
    if mime.is_empty() {
        return None;
    }
    let payload = rest[semi..].strip_prefix(";base64,")?;
    if payload.is_empty() {
        return None;
    }
    Some((node_base64_decode(payload), mime.to_string()))
}

/// Node `Buffer.from(str, "base64")`: accepts base64 and base64url alphabets,
/// skips anything else, stops at the first `=`.
fn node_base64_decode(input: &str) -> Vec<u8> {
    let mut clean = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '+' | '/' => clean.push(c),
            '-' => clean.push('+'),
            '_' => clean.push('/'),
            '=' => break,
            _ => {}
        }
    }
    if clean.len() % 4 == 1 {
        clean.pop();
    }
    base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(clean.as_bytes())
        .or_else(|_| {
            // Non-canonical trailing bits: Node ignores them.
            let cfg = base64::engine::GeneralPurposeConfig::new()
                .with_decode_allow_trailing_bits(true)
                .with_decode_padding_mode(base64::engine::DecodePaddingMode::RequireNone);
            base64::engine::GeneralPurpose::new(&base64::alphabet::STANDARD, cfg).decode(clean.as_bytes())
        })
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// drawingFileStore.ts

#[derive(Debug, Clone, PartialEq)]
pub struct DrawingFileRow {
    pub drawing_id: String,
    pub file_id: String,
    pub mime_type: String,
    pub size_bytes: i64,
    pub storage: String,
    pub s3_key: Option<String>,
    pub data: Option<Vec<u8>>,
    pub created_at: i64,
}

impl DrawingFileRow {
    /// `hasDrawingFileContent`
    pub fn has_content(&self) -> bool {
        (self.storage == "s3" && self.s3_key.as_deref().is_some_and(|k| !k.is_empty()))
            || (self.storage == "db" && self.data.is_some())
    }
}

/// Values for a new DrawingFile row.
#[derive(Debug, Clone)]
pub struct FileContent {
    pub drawing_id: String,
    pub file_id: String,
    pub mime_type: String,
    pub size_bytes: i64,
    pub storage: &'static str,
    pub s3_key: Option<String>,
    pub data: Option<Vec<u8>>,
}

pub fn find_drawing_file(c: &Connection, drawing_id: &str, file_id: &str) -> rusqlite::Result<Option<DrawingFileRow>> {
    c.query_row(
        r#"SELECT "drawingId","fileId","mimeType","sizeBytes","storage","s3Key","data","createdAt"
           FROM "DrawingFile" WHERE "drawingId" = ?1 AND "fileId" = ?2"#,
        [drawing_id, file_id],
        |r| {
            Ok(DrawingFileRow {
                drawing_id: r.get(0)?,
                file_id: r.get(1)?,
                mime_type: r.get(2)?,
                size_bytes: r.get(3)?,
                storage: r.get(4)?,
                s3_key: r.get(5)?,
                data: r.get(6)?,
                created_at: crate::db::dt(r, 7)?,
            })
        },
    )
    .optional()
}

/// `storeDrawingFileOnce`: insert an immutable file id without replacing a
/// concurrent winner's bytes; repair a legacy empty row only while still empty.
pub fn store_drawing_file_once(c: &Connection, content: &FileContent) -> Result<DrawingFileRow, DbError> {
    // Atomic native upsert: the first writer wins, later writers read its row.
    c.execute(
        r#"INSERT INTO "DrawingFile" ("drawingId","fileId","mimeType","sizeBytes","storage","s3Key","data","createdAt")
           VALUES (?1,?2,?3,?4,?5,?6,?7,?8)
           ON CONFLICT ("drawingId","fileId") DO UPDATE SET "fileId" = excluded."fileId""#,
        rusqlite::params![
            content.drawing_id,
            content.file_id,
            content.mime_type,
            content.size_bytes,
            content.storage,
            content.s3_key,
            content.data,
            crate::util::now_ms()
        ],
    )?;
    let stored = find_drawing_file(c, &content.drawing_id, &content.file_id)?
        .ok_or(DbError::Sqlite(rusqlite::Error::QueryReturnedNoRows))?;
    if stored.has_content() {
        return Ok(stored);
    }
    c.execute(
        r#"UPDATE "DrawingFile" SET "drawingId" = ?1, "fileId" = ?2, "mimeType" = ?3, "sizeBytes" = ?4,
               "storage" = ?5, "s3Key" = ?6, "data" = ?7
           WHERE "drawingId" = ?1 AND "fileId" = ?2 AND (
               ("storage" = 'db' AND "data" IS NULL) OR ("storage" = 's3' AND "s3Key" IS NULL) OR ("storage" = 's3' AND "s3Key" = ''))"#,
        rusqlite::params![
            content.drawing_id,
            content.file_id,
            content.mime_type,
            content.size_bytes,
            content.storage,
            content.s3_key,
            content.data
        ],
    )?;
    find_drawing_file(c, &content.drawing_id, &content.file_id)?.ok_or(DbError::Sqlite(rusqlite::Error::QueryReturnedNoRows))
}

/// `cleanupUnusedS3Upload`: reclaim only this request's fresh generation when another row won.
pub async fn cleanup_unused_s3_upload(http: &reqwest::Client, s3c: &S3Client, fresh_key: &str, stored: &DrawingFileRow) {
    if stored.storage == "s3" && stored.s3_key.as_deref() == Some(fresh_key) {
        return;
    }
    if let Err(e) = s3c.delete_object(http, fresh_key).await {
        eprintln!("[files] Failed to cleanup unused S3 upload {{ freshKey: {fresh_key:?}, error: {e:?} }}");
    }
}

fn file_url(s3c: Option<&S3Client>, row: &DrawingFileRow, drawing_id: &str, file_id: &str) -> String {
    match (s3c, row.storage.as_str(), row.s3_key.as_deref()) {
        (Some(c), "s3", Some(key)) if !key.is_empty() && c.public_url_base().is_some() => c.public_url(key),
        _ => format!("/api/files/{drawing_id}/{file_id}"),
    }
}

fn with_ref(file: &Value, mime: &str, url: String) -> Value {
    let mut obj = file.as_object().cloned().unwrap_or_default();
    obj.insert("mimeType".into(), Value::String(mime.to_string()));
    obj.insert("dataURL".into(), Value::String(url));
    Value::Object(obj)
}

/// `randomUUID()` — generation directory for fresh S3 uploads.
fn generation() -> String {
    crate::util::uuid_v4()
}

/// The core of internDrawingFiles with explicit dependencies.
/// Returns `Some(new value)` to replace the entry, `None` to drop it, or the
/// unchanged entry when it is not an inline data URL.
async fn process_file(
    db: &Db,
    http: &reqwest::Client,
    s3c: Option<&'static S3Client>,
    user_id: &str,
    drawing_id: &str,
    file_id: &str,
    file: &Value,
) -> Result<Option<Value>, ApiError> {
    if !is_valid_file_id(file_id) {
        eprintln!("[files] Skipping file with invalid id: {}", serde_json::to_string(file_id).unwrap_or_default());
        return Ok(None);
    }
    let Some(data_url) = file.get("dataURL").and_then(Value::as_str).filter(|d| d.starts_with("data:")) else {
        return Ok(Some(file.clone()));
    };
    let Some((buffer, mime_type)) = decode_data_url(data_url) else {
        return Ok(Some(file.clone()));
    };

    let (did, fid) = (drawing_id.to_string(), file_id.to_string());
    let existing = db.call(move |c| Ok(find_drawing_file(c, &did, &fid)?)).await?;
    if let Some(existing) = existing.filter(DrawingFileRow::has_content) {
        let url = file_url(s3c, &existing, drawing_id, file_id);
        return Ok(Some(with_ref(file, &existing.mime_type, url)));
    }

    let size_bytes = buffer.len() as i64;
    let stored = if let Some(c) = s3c {
        let ext = mime_ext(&mime_type).unwrap_or("bin");
        let key = c.build_key(user_id, drawing_id, file_id, ext, Some(&generation()));
        c.upload_buffer(http, &key, buffer, &mime_type).await?;
        let content = FileContent {
            drawing_id: drawing_id.to_string(),
            file_id: file_id.to_string(),
            mime_type,
            size_bytes,
            storage: "s3",
            s3_key: Some(key.clone()),
            data: None,
        };
        let stored = db.call(move |conn| store_drawing_file_once(conn, &content)).await?;
        cleanup_unused_s3_upload(http, c, &key, &stored).await;
        stored
    } else {
        let content = FileContent {
            drawing_id: drawing_id.to_string(),
            file_id: file_id.to_string(),
            mime_type,
            size_bytes,
            storage: "db",
            s3_key: None,
            data: Some(buffer),
        };
        db.call(move |conn| store_drawing_file_once(conn, &content)).await?
    };
    let url = file_url(s3c, &stored, drawing_id, file_id);
    Ok(Some(with_ref(file, &stored.mime_type, url)))
}

/// internDrawingFiles with explicit dependencies (`s3c = None` → database-bytes mode).
pub async fn intern_drawing_files_with(
    db: &Db,
    http: &reqwest::Client,
    s3c: Option<&'static S3Client>,
    files: Map<String, Value>,
    user_id: &str,
    drawing_id: &str,
) -> Result<Map<String, Value>, ApiError> {
    let mut result = files.clone();
    let entries: Vec<(String, Value)> = files.into_iter().collect();
    for chunk in entries.chunks(UPLOAD_CONCURRENCY) {
        let outcomes = futures_util::future::join_all(
            chunk.iter().map(|(id, file)| process_file(db, http, s3c, user_id, drawing_id, id, file)),
        )
        .await;
        // Promise.all: apply what finished, then surface the first failure.
        let mut first_err = None;
        for ((id, _), outcome) in chunk.iter().zip(outcomes) {
            match outcome {
                Ok(Some(v)) => {
                    result.insert(id.clone(), v);
                }
                Ok(None) => {
                    result.shift_remove(id);
                }
                Err(e) => {
                    first_err.get_or_insert(e);
                }
            }
        }
        if let Some(e) = first_err {
            return Err(e);
        }
    }
    Ok(result)
}

/// internDrawingFiles(files, userId, drawingId): store inline dataURLs, rewrite to refs.
pub async fn intern_drawing_files(
    st: &AppState,
    files: Map<String, Value>,
    user_id: &str,
    drawing_id: &str,
) -> Result<Map<String, Value>, ApiError> {
    intern_drawing_files_with(&st.db, st.http(), s3::client(), files, user_id, drawing_id).await
}

/// rewritePreviewForInternedFiles(preview, originalFiles, processedFiles)
pub fn rewrite_preview_for_interned_files(preview: &Value, original: &Map<String, Value>, processed: &Map<String, Value>) -> Value {
    let Value::String(p) = preview else { return preview.clone() };
    if p.is_empty() {
        return preview.clone();
    }
    let mut out = p.clone();
    for (id, proc_file) in processed {
        let (Some(o), Some(n)) = (
            original.get(id).and_then(|f| f.get("dataURL")).and_then(|v| v.as_str()),
            proc_file.get("dataURL").and_then(|v| v.as_str()),
        ) else {
            continue;
        };
        if o == n {
            continue;
        }
        out = if o.is_empty() {
            // JS `split("")` splits between every character.
            out.chars().map(String::from).collect::<Vec<_>>().join(n)
        } else {
            out.split(o).collect::<Vec<_>>().join(n)
        };
    }
    Value::String(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn temp_db() -> (tempfile::TempDir, Db) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dev.db");
        {
            let mut c = Connection::open(&path).unwrap();
            crate::db::migrate_deploy(&mut c).unwrap();
        }
        let db = Db::open(&path).unwrap();
        (dir, db)
    }

    fn seed_drawing(db: &Db) -> (String, String) {
        let c = db.get().unwrap();
        let uid = crate::util::uuid_v4();
        let did = crate::util::uuid_v4();
        let now = crate::util::now_ms();
        c.execute(
            r#"INSERT INTO "User" ("id","email","passwordHash","name","role","mustResetPassword","isActive","createdAt","updatedAt")
               VALUES (?1,?2,'unused','Owner','USER',0,1,?3,?3)"#,
            rusqlite::params![uid, format!("{uid}@test.local"), now],
        )
        .unwrap();
        c.execute(
            r#"INSERT INTO "Drawing" ("id","name","elements","appState","files","userId","version","createdAt","updatedAt")
               VALUES (?1,'Retention','[]','{}','{}',?2,1,?3,?3)"#,
            rusqlite::params![did, uid, now],
        )
        .unwrap();
        (uid, did)
    }

    fn insert_row(db: &Db, did: &str, fid: &str, storage: &str, s3_key: Option<&str>, data: Option<&[u8]>) {
        db.get()
            .unwrap()
            .execute(
                r#"INSERT INTO "DrawingFile" ("drawingId","fileId","mimeType","sizeBytes","storage","s3Key","data","createdAt")
                   VALUES (?1,?2,'image/png',?3,?4,?5,?6,?7)"#,
                rusqlite::params![did, fid, data.map(|d| d.len() as i64).unwrap_or(0), storage, s3_key, data, crate::util::now_ms()],
            )
            .unwrap();
    }

    fn row(db: &Db, did: &str, fid: &str) -> Option<DrawingFileRow> {
        find_drawing_file(&db.get().unwrap(), did, fid).unwrap()
    }

    fn http() -> reqwest::Client {
        crate::net::build_http_client()
    }

    #[test]
    fn decode_data_url_matches_node() {
        let (bytes, mime) = decode_data_url("data:image/png;base64,AQID").unwrap();
        assert_eq!((bytes, mime.as_str()), (vec![1, 2, 3], "image/png"));
        assert_eq!(decode_data_url("data:image/png;base64,CQkJ").unwrap().0, vec![9, 9, 9]);
        assert_eq!(decode_data_url("data:image/png;base64,AAAA").unwrap().0, vec![0, 0, 0]);
        assert!(decode_data_url("data:;base64,AAAA").is_none());
        assert!(decode_data_url("data:image/png,AAAA").is_none());
        assert!(decode_data_url("https://x/y.png").is_none());
        assert_eq!(decode_data_url("data:image/png;base64,AQ\nID").unwrap().0, vec![1, 2, 3]);
        assert!(is_valid_file_id("img-1_A"));
        assert!(!is_valid_file_id("../x"));
        assert!(!is_valid_file_id(""));
    }

    #[tokio::test]
    async fn interns_inline_data_urls_into_db_rows() {
        let (_dir, db) = temp_db();
        let (uid, did) = seed_drawing(&db);
        let files = json!({
            "img-x": {"id": "img-x", "mimeType": "image/jpeg", "dataURL": "data:image/png;base64,AQID", "created": 1},
            "external": {"id": "external", "mimeType": "image/png", "dataURL": "https://external.example/image.png"},
            "../evil": {"dataURL": "data:image/png;base64,AQID"},
        });
        let out = intern_drawing_files_with(&db, &http(), None, files.as_object().unwrap().clone(), &uid, &did)
            .await
            .unwrap();
        assert_eq!(out.keys().collect::<Vec<_>>(), vec!["img-x", "external"]);
        assert_eq!(out["img-x"]["dataURL"], format!("/api/files/{did}/img-x"));
        assert_eq!(out["img-x"]["mimeType"], "image/png");
        assert_eq!(out["img-x"]["created"], 1);
        assert_eq!(out["external"], files["external"]);
        let r = row(&db, &did, "img-x").unwrap();
        assert_eq!((r.storage.as_str(), r.data.as_deref(), r.size_bytes), ("db", Some(&[1u8, 2, 3][..]), 3));
        assert!(row(&db, &did, "external").is_none());
    }

    /// file-retention: "does not reupload immutable existing S3 bytes from a stale inline entry"
    /// and drawing-file-store: "keeps immutable uploaded image bytes when an old scene resends the file id".
    #[tokio::test]
    async fn existing_content_is_immutable() {
        let (_dir, db) = temp_db();
        let (uid, did) = seed_drawing(&db);
        insert_row(&db, &did, "image", "s3", Some("owner/drawing/image.png"), None);
        insert_row(&db, &did, "bytes", "db", None, Some(&[1, 2, 3, 4]));
        let files = json!({
            "image": {"dataURL": "data:image/png;base64,AAAA"},
            "bytes": {"dataURL": "data:image/png;base64,AAAA"},
        });
        // s3c = None: an upload attempt would have stored db bytes instead.
        let out = intern_drawing_files_with(&db, &http(), None, files.as_object().unwrap().clone(), &uid, &did)
            .await
            .unwrap();
        assert_eq!(out["image"]["dataURL"], format!("/api/files/{did}/image"));
        assert_eq!(out["bytes"]["dataURL"], format!("/api/files/{did}/bytes"));
        assert_eq!(row(&db, &did, "image").unwrap().s3_key.as_deref(), Some("owner/drawing/image.png"));
        assert_eq!(row(&db, &did, "bytes").unwrap().data.as_deref(), Some(&[1u8, 2, 3, 4][..]));
    }

    /// file-retention: "keeps database winner bytes after a stale missing-row lookup".
    #[test]
    fn store_once_keeps_winner_bytes() {
        let (_dir, db) = temp_db();
        let (_uid, did) = seed_drawing(&db);
        insert_row(&db, &did, "image", "db", None, Some(&[1, 2, 3, 4]));
        let c = db.get().unwrap();
        let stored = store_drawing_file_once(
            &c,
            &FileContent {
                drawing_id: did.clone(),
                file_id: "image".into(),
                mime_type: "image/jpeg".into(),
                size_bytes: 3,
                storage: "db",
                s3_key: None,
                data: Some(vec![9, 9, 9]),
            },
        )
        .unwrap();
        assert_eq!(stored.data.as_deref(), Some(&[1u8, 2, 3, 4][..]));
        assert_eq!(stored.mime_type, "image/png");
    }

    /// file-retention: "repairs an empty legacy row once when two stores race" and
    /// "uses a native upsert for simultaneous first stores without changing winner bytes".
    #[test]
    fn concurrent_stores_agree_on_one_winner() {
        for legacy_empty_row in [true, false] {
            let (_dir, db) = temp_db();
            let (_uid, did) = seed_drawing(&db);
            if legacy_empty_row {
                insert_row(&db, &did, "image", "db", None, None);
            }
            let rows: Vec<DrawingFileRow> = [vec![1u8, 2, 3], vec![9, 9, 9]]
                .into_iter()
                .map(|bytes| {
                    let db = db.clone();
                    let did = did.clone();
                    std::thread::spawn(move || {
                        let c = db.get().unwrap();
                        store_drawing_file_once(
                            &c,
                            &FileContent {
                                drawing_id: did,
                                file_id: "image".into(),
                                mime_type: "image/png".into(),
                                size_bytes: 3,
                                storage: "db",
                                s3_key: None,
                                data: Some(bytes),
                            },
                        )
                        .unwrap()
                    })
                })
                .collect::<Vec<_>>()
                .into_iter()
                .map(|h| h.join().unwrap())
                .collect();
            assert!(rows[0].data.is_some());
            assert_eq!(rows[0].data, rows[1].data);
            assert_eq!(row(&db, &did, "image").unwrap().data, rows[0].data);
        }
    }

    /// file-retention: "preserves existing managed bytes when later interning fails".
    #[tokio::test]
    async fn failure_in_later_batch_keeps_existing_bytes() {
        let (_dir, db) = temp_db();
        let (uid, did) = seed_drawing(&db);
        insert_row(&db, &did, "existing", "db", None, Some(&[1, 2, 3, 4]));
        let mut files = Map::new();
        files.insert("existing".into(), json!({"dataURL": "data:image/png;base64,AAAA"}));
        for i in 0..7 {
            files.insert(format!("ref-{i}"), json!({"dataURL": "https://files.example/image.png"}));
        }
        files.insert("fail".into(), json!({"dataURL": "data:image/png;base64,AAAA"}));
        // Make the second batch's store fail like the mocked upsert upstream.
        let c = db.get().unwrap();
        c.execute_batch(
            r#"CREATE TRIGGER fail_store BEFORE INSERT ON "DrawingFile" WHEN NEW."fileId" = 'fail'
               BEGIN SELECT RAISE(ABORT, 'simulated storage failure'); END;"#,
        )
        .unwrap();
        let err = intern_drawing_files_with(&db, &http(), None, files, &uid, &did).await.unwrap_err();
        assert!(format!("{err:?}").contains("simulated storage failure"));
        assert_eq!(row(&db, &did, "existing").unwrap().data.as_deref(), Some(&[1u8, 2, 3, 4][..]));
    }

    #[test]
    fn preview_rewrite() {
        let original = json!({"a": {"dataURL": "data:image/png;base64,AQID"}, "b": {"dataURL": "x"}});
        let processed = json!({"a": {"dataURL": "/api/files/d/a"}, "b": {"dataURL": "x"}});
        let preview = json!("<image href=\"data:image/png;base64,AQID\"/><image href=\"data:image/png;base64,AQID\"/>");
        let out = rewrite_preview_for_interned_files(&preview, original.as_object().unwrap(), processed.as_object().unwrap());
        assert_eq!(out, json!("<image href=\"/api/files/d/a\"/><image href=\"/api/files/d/a\"/>"));
        assert_eq!(rewrite_preview_for_interned_files(&json!(null), &Map::new(), &Map::new()), json!(null));
    }
}
