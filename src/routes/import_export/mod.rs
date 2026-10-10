//! routes/importExport/* — `.excalidash` export/import and legacy SQLite import.
//!
//! `shared.ts` helpers live here; each upstream route file has its own module.
mod excalidash_import;
mod export;
pub mod export_files;
mod legacy_sqlite_import;

use axum::{
    extract::{DefaultBodyLimit, FromRequest, Multipart, Request},
    routing::{get, post},
    Router,
};
use rusqlite::{Connection, OptionalExtension, Transaction};
use serde_json::{Map, Value};
use std::{
    collections::HashSet,
    io::Read,
    path::{Path, PathBuf},
};
use tokio::io::AsyncWriteExt;

use crate::http::error::ApiError;
use crate::state::AppState;

// index.ts limits.
pub const MAX_IMPORT_ARCHIVE_ENTRIES: usize = 6000;
pub const MAX_IMPORT_COLLECTIONS: usize = 1000;
pub const MAX_IMPORT_DRAWINGS: usize = 5000;
pub const MAX_IMPORT_MANIFEST_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_IMPORT_TOTAL_EXTRACTED_BYTES: usize = 120 * 1024 * 1024;

/// MAX_IMPORT_DRAWING_BYTES = min(config.uploadMaxBytes, MAX_IMPORT_TOTAL_EXTRACTED_BYTES)
pub fn max_import_drawing_bytes() -> usize {
    let upload = crate::config::config().upload_max_bytes;
    let total = MAX_IMPORT_TOTAL_EXTRACTED_BYTES as f64;
    let v = if upload < total { upload } else { total };
    if v.is_finite() && v > 0.0 { v as usize } else { 0 }
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/export/excalidash", get(export::export_excalidash))
        .route(
            "/import/excalidash/verify",
            post(excalidash_import::verify).layer(DefaultBodyLimit::disable()),
        )
        .route("/import/excalidash", post(excalidash_import::import).layer(DefaultBodyLimit::disable()))
        .route(
            "/import/sqlite/legacy/verify",
            post(legacy_sqlite_import::verify).layer(DefaultBodyLimit::disable()),
        )
        .route("/import/sqlite/legacy", post(legacy_sqlite_import::import).layer(DefaultBodyLimit::disable()))
}

// ---------------------------------------------------------------------------
// ImportValidationError

#[derive(Debug, Clone, PartialEq)]
pub struct ImportValidationError {
    pub message: String,
    pub status: u16,
}

impl ImportValidationError {
    pub fn new(message: impl Into<String>) -> Self {
        ImportValidationError { message: message.into(), status: 400 }
    }
    pub fn with_status(message: impl Into<String>, status: u16) -> Self {
        ImportValidationError { message: message.into(), status }
    }
}

/// Errors inside an import transaction: validation (handled by the route) or
/// anything else (rethrown upstream → errorHandler / generic catch).
#[derive(Debug)]
pub enum ImportError {
    Validation(ImportValidationError),
    Other(String),
}

impl From<ImportValidationError> for ImportError {
    fn from(e: ImportValidationError) -> Self {
        ImportError::Validation(e)
    }
}
impl From<rusqlite::Error> for ImportError {
    fn from(e: rusqlite::Error) -> Self {
        ImportError::Other(e.to_string())
    }
}
impl From<crate::db::DbError> for ImportError {
    fn from(e: crate::db::DbError) -> Self {
        ImportError::Other(e.to_string())
    }
}

/// `prisma.$transaction(async (tx) => ...)`: commit on Ok, roll back on Err.
pub fn run_transaction<R>(
    c: &mut Connection,
    f: impl FnOnce(&Transaction<'_>) -> Result<R, ImportError>,
) -> Result<R, ImportError> {
    let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let out = f(&tx)?;
    tx.commit()?;
    Ok(out)
}

// ---------------------------------------------------------------------------
// Archive paths

/// Node `path.posix.normalize`.
pub fn posix_normalize(path: &str) -> String {
    if path.is_empty() {
        return ".".into();
    }
    let is_absolute = path.starts_with('/');
    let trailing = path.ends_with('/');
    let mut out: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                if matches!(out.last(), Some(last) if *last != "..") {
                    out.pop();
                } else if !is_absolute {
                    out.push("..");
                }
            }
            s => out.push(s),
        }
    }
    let mut p = out.join("/");
    if p.is_empty() {
        if is_absolute {
            return "/".into();
        }
        return if trailing { "./".into() } else { ".".into() };
    }
    if trailing {
        p.push('/');
    }
    if is_absolute { format!("/{p}") } else { p }
}

fn normalize_archive_path(file_path: &str) -> String {
    posix_normalize(&file_path.replace('\\', "/"))
}

/// assertSafeArchivePath
pub fn assert_safe_archive_path(file_path: &str) -> Result<(), ImportValidationError> {
    let n = normalize_archive_path(file_path);
    if n.is_empty() || n.starts_with('/') || n == ".." || n.starts_with("../") || n.contains('\0') {
        return Err(ImportValidationError::new(format!("Unsafe archive path: {file_path}")));
    }
    Ok(())
}

/// JSZip `utils.resolve` applied to entry names on load.
fn jszip_resolve(path: &str) -> String {
    let parts: Vec<&str> = path.split('/').collect();
    let last = parts.len().saturating_sub(1);
    let mut out: Vec<&str> = Vec::new();
    for (i, part) in parts.iter().enumerate() {
        if *part == "." || (part.is_empty() && i != 0 && i != last) {
            continue;
        } else if *part == ".." {
            out.pop();
        } else {
            out.push(part);
        }
    }
    out.join("/")
}

/// A loaded zip archive with JSZip's name semantics (resolved names, later
/// duplicates win, directories excluded from `file()` lookups).
pub struct LoadedZip {
    archive: zip::ZipArchive<std::io::Cursor<Vec<u8>>>,
    /// Non-directory entries: resolved name → index, in first-seen order.
    files: Vec<(String, usize)>,
}

impl LoadedZip {
    /// `JSZip.loadAsync(buffer)`; errors are thrown (→ 500).
    pub fn load(bytes: Vec<u8>) -> Result<LoadedZip, String> {
        let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes)).map_err(|e| e.to_string())?;
        let mut files: Vec<(String, usize)> = Vec::new();
        for i in 0..archive.len() {
            let f = archive.by_index_raw(i).map_err(|e| e.to_string())?;
            let raw_name = String::from_utf8_lossy(f.name_raw()).into_owned();
            let is_dir = f.is_dir() || raw_name.ends_with('/');
            if is_dir {
                continue;
            }
            let name = jszip_resolve(&raw_name);
            if let Some(slot) = files.iter_mut().find(|(n, _)| *n == name) {
                slot.1 = i;
            } else {
                files.push((name, i));
            }
        }
        Ok(LoadedZip { archive, files })
    }

    /// assertSafeZipArchive
    pub fn assert_safe(&self, max_entries: usize) -> Result<(), ImportValidationError> {
        if self.files.len() > max_entries {
            return Err(ImportValidationError::new("Archive contains too many files"));
        }
        for (name, _) in &self.files {
            assert_safe_archive_path(name)?;
        }
        Ok(())
    }

    /// getSafeZipEntry: index of the entry, `None` when missing.
    pub fn safe_entry(&self, file_path: &str) -> Result<Option<usize>, ImportValidationError> {
        let normalized = normalize_archive_path(file_path);
        assert_safe_archive_path(&normalized)?;
        Ok(self.files.iter().find(|(n, _)| *n == normalized).map(|(_, i)| *i))
    }

    /// `entry.async("string")`, reading at most `cap + 1` bytes. Returns the
    /// decoded string and whether it exceeded `cap` UTF-8 bytes.
    pub fn read_string(&mut self, index: usize, cap: usize) -> Result<(String, bool), String> {
        let f = self.archive.by_index(index).map_err(|e| e.to_string())?;
        let mut buf = Vec::new();
        f.take(cap as u64 + 1).read_to_end(&mut buf).map_err(|e| e.to_string())?;
        if buf.len() > cap {
            // Lossy decoding never shrinks invalid input, so the string is too large too.
            return Ok((String::new(), true));
        }
        let s = String::from_utf8_lossy(&buf).into_owned();
        let too_big = s.len() > cap;
        Ok((s, too_big))
    }
}

// ---------------------------------------------------------------------------
// Naming helpers

fn is_js_space(c: char) -> bool {
    matches!(
        c,
        '\t' | '\n' | '\u{0B}' | '\u{0C}' | '\r' | ' ' | '\u{A0}' | '\u{1680}' | '\u{2000}'..='\u{200A}'
            | '\u{2028}' | '\u{2029}' | '\u{202F}' | '\u{205F}' | '\u{3000}' | '\u{FEFF}'
    )
}

/// sanitizePathSegment
pub fn sanitize_path_segment(input: &str, fallback: &str) -> String {
    let value = crate::security::js_trim(input);
    let mut replaced = String::with_capacity(value.len());
    for c in value.chars() {
        if matches!(c, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*') || (c as u32) <= 0x1F {
            replaced.push('_');
        } else {
            replaced.push(c);
        }
    }
    let mut collapsed = String::with_capacity(replaced.len());
    let mut in_space = false;
    for c in replaced.chars() {
        if is_js_space(c) {
            if !in_space {
                collapsed.push(' ');
            }
            in_space = true;
        } else {
            collapsed.push(c);
            in_space = false;
        }
    }
    let sliced = crate::util::js_slice(&collapsed, 120);
    let cleaned = crate::security::js_trim(&sliced);
    let without_dots = crate::security::js_trim(cleaned.trim_start_matches('.'));
    if without_dots.is_empty() || without_dots == "." || without_dots == ".." {
        return fallback.to_string();
    }
    without_dots.to_string()
}

/// makeUniqueName
pub fn make_unique_name(base: &str, used: &mut HashSet<String>) -> String {
    let mut candidate = base.to_string();
    let mut n = 2;
    while used.contains(&candidate) {
        candidate = format!("{base}__{n}");
        n += 1;
    }
    used.insert(candidate.clone());
    candidate
}

/// findFirstDuplicate
pub fn find_first_duplicate<'a>(values: impl IntoIterator<Item = &'a str>) -> Option<String> {
    let mut seen = HashSet::new();
    for v in values {
        if !seen.insert(v) {
            return Some(v.to_string());
        }
    }
    None
}

/// normalizeNonEmptyId
pub fn normalize_non_empty_id(value: Option<&str>) -> Option<String> {
    let t = crate::security::js_trim(value?);
    if t.is_empty() { None } else { Some(t.to_string()) }
}

/// findSqliteTable
pub fn find_sqlite_table(tables: &[String], candidates: &[&str]) -> Option<String> {
    // new Map(tables.map(t => [t.toLowerCase(), t])): the last duplicate wins.
    for cand in candidates {
        let lower = cand.to_lowercase();
        if let Some(found) = tables.iter().rev().find(|t| t.to_lowercase() == lower) {
            return Some(found.clone());
        }
    }
    None
}

/// assertImportedScene
pub fn assert_imported_scene(elements: &Value, app_state: &Value, files: &Value) -> Result<(), ImportValidationError> {
    if !elements.is_array() || !app_state.is_object() || !files.is_object() {
        return Err(ImportValidationError::new("Drawing contains invalid scene fields"));
    }
    Ok(())
}

/// getRequiredImportedFileIds
pub fn get_required_imported_file_ids(
    source_files: &Map<String, Value>,
    processed_files: &Map<String, Value>,
    drawing_id: &str,
    known_before: &HashSet<String>,
) -> Vec<String> {
    let managed = format!("/api/files/{drawing_id}/");
    processed_files
        .iter()
        .filter(|(file_id, file)| {
            let processed_url = file.get("dataURL");
            let source_url = source_files.get(*file_id).and_then(|f| f.get("dataURL"));
            known_before.contains(*file_id)
                || processed_url.and_then(|v| v.as_str()) == Some(format!("{managed}{file_id}").as_str())
                || match (source_url.and_then(|v| v.as_str()), processed_url.and_then(|v| v.as_str())) {
                    (Some(s), Some(p)) => s.starts_with("data:") && p != s,
                    _ => false,
                }
        })
        .map(|(id, _)| id.clone())
        .collect()
}

/// assertImportedFilesAvailable
pub fn assert_imported_files_available(
    tx: &Connection,
    drawing_id: &str,
    required: &[String],
) -> Result<(), ImportError> {
    if required.is_empty() {
        return Ok(());
    }
    let unique: HashSet<&String> = required.iter().collect();
    let placeholders = (0..unique.len()).map(|i| format!("?{}", i + 2)).collect::<Vec<_>>().join(",");
    let sql = format!(r#"SELECT COUNT(*) FROM "DrawingFile" WHERE "drawingId" = ?1 AND "fileId" IN ({placeholders})"#);
    let mut params: Vec<&dyn rusqlite::ToSql> = vec![&drawing_id];
    for id in &unique {
        params.push(*id);
    }
    let stored: i64 = tx.query_row(&sql, params.as_slice(), |r| r.get(0))?;
    if stored as usize != required.len() {
        return Err(ImportValidationError::with_status("Drawing image bytes changed during import; please try again", 409).into());
    }
    Ok(())
}

/// The fields of a live drawing that replaceImportedDrawing snapshots.
#[derive(Debug, Clone)]
pub struct ExistingDrawing {
    pub id: String,
    pub user_id: String,
    pub version: i64,
    pub elements: String,
    pub app_state: String,
    pub files: String,
}

pub fn find_existing_drawing(c: &Connection, id: &str) -> rusqlite::Result<Option<ExistingDrawing>> {
    c.query_row(
        r#"SELECT "id","userId","version","elements","appState","files" FROM "Drawing" WHERE "id" = ?1"#,
        [id],
        |r| {
            Ok(ExistingDrawing {
                id: r.get(0)?,
                user_id: r.get(1)?,
                version: r.get(2)?,
                elements: r.get(3)?,
                app_state: r.get(4)?,
                files: r.get(5)?,
            })
        },
    )
    .optional()
}

/// Replacement scene for an existing drawing.
pub struct DrawingUpdate<'a> {
    pub name: Option<&'a str>,
    pub elements: &'a str,
    pub app_state: Option<&'a str>,
    pub files: &'a str,
    /// `None` = leave unchanged; `Some(None)` = set NULL.
    pub preview: Option<Option<&'a str>>,
    /// `None` = leave unchanged; `Some(None)` = set NULL.
    pub collection_id: Option<Option<&'a str>>,
}

/// replaceImportedDrawing: snapshot the live scene, then version-guarded update.
pub fn replace_imported_drawing(tx: &Connection, existing: &ExistingDrawing, data: &DrawingUpdate<'_>) -> Result<(), ImportError> {
    let now = crate::util::now_ms();
    tx.execute(
        r#"INSERT INTO "DrawingSnapshot" ("id","drawingId","version","elements","appState","files","createdAt") VALUES (?1,?2,?3,?4,?5,?6,?7)"#,
        rusqlite::params![
            crate::util::uuid_v4(),
            existing.id,
            existing.version,
            crate::snapshots::encode_field(&existing.elements, true),
            crate::snapshots::encode_field(&existing.app_state, true),
            crate::snapshots::encode_field(&existing.files, true),
            now
        ],
    )?;
    let mut sets: Vec<String> = Vec::new();
    let mut params: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
    let mut push = |col: &str, v: Box<dyn rusqlite::ToSql>, sets: &mut Vec<String>| {
        params.push(v);
        sets.push(format!(r#""{col}" = ?{}"#, params.len()));
    };
    if let Some(n) = data.name {
        push("name", Box::new(n.to_string()), &mut sets);
    }
    push("elements", Box::new(data.elements.to_string()), &mut sets);
    if let Some(a) = data.app_state {
        push("appState", Box::new(a.to_string()), &mut sets);
    }
    push("files", Box::new(data.files.to_string()), &mut sets);
    if let Some(p) = data.preview {
        push("preview", Box::new(p.map(str::to_string)), &mut sets);
    }
    if let Some(cid) = data.collection_id {
        push("collectionId", Box::new(cid.map(str::to_string)), &mut sets);
    }
    push("updatedAt", Box::new(now), &mut sets);
    let n = params.len();
    let sql = format!(
        r#"UPDATE "Drawing" SET {}, "version" = "version" + 1 WHERE "id" = ?{} AND "userId" = ?{} AND "version" = ?{}"#,
        sets.join(", "),
        n + 1,
        n + 2,
        n + 3
    );
    params.push(Box::new(existing.id.clone()));
    params.push(Box::new(existing.user_id.clone()));
    params.push(Box::new(existing.version));
    let refs: Vec<&dyn rusqlite::ToSql> = params.iter().map(|b| b.as_ref()).collect();
    let updated = tx.execute(&sql, refs.as_slice())?;
    if updated != 1 {
        return Err(ImportValidationError::with_status("Drawing changed during import; please try again", 409).into());
    }
    Ok(())
}

/// `prisma.collection.create({ data: { id, name, userId } })`
pub fn create_collection(tx: &Connection, id: &str, name: &str, user_id: &str) -> rusqlite::Result<()> {
    let now = crate::util::now_ms();
    tx.execute(
        r#"INSERT INTO "Collection" ("id","name","userId","createdAt","updatedAt") VALUES (?1,?2,?3,?4,?4)"#,
        rusqlite::params![id, name, user_id, now],
    )?;
    Ok(())
}

pub fn rename_collection(tx: &Connection, id: &str, name: &str) -> rusqlite::Result<()> {
    tx.execute(
        r#"UPDATE "Collection" SET "name" = ?1, "updatedAt" = ?2 WHERE "id" = ?3"#,
        rusqlite::params![name, crate::util::now_ms(), id],
    )?;
    Ok(())
}

/// Collection owner (`findUnique({ where: { id } })`).
pub fn collection_owner(tx: &Connection, id: &str) -> rusqlite::Result<Option<String>> {
    tx.query_row(r#"SELECT "userId" FROM "Collection" WHERE "id" = ?1"#, [id], |r| r.get(0)).optional()
}

#[derive(Clone, Copy)]
pub struct NewDrawing<'a> {
    pub id: &'a str,
    pub name: &'a str,
    pub elements: &'a str,
    pub app_state: &'a str,
    pub files: &'a str,
    pub preview: Option<&'a str>,
    pub version: i64,
    pub user_id: &'a str,
    pub collection_id: Option<&'a str>,
}

pub fn create_drawing(tx: &Connection, d: &NewDrawing<'_>) -> rusqlite::Result<()> {
    let now = crate::util::now_ms();
    tx.execute(
        r#"INSERT INTO "Drawing" ("id","name","elements","appState","files","preview","version","userId","collectionId","createdAt","updatedAt")
           VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?10)"#,
        rusqlite::params![d.id, d.name, d.elements, d.app_state, d.files, d.preview, d.version, d.user_id, d.collection_id, now],
    )?;
    Ok(())
}

/// File ids already stored for a drawing (`knownFileIdsBeforeImport`).
pub fn known_file_ids(c: &Connection, drawing_id: &str) -> rusqlite::Result<HashSet<String>> {
    let mut st = c.prepare(r#"SELECT "fileId" FROM "DrawingFile" WHERE "drawingId" = ?1"#)?;
    let rows = st.query_map([drawing_id], |r| r.get::<_, String>(0))?;
    rows.collect()
}

/// Latest embedded Prisma migration (getCurrentLatestPrismaMigrationName).
pub fn current_latest_migration_name() -> Option<String> {
    crate::db::MIGRATIONS
        .iter()
        .map(|(n, _)| *n)
        .filter(|n| n.len() > 15 && n.as_bytes()[..14].iter().all(u8::is_ascii_digit) && n.as_bytes()[14] == b'_')
        .max()
        .map(str::to_string)
}

// ---------------------------------------------------------------------------
// multer: upload.single(field) with dest = uploads dir

/// A file staged by multer (`req.file`); deleted when dropped (removeFileIfExists).
pub struct StagedUpload {
    pub path: PathBuf,
    pub original_name: String,
}

impl Drop for StagedUpload {
    fn drop(&mut self) {
        if let Err(e) = std::fs::remove_file(&self.path) {
            eprintln!("Failed to remove file {{ filePath: {:?}, error: {e} }}", self.path.display().to_string());
        }
    }
}

/// `upload.single(field)`: stream the single expected file into the uploads
/// directory under a random 32-hex name. `Ok(None)` = no file (`!req.file`).
/// Multer errors (unexpected field, size/count limits, file filter) are
/// thrown to errorHandler, i.e. a 500.
pub async fn receive_single_file(st: &AppState, req: Request, field_name: &str) -> Result<Option<StagedUpload>, ApiError> {
    let ct = req.headers().get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    if !crate::http::body::mime_essence(&ct).starts_with("multipart/") {
        return Ok(None);
    }
    let mut multipart = match Multipart::from_request(req, &()).await {
        Ok(m) => m,
        Err(e) => return Err(ApiError::internal(e.body_text())),
    };
    let limit = st.cfg.upload_max_bytes;
    let dir = st.cfg.uploads_dir.clone();
    let mut staged: Option<StagedUpload> = None;
    loop {
        let field = match multipart.next_field().await {
            Ok(Some(f)) => f,
            Ok(None) => break,
            Err(e) => return Err(ApiError::internal(e.body_text())),
        };
        let Some(original_name) = field.file_name().map(str::to_string) else {
            // Text field: multer puts it on req.body; drain it.
            drain_field(field).await?;
            continue;
        };
        if original_name.is_empty() {
            drain_field(field).await?;
            continue;
        }
        let name = field.name().unwrap_or("").to_string();
        if staged.is_some() {
            return Err(ApiError::internal("Too many files"));
        }
        if name != field_name {
            return Err(ApiError::internal("Unexpected field"));
        }
        if name == "db" && !(original_name.ends_with(".db") || original_name.ends_with(".sqlite")) {
            return Err(ApiError::internal("Only .db or .sqlite files are allowed"));
        }
        let _ = tokio::fs::create_dir_all(&dir).await;
        let path = dir.join(hex::encode(crate::util::random_bytes(16)));
        let mut file = tokio::fs::File::create(&path).await.map_err(|e| ApiError::internal(e.to_string()))?;
        let upload = StagedUpload { path, original_name };
        let mut field = field;
        let mut written: f64 = 0.0;
        loop {
            match field.chunk().await {
                Ok(Some(chunk)) => {
                    written += chunk.len() as f64;
                    if written > limit {
                        return Err(ApiError::internal("File too large"));
                    }
                    file.write_all(&chunk).await.map_err(|e| ApiError::internal(e.to_string()))?;
                }
                Ok(None) => break,
                Err(e) => return Err(ApiError::internal(e.body_text())),
            }
        }
        file.flush().await.map_err(|e| ApiError::internal(e.to_string()))?;
        staged = Some(upload);
    }
    Ok(staged)
}

async fn drain_field(mut field: axum::extract::multipart::Field<'_>) -> Result<(), ApiError> {
    loop {
        match field.chunk().await {
            Ok(Some(_)) => {}
            Ok(None) => return Ok(()),
            Err(e) => return Err(ApiError::internal(e.body_text())),
        }
    }
}

/// resolveSafeUploadedFilePath / resolveStagedUploadPath: the staged file must
/// be a 32-hex multer temp name directly inside the (canonical) upload root.
pub fn resolve_safe_uploaded_file_path(file: &StagedUpload, upload_root: &Path) -> Result<PathBuf, ImportValidationError> {
    let invalid = || ImportValidationError::new("Invalid upload path");
    let root = std::fs::canonicalize(upload_root).map_err(|_| invalid())?;
    let name = file.path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    if name.len() != 32 || !name.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err(invalid());
    }
    Ok(root.join(name))
}

pub fn read_file(path: &Path) -> Result<Vec<u8>, ApiError> {
    std::fs::read(path).map_err(|e| ApiError::internal(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn posix_normalize_matches_node() {
        assert_eq!(posix_normalize(""), ".");
        assert_eq!(posix_normalize("a//b/./c/"), "a/b/c/");
        assert_eq!(posix_normalize("../a"), "../a");
        assert_eq!(posix_normalize("a/../../b"), "../b");
        assert_eq!(posix_normalize("/../a"), "/a");
        assert_eq!(posix_normalize("a/.."), ".");
    }

    #[test]
    fn archive_path_safety() {
        assert!(assert_safe_archive_path("Unorganized/a.excalidraw").is_ok());
        assert_eq!(
            assert_safe_archive_path("..\\evil").unwrap_err().message,
            "Unsafe archive path: ..\\evil"
        );
        assert!(assert_safe_archive_path("/etc/passwd").is_err());
        assert!(assert_safe_archive_path("a/../../b").is_err());
        assert!(assert_safe_archive_path("a\0b").is_err());
        assert!(assert_safe_archive_path("").is_ok()); // normalize("") === "."
    }

    #[test]
    fn jszip_resolve_names() {
        assert_eq!(jszip_resolve("../x"), "x");
        assert_eq!(jszip_resolve("/abs/x"), "/abs/x");
        assert_eq!(jszip_resolve("a/./b//c"), "a/b/c");
        assert_eq!(jszip_resolve("dir/"), "dir/");
    }

    #[test]
    fn path_segments() {
        assert_eq!(sanitize_path_segment("  My: Coll/ection  ", "Collection"), "My_ Coll_ection");
        assert_eq!(sanitize_path_segment("...", "Collection"), "Collection");
        assert_eq!(sanitize_path_segment("..hidden", "x"), "hidden");
        assert_eq!(sanitize_path_segment("a\t\n b", "x"), "a__ b");
        assert_eq!(sanitize_path_segment("a \u{3000}\u{A0} b", "x"), "a b");
        assert_eq!(sanitize_path_segment(&"x".repeat(200), "x").len(), 120);
        let mut used = HashSet::new();
        assert_eq!(make_unique_name("Unorganized", &mut used), "Unorganized");
        assert_eq!(make_unique_name("Unorganized", &mut used), "Unorganized__2");
        assert_eq!(make_unique_name("Unorganized", &mut used), "Unorganized__3");
    }

    #[test]
    fn duplicates_and_tables() {
        assert_eq!(find_first_duplicate(["a", "b", "a"]), Some("a".into()));
        assert_eq!(find_first_duplicate(["a", "b"]), None);
        let tables = vec!["drawings".to_string(), "collections".to_string()];
        assert_eq!(find_sqlite_table(&tables, &["Drawing", "drawings"]), Some("drawings".into()));
        assert_eq!(find_sqlite_table(&tables, &["Missing"]), None);
        assert_eq!(normalize_non_empty_id(Some("  ")), None);
        assert_eq!(normalize_non_empty_id(Some(" a ")), Some("a".into()));
    }

    #[test]
    fn latest_migration_is_embedded() {
        assert_eq!(current_latest_migration_name().as_deref(), crate::db::MIGRATIONS.last().map(|(n, _)| *n));
    }

    fn migrated_db() -> Connection {
        let mut c = Connection::open_in_memory().unwrap();
        c.execute_batch("PRAGMA foreign_keys = OFF;").unwrap();
        crate::db::migrate_deploy(&mut c).unwrap();
        c.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
        c.execute(
            r#"INSERT INTO "User" ("id","email","passwordHash","name","createdAt","updatedAt") VALUES ('u','u@example.test','x','U',1,1)"#,
            [],
        )
        .unwrap();
        c.execute(
            r##"INSERT INTO "Drawing" ("id","name","elements","appState","files","version","userId","createdAt","updatedAt")
               VALUES ('d','Keep','[{"id":"saved"}]','{"viewBackgroundColor":"#fedcba"}','{"saved-image":{}}',7,'u',1,1)"##,
            [],
        )
        .unwrap();
        c.execute(
            r#"INSERT INTO "DrawingSnapshot" ("id","drawingId","version","elements","appState","files","createdAt") VALUES ('s','d',6,'[]','{}','{}',1)"#,
            [],
        )
        .unwrap();
        c
    }

    fn drawing_row(c: &Connection) -> (String, i64, String, i64) {
        c.query_row(r#"SELECT "elements","version","files","updatedAt" FROM "Drawing" WHERE "id"='d'"#, [], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
        })
        .unwrap()
    }

    fn snapshot_count(c: &Connection) -> i64 {
        c.query_row(r#"SELECT COUNT(*) FROM "DrawingSnapshot""#, [], |r| r.get(0)).unwrap()
    }

    const EMPTY: DrawingUpdate<'static> =
        DrawingUpdate { name: None, elements: "[]", app_state: Some("{}"), files: "{}", preview: None, collection_id: None };

    /// imports-compat: "rolls back the import scene and safety snapshot if later processing fails"
    #[test]
    fn replace_rolls_back_with_later_failure() {
        let mut c = migrated_db();
        let before = drawing_row(&c);
        let existing = find_existing_drawing(&c, "d").unwrap().unwrap();
        let r: Result<(), ImportError> = run_transaction(&mut c, |tx| {
            replace_imported_drawing(tx, &existing, &EMPTY)?;
            Err(ImportError::Other("later import processing failed".into()))
        });
        assert!(matches!(r, Err(ImportError::Other(m)) if m == "later import processing failed"));
        assert_eq!(drawing_row(&c), before);
        assert_eq!(snapshot_count(&c), 1);
    }

    /// imports-compat: "rolls back the safety snapshot when an import loses its version guard"
    #[test]
    fn replace_version_guard_conflict() {
        let mut c = migrated_db();
        let before = drawing_row(&c);
        let mut existing = find_existing_drawing(&c, "d").unwrap().unwrap();
        existing.version -= 1;
        let r = run_transaction(&mut c, |tx| replace_imported_drawing(tx, &existing, &EMPTY));
        assert!(matches!(r, Err(ImportError::Validation(ImportValidationError { status: 409, .. }))));
        assert_eq!(drawing_row(&c), before);
        assert_eq!(snapshot_count(&c), 1);
    }

    #[test]
    fn replace_snapshots_and_increments() {
        let mut c = migrated_db();
        let existing = find_existing_drawing(&c, "d").unwrap().unwrap();
        run_transaction(&mut c, |tx| replace_imported_drawing(tx, &existing, &EMPTY)).unwrap();
        let (elements, version, _, _) = drawing_row(&c);
        assert_eq!((elements.as_str(), version), ("[]", 8));
        let (v, el): (i64, String) = c
            .query_row(r#"SELECT "version","elements" FROM "DrawingSnapshot" WHERE "version" = 7"#, [], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap();
        assert_eq!(v, 7);
        assert_eq!(crate::snapshots::decode_field(&el).unwrap(), r#"[{"id":"saved"}]"#);
    }

    /// imports-compat: "rejects import if cleanup reclaims newly interned bytes before scene commit"
    /// (the interning race itself needs the files module; this covers the guard).
    #[test]
    fn reclaimed_interned_bytes_are_detected() {
        let c = migrated_db();
        let source: Map<String, Value> =
            serde_json::from_str(r#"{"pending":{"id":"pending","dataURL":"data:image/png;base64,AQID"}}"#).unwrap();
        let processed: Map<String, Value> =
            serde_json::from_str(r#"{"pending":{"id":"pending","dataURL":"/api/files/d/pending"}}"#).unwrap();
        let required = get_required_imported_file_ids(&source, &processed, "d", &HashSet::new());
        assert_eq!(required, vec!["pending".to_string()]);
        let err = assert_imported_files_available(&c, "d", &required).unwrap_err();
        assert!(matches!(err, ImportError::Validation(ImportValidationError { status: 409, ref message })
            if message == "Drawing image bytes changed during import; please try again"));
        c.execute(
            r#"INSERT INTO "DrawingFile" ("drawingId","fileId","mimeType","sizeBytes","storage","data","createdAt") VALUES ('d','pending','image/png',3,'db',x'010203',1)"#,
            [],
        )
        .unwrap();
        assert!(assert_imported_files_available(&c, "d", &required).is_ok());
        // External references and unchanged inline data are not required.
        let ext: Map<String, Value> = serde_json::from_str(r#"{"e":{"dataURL":"https://x.example/a.png"}}"#).unwrap();
        assert!(get_required_imported_file_ids(&ext, &ext, "d", &HashSet::new()).is_empty());
        let known: HashSet<String> = ["e".to_string()].into();
        assert_eq!(get_required_imported_file_ids(&ext, &ext, "d", &known), vec!["e".to_string()]);
    }
}
