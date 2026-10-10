//! routes/importExport/legacySqliteImportRoutes.ts — POST /import/sqlite/legacy[/verify].
use axum::extract::{Request, State};
use rusqlite::{types::Value as Sql, Connection, OpenFlags};
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::time::Duration;

use super::excalidash_import::{intern_all, resolve_final_ids};
use super::*;
use crate::http::ctx::Ctx;
use crate::http::error::{ok, status_json, ApiError, ApiResult};
use crate::state::AppState;

const INSPECT_UNAVAILABLE: &str = "Failed to open the SQLite database for inspection. If you're on Node < 22, you may need to rebuild native dependencies (e.g. `cd backend && npm rebuild better-sqlite3`).";
const IMPORT_UNAVAILABLE: &str = "Failed to open the SQLite database for import. If you're on Node < 22, you may need to rebuild native dependencies (e.g. `cd backend && npm rebuild better-sqlite3`).";

fn unavailable(message: &str) -> ApiResult {
    status_json(500, json!({"error": "Legacy DB support unavailable", "message": message}))
}

fn legacy_invalid(message: impl Into<String>) -> ApiResult {
    status_json(400, json!({"error": "Invalid legacy DB", "message": message.into()}))
}

/// openReadonlySqliteDb
fn open_readonly(path: &Path) -> rusqlite::Result<Connection> {
    Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX)
}

/// index.ts validateSqliteHeader
fn validate_sqlite_header(path: &Path) -> bool {
    use std::io::Read;
    let mut buf = [0u8; 16];
    let read = std::fs::File::open(path).and_then(|mut f| {
        let mut n = 0;
        while n < 16 {
            let r = f.read(&mut buf[n..])?;
            if r == 0 {
                break;
            }
            n += r;
        }
        Ok(n)
    });
    let n = match read {
        Ok(n) => n,
        Err(e) => {
            eprintln!("Failed to validate SQLite header: {e}");
            return false;
        }
    };
    if n < 16 {
        eprintln!("File too small to be a valid SQLite database");
        return false;
    }
    let expected = b"SQLite format 3\0";
    if &buf != expected {
        eprintln!(
            "Invalid SQLite file header detected {{ filePath: {:?}, header: {:?}, expected: {:?} }}",
            path.display().to_string(),
            hex::encode(buf),
            hex::encode(expected)
        );
        return false;
    }
    true
}

/// verifyDatabaseIntegrityAsync: header check, then `PRAGMA integrity_check`
/// on a read-only connection with a 10s timeout (workers/db-verify.js).
pub async fn verify_database_integrity(path: &Path) -> bool {
    if !validate_sqlite_header(path) {
        return false;
    }
    let p = path.to_path_buf();
    let conn = match tokio::task::spawn_blocking(move || open_readonly(&p)).await {
        Ok(Ok(c)) => c,
        _ => return false,
    };
    let interrupt = conn.get_interrupt_handle();
    let task = tokio::task::spawn_blocking(move || {
        let r: rusqlite::Result<String> = conn.query_row("PRAGMA integrity_check;", [], |r| r.get(0));
        matches!(r.as_deref(), Ok("ok"))
    });
    match tokio::time::timeout(Duration::from_secs(10), task).await {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => {
            eprintln!("Worker error: {e}");
            false
        }
        Err(_) => {
            eprintln!("Integrity check worker timed out {{ filePath: {:?} }}", path.display().to_string());
            interrupt.interrupt();
            false
        }
    }
}

fn table_names(db: &Connection) -> rusqlite::Result<Vec<String>> {
    let mut s = db.prepare("SELECT name FROM sqlite_master WHERE type='table'")?;
    let rows = s.query_map([], |r| {
        Ok(match r.get_ref(0)? {
            rusqlite::types::ValueRef::Text(t) => String::from_utf8_lossy(t).into_owned(),
            rusqlite::types::ValueRef::Integer(i) => i.to_string(),
            rusqlite::types::ValueRef::Real(f) => crate::util::js_num_str(f),
            _ => String::new(),
        })
    })?;
    rows.collect()
}

fn count(db: &Connection, table: &str) -> rusqlite::Result<i64> {
    db.query_row(&format!(r#"SELECT COUNT(1) as c FROM "{table}""#), [], |r| r.get(0))
}

/// `String(value)` for a SQLite value (verify's duplicate-id messages).
fn js_string(v: &Sql) -> String {
    match v {
        Sql::Null => "null".into(),
        Sql::Integer(i) => i.to_string(),
        Sql::Real(f) => crate::util::js_num_str(*f),
        Sql::Text(t) => t.clone(),
        Sql::Blob(b) => String::from_utf8_lossy(b).into_owned(),
    }
}

/// `row?.id` truthiness.
fn truthy(v: &Sql) -> bool {
    match v {
        Sql::Null => false,
        Sql::Integer(i) => *i != 0,
        Sql::Real(f) => *f != 0.0 && !f.is_nan(),
        Sql::Text(t) => !t.is_empty(),
        Sql::Blob(_) => true,
    }
}

fn duplicate_id(db: &Connection, table: &str) -> rusqlite::Result<Option<Sql>> {
    use rusqlite::OptionalExtension;
    db.query_row(
        &format!(r#"SELECT id FROM "{table}" WHERE id IS NOT NULL GROUP BY id HAVING COUNT(1) > 1 LIMIT 1"#),
        [],
        |r| r.get::<_, Sql>(0),
    )
    .optional()
}

enum Inspect {
    Respond(u16, Value),
}

fn inspect_for_verify(path: &Path) -> rusqlite::Result<Inspect> {
    let db = open_readonly(path)?;
    let tables = table_names(&db)?;
    let drawing_table = find_sqlite_table(&tables, &["Drawing", "drawings"]);
    let collection_table = find_sqlite_table(&tables, &["Collection", "collections"]);
    let bad = |m: String| Ok(Inspect::Respond(400, json!({"error": "Invalid legacy DB", "message": m})));
    let Some(drawing_table) = drawing_table else { return bad("Missing Drawing table".into()) };
    let drawings = count(&db, &drawing_table)?;
    let collections = match &collection_table {
        Some(t) => count(&db, t)?,
        None => 0,
    };
    if drawings as usize > MAX_IMPORT_DRAWINGS {
        return bad(format!("Too many drawings (max {MAX_IMPORT_DRAWINGS})"));
    }
    if collections as usize > MAX_IMPORT_COLLECTIONS {
        return bad(format!("Too many collections (max {MAX_IMPORT_COLLECTIONS})"));
    }
    if let Some(id) = duplicate_id(&db, &drawing_table)?.filter(truthy) {
        return bad(format!("Duplicate drawing id in legacy DB: {}", js_string(&id)));
    }
    if let Some(t) = &collection_table {
        if let Some(id) = duplicate_id(&db, t)?.filter(truthy) {
            return bad(format!("Duplicate collection id in legacy DB: {}", js_string(&id)));
        }
    }
    let mut latest: Option<String> = None;
    if let Some(t) = find_sqlite_table(&tables, &["_prisma_migrations"]) {
        use rusqlite::OptionalExtension;
        let row = db
            .query_row(
                &format!(r#"SELECT migration_name as name, finished_at as finishedAt FROM "{t}" ORDER BY finished_at DESC LIMIT 1"#),
                [],
                |r| r.get::<_, Sql>(0),
            )
            .optional();
        if let Ok(Some(name)) = row {
            if truthy(&name) {
                latest = Some(js_string(&name));
            }
        }
    }
    Ok(Inspect::Respond(
        200,
        json!({
            "valid": true,
            "drawings": drawings,
            "collections": collections,
            "latestMigration": latest,
            "currentLatestMigration": current_latest_migration_name(),
        }),
    ))
}

async fn stage_db(st: &AppState, req: Request) -> Result<Result<(StagedUpload, PathBuf), ApiResult>, ApiError> {
    let Some(file) = receive_single_file(st, req, "db").await? else {
        return Ok(Err(status_json(400, json!({"error": "No file uploaded"}))));
    };
    match resolve_safe_uploaded_file_path(&file, &st.cfg.uploads_dir) {
        Ok(p) => Ok(Ok((file, p))),
        Err(e) => Ok(Err(status_json(e.status, json!({"error": "Invalid upload", "message": e.message})))),
    }
}

pub async fn verify(State(st): State<AppState>, ctx: Ctx, req: Request) -> ApiResult {
    let _user = crate::auth::require_auth(&st.db, &ctx).await?;
    let (_staged, path) = match stage_db(&st, req).await? {
        Ok(v) => v,
        Err(r) => return r,
    };
    if !verify_database_integrity(&path).await {
        return status_json(400, json!({"error": "Invalid database format"}));
    }
    match tokio::task::spawn_blocking(move || inspect_for_verify(&path)).await {
        Ok(Ok(Inspect::Respond(s, b))) => status_json(s, b),
        _ => unavailable(INSPECT_UNAVAILABLE),
    }
}

type Row = HashMap<String, Sql>;

fn select_all(db: &Connection, table: &str) -> rusqlite::Result<Vec<Row>> {
    let mut s = db.prepare(&format!(r#"SELECT * FROM "{table}""#))?;
    let names: Vec<String> = s.column_names().into_iter().map(str::to_string).collect();
    let rows = s.query_map([], |r| {
        let mut m = HashMap::new();
        for (i, n) in names.iter().enumerate() {
            m.insert(n.clone(), r.get::<_, Sql>(i)?);
        }
        Ok(m)
    })?;
    rows.collect()
}

fn text<'a>(row: &'a Row, key: &str) -> Option<&'a str> {
    match row.get(key) {
        Some(Sql::Text(t)) => Some(t.as_str()),
        _ => None,
    }
}

/// parseOptionalJson(raw, fallback); `None` stands for `undefined`.
fn parse_optional_json(raw: Option<&Sql>, fallback: Option<Value>) -> Result<Option<Value>, ImportValidationError> {
    match raw {
        Some(Sql::Text(t)) => serde_json::from_str(t)
            .map(Some)
            .map_err(|_| ImportValidationError::new("Legacy drawing contains invalid JSON")),
        // A BLOB arrives as a Buffer (an object) and is returned as-is.
        Some(Sql::Blob(_)) => Ok(Some(json!({}))),
        _ => Ok(fallback),
    }
}

/// `Number(value)` for a column that may be missing (`undefined`).
fn js_number(raw: Option<&Sql>) -> f64 {
    match raw {
        None => f64::NAN,
        Some(Sql::Null) => 0.0,
        Some(Sql::Integer(i)) => *i as f64,
        Some(Sql::Real(f)) => *f,
        Some(Sql::Text(t)) => crate::config::js_number(t),
        Some(Sql::Blob(_)) => f64::NAN,
    }
}

struct PreparedLegacy {
    imported_id: Option<String>,
    name: String,
    elements: Vec<Value>,
    app_state: Value,
    files: Map<String, Value>,
    preview: Option<String>,
    collection_id_raw: Option<String>,
    collection_name_raw: Option<String>,
    version: f64,
}

struct LegacyCollection {
    id: Option<String>,
    name: String,
}

enum Loaded {
    Respond(ApiResult),
    Data { collections: Vec<LegacyCollection>, drawings: Vec<PreparedLegacy>, has_trash: bool },
}

fn load_legacy(path: &Path) -> Result<Loaded, ImportError> {
    let db = open_readonly(path)?;
    let tables = table_names(&db)?;
    let Some(drawing_table) = find_sqlite_table(&tables, &["Drawing", "drawings"]) else {
        return Ok(Loaded::Respond(legacy_invalid("Missing Drawing table")));
    };
    let collection_table = find_sqlite_table(&tables, &["Collection", "collections"]);
    let collections = match &collection_table {
        Some(t) => select_all(&db, t)?,
        None => Vec::new(),
    };
    let drawings = select_all(&db, &drawing_table)?;
    drop(db);
    if collections.len() > MAX_IMPORT_COLLECTIONS {
        return Ok(Loaded::Respond(legacy_invalid(format!("Too many collections (max {MAX_IMPORT_COLLECTIONS})"))));
    }
    if drawings.len() > MAX_IMPORT_DRAWINGS {
        return Ok(Loaded::Respond(legacy_invalid(format!("Too many drawings (max {MAX_IMPORT_DRAWINGS})"))));
    }
    let col_ids: Vec<String> = collections.iter().filter_map(|c| normalize_non_empty_id(text(c, "id"))).collect();
    if let Some(d) = find_first_duplicate(col_ids.iter().map(String::as_str)) {
        return Ok(Loaded::Respond(legacy_invalid(format!("Duplicate collection id in legacy DB: {d}"))));
    }
    let drawing_ids: Vec<String> = drawings.iter().filter_map(|d| normalize_non_empty_id(text(d, "id"))).collect();
    if let Some(d) = find_first_duplicate(drawing_ids.iter().map(String::as_str)) {
        return Ok(Loaded::Respond(legacy_invalid(format!("Duplicate drawing id in legacy DB: {d}"))));
    }
    let mut prepared = Vec::with_capacity(drawings.len());
    for d in &drawings {
        let name = text(d, "name").unwrap_or("Untitled Drawing").to_string();
        let elements = parse_optional_json(d.get("elements"), None)?.unwrap_or(Value::Null);
        let app_state = parse_optional_json(d.get("appState"), Some(json!({})))?.unwrap_or(Value::Null);
        let files = parse_optional_json(d.get("files"), Some(json!({})))?.unwrap_or(Value::Null);
        let preview = text(d, "preview").map(str::to_string);
        assert_imported_scene(&elements, &app_state, &files)?;
        let payload = json!({
            "name": name,
            "elements": elements,
            "appState": app_state,
            "files": files,
            "preview": preview,
            "collectionId": null,
        });
        if !crate::security::validate_imported_drawing(&payload) {
            return Ok(Loaded::Respond(status_json(
                400,
                json!({"error": "Invalid imported drawing", "message": "Legacy database contains invalid drawing data"}),
            )));
        }
        let sanitized = crate::security::sanitize_drawing_data(
            &payload["elements"],
            &payload["appState"],
            Some(&payload["files"]),
            Some(&payload["preview"]),
        )
        .map_err(|e| ImportError::Other(format!("{e:?}")))?;
        let clean_name = crate::security::sanitize_text(&name, 255);
        prepared.push(PreparedLegacy {
            imported_id: text(d, "id").map(str::to_string),
            name: if clean_name.is_empty() { "Untitled Drawing".into() } else { clean_name },
            elements: sanitized.elements,
            app_state: sanitized.app_state,
            files: match sanitized.files {
                Some(Value::Object(m)) => m,
                _ => Map::new(),
            },
            preview: match sanitized.preview {
                Some(Value::String(s)) => Some(s),
                _ => None,
            },
            collection_id_raw: text(d, "collectionId").map(str::to_string),
            collection_name_raw: text(d, "collectionName").map(str::to_string),
            version: js_number(d.get("version")),
        });
    }
    let has_trash = drawings.iter().any(|d| text(d, "collectionId") == Some("trash"));
    let collections = collections
        .iter()
        .map(|c| LegacyCollection {
            id: text(c, "id").map(str::to_string),
            name: text(c, "name").unwrap_or("Collection").to_string(),
        })
        .collect();
    Ok(Loaded::Data { collections, drawings: prepared, has_trash })
}

fn counts(created: usize, updated: usize, conflicts: usize) -> Value {
    json!({"created": created, "updated": updated, "idConflicts": conflicts})
}

pub async fn import(State(st): State<AppState>, ctx: Ctx, req: Request) -> ApiResult {
    let user = crate::auth::require_auth(&st.db, &ctx).await?;
    let user_id = user.id.clone();
    let (_staged, path) = match stage_db(&st, req).await? {
        Ok(v) => v,
        Err(r) => return r,
    };
    if !verify_database_integrity(&path).await {
        return status_json(400, json!({"error": "Invalid database format"}));
    }
    match run_import(&st, &user_id, path).await {
        Ok(r) => r,
        Err(ImportError::Validation(e)) => {
            status_json(e.status, json!({"error": "Invalid imported drawing", "message": e.message}))
        }
        Err(ImportError::Other(e)) => {
            eprintln!("[import/legacy] {e}");
            unavailable(IMPORT_UNAVAILABLE)
        }
    }
}

async fn run_import(st: &AppState, user_id: &str, path: PathBuf) -> Result<ApiResult, ImportError> {
    let loaded = tokio::task::spawn_blocking(move || load_legacy(&path))
        .await
        .map_err(|e| ImportError::Other(e.to_string()))??;
    let (collections, mut drawings, has_trash) = match loaded {
        Loaded::Respond(r) => return Ok(r),
        Loaded::Data { collections, drawings, has_trash } => (collections, drawings, has_trash),
    };
    let resolved = resolve_final_ids(st, user_id, drawings.iter().map(|d| d.imported_id.clone()).collect()).await?;
    for (d, (final_id, _)) in drawings.iter_mut().zip(&resolved) {
        if d.imported_id.is_none() {
            d.imported_id = Some(final_id.clone());
        }
    }
    let final_ids: Vec<String> = resolved.iter().map(|(id, _)| id.clone()).collect();
    let processed = intern_all(st, user_id, drawings.iter().map(|d| d.files.clone()).collect(), &final_ids)
        .await
        .map_err(|e| ImportError::Other(format!("{e:?}")))?;

    let uid = user_id.to_string();
    let result = st
        .db
        .call(move |c| {
            Ok(run_transaction(c, |tx| {
                let trash_id = crate::trash::user_trash_collection_id(&uid);
                if has_trash {
                    crate::trash::ensure_trash_collection(tx, &uid)?;
                }
                let mut map: HashMap<String, String> = HashMap::new();
                let (mut c_created, mut c_updated, mut c_conflicts) = (0, 0, 0);
                let (mut d_created, mut d_updated, mut d_conflicts) = (0, 0, 0);
                for col in &collections {
                    let name = crate::security::sanitize_text(&col.name, 100);
                    let clean = if name.is_empty() { "Collection".to_string() } else { name };
                    if col.id.as_deref() == Some("trash") || col.name == "Trash" {
                        let key = col.id.clone().filter(|s| !s.is_empty()).unwrap_or_else(|| "trash".into());
                        map.insert(key, trash_id.clone());
                        continue;
                    }
                    let Some(id) = col.id.clone().filter(|s| !s.is_empty()) else {
                        let new_id = crate::util::uuid_v4();
                        create_collection(tx, &new_id, &clean, &uid)?;
                        map.insert(format!("__name:{}", col.name), new_id);
                        c_created += 1;
                        continue;
                    };
                    match collection_owner(tx, &id)? {
                        None => {
                            create_collection(tx, &id, &clean, &uid)?;
                            map.insert(id.clone(), id);
                            c_created += 1;
                        }
                        Some(owner) if owner == uid => {
                            rename_collection(tx, &id, &clean)?;
                            map.insert(id.clone(), id);
                            c_updated += 1;
                        }
                        Some(_) => {
                            let new_id = crate::util::uuid_v4();
                            create_collection(tx, &new_id, &clean, &uid)?;
                            map.insert(id, new_id);
                            c_created += 1;
                            c_conflicts += 1;
                        }
                    }
                }
                let resolve = |id: &Option<String>, name: &Option<String>| -> Option<String> {
                    if id.as_deref() == Some("trash") || name.as_deref() == Some("Trash") {
                        return Some(trash_id.clone());
                    }
                    if let Some(i) = id.as_deref().filter(|s| !s.is_empty()) {
                        if let Some(v) = map.get(i) {
                            return Some(v.clone());
                        }
                    }
                    if let Some(n) = name.as_deref().filter(|s| !s.is_empty()) {
                        if let Some(v) = map.get(&format!("__name:{n}")) {
                            return Some(v.clone());
                        }
                    }
                    None
                };
                for (i, d) in drawings.iter().enumerate() {
                    let processed_files = &processed[i];
                    let target = resolve(&d.collection_id_raw, &d.collection_name_raw);
                    let existing = match &d.imported_id {
                        Some(id) => find_existing_drawing(tx, id)?,
                        None => None,
                    };
                    let final_id = &resolved[i].0;
                    let required = get_required_imported_file_ids(&d.files, processed_files, final_id, &resolved[i].1);
                    assert_imported_files_available(tx, final_id, &required)?;
                    let elements_json = serde_json::to_string(&d.elements).unwrap_or_default();
                    let app_state_json = serde_json::to_string(&d.app_state).unwrap_or_default();
                    let files_json = serde_json::to_string(processed_files).unwrap_or_default();
                    let version = if d.version.is_finite() { d.version } else { 1.0 };
                    if version.fract() != 0.0 || version < i32::MIN as f64 || version > i32::MAX as f64 {
                        return Err(ImportError::Other(format!("Invalid value for argument `version`: {version}")));
                    }
                    let base = NewDrawing {
                        id: final_id,
                        name: &d.name,
                        elements: &elements_json,
                        app_state: &app_state_json,
                        files: &files_json,
                        preview: d.preview.as_deref(),
                        version: version as i64,
                        user_id: &uid,
                        collection_id: target.as_deref(),
                    };
                    match existing {
                        None => {
                            create_drawing(tx, &base)?;
                            d_created += 1;
                        }
                        Some(ex) if ex.user_id == uid => {
                            replace_imported_drawing(
                                tx,
                                &ex,
                                &DrawingUpdate {
                                    name: Some(&d.name),
                                    elements: &elements_json,
                                    app_state: Some(&app_state_json),
                                    files: &files_json,
                                    preview: Some(d.preview.as_deref()),
                                    collection_id: Some(target.as_deref()),
                                },
                            )?;
                            d_updated += 1;
                        }
                        Some(_) => {
                            let create_id =
                                if Some(final_id) == d.imported_id.as_ref() { crate::util::uuid_v4() } else { final_id.clone() };
                            if create_id != *final_id {
                                let imported = d.imported_id.clone().unwrap_or_default();
                                eprintln!(
                                    "[import/legacy] race conflict on drawing {imported}; creating under {create_id}; S3 objects keyed under {imported} are now orphans"
                                );
                            }
                            create_drawing(tx, &NewDrawing { id: &create_id, ..base })?;
                            d_created += 1;
                            d_conflicts += 1;
                        }
                    }
                }
                Ok(json!({
                    "success": true,
                    "collections": counts(c_created, c_updated, c_conflicts),
                    "drawings": counts(d_created, d_updated, d_conflicts),
                }))
            }))
        })
        .await??;
    st.drawings_cache.invalidate(None);
    Ok(ok(result))
}
