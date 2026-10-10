//! routes/storage.ts + routes/storage/*
//!   POST   /drawings/:id/trim          – trim deleted elements and orphaned files
//!   GET    /drawings/:id/files/diff    – three-way file comparison
//!   DELETE /drawings/:id/files/orphans – delete selected orphaned files
use axum::{
    extract::{Path, State},
    routing::{delete, get, post},
    Router,
};
use rusqlite::{Connection, OptionalExtension};
use serde_json::{json, Map, Value};
use std::collections::{HashMap, HashSet};

use crate::auth::middleware::require_auth;
use crate::files::is_valid_file_id;
use crate::http::body::Body;
use crate::http::ctx::Ctx;
use crate::http::error::{ok, status_json, ApiError, ApiResult};
use crate::s3::{self, S3Object};
use crate::state::AppState;

const S3_DELETE_CONCURRENCY: usize = 8;

// ---------------------------------------------------------------------------
// storage/retainedFiles.ts

/// `collectRetainedDrawingFileIds`: file ids referenced by the live scene or any
/// retained snapshot. `None` when any scene is unreadable (keep everything).
/// Call inside the cleanup transaction.
pub fn collect_retained_drawing_file_ids(c: &Connection, drawing_id: &str) -> rusqlite::Result<Option<HashSet<String>>> {
    let current: Option<(String, String)> = c
        .query_row(r#"SELECT "elements","files" FROM "Drawing" WHERE "id" = ?1"#, [drawing_id], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .optional()?;
    let mut scenes: Vec<(String, String)> = current.into_iter().collect();
    {
        let mut stmt = c.prepare(r#"SELECT "elements","files" FROM "DrawingSnapshot" WHERE "drawingId" = ?1"#)?;
        for row in stmt.query_map([drawing_id], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))? {
            scenes.push(row?);
        }
    }
    let mut retained = HashSet::new();
    for (elements, files) in scenes {
        let parse = |raw: &str| -> Option<Value> {
            let decoded = crate::snapshots::decode_field(raw).ok()?;
            serde_json::from_str(&decoded).ok()
        };
        let (Some(Value::Array(elements)), Some(Value::Object(files))) = (parse(&elements), parse(&files)) else {
            return Ok(None);
        };
        retained.extend(files.keys().cloned());
        for el in elements {
            if let Some(id) = el.as_object().and_then(|o| o.get("fileId")).and_then(Value::as_str) {
                retained.insert(id.to_string());
            }
        }
    }
    Ok(Some(retained))
}

// ---------------------------------------------------------------------------
// storage/helpers.ts + plans.ts

#[derive(Debug, Clone)]
pub struct StoredFileRecord {
    pub file_id: String,
    pub storage: String,
    pub s3_key: Option<String>,
    pub mime_type: String,
    pub size_bytes: i64,
}

fn js_truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64().is_some_and(|f| f != 0.0 && !f.is_nan()),
        Some(Value::String(s)) => !s.is_empty(),
        Some(_) => true,
    }
}

/// Property access on a JS value: null/undefined elements throw a TypeError.
fn prop<'a>(el: &'a Value, key: &str) -> Result<Option<&'a Value>, ApiError> {
    match el {
        Value::Null => Err(ApiError::internal(format!("Cannot read properties of null (reading '{key}')"))),
        Value::Object(o) => Ok(o.get(key)),
        _ => Ok(None),
    }
}

fn is_deleted(el: &Value) -> Result<bool, ApiError> {
    Ok(js_truthy(prop(el, "isDeleted")?))
}

fn image_file_id(el: &Value) -> Result<Option<&str>, ApiError> {
    if prop(el, "type")?.and_then(Value::as_str) != Some("image") {
        return Ok(None);
    }
    Ok(prop(el, "fileId")?.and_then(Value::as_str).filter(|s| !s.is_empty()))
}

/// `collectReferencedFileIds` (insertion-ordered set).
fn collect_referenced_file_ids(elements: &[Value], include_deleted: bool) -> Result<Vec<String>, ApiError> {
    let mut ids: Vec<String> = Vec::new();
    for el in elements {
        if !include_deleted && is_deleted(el)? {
            continue;
        }
        if let Some(id) = image_file_id(el)? {
            if !ids.iter().any(|x| x == id) {
                ids.push(id.to_string());
            }
        }
    }
    Ok(ids)
}

/// `fileIdFromS3Key`
pub fn file_id_from_s3_key(key: &str) -> Option<String> {
    let last = key.rsplit('/').next().unwrap_or("");
    if last.is_empty() {
        return None;
    }
    match last.rfind('.') {
        Some(i) if i > 0 => Some(last[..i].to_string()),
        _ => Some(last.to_string()),
    }
}

/// `buildTrimS3CleanupPlan` → (orphanKeys, orphanFileIds)
pub fn build_trim_s3_cleanup_plan(surviving: &HashSet<String>, records: &[StoredFileRecord]) -> (Vec<String>, Vec<String>) {
    let mut keys: Vec<String> = Vec::new();
    let mut ids: Vec<String> = Vec::new();
    for r in records {
        if surviving.contains(&r.file_id) {
            continue;
        }
        if let Some(k) = r.s3_key.as_deref().filter(|k| !k.is_empty()) {
            if !keys.iter().any(|x| x == k) {
                keys.push(k.to_string());
            }
        }
        if !ids.contains(&r.file_id) {
            ids.push(r.file_id.clone());
        }
    }
    (keys, ids)
}

fn build_files_diff_response(
    elements: &[Value],
    files: &[String],
    records: &[StoredFileRecord],
    s3_objects: &[S3Object],
) -> Result<Value, ApiError> {
    let all_refs = collect_referenced_file_ids(elements, true)?;
    let active_refs = collect_referenced_file_ids(elements, false)?;
    let sqlite_ids: Vec<&String> = {
        let mut v: Vec<&String> = Vec::new();
        for f in files {
            if !v.contains(&f) {
                v.push(f);
            }
        }
        v
    };
    let total_stored = if !s3_objects.is_empty() { s3_objects.len() } else { records.len() };

    let mut record_map: HashMap<&str, &StoredFileRecord> = HashMap::new();
    for r in records {
        record_map.insert(&r.file_id, r);
    }
    let mut s3_map: HashMap<Option<String>, &S3Object> = HashMap::new();
    for o in s3_objects {
        s3_map.insert(file_id_from_s3_key(&o.key), o);
    }
    let mut all: Vec<String> = Vec::new();
    let mut push = |id: &str| {
        if !all.iter().any(|x| x == id) {
            all.push(id.to_string());
        }
    };
    all_refs.iter().for_each(|id| push(id));
    sqlite_ids.iter().for_each(|id| push(id));
    records.iter().for_each(|r| push(&r.file_id));
    for o in s3_objects {
        if let Some(id) = file_id_from_s3_key(&o.key) {
            push(&id);
        }
    }

    let rows: Vec<Value> = all
        .iter()
        .map(|id| {
            let record = record_map.get(id.as_str()).copied();
            let object = s3_map.get(&Some(id.clone())).copied();
            json!({
                "fileId": id,
                "inCanvas": all_refs.contains(id),
                "inCanvasActive": active_refs.contains(id),
                "inSqlite": sqlite_ids.contains(&id),
                "inS3": object.is_some() || record.is_some_and(|r| r.storage == "db"),
                "inS3Record": record.is_some(),
                "s3Key": record.and_then(|r| r.s3_key.clone()).or_else(|| object.map(|o| o.key.clone())),
                "mimeType": record.map(|r| r.mime_type.clone()),
                "s3SizeBytes": object.map(|o| json!(o.size)).or_else(|| record.map(|r| json!(r.size_bytes))),
            })
        })
        .collect();
    Ok(json!({
        "summary": {
            "totalCanvasRefs": all_refs.len(),
            "totalSqliteFiles": sqlite_ids.len(),
            "totalS3Files": total_stored,
        },
        "files": rows,
    }))
}

// ---------------------------------------------------------------------------
// shared helpers

struct DrawingRow {
    name: String,
    elements: String,
    files: String,
    version: i64,
}

async fn find_owned_drawing(st: &AppState, id: &str, user_id: &str) -> Result<Option<DrawingRow>, ApiError> {
    let (id, uid) = (id.to_string(), user_id.to_string());
    Ok(st
        .db
        .call(move |c| {
            Ok(c.query_row(
                r#"SELECT "name","elements","files","version" FROM "Drawing" WHERE "id" = ?1 AND "userId" = ?2 LIMIT 1"#,
                [&id, &uid],
                |r| Ok(DrawingRow { name: r.get(0)?, elements: r.get(1)?, files: r.get(2)?, version: r.get(3)? }),
            )
            .optional()?)
        })
        .await?)
}

/// index.ts parseJsonField(raw, fallback)
fn parse_json_field(raw: &str, fallback: Value) -> Value {
    if raw.is_empty() {
        return fallback;
    }
    match serde_json::from_str(raw) {
        Ok(v) => v,
        Err(e) => {
            let preview: String = crate::util::js_slice(raw, 50);
            eprintln!("Failed to parse JSON field {{ error: {e:?}, valuePreview: {preview:?} }}");
            fallback
        }
    }
}

fn as_elements(v: Value) -> Result<Vec<Value>, ApiError> {
    match v {
        Value::Array(a) => Ok(a),
        _ => Err(ApiError::internal("elements.filter is not a function")),
    }
}

/// `Object.entries(files)` for the parsed files field.
fn as_files(v: Value) -> Result<Map<String, Value>, ApiError> {
    match v {
        Value::Object(m) => Ok(m),
        Value::Array(a) => Ok(a.into_iter().enumerate().map(|(i, v)| (i.to_string(), v)).collect()),
        Value::Null => Err(ApiError::internal("Cannot convert undefined or null to object")),
        _ => Ok(Map::new()),
    }
}

/// JSON.stringify for values that came from JSON.parse: integral floats print as integers.
pub fn js_stringify(v: &Value) -> String {
    fn norm(v: &Value) -> Value {
        match v {
            Value::Number(n) if n.is_f64() => {
                let f = n.as_f64().unwrap_or(0.0);
                if f.is_finite() && f == f.trunc() && f.abs() < 9.0e15 {
                    json!(f as i64)
                } else {
                    v.clone()
                }
            }
            Value::Array(a) => Value::Array(a.iter().map(norm).collect()),
            Value::Object(o) => Value::Object(o.iter().map(|(k, v)| (k.clone(), norm(v))).collect()),
            _ => v.clone(),
        }
    }
    serde_json::to_string(&norm(v)).unwrap_or_default()
}

fn select_records(c: &Connection, drawing_id: &str) -> rusqlite::Result<Vec<StoredFileRecord>> {
    let mut stmt = c.prepare(
        r#"SELECT "fileId","storage","s3Key","mimeType","sizeBytes" FROM "DrawingFile" WHERE "drawingId" = ?1"#,
    )?;
    let rows = stmt.query_map([drawing_id], |r| {
        Ok(StoredFileRecord {
            file_id: r.get(0)?,
            storage: r.get(1)?,
            s3_key: r.get(2)?,
            mime_type: r.get(3)?,
            size_bytes: r.get(4)?,
        })
    })?;
    rows.collect()
}

fn delete_rows(c: &Connection, drawing_id: &str, file_ids: &[String]) -> rusqlite::Result<()> {
    for fid in file_ids {
        c.execute(r#"DELETE FROM "DrawingFile" WHERE "drawingId" = ?1 AND "fileId" = ?2"#, [drawing_id, fid])?;
    }
    Ok(())
}

/// Guarded scene write (`updateMany where {id, version}`); false on version conflict.
fn guarded_update(c: &Connection, id: &str, version: i64, elements: &str, files: &str) -> rusqlite::Result<bool> {
    let n = c.execute(
        r#"UPDATE "Drawing" SET "elements" = ?1, "files" = ?2, "version" = "version" + 1, "updatedAt" = ?3
           WHERE "id" = ?4 AND "version" = ?5"#,
        rusqlite::params![elements, files, crate::util::now_ms(), id, version],
    )?;
    Ok(n > 0)
}

/// storage/s3Delete.ts `deleteS3KeysInBatches` → (deleted, errors)
pub async fn delete_s3_keys_in_batches(st: &AppState, keys: &[String], log_prefix: &str) -> (usize, usize) {
    let Some(c) = s3::client() else { return (0, keys.len()) };
    let (mut deleted, mut errors) = (0, 0);
    for batch in keys.chunks(S3_DELETE_CONCURRENCY) {
        let results = futures_util::future::join_all(batch.iter().map(|k| c.delete_object(st.http(), k))).await;
        for (key, r) in batch.iter().zip(results) {
            match r {
                Ok(()) => deleted += 1,
                Err(e) => {
                    eprintln!("{log_prefix} Failed to delete S3 object: {key} {e}");
                    errors += 1;
                }
            }
        }
    }
    (deleted, errors)
}

fn notify_server_state_change(st: &AppState, drawing_id: &str) {
    crate::socket::emit_to_drawing(st, drawing_id, "drawing-server-update", &json!({ "drawingId": drawing_id }));
}

fn confirm_mismatch() -> ApiResult {
    status_json(403, json!({ "error": "confirmName does not match drawing name" }))
}

fn version_conflict(message: &str) -> ApiResult {
    status_json(409, json!({ "error": "Conflict", "code": "VERSION_CONFLICT", "message": message }))
}

// ---------------------------------------------------------------------------
// routes

async fn trim(State(st): State<AppState>, ctx: Ctx, Path(id): Path<String>, body: Body) -> ApiResult {
    let user = require_auth(&st.db, &ctx).await?;
    let Some(drawing) = find_owned_drawing(&st, &id, &user.id).await? else {
        return status_json(404, json!({ "error": "Drawing not found" }));
    };
    if body.str("confirmName") != Some(drawing.name.as_str()) {
        return confirm_mismatch();
    }

    let elements = as_elements(parse_json_field(&drawing.elements, json!([])))?;
    let files = as_files(parse_json_field(&drawing.files, json!({})))?;
    // buildTrimPlan
    let mut active = Vec::new();
    for el in &elements {
        if !is_deleted(el)? {
            active.push(el.clone());
        }
    }
    let surviving: HashSet<String> = collect_referenced_file_ids(&active, false)?.into_iter().collect();
    let cleaned: Map<String, Value> = files.iter().filter(|(k, _)| surviving.contains(*k)).map(|(k, v)| (k.clone(), v.clone())).collect();
    let elements_removed = elements.len() - active.len();
    let files_removed = files.len() - cleaned.len();

    let (elements_json, files_json) = (js_stringify(&Value::Array(active)), js_stringify(&Value::Object(cleaned)));
    let (did, version) = (id.clone(), drawing.version);
    let plan = st
        .db
        .tx(move |tx| {
            if !guarded_update(tx, &did, version, &elements_json, &files_json)? {
                return Ok(None);
            }
            let retained = collect_retained_drawing_file_ids(tx, &did)?;
            let records = select_records(tx, &did)?;
            let plan = match retained {
                Some(r) => build_trim_s3_cleanup_plan(&r, &records),
                None => (Vec::new(), Vec::new()),
            };
            if !plan.1.is_empty() {
                delete_rows(tx, &did, &plan.1)?;
            }
            Ok(Some(plan))
        })
        .await?;
    let Some((orphan_keys, _)) = plan else {
        return version_conflict("Drawing has changed since it was loaded for trimming.");
    };

    let (mut s3_deleted, mut s3_errors) = (0, 0);
    if s3::is_s3_enabled() && !orphan_keys.is_empty() {
        (s3_deleted, s3_errors) = delete_s3_keys_in_batches(&st, &orphan_keys, "[storage/trim]").await;
    }

    st.drawings_cache.invalidate(None);
    notify_server_state_change(&st, &id);

    ok(json!({
        "trimmed": {
            "elementsRemoved": elements_removed,
            "filesRemoved": files_removed,
            "s3ObjectsDeleted": s3_deleted,
            "s3DeleteErrors": s3_errors,
        }
    }))
}

async fn files_diff(State(st): State<AppState>, ctx: Ctx, Path(id): Path<String>) -> ApiResult {
    let user = require_auth(&st.db, &ctx).await?;
    let Some(drawing) = find_owned_drawing(&st, &id, &user.id).await? else {
        return status_json(404, json!({ "error": "Drawing not found" }));
    };
    let elements = as_elements(parse_json_field(&drawing.elements, json!([])))?;
    let files = as_files(parse_json_field(&drawing.files, json!({})))?;
    let did = id.clone();
    let records = st.db.call(move |c| Ok(select_records(c, &did)?)).await?;
    let objects = match s3::client() {
        Some(c) => c.list_objects(st.http(), &c.drawing_prefix(&user.id, &id)).await?,
        None => Vec::new(),
    };
    let keys: Vec<String> = files.keys().cloned().collect();
    ok(build_files_diff_response(&elements, &keys, &records, &objects)?)
}

async fn delete_orphans(State(st): State<AppState>, ctx: Ctx, Path(id): Path<String>, body: Body) -> ApiResult {
    let user = require_auth(&st.db, &ctx).await?;
    let raw_ids = match body.get("fileIds") {
        Some(Value::Array(a)) if !a.is_empty() => a.clone(),
        _ => return status_json(400, json!({ "error": "fileIds must be a non-empty array" })),
    };
    let invalid: Vec<Value> = raw_ids.iter().filter(|v| !v.as_str().is_some_and(is_valid_file_id)).cloned().collect();
    if !invalid.is_empty() {
        return status_json(400, json!({ "error": "fileIds contains invalid entries", "invalidFileIds": invalid }));
    }
    let file_ids: Vec<String> = raw_ids.iter().filter_map(|v| v.as_str().map(str::to_string)).collect();

    let Some(drawing) = find_owned_drawing(&st, &id, &user.id).await? else {
        return status_json(404, json!({ "error": "Drawing not found" }));
    };
    if body.str("confirmName") != Some(drawing.name.as_str()) {
        return confirm_mismatch();
    }

    let elements = as_elements(parse_json_field(&drawing.elements, json!([])))?;
    let mut files = as_files(parse_json_field(&drawing.files, json!({})))?;
    // buildOrphanDeletePlan
    let active_refs = collect_referenced_file_ids(&elements, false)?;
    let blocked: Vec<&String> = file_ids.iter().filter(|f| active_refs.contains(f)).collect();
    if !blocked.is_empty() {
        return status_json(
            400,
            json!({ "error": "Cannot delete files referenced by active elements", "blockedFileIds": blocked }),
        );
    }
    let deleted_set: HashSet<&String> = file_ids.iter().collect();
    for f in &file_ids {
        files.shift_remove(f);
    }
    let mut cleaned_elements = Vec::new();
    for el in elements {
        let drop = is_deleted(&el)?
            && prop(&el, "type")?.and_then(Value::as_str) == Some("image")
            && prop(&el, "fileId")?.and_then(Value::as_str).is_some_and(|f| deleted_set.contains(&f.to_string()));
        if !drop {
            cleaned_elements.push(el);
        }
    }

    let (files_json, elements_json) = (js_stringify(&Value::Object(files)), js_stringify(&Value::Array(cleaned_elements)));
    let (did, version, ids) = (id.clone(), drawing.version, file_ids.clone());
    let records = st
        .db
        .tx(move |tx| {
            if !guarded_update(tx, &did, version, &elements_json, &files_json)? {
                return Ok(None);
            }
            let retained = collect_retained_drawing_file_ids(tx, &did)?;
            let deletable: Vec<String> = match retained {
                Some(r) => ids.into_iter().filter(|f| !r.contains(f)).collect(),
                None => Vec::new(),
            };
            let records: Vec<StoredFileRecord> =
                select_records(tx, &did)?.into_iter().filter(|r| deletable.contains(&r.file_id)).collect();
            delete_rows(tx, &did, &deletable)?;
            Ok(Some(records))
        })
        .await?;
    let Some(records) = records else {
        return version_conflict("Drawing has changed since it was loaded for cleanup.");
    };

    let mut s3_errors = 0;
    if s3::is_s3_enabled() {
        let keys: Vec<String> = records
            .into_iter()
            .filter(|r| r.storage == "s3")
            .filter_map(|r| r.s3_key.filter(|k| !k.is_empty()))
            .collect();
        s3_errors = delete_s3_keys_in_batches(&st, &keys, "[storage/orphans]").await.1;
    }

    st.drawings_cache.invalidate(None);
    notify_server_state_change(&st, &id);

    ok(json!({ "deleted": file_ids.len(), "errors": s3_errors }))
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/drawings/{id}/trim", post(trim))
        .route("/drawings/{id}/files/diff", get(files_diff))
        .route("/drawings/{id}/files/orphans", delete(delete_orphans))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(file_id: &str, key: Option<&str>) -> StoredFileRecord {
        StoredFileRecord {
            file_id: file_id.into(),
            storage: if key.is_some() { "s3" } else { "db" }.into(),
            s3_key: key.map(str::to_string),
            mime_type: "image/png".into(),
            size_bytes: 3,
        }
    }

    /// s3-generation-keys.integration.ts (key parsing + cleanup plan part).
    #[test]
    fn generation_keys_and_trim_plan() {
        let legacy = "excalidash/owner/drawing/image-id.png";
        let current = "excalidash/owner/drawing/generation/image-id.png";
        assert_eq!(file_id_from_s3_key(legacy).as_deref(), Some("image-id"));
        assert_eq!(file_id_from_s3_key(current).as_deref(), Some("image-id"));
        assert_eq!(file_id_from_s3_key("a/.hidden").as_deref(), Some(".hidden"));
        assert_eq!(file_id_from_s3_key("a/"), None);
        let records = [rec("image-id", Some(current))];
        let keep: HashSet<String> = ["image-id".to_string()].into();
        assert!(build_trim_s3_cleanup_plan(&keep, &records).0.is_empty());
        assert_eq!(build_trim_s3_cleanup_plan(&HashSet::new(), &records).0, vec![current.to_string()]);
    }

    #[test]
    fn diff_rows() {
        let elements = vec![
            json!({"type": "image", "fileId": "a"}),
            json!({"type": "image", "fileId": "b", "isDeleted": true}),
        ];
        let files = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        let records = [rec("a", None), rec("d", Some("p/u/x/gen/d.png"))];
        let objects = [S3Object { key: "p/u/x/gen/d.png".into(), size: 9 }, S3Object { key: "p/u/x/e.png".into(), size: 1 }];
        let out = build_files_diff_response(&elements, &files, &records, &objects).unwrap();
        assert_eq!(out["summary"], json!({"totalCanvasRefs": 2, "totalSqliteFiles": 3, "totalS3Files": 2}));
        let ids: Vec<&str> = out["files"].as_array().unwrap().iter().map(|r| r["fileId"].as_str().unwrap()).collect();
        assert_eq!(ids, vec!["a", "b", "c", "d", "e"]);
        assert_eq!(
            out["files"][0],
            json!({"fileId": "a", "inCanvas": true, "inCanvasActive": true, "inSqlite": true, "inS3": true,
                   "inS3Record": true, "s3Key": null, "mimeType": "image/png", "s3SizeBytes": 3})
        );
        assert_eq!(out["files"][3]["s3SizeBytes"], 9);
        assert_eq!(out["files"][4]["inS3Record"], false);
        assert_eq!(out["files"][4]["s3Key"], "p/u/x/e.png");
    }

    #[test]
    fn stringify_normalizes_integral_floats() {
        let v: Value = serde_json::from_str(r#"{"x":1e2,"y":1.5,"z":[3]}"#).unwrap();
        assert_eq!(js_stringify(&v), r#"{"x":100,"y":1.5,"z":[3]}"#);
    }
}
