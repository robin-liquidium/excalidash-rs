//! routes/importExport/excalidashImportRoutes.ts — POST /import/excalidash[/verify].
use axum::extract::{Request, State};
use serde_json::{json, Map, Value};
use std::collections::{HashMap, HashSet};

use super::*;
use crate::http::ctx::Ctx;
use crate::http::error::{ok, status_json, ApiError, ApiResult};
use crate::state::AppState;

struct ManifestCollection {
    id: String,
    name: String,
}

struct ManifestDrawing {
    id: String,
    name: String,
    file_path: String,
    collection_id: Option<String>,
    version: Option<f64>,
}

struct Manifest {
    exported_at: String,
    backend_version: Option<String>,
    collections: Vec<ManifestCollection>,
    drawings: Vec<ManifestDrawing>,
}

fn str_min1(v: Option<&Value>) -> Option<String> {
    match v {
        Some(Value::String(s)) if !s.is_empty() => Some(s.clone()),
        _ => None,
    }
}

fn opt_str_ok(v: Option<&Value>) -> bool {
    matches!(v, None | Some(Value::String(_)))
}

/// excalidashManifestSchemaV1.safeParse
fn parse_manifest(v: &Value) -> Option<Manifest> {
    let o = v.as_object()?;
    if o.get("format")?.as_str()? != "excalidash" {
        return None;
    }
    if o.get("formatVersion")?.as_f64()? != 1.0 {
        return None;
    }
    let exported_at = str_min1(o.get("exportedAt"))?;
    if !opt_str_ok(o.get("excalidashBackendVersion")) || !opt_str_ok(o.get("userId")) {
        return None;
    }
    str_min1(o.get("unorganizedFolder"))?;
    let mut collections = Vec::new();
    for c in o.get("collections")?.as_array()? {
        let c = c.as_object()?;
        let id = str_min1(c.get("id"))?;
        let name = c.get("name")?.as_str()?.to_string();
        str_min1(c.get("folder"))?;
        if !opt_str_ok(c.get("createdAt")) || !opt_str_ok(c.get("updatedAt")) {
            return None;
        }
        collections.push(ManifestCollection { id, name });
    }
    let mut drawings = Vec::new();
    for d in o.get("drawings")?.as_array()? {
        let d = d.as_object()?;
        let id = str_min1(d.get("id"))?;
        let name = d.get("name")?.as_str()?.to_string();
        let file_path = str_min1(d.get("filePath"))?;
        let collection_id = match d.get("collectionId")? {
            Value::Null => None,
            Value::String(s) => Some(s.clone()),
            _ => return None,
        };
        let version = match d.get("version") {
            None => None,
            Some(Value::Number(n)) => {
                let f = n.as_f64()?;
                if f.fract() != 0.0 || !f.is_finite() {
                    return None;
                }
                Some(f)
            }
            Some(_) => return None,
        };
        if !opt_str_ok(d.get("createdAt")) || !opt_str_ok(d.get("updatedAt")) {
            return None;
        }
        drawings.push(ManifestDrawing { id, name, file_path, collection_id, version });
    }
    Some(Manifest {
        exported_at,
        backend_version: match o.get("excalidashBackendVersion") {
            Some(Value::String(s)) => Some(s.clone()),
            _ => None,
        },
        collections,
        drawings,
    })
}

/// An early `res.status(status).json(body)`.
type Early = (u16, Value);

fn invalid(status: u16, error: &str, message: impl Into<String>) -> Early {
    (status, json!({"error": error, "message": message.into()}))
}

/// Shared prefix of both routes: safety checks, manifest parsing and limits.
fn load_manifest(zip: &mut LoadedZip) -> Result<Result<(Manifest, usize), Early>, ApiError> {
    if let Err(e) = zip.assert_safe(MAX_IMPORT_ARCHIVE_ENTRIES) {
        return Ok(Err(invalid(e.status, "Invalid backup", e.message)));
    }
    let entry = zip.safe_entry("excalidash.manifest.json").map_err(|e| ApiError::internal(e.message))?;
    let Some(idx) = entry else {
        return Ok(Err(invalid(400, "Invalid backup", "Missing excalidash.manifest.json")));
    };
    let (raw, too_big) = zip.read_string(idx, MAX_IMPORT_MANIFEST_BYTES).map_err(ApiError::internal)?;
    if too_big {
        return Ok(Err(invalid(400, "Invalid backup manifest", "excalidash.manifest.json is too large")));
    }
    let Ok(json) = serde_json::from_str::<Value>(&raw) else {
        return Ok(Err(invalid(400, "Invalid backup manifest", "excalidash.manifest.json is not valid JSON")));
    };
    let Some(manifest) = parse_manifest(&json) else {
        return Ok(Err(invalid(400, "Invalid backup manifest", "Malformed excalidash.manifest.json")));
    };
    let m = "Invalid backup manifest";
    if manifest.collections.len() > MAX_IMPORT_COLLECTIONS {
        return Ok(Err(invalid(400, m, format!("Too many collections (max {MAX_IMPORT_COLLECTIONS})"))));
    }
    if manifest.drawings.len() > MAX_IMPORT_DRAWINGS {
        return Ok(Err(invalid(400, m, format!("Too many drawings (max {MAX_IMPORT_DRAWINGS})"))));
    }
    if let Some(d) = find_first_duplicate(manifest.collections.iter().map(|c| c.id.as_str())) {
        return Ok(Err(invalid(400, m, format!("Duplicate collection id in manifest: {d}"))));
    }
    if let Some(d) = find_first_duplicate(manifest.drawings.iter().map(|c| c.id.as_str())) {
        return Ok(Err(invalid(400, m, format!("Duplicate drawing id in manifest: {d}"))));
    }
    if let Some(d) = find_first_duplicate(manifest.drawings.iter().map(|c| c.file_path.as_str())) {
        return Ok(Err(invalid(400, m, format!("Duplicate drawing file path in manifest: {d}"))));
    }
    Ok(Ok((manifest, raw.len())))
}

/// Receive the `archive` upload and resolve the staged path (shared by both routes).
async fn stage_archive(st: &AppState, req: Request) -> Result<Result<(StagedUpload, PathBuf), Early>, ApiError> {
    let Some(file) = receive_single_file(st, req, "archive").await? else {
        return Ok(Err((400, json!({"error": "No file uploaded"}))));
    };
    match resolve_safe_uploaded_file_path(&file, &st.cfg.uploads_dir) {
        Ok(p) => Ok(Ok((file, p))),
        Err(e) => Ok(Err(invalid(e.status, "Invalid upload", e.message))),
    }
}

pub async fn verify(State(st): State<AppState>, ctx: Ctx, req: Request) -> ApiResult {
    let _user = crate::auth::require_auth(&st.db, &ctx).await?;
    let (_staged, path) = match stage_archive(&st, req).await? {
        Ok(v) => v,
        Err((s, b)) => return status_json(s, b),
    };
    let outcome = tokio::task::spawn_blocking(move || -> Result<Early, ApiError> {
        let mut zip = LoadedZip::load(read_file(&path)?).map_err(ApiError::internal)?;
        let manifest = match load_manifest(&mut zip)? {
            Ok((m, _)) => m,
            Err(early) => return Ok(early),
        };
        for d in &manifest.drawings {
            // getSafeZipEntry throws here without a catch → errorHandler.
            let entry = zip.safe_entry(&d.file_path).map_err(|e| ApiError::internal(e.message))?;
            if entry.is_none() {
                return Ok(invalid(400, "Invalid backup", format!("Missing drawing file: {}", d.file_path)));
            }
        }
        Ok((
            200,
            json!({
                "valid": true,
                "formatVersion": 1,
                "exportedAt": manifest.exported_at,
                "excalidashBackendVersion": manifest.backend_version.filter(|v| !v.is_empty()),
                "collections": manifest.collections.len(),
                "drawings": manifest.drawings.len(),
            }),
        ))
    })
    .await
    .map_err(|e| ApiError::internal(e.to_string()))??;
    status_json(outcome.0, outcome.1)
}

pub struct PreparedDrawing {
    pub id: String,
    pub name: String,
    pub version: Option<f64>,
    pub collection_id: Option<String>,
    pub elements: Vec<Value>,
    pub app_state: Value,
    pub files: Map<String, Value>,
}

fn prepare_drawings(zip: &mut LoadedZip, manifest: &Manifest, manifest_len: usize) -> Result<Vec<PreparedDrawing>, ImportError> {
    let max_drawing = max_import_drawing_bytes();
    let mut prepared = Vec::with_capacity(manifest.drawings.len());
    let mut extracted = manifest_len;
    for d in &manifest.drawings {
        let Some(idx) = zip.safe_entry(&d.file_path)? else {
            return Err(ImportValidationError::new(format!("Missing drawing file: {}", d.file_path)).into());
        };
        let (raw, too_big) = zip.read_string(idx, max_drawing).map_err(ImportError::Other)?;
        if too_big {
            return Err(ImportValidationError::new(format!("Drawing is too large: {}", d.file_path)).into());
        }
        extracted += raw.len();
        if extracted > MAX_IMPORT_TOTAL_EXTRACTED_BYTES {
            return Err(ImportValidationError::new("Backup contents exceed maximum import size").into());
        }
        let parsed: Value = serde_json::from_str(&raw)
            .map_err(|_| ImportValidationError::new(format!("Drawing JSON is invalid: {}", d.file_path)))?;
        let field = |k: &str| parsed.as_object().and_then(|o| o.get(k)).cloned();
        let elements = field("elements").unwrap_or(Value::Null);
        let app_state = field("appState").unwrap_or_else(|| json!({}));
        let files = field("files").unwrap_or_else(|| json!({}));
        assert_imported_scene(&elements, &app_state, &files)?;
        let imported = json!({
            "name": d.name,
            "elements": elements,
            "appState": app_state,
            "files": files,
            "preview": null,
            "collectionId": d.collection_id,
        });
        if !crate::security::validate_imported_drawing(&imported) {
            return Err(ImportValidationError::new(format!("Drawing failed validation: {}", d.file_path)).into());
        }
        let sanitized = crate::security::sanitize_drawing_data(&imported["elements"], &imported["appState"], Some(&imported["files"]), Some(&Value::Null))
            .map_err(|e| ImportError::Other(format!("{e:?}")))?;
        let name = crate::security::sanitize_text(&d.name, 255);
        prepared.push(PreparedDrawing {
            id: d.id.clone(),
            name: if name.is_empty() { "Untitled Drawing".into() } else { name },
            version: d.version,
            collection_id: d.collection_id.clone(),
            elements: sanitized.elements,
            app_state: sanitized.app_state,
            files: match sanitized.files {
                Some(Value::Object(m)) => m,
                _ => Map::new(),
            },
        });
    }
    Ok(prepared)
}

/// Pre-transaction steps shared with the legacy importer: final ids
/// (re-keyed when another user owns the id) and already-stored file ids.
pub async fn resolve_final_ids(
    st: &AppState,
    user_id: &str,
    ids: Vec<Option<String>>,
) -> Result<Vec<(String, HashSet<String>)>, crate::db::DbError> {
    let uid = user_id.to_string();
    st.db
        .call(move |c| {
            let mut out = Vec::with_capacity(ids.len());
            for id in ids {
                let final_id = match id {
                    None => crate::util::uuid_v4(),
                    Some(id) => {
                        use rusqlite::OptionalExtension;
                        let owner: Option<String> =
                            c.query_row(r#"SELECT "userId" FROM "Drawing" WHERE "id" = ?1"#, [&id], |r| r.get(0)).optional()?;
                        match owner {
                            Some(o) if o != uid => crate::util::uuid_v4(),
                            _ => id,
                        }
                    }
                };
                let known = known_file_ids(c, &final_id)?;
                out.push((final_id, known));
            }
            Ok(out)
        })
        .await
}

/// internDrawingFiles in batches of S3_UPLOAD_CONCURRENCY.
pub async fn intern_all(
    st: &AppState,
    user_id: &str,
    files: Vec<Map<String, Value>>,
    final_ids: &[String],
) -> Result<Vec<Map<String, Value>>, ApiError> {
    const S3_UPLOAD_CONCURRENCY: usize = 8;
    let mut out = Vec::with_capacity(files.len());
    let mut iter = files.into_iter().zip(final_ids.iter()).peekable();
    while iter.peek().is_some() {
        let batch: Vec<_> = iter
            .by_ref()
            .take(S3_UPLOAD_CONCURRENCY)
            .map(|(f, id)| crate::files::intern_drawing_files(st, f, user_id, id))
            .collect();
        for r in futures_util::future::join_all(batch).await {
            out.push(r?);
        }
    }
    Ok(out)
}

fn as_prisma_int(v: f64) -> Result<i64, ImportError> {
    if v.fract() != 0.0 || v < i32::MIN as f64 || v > i32::MAX as f64 {
        return Err(ImportError::Other(format!("Invalid value for argument `version`: {v}")));
    }
    Ok(v as i64)
}

fn counts(created: usize, updated: usize, conflicts: usize) -> Value {
    json!({"created": created, "updated": updated, "idConflicts": conflicts})
}

pub async fn import(State(st): State<AppState>, ctx: Ctx, req: Request) -> ApiResult {
    let user = crate::auth::require_auth(&st.db, &ctx).await?;
    let user_id = user.id.clone();
    let (_staged, path) = match stage_archive(&st, req).await? {
        Ok(v) => v,
        Err((s, b)) => return status_json(s, b),
    };
    let parsed = tokio::task::spawn_blocking(move || -> Result<Result<(Manifest, Vec<PreparedDrawing>), Early>, ApiError> {
        let mut zip = LoadedZip::load(read_file(&path)?).map_err(ApiError::internal)?;
        let (manifest, manifest_len) = match load_manifest(&mut zip)? {
            Ok(v) => v,
            Err(early) => return Ok(Err(early)),
        };
        match prepare_drawings(&mut zip, &manifest, manifest_len) {
            Ok(p) => Ok(Ok((manifest, p))),
            Err(ImportError::Validation(e)) => Ok(Err(invalid(e.status, "Invalid backup", e.message))),
            Err(ImportError::Other(e)) => Err(ApiError::internal(e)),
        }
    })
    .await
    .map_err(|e| ApiError::internal(e.to_string()))??;
    let (manifest, prepared) = match parsed {
        Ok(v) => v,
        Err((s, b)) => return status_json(s, b),
    };

    let resolved = resolve_final_ids(&st, &user_id, prepared.iter().map(|p| Some(p.id.clone())).collect()).await?;
    let final_ids: Vec<String> = resolved.iter().map(|(id, _)| id.clone()).collect();
    let processed = intern_all(&st, &user_id, prepared.iter().map(|p| p.files.clone()).collect(), &final_ids).await?;

    let uid = user_id.clone();
    let result = st
        .db
        .call(move |c| {
            Ok(run_transaction(c, |tx| {
                let trash_id = crate::trash::user_trash_collection_id(&uid);
                let mut collection_map: HashMap<String, String> = HashMap::new();
                let (mut c_created, mut c_updated, mut c_conflicts) = (0, 0, 0);
                let (mut d_created, mut d_updated, mut d_conflicts) = (0, 0, 0);
                let needs_trash = manifest.collections.iter().any(|c| c.id == "trash")
                    || prepared.iter().any(|d| d.collection_id.as_deref() == Some("trash"));
                if needs_trash {
                    crate::trash::ensure_trash_collection(tx, &uid)?;
                }
                for col in &manifest.collections {
                    if col.id == "trash" {
                        collection_map.insert("trash".into(), trash_id.clone());
                        continue;
                    }
                    let name = crate::security::sanitize_text(&col.name, 100);
                    let name = if name.is_empty() { "Collection".to_string() } else { name };
                    match collection_owner(tx, &col.id)? {
                        None => {
                            create_collection(tx, &col.id, &name, &uid)?;
                            collection_map.insert(col.id.clone(), col.id.clone());
                            c_created += 1;
                        }
                        Some(owner) if owner == uid => {
                            rename_collection(tx, &col.id, &name)?;
                            collection_map.insert(col.id.clone(), col.id.clone());
                            c_updated += 1;
                        }
                        Some(_) => {
                            let new_id = crate::util::uuid_v4();
                            create_collection(tx, &new_id, &name, &uid)?;
                            collection_map.insert(col.id.clone(), new_id);
                            c_created += 1;
                            c_conflicts += 1;
                        }
                    }
                }
                let resolve = |cid: &Option<String>| -> Option<String> {
                    match cid.as_deref() {
                        None | Some("") => None,
                        Some("trash") => Some(trash_id.clone()),
                        Some(id) => collection_map.get(id).cloned(),
                    }
                };
                for (i, p) in prepared.iter().enumerate() {
                    let processed_files = &processed[i];
                    let target = resolve(&p.collection_id);
                    let existing = find_existing_drawing(tx, &p.id)?;
                    let final_id = &resolved[i].0;
                    let required = get_required_imported_file_ids(&p.files, processed_files, final_id, &resolved[i].1);
                    assert_imported_files_available(tx, final_id, &required)?;
                    let elements_json = serde_json::to_string(&p.elements).unwrap_or_default();
                    let app_state_json = serde_json::to_string(&p.app_state).unwrap_or_default();
                    let files_json = serde_json::to_string(processed_files).unwrap_or_default();
                    let version = as_prisma_int(p.version.unwrap_or(1.0))?;
                    let base = NewDrawing {
                        id: &p.id,
                        name: &p.name,
                        elements: &elements_json,
                        app_state: &app_state_json,
                        files: &files_json,
                        preview: None,
                        version,
                        user_id: &uid,
                        collection_id: target.as_deref(),
                    };
                    match existing {
                        None => {
                            create_drawing(tx, &NewDrawing { id: final_id, ..base })?;
                            d_created += 1;
                        }
                        Some(ex) if ex.user_id == uid => {
                            replace_imported_drawing(
                                tx,
                                &ex,
                                &DrawingUpdate {
                                    name: Some(&p.name),
                                    elements: &elements_json,
                                    app_state: Some(&app_state_json),
                                    files: &files_json,
                                    preview: Some(None),
                                    collection_id: Some(target.as_deref()),
                                },
                            )?;
                            d_updated += 1;
                        }
                        Some(_) => {
                            let create_id = if *final_id == p.id { crate::util::uuid_v4() } else { final_id.clone() };
                            if create_id != *final_id {
                                eprintln!(
                                    "[import/excalidash] race conflict on drawing {}; creating under {create_id}; S3 objects keyed under {} are now orphans",
                                    p.id, p.id
                                );
                            }
                            create_drawing(tx, &NewDrawing { id: &create_id, ..base })?;
                            d_created += 1;
                            d_conflicts += 1;
                        }
                    }
                }
                Ok(json!({
                    "collections": counts(c_created, c_updated, c_conflicts),
                    "drawings": counts(d_created, d_updated, d_conflicts),
                }))
            }))
        })
        .await?;
    match result {
        Ok(r) => {
            st.drawings_cache.invalidate(None);
            let mut body = json!({"success": true, "message": "Backup imported successfully"});
            if let (Some(b), Value::Object(r)) = (body.as_object_mut(), r) {
                b.extend(r);
            }
            ok(body)
        }
        Err(ImportError::Validation(e)) => status_json(e.status, json!({"error": "Import failed", "message": e.message})),
        Err(ImportError::Other(e)) => Err(ApiError::internal(e)),
    }
}
