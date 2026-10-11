//! routes/importExport/exportRoutes.ts — GET /export/excalidash.
use axum::{
    extract::State,
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use serde_json::{json, Map, Value};
use std::collections::{HashMap, HashSet};
use std::io::Write;

use super::export_files::{embed_drawing_files_for_export, ExportFileRecord};
use super::{assert_safe_archive_path, make_unique_name, sanitize_path_segment};
use crate::http::ctx::Ctx;
use crate::http::error::{ApiError, ApiResult};
use crate::state::AppState;
use crate::trash::{is_trash_collection_id, to_public, user_trash_collection_id};

struct DrawingRow {
    id: String,
    name: String,
    elements: String,
    app_state: String,
    files: String,
    version: i64,
    collection_id: Option<String>,
    created_at: i64,
    updated_at: i64,
}

#[derive(Clone)]
struct CollectionRow {
    id: String,
    name: String,
    created_at: i64,
    updated_at: i64,
}

/// index.ts parseJsonField
pub fn parse_json_field(raw: &str, fallback: Value) -> Value {
    if raw.is_empty() {
        return fallback;
    }
    match serde_json::from_str::<Value>(raw) {
        Ok(v) => v,
        Err(e) => {
            eprintln!(
                "Failed to parse JSON field {{ error: SyntaxError: {e}, valuePreview: {:?} }}",
                crate::util::js_slice(raw, 50)
            );
            fallback
        }
    }
}

/// `{ ...value }` for a parsed `files` field.
fn spread_object(v: Value) -> Map<String, Value> {
    match v {
        Value::Object(m) => m,
        Value::Array(a) => a.into_iter().enumerate().map(|(i, v)| (i.to_string(), v)).collect(),
        _ => Map::new(),
    }
}

fn pretty(v: &Value) -> String {
    serde_json::to_string_pretty(v).unwrap_or_default()
}

pub async fn export_excalidash(State(st): State<AppState>, ctx: Ctx) -> ApiResult {
    let user = crate::auth::require_auth(&st.db, &ctx).await?;
    let user_id = user.id.clone();
    let trash_collection_id = user_trash_collection_id(&user_id);

    let query = crate::http::body::parse_query_values(ctx.query.as_deref().unwrap_or(""));
    let ext = query.get("ext").and_then(|v| v.as_str()).map(|s| s.to_lowercase()).unwrap_or_default();
    let date = crate::util::iso_now()[..10].to_string();
    let filename = if ext == "zip" {
        format!("excalidash-backup-{date}.excalidash.zip")
    } else {
        format!("excalidash-backup-{date}.excalidash")
    };
    let exported_at = crate::util::iso_now();

    let uid = user_id.clone();
    let (drawings, user_collections) = st
        .db
        .call(move |c| {
            let mut s = c.prepare(
                r#"SELECT "id","name","elements","appState","files","version","collectionId","createdAt","updatedAt" FROM "Drawing" WHERE "userId" = ?1"#,
            )?;
            let drawings = s
                .query_map([&uid], |r| {
                    Ok(DrawingRow {
                        id: r.get(0)?,
                        name: r.get(1)?,
                        elements: r.get(2)?,
                        app_state: r.get(3)?,
                        files: r.get(4)?,
                        version: r.get(5)?,
                        collection_id: r.get(6)?,
                        created_at: crate::db::dt(r, 7)?,
                        updated_at: crate::db::dt(r, 8)?,
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let mut s = c.prepare(r#"SELECT "id","name","createdAt","updatedAt" FROM "Collection" WHERE "userId" = ?1"#)?;
            let cols = s
                .query_map([&uid], |r| {
                    Ok(CollectionRow { id: r.get(0)?, name: r.get(1)?, created_at: crate::db::dt(r, 2)?, updated_at: crate::db::dt(r, 3)? })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok((drawings, cols))
        })
        .await?;

    let has_internal_trash = user_collections.iter().any(|c| c.id == trash_collection_id);
    let mut collections_to_export: Vec<CollectionRow> =
        user_collections.into_iter().filter(|c| !(has_internal_trash && c.id == "trash")).collect();
    let has_trash_drawings = drawings.iter().any(|d| is_trash_collection_id(d.collection_id.as_deref(), &user_id));
    if has_trash_drawings && !collections_to_export.iter().any(|c| is_trash_collection_id(Some(&c.id), &user_id)) {
        let uid = user_id.clone();
        let tid = trash_collection_id.clone();
        let trash = st
            .db
            .call(move |c| {
                use rusqlite::OptionalExtension;
                Ok(c.query_row(
                    r#"SELECT "id","name","createdAt","updatedAt" FROM "Collection" WHERE "userId" = ?1 AND "id" IN (?2, 'trash') LIMIT 1"#,
                    [&uid, &tid],
                    |r| Ok(CollectionRow { id: r.get(0)?, name: r.get(1)?, created_at: crate::db::dt(r, 2)?, updated_at: crate::db::dt(r, 3)? }),
                )
                .optional()?)
            })
            .await?;
        if let Some(t) = trash {
            collections_to_export.push(t);
        }
    }

    let proto = if ctx.secure { "https" } else { "http" };
    let export_source = format!("{proto}://{}", ctx.header("host").unwrap_or("undefined"));
    let mut used = HashSet::new();
    let unorganized_folder = make_unique_name("Unorganized", &mut used);
    let mut folder_by_collection: HashMap<String, String> = HashMap::new();
    for c in &collections_to_export {
        let base = sanitize_path_segment(&c.name, "Collection");
        let folder = make_unique_name(&base, &mut used);
        folder_by_collection.insert(c.id.clone(), folder);
    }

    let mut drawings_manifest: Vec<Value> = Vec::with_capacity(drawings.len());
    let mut file_paths: Vec<String> = Vec::with_capacity(drawings.len());
    for d in &drawings {
        let folder = d
            .collection_id
            .as_ref()
            .filter(|c| !c.is_empty())
            .and_then(|c| folder_by_collection.get(c))
            .cloned()
            .unwrap_or_else(|| unorganized_folder.clone());
        let base = sanitize_path_segment(&d.name, "Untitled");
        let file_path = format!("{folder}/{base}__{}.excalidraw", crate::util::js_slice(&d.id, 8));
        drawings_manifest.push(json!({
            "id": d.id,
            "name": d.name,
            "filePath": file_path,
            "collectionId": to_public(d.collection_id.as_deref(), &user_id),
            "version": d.version,
            "createdAt": crate::util::iso_from_ms(d.created_at),
            "updatedAt": crate::util::iso_from_ms(d.updated_at),
        }));
        file_paths.push(file_path);
    }

    let mut manifest_collections: Vec<Value> = Vec::new();
    let mut seen_ids: HashSet<String> = HashSet::new();
    for c in &collections_to_export {
        let id = to_public(Some(&c.id), &user_id).filter(|s| !s.is_empty()).unwrap_or_else(|| c.id.clone());
        if !seen_ids.insert(id.clone()) {
            continue;
        }
        let folder = folder_by_collection
            .get(&c.id)
            .filter(|f| !f.is_empty())
            .cloned()
            .unwrap_or_else(|| sanitize_path_segment(&c.name, "Collection"));
        manifest_collections.push(json!({
            "id": id,
            "name": if is_trash_collection_id(Some(&c.id), &user_id) { "Trash".to_string() } else { c.name.clone() },
            "folder": folder,
            "createdAt": crate::util::iso_from_ms(c.created_at),
            "updatedAt": crate::util::iso_from_ms(c.updated_at),
        }));
    }

    let version = crate::backend_version();
    let manifest = json!({
        "format": "excalidash",
        "formatVersion": 1,
        "exportedAt": exported_at,
        "excalidashBackendVersion": version,
        "userId": user_id,
        "unorganizedFolder": unorganized_folder,
        "collections": manifest_collections,
        "drawings": drawings_manifest,
    });

    // Finish all fallible image bundling before starting the response.
    let mut exported_files: Vec<Map<String, Value>> = Vec::with_capacity(drawings.len());
    for d in &drawings {
        let did = d.id.clone();
        let records = st
            .db
            .call(move |c| {
                let mut s = c.prepare(r#"SELECT "fileId","mimeType","storage","s3Key","data" FROM "DrawingFile" WHERE "drawingId" = ?1"#)?;
                let rows = s
                    .query_map([&did], |r| {
                        Ok(ExportFileRecord {
                            file_id: r.get(0)?,
                            mime_type: r.get(1)?,
                            storage: r.get(2)?,
                            s3_key: r.get(3)?,
                            data: r.get(4)?,
                        })
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                Ok(rows)
            })
            .await?;
        let files = spread_object(parse_json_field(&d.files, json!({})));
        let http = st.http().clone();
        let embedded = embed_drawing_files_for_export(&files, &records, move |key: String| {
            let http = http.clone();
            async move { crate::s3::download_buffer(&http, &key).await.map_err(|e| e.to_string()) }
        })
        .await
        .map_err(ApiError::internal)?;
        exported_files.push(embedded);
    }
    for p in &file_paths {
        assert_safe_archive_path(p).map_err(|e| ApiError::internal(e.message))?;
    }

    let mut entries: Vec<(String, String)> = Vec::with_capacity(drawings.len() + 2);
    entries.push(("excalidash.manifest.json".into(), pretty(&manifest)));
    for ((d, files), path) in drawings.iter().zip(exported_files).zip(&file_paths) {
        let data = json!({
            "type": "excalidraw",
            "version": 2,
            "source": export_source,
            "elements": parse_json_field(&d.elements, json!([])),
            "appState": parse_json_field(&d.app_state, json!({})),
            "files": Value::Object(files),
            "excalidash": {
                "drawingId": d.id,
                "collectionId": d.collection_id,
                "exportedAt": exported_at,
            },
        });
        entries.push((path.clone(), pretty(&data)));
    }
    let readme = format!(
        "ExcaliDash Backup (.excalidash)\n\nThis file is a zip archive containing a versioned ExcaliDash manifest and your drawings,\norganized into folders by collection.\n\nFiles:\n- excalidash.manifest.json (required)\n- <Collection Folder>/*.excalidraw\n\nExportedAt: {exported_at}\nFormatVersion: 1\nBackendVersion: {version}\nCollections: {}\nDrawings: {}\n",
        collections_to_export.len(),
        drawings.len()
    );
    entries.push(("README.txt".into(), readme));

    let zipped = tokio::task::spawn_blocking(move || build_zip(entries))
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    let bytes = match zipped {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Archive error: {e}");
            return Err(ApiError::json(500, json!({"error": "Failed to create archive"})));
        }
    };
    // archiver pipes the archive into the response: chunked transfer, no Content-Length.
    let chunks: Vec<Result<bytes::Bytes, std::io::Error>> = bytes
        .chunks(64 * 1024)
        .map(|c| Ok(bytes::Bytes::copy_from_slice(c)))
        .collect();
    let body = axum::body::Body::from_stream(futures_util::stream::iter(chunks));
    let mut res = (StatusCode::OK, body).into_response();
    let h = res.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/zip"));
    if let Ok(v) = HeaderValue::from_str(&format!("attachment; filename=\"{filename}\"")) {
        h.insert(header::CONTENT_DISPOSITION, v);
    }
    Ok::<Response, ApiError>(res)
}

/// archiver("zip", { zlib: { level: 9 } }) with the entries in order.
fn build_zip(entries: Vec<(String, String)>) -> Result<Vec<u8>, String> {
    use chrono::{Datelike, Timelike};
    let now = chrono::Local::now();
    let mtime = zip::DateTime::from_date_and_time(
        now.year().clamp(1980, 2107) as u16,
        now.month() as u8,
        now.day() as u8,
        now.hour() as u8,
        now.minute() as u8,
        now.second() as u8,
    )
    .unwrap_or_default();
    let opts = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .compression_level(Some(9))
        .last_modified_time(mtime)
        .unix_permissions(0o644);
    let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    for (name, content) in entries {
        w.start_file(name, opts).map_err(|e| e.to_string())?;
        w.write_all(content.as_bytes()).map_err(|e| e.to_string())?;
    }
    Ok(w.finish().map_err(|e| e.to_string())?.into_inner())
}
