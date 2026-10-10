//! drawingReadRoutes.ts, drawingCreateUpdateRoutes.ts, drawingDeleteDuplicateRoutes.ts.
use axum::extract::{Path, State};
use rusqlite::OptionalExtension;
use serde_json::{json, Map, Value};
use std::collections::HashSet;

use super::scene::{apply_scene_update, collect_retained_drawing_file_ids, SceneError, SceneMutation, UpdateData, VersionGuard};
use super::schema::{parse_create, parse_update, schema_error};
use super::{audit, err_only, opt_str_json, parse_json_field, principal, DrawingRow};
use crate::authz::get_drawing_access;
use crate::files::{intern_drawing_files, rewrite_preview_for_interned_files};
use crate::http::body::Body;
use crate::http::ctx::Ctx;
use crate::http::error::{ok, ApiError, ApiResult};
use crate::state::AppState;
use crate::trash::{ensure_trash_collection, is_trash_collection_id, to_internal, to_public, user_trash_collection_id};

fn drawing_not_found() -> ApiError {
    ApiError::err(404, "Drawing not found", "Drawing does not exist")
}

fn conflict(current_version: Value) -> ApiError {
    ApiError::json(
        409,
        json!({
            "error": "Conflict",
            "code": "VERSION_CONFLICT",
            "message": "Drawing has changed since this editor state was loaded.",
            "currentVersion": current_version,
        }),
    )
}

/// GET /drawings/:id (and GET /drawings/shared, which Express registers first).
pub async fn get_drawing_or_shared(State(st): State<AppState>, ctx: Ctx, Path(id): Path<String>) -> ApiResult {
    if id == "shared" {
        return super::list::shared_drawings(st, ctx).await;
    }
    let opt = crate::auth::optional_auth(&st.db, &ctx).await;
    let principal = principal(&opt);
    let (id2, p2) = (id.clone(), principal.clone());
    let (access, drawing) = st
        .db
        .call(move |c| Ok((get_drawing_access(c, p2.as_deref(), &id2, None)?, DrawingRow::find(c, &id2)?)))
        .await?;
    if !access.can_view() {
        if let Some(e) = super::auth_error(&opt) {
            return Err(e);
        }
        return Err(drawing_not_found());
    }
    let Some(d) = drawing else { return Err(drawing_not_found()) };
    let is_owner = principal.as_deref() == Some(d.user_id.as_str());
    let cid = if is_owner { opt_str_json(to_public(d.collection_id.as_deref(), &d.user_id)) } else { Value::Null };
    let mut m = d.to_json_with(cid);
    m.insert("accessLevel".into(), json!(access.as_str()));
    ok(Value::Object(m))
}

async fn list_drawing_file_ids(st: &AppState, drawing_id: &str) -> Result<HashSet<String>, ApiError> {
    let id = drawing_id.to_string();
    Ok(st
        .db
        .call(move |c| {
            let mut s = c.prepare(r#"SELECT "fileId" FROM "DrawingFile" WHERE "drawingId" = ?1"#)?;
            let v: HashSet<String> = s.query_map([&id], |r| r.get(0))?.collect::<Result<_, _>>()?;
            Ok(v)
        })
        .await?)
}

/// cleanupUnreferencedInternedFiles (failed creation only).
async fn cleanup_unreferenced_interned_files(st: &AppState, drawing_id: &str, known: &HashSet<String>, processed: &Map<String, Value>) {
    let candidates: Vec<String> = processed.keys().filter(|k| !known.contains(*k)).cloned().collect();
    if candidates.is_empty() {
        return;
    }
    let id = drawing_id.to_string();
    let r = st
        .db
        .tx(move |tx| {
            let Some(referenced) = collect_retained_drawing_file_ids(tx, &id)? else { return Ok(()) };
            for f in candidates.iter().filter(|f| !referenced.contains(*f)) {
                tx.execute(r#"DELETE FROM "DrawingFile" WHERE "drawingId" = ?1 AND "fileId" = ?2"#, [&id, f])?;
            }
            Ok(())
        })
        .await;
    if let Err(e) = r {
        eprintln!("[files] interned-file cleanup failed: {e}");
    }
}

/// POST /drawings
pub async fn create_drawing(State(st): State<AppState>, ctx: Ctx, body: Body) -> ApiResult {
    let user = crate::auth::require_auth(&st.db, &ctx).await?;
    let imported = ctx.header("x-imported-file") == Some("true");
    if imported && !crate::security::validate_imported_drawing(&body.value()) {
        return Err(ApiError::err(
            400,
            "Invalid imported drawing file",
            "The imported file contains potentially malicious content or invalid structure",
        ));
    }
    let payload = parse_create(body.0.as_ref()).map_err(schema_error)?;
    let name = payload.name.clone().unwrap_or_else(|| "Untitled Drawing".into());
    let raw_cid: Option<String> = payload.collection_id.clone().flatten();
    let target_cid = to_internal(raw_cid.as_deref(), &user.id);

    if let Some(t) = target_cid.clone().filter(|t| !is_trash_collection_id(Some(t), &user.id)) {
        let uid = user.id.clone();
        let verdict = st
            .db
            .call(move |c| {
                let owner: Option<String> = c
                    .query_row(r#"SELECT "userId" FROM "Collection" WHERE "id" = ?1 LIMIT 1"#, [&t], |r| r.get(0))
                    .optional()?;
                Ok(match owner {
                    None => Some(404),
                    Some(o) if o == uid => None,
                    Some(_) => {
                        let share = crate::db::exists(
                            c,
                            r#"SELECT 1 FROM "CollectionShare" WHERE "collectionId" = ?1 AND "granteeUserId" = ?2 AND "role" = 'edit' LIMIT 1"#,
                            [&t, &uid],
                        )?;
                        if share { None } else { Some(403) }
                    }
                })
            })
            .await?;
        match verdict {
            Some(404) => return Err(err_only(404, "Collection not found")),
            Some(_) => return Err(err_only(403, "No edit access to this collection")),
            None => {}
        }
    } else if raw_cid.as_deref() == Some("trash") {
        let uid = user.id.clone();
        st.db.call(move |c| Ok(ensure_trash_collection(c, &uid)?)).await?;
    }

    let new_id = crate::util::uuid_v4();
    let original_files = payload.files.clone().unwrap_or_default();
    let known_before = list_drawing_file_ids(&st, &new_id).await?;
    let processed = intern_drawing_files(&st, original_files.clone(), &user.id, &new_id).await?;
    let preview_in = payload.preview.clone().flatten().map(Value::String).unwrap_or(Value::Null);
    let preview = match rewrite_preview_for_interned_files(&preview_in, &original_files, &processed) {
        Value::String(s) => Some(s),
        _ => None,
    };
    let elements = Value::Array(payload.elements.clone().unwrap_or_default()).to_string();
    let app_state = payload.app_state.clone().unwrap_or(json!({})).to_string();
    let files = Value::Object(processed.clone()).to_string();
    let (nid, uid, cid) = (new_id.clone(), user.id.clone(), target_cid.clone());
    let created = st
        .db
        .call(move |c| {
            let now = crate::util::now_ms();
            c.execute(
                r#"INSERT INTO "Drawing" ("id","name","elements","appState","files","preview","version","userId","collectionId","createdAt","updatedAt")
                   VALUES (?1,?2,?3,?4,?5,?6,1,?7,?8,?9,?9)"#,
                rusqlite::params![nid, name, elements, app_state, files, preview, uid, cid, now],
            )?;
            Ok(DrawingRow::find(c, &nid)?)
        })
        .await;
    let created = match created {
        Ok(Some(d)) => d,
        Ok(None) => return Err(ApiError::internal("Drawing create failed")),
        Err(e) => {
            cleanup_unreferenced_interned_files(&st, &new_id, &known_before, &processed).await;
            return Err(e.into());
        }
    };
    st.drawings_cache.invalidate(None);
    let cid = opt_str_json(to_public(created.collection_id.as_deref(), &user.id));
    ok(Value::Object(created.to_json_with(cid)))
}

/// PUT /drawings/:id
pub async fn update_drawing(State(st): State<AppState>, ctx: Ctx, Path(id): Path<String>, body: Body) -> ApiResult {
    let opt = crate::auth::optional_auth(&st.db, &ctx).await;
    let principal = principal(&opt);
    let (id2, p2) = (id.clone(), principal.clone());
    let (access, existing) = st
        .db
        .call(move |c| Ok((get_drawing_access(c, p2.as_deref(), &id2, None)?, DrawingRow::find(c, &id2)?)))
        .await?;
    if !access.can_edit() {
        if let Some(e) = super::auth_error(&opt) {
            return Err(e);
        }
        return Err(drawing_not_found());
    }
    let Some(existing) = existing else { return Err(err_only(404, "Drawing not found")) };

    let payload = match parse_update(body.0.as_ref()) {
        Ok(p) => p,
        Err(e) => {
            if st.cfg.node_env == "development" {
                eprintln!("[API] Validation failed {{ id: {id:?} }}");
            }
            return Err(schema_error(e));
        }
    };

    let owner = existing.user_id.clone();
    let acting = principal.clone().unwrap_or_else(|| owner.clone());
    let trash_id = user_trash_collection_id(&owner);
    let is_scene = payload.elements.is_some() || payload.app_state.is_some() || payload.files.is_some();
    if is_scene {
        if let Some(v) = payload.version {
            if v != existing.version {
                return Err(conflict(json!(existing.version)));
            }
        }
    }

    let mut data = UpdateData {
        name: payload.name.clone(),
        elements: payload.elements.clone().map(|e| Value::Array(e).to_string()),
        app_state: payload.app_state.as_ref().map(|a| a.to_string()),
        ..Default::default()
    };
    let mut processed_files: Option<Map<String, Value>> = None;
    let mut required: Vec<String> = vec![];
    if let Some(files) = &payload.files {
        let known = list_drawing_file_ids(&st, &id).await?;
        let processed = intern_drawing_files(&st, files.clone(), &owner, &id).await?;
        let managed = format!("/api/files/{id}/");
        required = processed
            .iter()
            .filter(|(fid, file)| {
                let processed_url = file.get("dataURL");
                let original_url = files.get(*fid).and_then(|f| f.get("dataURL"));
                known.contains(*fid)
                    || processed_url.and_then(|v| v.as_str()) == Some(format!("{managed}{fid}").as_str())
                    || matches!((original_url, processed_url), (Some(Value::String(o)), Some(Value::String(p))) if o.starts_with("data:") && p != o)
            })
            .map(|(fid, _)| fid.clone())
            .collect();
        processed_files = Some(processed);
    }
    if let Some(preview) = &payload.preview {
        let pv = preview.clone().map(Value::String).unwrap_or(Value::Null);
        let processed_preview = match &processed_files {
            Some(pf) => rewrite_preview_for_interned_files(&pv, payload.files.as_ref().unwrap_or(&Map::new()), pf),
            None => pv,
        };
        data.preview = Some(processed_preview.as_str().map(str::to_string));
    }

    if let Some(cid) = &payload.collection_id {
        if !access.is_owner() {
            return Err(ApiError::err(403, "Forbidden", "Only the owner can move drawings between collections"));
        }
        match cid.as_deref() {
            Some("trash") => {
                let o = owner.clone();
                st.db.call(move |c| Ok(ensure_trash_collection(c, &o)?)).await?;
                data.collection_id = Some(Some(trash_id.clone()));
            }
            Some(cid) => {
                let (c2, a2) = (cid.to_string(), acting.clone());
                let allowed = st
                    .db
                    .call(move |c| {
                        Ok(crate::db::exists(
                            c,
                            r#"SELECT 1 FROM "Collection" WHERE "id" = ?1 AND "userId" = ?2 LIMIT 1"#,
                            [&c2, &a2],
                        )? || crate::db::exists(
                            c,
                            r#"SELECT 1 FROM "CollectionShare" WHERE "collectionId" = ?1 AND "granteeUserId" = ?2 AND "role" = 'edit' LIMIT 1"#,
                            [&c2, &a2],
                        )?)
                    })
                    .await?;
                if !allowed {
                    return Err(err_only(404, "Collection not found"));
                }
                data.collection_id = Some(Some(cid.to_string()));
            }
            None => data.collection_id = Some(None),
        }
    }

    let updated = if is_scene {
        let guard = match payload.version {
            Some(v) => VersionGuard::Exact(v),
            None => VersionGuard::Optimistic,
        };
        let retries = if payload.version.is_none() { 2 } else { 0 };
        let mutation = SceneMutation { data, incoming_files: processed_files, required_file_ids: required };
        match apply_scene_update(&st, &id, guard, retries, mutation).await {
            Ok(d) => d,
            Err(SceneError::Conflict) => {
                let id2 = id.clone();
                let latest = st
                    .db
                    .call(move |c| {
                        Ok(c.query_row(r#"SELECT "version" FROM "Drawing" WHERE "id" = ?1"#, [&id2], |r| r.get::<_, i64>(0))
                            .optional()?)
                    })
                    .await?;
                return Err(conflict(json!(latest)));
            }
            Err(SceneError::Db(e)) => return Err(e.into()),
        }
    } else {
        if data.is_empty() {
            // Prisma updateMany with no data reports count 0.
            return Err(err_only(404, "Drawing not found"));
        }
        let id2 = id.clone();
        let row = st
            .db
            .call(move |c| {
                let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = vec![];
                let mut sets = data.sets(&mut params);
                params.push(Box::new(crate::util::now_ms()));
                sets.push(format!(r#""updatedAt" = ?{}"#, params.len()));
                params.push(Box::new(id2.clone()));
                let sql = format!(r#"UPDATE "Drawing" SET {} WHERE "id" = ?{}"#, sets.join(", "), params.len());
                let refs: Vec<&dyn rusqlite::types::ToSql> = params.iter().map(|b| b.as_ref()).collect();
                if c.execute(&sql, refs.as_slice())? == 0 {
                    return Ok(None);
                }
                Ok(DrawingRow::find(c, &id2)?)
            })
            .await?;
        match row {
            Some(d) => d,
            None => return Err(err_only(404, "Drawing not found")),
        }
    };
    st.drawings_cache.invalidate(None);

    let saved_elements = parse_json_field(Some(&updated.elements), json!([]));
    let saved_files = parse_json_field(Some(&updated.files), json!({}));
    if is_scene {
        let order: Vec<Value> = saved_elements
            .as_array()
            .map(|a| a.iter().filter_map(|e| e.get("id").filter(|v| v.is_string()).cloned()).collect())
            .unwrap_or_default();
        crate::socket::emit_to_drawing(
            &st,
            &id,
            "element-update",
            &json!({
                "drawingId": id,
                "persisted": true,
                "elements": saved_elements,
                "files": saved_files,
                "elementOrder": order,
            }),
        );
    }
    let mut m = updated.to_map();
    m.insert("collectionId".into(), opt_str_json(to_public(updated.collection_id.as_deref(), &owner)));
    m.insert("elements".into(), saved_elements);
    m.insert("appState".into(), parse_json_field(Some(&updated.app_state), json!({})));
    m.insert("files".into(), saved_files);
    m.insert("accessLevel".into(), json!(access.as_str()));
    ok(Value::Object(m))
}

/// cleanupS3FilesForDrawing (database rows; S3 objects when S3 is enabled).
async fn cleanup_files_for_drawing(st: &AppState, drawing_id: &str) -> Result<(), ApiError> {
    if crate::s3::is_s3_enabled() {
        // TODO(s3): delete listS3Objects(drawingS3Prefix) + recorded s3Keys once src/s3.rs exposes them.
        eprintln!("[s3] object cleanup for drawing {drawing_id} is not available in this build");
    }
    let id = drawing_id.to_string();
    st.db
        .call(move |c| {
            c.execute(r#"DELETE FROM "DrawingFile" WHERE "drawingId" = ?1"#, [&id])?;
            Ok(())
        })
        .await?;
    Ok(())
}

/// DELETE /drawings/:id
pub async fn delete_drawing(State(st): State<AppState>, ctx: Ctx, Path(id): Path<String>) -> ApiResult {
    let user = crate::auth::require_auth(&st.db, &ctx).await?;
    let (id2, uid) = (id.clone(), user.id.clone());
    let name: Option<String> = st
        .db
        .call(move |c| {
            Ok(c.query_row(
                r#"SELECT "name" FROM "Drawing" WHERE "id" = ?1 AND "userId" = ?2 LIMIT 1"#,
                [&id2, &uid],
                |r| r.get(0),
            )
            .optional()?)
        })
        .await?;
    let Some(name) = name else { return Err(err_only(404, "Drawing not found")) };
    if let Err(e) = cleanup_files_for_drawing(&st, &id).await {
        eprintln!("[s3] Failed to cleanup deleted drawing files {{ drawingId: {id:?}, error: {e:?} }}");
    }
    let (id2, uid) = (id.clone(), user.id.clone());
    let n = st
        .db
        .call(move |c| Ok(c.execute(r#"DELETE FROM "Drawing" WHERE "id" = ?1 AND "userId" = ?2"#, [&id2, &uid])?))
        .await?;
    if n == 0 {
        return Err(err_only(404, "Drawing not found"));
    }
    st.drawings_cache.invalidate(None);
    audit(&st, &ctx, &user.id, "drawing_deleted", format!("drawing:{id}"), json!({"drawingId": id, "drawingName": name})).await;
    ok(json!({ "success": true }))
}

/// cloneS3FileReferences (database-bytes mode; S3 records keep their URLs until s3.rs lands).
async fn clone_file_references(
    st: &AppState,
    source: &str,
    target: &str,
    files: Map<String, Value>,
) -> Result<Map<String, Value>, ApiError> {
    let (s, t) = (source.to_string(), target.to_string());
    Ok(st
        .db
        .call(move |c| {
            let mut stmt = c.prepare(r#"SELECT "fileId","storage" FROM "DrawingFile" WHERE "drawingId" = ?1"#)?;
            let records: Vec<(String, String)> =
                stmt.query_map([&s], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<Result<_, _>>()?;
            let mut cloned = files;
            for (file_id, storage) in records {
                if storage == "s3" {
                    // TODO(s3): copyS3Object to the target drawing prefix.
                    eprintln!("[s3] cloning S3-backed file {file_id} is not available in this build");
                    continue;
                }
                c.execute(
                    r#"INSERT INTO "DrawingFile" ("drawingId","fileId","mimeType","sizeBytes","storage","s3Key","data","createdAt")
                       SELECT ?1,"fileId","mimeType","sizeBytes",'db',NULL,"data",?4 FROM "DrawingFile" WHERE "drawingId" = ?2 AND "fileId" = ?3
                       ON CONFLICT("drawingId","fileId") DO UPDATE SET "storage"='db',"s3Key"=NULL,"data"=excluded."data","mimeType"=excluded."mimeType","sizeBytes"=excluded."sizeBytes""#,
                    rusqlite::params![t, s, file_id, crate::util::now_ms()],
                )?;
                if let Some(Value::Object(f)) = cloned.get_mut(&file_id) {
                    f.insert("dataURL".into(), json!(format!("/api/files/{t}/{file_id}")));
                } else if let Some(entry) = cloned.get_mut(&file_id) {
                    if !entry.is_null() {
                        // `{...nonObject, dataURL}` spreads to a plain object.
                        *entry = json!({ "dataURL": format!("/api/files/{t}/{file_id}") });
                    }
                }
            }
            Ok(cloned)
        })
        .await?)
}

/// POST /drawings/:id/duplicate
pub async fn duplicate_drawing(State(st): State<AppState>, ctx: Ctx, Path(id): Path<String>) -> ApiResult {
    let user = crate::auth::require_auth(&st.db, &ctx).await?;
    let (id2, uid) = (id.clone(), user.id.clone());
    let original = st
        .db
        .call(move |c| Ok(DrawingRow::find(c, &id2)?.filter(|d| d.user_id == uid)))
        .await?;
    let Some(original) = original else { return Err(err_only(404, "Original drawing not found")) };
    let mut dup_cid = original.collection_id.clone();
    if is_trash_collection_id(original.collection_id.as_deref(), &user.id) {
        let uid = user.id.clone();
        st.db.call(move |c| Ok(ensure_trash_collection(c, &uid)?)).await?;
        dup_cid = Some(user_trash_collection_id(&user.id));
    }
    let new_id = crate::util::uuid_v4();
    let original_files = match parse_json_field(Some(&original.files), json!({})) {
        Value::Object(m) => m,
        _ => Map::new(),
    };
    let dup_files = clone_file_references(&st, &original.id, &new_id, original_files.clone()).await?;
    let preview_in = opt_str_json(original.preview.clone());
    let preview = match rewrite_preview_for_interned_files(&preview_in, &original_files, &dup_files) {
        Value::String(s) => Some(s),
        _ => original.preview.clone(),
    };
    let (nid, uid) = (new_id.clone(), user.id.clone());
    let name = format!("{} (Copy)", original.name);
    let files = Value::Object(dup_files).to_string();
    let created = st
        .db
        .call(move |c| {
            let now = crate::util::now_ms();
            c.execute(
                r#"INSERT INTO "Drawing" ("id","name","elements","appState","files","preview","version","userId","collectionId","createdAt","updatedAt")
                   VALUES (?1,?2,?3,?4,?5,?6,1,?7,?8,?9,?9)"#,
                rusqlite::params![nid, name, original.elements, original.app_state, files, preview, uid, dup_cid, now],
            )?;
            Ok(DrawingRow::find(c, &nid)?)
        })
        .await?
        .ok_or_else(|| ApiError::internal("Drawing duplicate failed"))?;
    st.drawings_cache.invalidate(None);
    let cid = opt_str_json(to_public(created.collection_id.as_deref(), &user.id));
    ok(Value::Object(created.to_json_with(cid)))
}
