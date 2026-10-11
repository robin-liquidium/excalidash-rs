//! drawingHistoryRoutes.ts — snapshot list / read / restore.
use axum::extract::{Path, State};
use crate::sql::OptionalExtension;
use serde_json::{json, Value};

use super::scene::{apply_scene_update, SceneError, SceneMutation, UpdateData, VersionGuard};
use super::{err_only, parse_json_field, principal, query, DrawingRow};
use crate::authz::{get_drawing_access, Access};
use crate::http::ctx::Ctx;
use crate::http::error::{ok, ApiError, ApiResult};
use crate::snapshots::decode_field;
use crate::state::AppState;

struct Snapshot {
    id: String,
    drawing_id: String,
    version: i64,
    elements: String,
    app_state: String,
    files: String,
    created_at: i64,
}

fn find_snapshot(c: &crate::sql::Connection, id: &str, drawing_id: &str) -> crate::sql::Result<Option<Snapshot>> {
    c.query_row(
        r#"SELECT "id","drawingId","version","elements","appState","files","createdAt" FROM "DrawingSnapshot" WHERE "id" = ?1 AND "drawingId" = ?2 LIMIT 1"#,
        [id, drawing_id],
        |r| {
            Ok(Snapshot {
                id: r.get(0)?,
                drawing_id: r.get(1)?,
                version: r.get(2)?,
                elements: r.get(3)?,
                app_state: r.get(4)?,
                files: r.get(5)?,
                created_at: crate::db::dt(r, 6)?,
            })
        },
    )
    .optional()
}

/// Access check shared by the history routes (404 `{error}` / 401 auth error).
async fn access_for(st: &AppState, ctx: &Ctx, id: &str, need_edit: bool) -> Result<Access, ApiError> {
    let opt = crate::auth::optional_auth(&st.db, ctx).await;
    let (p, id2) = (principal(&opt), id.to_string());
    let access = st.db.call(move |c| Ok(get_drawing_access(c, p.as_deref(), &id2, None)?)).await?;
    let allowed = if need_edit { access.can_edit() } else { access.can_view() };
    if !allowed {
        if let Some(e) = super::auth_error(&opt) {
            return Err(e);
        }
        return Err(err_only(404, "Drawing not found"));
    }
    Ok(access)
}

/// JS `Number(x)` for a query value (`undefined` → default).
fn query_number(v: Option<&Value>, default: f64) -> f64 {
    match v {
        None => default,
        Some(Value::String(s)) => crate::config::js_number(s),
        Some(Value::Array(a)) if a.len() == 1 => query_number(a.first(), default),
        Some(_) => f64::NAN,
    }
}

fn is_safe_integer(n: f64) -> bool {
    n.is_finite() && n.fract() == 0.0 && n.abs() <= 9_007_199_254_740_991.0
}

/// GET /drawings/:id/history
pub async fn list_history(State(st): State<AppState>, ctx: Ctx, Path(id): Path<String>) -> ApiResult {
    access_for(&st, &ctx, &id, false).await?;
    let q = query(&ctx);
    let requested = query_number(q.get("limit"), 50.0);
    let offset = query_number(q.get("offset"), 0.0);
    if !is_safe_integer(requested)
        || requested < 1.0
        || !is_safe_integer(offset)
        || offset < 0.0
        || q.get("limit").is_some_and(|v| !v.is_string())
        || q.get("offset").is_some_and(|v| !v.is_string())
    {
        return Err(err_only(400, "Invalid history pagination"));
    }
    let limit = requested.min(200.0) as i64;
    let offset = offset as i64;
    let (snapshots, total) = st
        .db
        .call(move |c| {
            let mut s = c.prepare(
                r#"SELECT "id","version","createdAt" FROM "DrawingSnapshot" WHERE "drawingId" = ?1 ORDER BY "createdAt" DESC LIMIT ?2 OFFSET ?3"#,
            )?;
            let rows: Vec<Value> = s
                .query_map(crate::sql::params![id, limit, offset], |r| {
                    Ok(json!({
                        "id": r.get::<_, String>(0)?,
                        "version": r.get::<_, i64>(1)?,
                        "createdAt": crate::db::iso(r, 2)?,
                    }))
                })?
                .collect::<Result<_, _>>()?;
            let total: i64 =
                c.query_row(r#"SELECT COUNT(*) FROM "DrawingSnapshot" WHERE "drawingId" = ?1"#, [&id], |r| r.get(0))?;
            Ok((rows, total))
        })
        .await?;
    ok(json!({ "snapshots": snapshots, "totalCount": total }))
}

fn decode(v: &str) -> Result<String, ApiError> {
    decode_field(v).map_err(|e| ApiError::internal(e.to_string()))
}

/// GET /drawings/:id/history/:snapshotId
pub async fn get_snapshot(State(st): State<AppState>, ctx: Ctx, Path((id, snapshot_id)): Path<(String, String)>) -> ApiResult {
    access_for(&st, &ctx, &id, false).await?;
    let snap = st.db.call(move |c| Ok(find_snapshot(c, &snapshot_id, &id)?)).await?;
    let Some(s) = snap else { return Err(err_only(404, "Snapshot not found")) };
    let elements = decode(&s.elements)?;
    let app_state = decode(&s.app_state)?;
    let files = decode(&s.files)?;
    ok(json!({
        "id": s.id,
        "drawingId": s.drawing_id,
        "version": s.version,
        "elements": parse_json_field(Some(&elements), json!([])),
        "appState": parse_json_field(Some(&app_state), json!({})),
        "files": parse_json_field(Some(&files), json!({})),
        "createdAt": crate::util::iso_from_ms(s.created_at),
    }))
}

/// POST /drawings/:id/history/:snapshotId/restore
pub async fn restore_snapshot(State(st): State<AppState>, ctx: Ctx, Path((id, snapshot_id)): Path<(String, String)>) -> ApiResult {
    let access = access_for(&st, &ctx, &id, true).await?;
    let id2 = id.clone();
    let (drawing, snap) = st
        .db
        .call(move |c| Ok((DrawingRow::find(c, &id2)?, find_snapshot(c, &snapshot_id, &id2)?)))
        .await?;
    let Some(drawing) = drawing else { return Err(err_only(404, "Drawing not found")) };
    let Some(snap) = snap else { return Err(err_only(404, "Snapshot not found")) };
    let elements = decode(&snap.elements)?;
    let app_state = decode(&snap.app_state)?;
    let files = decode(&snap.files)?;
    let valid = matches!(
        (
            serde_json::from_str::<Value>(&elements),
            serde_json::from_str::<Value>(&app_state),
            serde_json::from_str::<Value>(&files),
        ),
        (Ok(Value::Array(_)), Ok(Value::Object(_)), Ok(Value::Object(_)))
    );
    if !valid {
        return Err(ApiError::err(
            400,
            "Invalid drawing history snapshot",
            "The snapshot cannot be restored without losing drawing data.",
        ));
    }
    let mutation = SceneMutation {
        data: UpdateData {
            elements: Some(elements),
            app_state: Some(app_state),
            files: Some(files),
            preview: Some(None),
            ..Default::default()
        },
        ..Default::default()
    };
    let updated = match apply_scene_update(&st, &id, VersionGuard::Exact(drawing.version), 0, mutation).await {
        Ok(d) => d,
        Err(SceneError::Conflict) => {
            return Err(ApiError::json(
                409,
                json!({"error": "Drawing changed during restore; please try again", "code": "VERSION_CONFLICT"}),
            ))
        }
        Err(SceneError::Db(e)) => return Err(e.into()),
    };
    st.drawings_cache.invalidate(None);
    let mut m = updated.to_map();
    m.insert("elements".into(), parse_json_field(Some(&updated.elements), json!([])));
    m.insert("appState".into(), parse_json_field(Some(&updated.app_state), json!({})));
    m.insert("files".into(), parse_json_field(Some(&updated.files), json!({})));
    m.insert("accessLevel".into(), json!(access.as_str()));
    ok(Value::Object(m))
}
