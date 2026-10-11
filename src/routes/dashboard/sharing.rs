//! drawingSharingRoutes.ts + drawingSharedVisibilityRoutes.ts.
use axum::extract::{Path, State};
use crate::sql::OptionalExtension;
use serde_json::{json, Value};

use super::{audit, drawing_owner, err_only, query};
use crate::authz::{build_share_link_token, hash_share_link_token, normalize_permission};
use crate::http::body::Body;
use crate::http::ctx::Ctx;
use crate::http::error::{ok, ApiError, ApiResult};
use crate::security::js_trim;
use crate::state::AppState;

fn not_found() -> ApiError {
    err_only(404, "Drawing not found")
}

async fn require_owner(st: &AppState, id: &str, user_id: &str) -> Result<(), ApiError> {
    match drawing_owner(st, id).await? {
        Some(o) if o == user_id => Ok(()),
        _ => Err(not_found()),
    }
}

/// Kick connected collaborators whose access just changed (best-effort).
async fn revoke_live_access(st: &AppState, drawing_id: &str) {
    crate::socket::revalidate_drawing_access(st, drawing_id).await;
}

/// GET /drawings/:id/share-resolve
pub async fn share_resolve(State(st): State<AppState>, ctx: Ctx, Path(id): Path<String>) -> ApiResult {
    let user = crate::auth::require_auth(&st.db, &ctx).await?;
    let q = match query(&ctx).get("q") {
        Some(Value::String(s)) => js_trim(s).to_lowercase(),
        _ => String::new(),
    };
    if crate::util::js_len(&q) < 3 {
        return ok(json!({ "users": [] }));
    }
    require_owner(&st, &id, &user.id).await?;
    let uid = user.id.clone();
    let users = st
        .db
        .call(move |c| {
            let like = format!("%{q}%");
            let mut s = c.prepare(
                r#"SELECT "id","name","email" FROM "User" WHERE "isActive" = 1 AND "id" <> ?1
                   AND ("email" LIKE ?2 OR "name" LIKE ?2 OR "username" LIKE ?2) LIMIT 10"#,
            )?;
            let rows: Vec<Value> = s
                .query_map(crate::sql::params![uid, like], |r| {
                    Ok(json!({"id": r.get::<_, String>(0)?, "name": r.get::<_, String>(1)?, "email": r.get::<_, String>(2)?}))
                })?
                .collect::<Result<_, _>>()?;
            Ok(rows)
        })
        .await?;
    ok(json!({ "users": users }))
}

const PERMISSION_SELECT: &str = r#"SELECT p."id",p."granteeUserId",p."permission",p."createdAt",p."updatedAt",u."id",u."name",u."email"
    FROM "DrawingPermission" p JOIN "User" u ON u."id" = p."granteeUserId""#;

fn permission_json(r: &crate::sql::Row<'_>) -> crate::sql::Result<Value> {
    Ok(json!({
        "id": r.get::<_, String>(0)?,
        "granteeUserId": r.get::<_, String>(1)?,
        "permission": r.get::<_, String>(2)?,
        "createdAt": crate::db::iso(r, 3)?,
        "updatedAt": crate::db::iso(r, 4)?,
        "granteeUser": {"id": r.get::<_, String>(5)?, "name": r.get::<_, String>(6)?, "email": r.get::<_, String>(7)?},
    }))
}

/// GET /drawings/:id/sharing
pub async fn get_sharing(State(st): State<AppState>, ctx: Ctx, Path(id): Path<String>) -> ApiResult {
    let user = crate::auth::require_auth(&st.db, &ctx).await?;
    require_owner(&st, &id, &user.id).await?;
    let (permissions, link_shares) = st
        .db
        .call(move |c| {
            let mut s = c.prepare(&format!(r#"{PERMISSION_SELECT} WHERE p."drawingId" = ?1 ORDER BY p."createdAt" DESC"#))?;
            let perms: Vec<Value> = s.query_map([&id], permission_json)?.collect::<Result<_, _>>()?;
            let mut s = c.prepare(
                r#"SELECT "id","permission","expiresAt","revokedAt","createdAt","updatedAt","lastUsedAt" FROM "DrawingLinkShare" WHERE "drawingId" = ?1 ORDER BY "createdAt" DESC"#,
            )?;
            let links: Vec<Value> = s
                .query_map([&id], |r| {
                    Ok(json!({
                        "id": r.get::<_, String>(0)?,
                        "permission": r.get::<_, String>(1)?,
                        "expiresAt": crate::db::iso(r, 2)?,
                        "revokedAt": crate::db::iso(r, 3)?,
                        "createdAt": crate::db::iso(r, 4)?,
                        "updatedAt": crate::db::iso(r, 5)?,
                        "lastUsedAt": crate::db::iso(r, 6)?,
                    }))
                })?
                .collect::<Result<_, _>>()?;
            Ok((perms, links))
        })
        .await?;
    ok(json!({ "permissions": permissions, "linkShares": link_shares }))
}

/// POST /drawings/:id/permissions
pub async fn upsert_permission(State(st): State<AppState>, ctx: Ctx, Path(id): Path<String>, body: Body) -> ApiResult {
    let user = crate::auth::require_auth(&st.db, &ctx).await?;
    require_owner(&st, &id, &user.id).await?;
    let grantee = body.str("granteeUserId").map(str::to_string);
    let permission = normalize_permission(body.str("permission"));
    let (Some(grantee), Some(permission)) = (grantee, permission) else {
        return Err(ApiError::err(400, "Validation error", "Invalid grantee or permission"));
    };
    if grantee.is_empty() {
        return Err(ApiError::err(400, "Validation error", "Invalid grantee or permission"));
    }
    if grantee == user.id {
        return Err(ApiError::err(400, "Validation error", "Cannot share with yourself"));
    }
    let (id2, g2, me, perm) = (id.clone(), grantee.clone(), user.id.clone(), permission.as_str().to_string());
    let saved = st
        .db
        .call(move |c| {
            let active: Option<bool> = c
                .query_row(r#"SELECT "isActive" FROM "User" WHERE "id" = ?1"#, [&g2], |r| crate::db::boolean(r, 0))
                .optional()?;
            if active != Some(true) {
                return Ok(None);
            }
            let now = crate::util::now_ms();
            c.execute(
                r#"INSERT INTO "DrawingPermission" ("id","drawingId","granteeUserId","permission","hidden","createdByUserId","createdAt","updatedAt")
                   VALUES (?1,?2,?3,?4,0,?5,?6,?6)
                   ON CONFLICT("drawingId","granteeUserId") DO UPDATE SET "permission" = excluded."permission", "createdByUserId" = excluded."createdByUserId", "updatedAt" = excluded."updatedAt""#,
                crate::sql::params![crate::util::uuid_v4(), id2, g2, perm, me, now],
            )?;
            Ok(Some(c.query_row(
                &format!(r#"{PERMISSION_SELECT} WHERE p."drawingId" = ?1 AND p."granteeUserId" = ?2"#),
                [&id2, &g2],
                permission_json,
            )?))
        })
        .await?;
    let Some(saved) = saved else { return Err(err_only(404, "User not found")) };
    st.drawings_cache.invalidate(None);
    audit(
        &st,
        &ctx,
        &user.id,
        "drawing_shared_user_upsert",
        format!("drawing:{id}"),
        json!({"drawingId": id, "granteeUserId": grantee, "permission": permission.as_str()}),
    )
    .await;
    ok(json!({ "permission": saved }))
}

/// DELETE /drawings/:id/permissions/:permId
pub async fn delete_permission(State(st): State<AppState>, ctx: Ctx, Path((id, perm_id)): Path<(String, String)>) -> ApiResult {
    let user = crate::auth::require_auth(&st.db, &ctx).await?;
    require_owner(&st, &id, &user.id).await?;
    let (id2, p2) = (id.clone(), perm_id.clone());
    st.db
        .call(move |c| {
            c.execute(r#"DELETE FROM "DrawingPermission" WHERE "id" = ?1 AND "drawingId" = ?2"#, [&p2, &id2])?;
            Ok(())
        })
        .await?;
    st.drawings_cache.invalidate(None);
    revoke_live_access(&st, &id).await;
    audit(
        &st,
        &ctx,
        &user.id,
        "drawing_shared_user_revoke",
        format!("drawing:{id}"),
        json!({"drawingId": id, "permissionId": perm_id}),
    )
    .await;
    ok(json!({ "success": true }))
}

/// JS `new Date(string).getTime()` (V8 semantics, see `crate::jsdate`).
fn parse_js_date(s: &str) -> Option<i64> {
    crate::jsdate::parse(s)
}

/// POST /drawings/:id/link-shares
pub async fn create_link_share(State(st): State<AppState>, ctx: Ctx, Path(id): Path<String>, body: Body) -> ApiResult {
    let user = crate::auth::require_auth(&st.db, &ctx).await?;
    require_owner(&st, &id, &user.id).await?;
    let Some(permission) = normalize_permission(body.str("permission")) else {
        return Err(ApiError::err(400, "Validation error", "Invalid permission"));
    };
    let is_edit = permission.can_edit();
    let now = crate::util::now_ms();
    let ls = &st.cfg.link_share;
    let max_ttl = ls.max_ttl_ms;
    let default_ttl = if is_edit { ls.edit_default_ttl_ms } else { ls.view_default_ttl_ms };
    let effective_default = if is_edit { default_ttl.min(max_ttl) } else { default_ttl };
    let has_key = body.get("expiresAt").is_some();
    let raw = body.get("expiresAt");

    let expires_at: Option<i64> = if has_key && raw == Some(&Value::Null) {
        None
    } else {
        let requested = match raw {
            Some(Value::String(s)) if !js_trim(s).is_empty() => parse_js_date(js_trim(s)),
            _ => None,
        };
        if let Some(req) = requested {
            let candidate = (req - now) as f64;
            if candidate < 60_000.0 {
                return Err(ApiError::err(400, "Validation error", "Expiry must be at least 1 minute in the future"));
            }
            let ttl = if is_edit { candidate.min(max_ttl) } else { candidate };
            Some(now + ttl as i64)
        } else if has_key {
            return Err(ApiError::err(400, "Validation error", "Invalid expiry"));
        } else {
            Some(now + effective_default as i64)
        }
    };

    let (id2, me, perm) = (id.clone(), user.id.clone(), permission.as_str().to_string());
    let token_hash = hash_share_link_token(&build_share_link_token());
    let created = st
        .db
        .call(move |c| {
            let now = crate::util::now_ms();
            c.execute(
                r#"UPDATE "DrawingLinkShare" SET "revokedAt" = ?1, "updatedAt" = ?1 WHERE "drawingId" = ?2 AND "revokedAt" IS NULL"#,
                crate::sql::params![now, id2],
            )?;
            let share_id = crate::util::uuid_v4();
            let created_at = crate::util::now_ms();
            c.execute(
                r#"INSERT INTO "DrawingLinkShare" ("id","drawingId","permission","tokenHash","passphraseHash","expiresAt","revokedAt","failedAttempts","lockedUntil","lastUsedAt","lastUsedIp","createdByUserId","createdAt","updatedAt")
                   VALUES (?1,?2,?3,?4,NULL,?5,NULL,0,NULL,NULL,NULL,?6,?7,?7)"#,
                crate::sql::params![share_id, id2, perm, token_hash, expires_at, me, created_at],
            )?;
            Ok(json!({
                "id": share_id,
                "permission": perm,
                "expiresAt": expires_at.map(crate::util::iso_from_ms),
                "revokedAt": null,
                "createdAt": crate::util::iso_from_ms(created_at),
            }))
        })
        .await?;
    audit(
        &st,
        &ctx,
        &user.id,
        "drawing_link_share_created",
        format!("drawing:{id}"),
        json!({"drawingId": id, "permission": permission.as_str(), "expiresAt": expires_at.map(crate::util::iso_from_ms)}),
    )
    .await;
    ok(json!({ "share": created }))
}

/// DELETE /drawings/:id/link-shares/:shareId
pub async fn revoke_link_share(State(st): State<AppState>, ctx: Ctx, Path((id, share_id)): Path<(String, String)>) -> ApiResult {
    let user = crate::auth::require_auth(&st.db, &ctx).await?;
    require_owner(&st, &id, &user.id).await?;
    let (id2, s2) = (id.clone(), share_id.clone());
    st.db
        .call(move |c| {
            let now = crate::util::now_ms();
            c.execute(
                r#"UPDATE "DrawingLinkShare" SET "revokedAt" = ?1, "updatedAt" = ?1 WHERE "id" = ?2 AND "drawingId" = ?3 AND "revokedAt" IS NULL"#,
                crate::sql::params![now, s2, id2],
            )?;
            Ok(())
        })
        .await?;
    revoke_live_access(&st, &id).await;
    audit(
        &st,
        &ctx,
        &user.id,
        "drawing_link_share_revoked",
        format!("drawing:{id}"),
        json!({"drawingId": id, "shareId": share_id}),
    )
    .await;
    ok(json!({ "success": true }))
}

/// PATCH /drawings/:id/shared-visibility
pub async fn shared_visibility(State(st): State<AppState>, ctx: Ctx, Path(id): Path<String>, body: Body) -> ApiResult {
    let user = crate::auth::require_auth(&st.db, &ctx).await?;
    let Some(hidden) = body.get("hidden").and_then(|v| v.as_bool()) else {
        return Err(ApiError::err(400, "Validation error", "`hidden` must be a boolean"));
    };
    let uid = user.id.clone();
    let n = st
        .db
        .call(move |c| {
            Ok(c.execute(
                r#"UPDATE "DrawingPermission" SET "hidden" = ?1, "updatedAt" = ?2 WHERE "drawingId" = ?3 AND "granteeUserId" = ?4"#,
                crate::sql::params![hidden, crate::util::now_ms(), id, uid],
            )?)
        })
        .await?;
    if n == 0 {
        return Err(err_only(404, "Shared drawing not found"));
    }
    ok(json!({ "success": true, "hidden": hidden }))
}
