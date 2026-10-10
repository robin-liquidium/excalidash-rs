//! auth/accountRoutes.ts: API keys, password change, password reset,
//! preferences and profile/email routes.
pub mod common;
mod password_reset;

use axum::{
    extract::{Path, State},
    response::Response,
    routing::{delete, get, post, put},
    Router,
};
use rusqlite::OptionalExtension;
use serde_json::{json, Map, Value};

use self::common::*;
use crate::auth::api_keys::{generate_api_key, parse_scopes, serialize_scopes, DEFAULT_API_KEY_SCOPES};
use crate::auth::require_auth;
use crate::auth::routes::helpers::{account_action_rate_limit, ensure_auth_enabled, require_csrf};
use crate::http::body::Body;
use crate::http::ctx::Ctx;
use crate::http::error::{ok, status_json, ApiError, ApiResult};
use crate::state::AppState;
use crate::util::{iso_from_ms, now_ms};

pub fn router() -> Router<AppState> {
    Router::new()
        .merge(password_reset::router())
        .route("/preferences", get(get_preferences).put(put_preferences))
        .route("/profile", put(put_profile))
        .route("/email", put(put_email))
        .route("/api-keys", get(list_api_keys).post(create_api_key))
        .route("/api-keys/{id}", delete(revoke_api_key))
        .route("/change-password", post(change_password))
        .route("/must-reset-password", post(must_reset_password))
}

/// requireAuth → (accountActionRateLimiter) → handler, with limiter headers applied.
macro_rules! guarded {
    ($st:expr, $ctx:expr, limited: $limited:expr, |$user:ident| $body:expr) => {{
        let $user = match require_auth(&$st.db, &$ctx).await {
            Ok(u) => u,
            Err(e) => return axum::response::IntoResponse::into_response(e),
        };
        let decision = if $limited {
            match account_action_rate_limit(&$ctx) {
                Ok(d) => Some(d),
                Err(r) => return r,
            }
        } else {
            None
        };
        finish(decision, $body)
    }};
}
pub(crate) use guarded;

// ---------------------------------------------------------------------------
// API keys

fn api_key_json(r: &rusqlite::Row<'_>) -> rusqlite::Result<Value> {
    let scopes: Option<String> = r.get(3)?;
    Ok(json!({
        "id": r.get::<_, String>(0)?,
        "name": r.get::<_, String>(1)?,
        "prefix": r.get::<_, String>(2)?,
        "scopes": parse_scopes(scopes.as_deref()),
        "lastUsedAt": opt_iso(crate::db::opt_dt(r, 4)?),
        "revokedAt": opt_iso(crate::db::opt_dt(r, 5)?),
        "createdAt": iso_from_ms(crate::db::dt(r, 6)?),
        "updatedAt": iso_from_ms(crate::db::dt(r, 7)?),
    }))
}

const API_KEY_COLS: &str = r#""id","name","prefix","scopes","lastUsedAt","revokedAt","createdAt","updatedAt""#;

async fn list_api_keys(State(st): State<AppState>, ctx: Ctx) -> Response {
    guarded!(st, ctx, limited: false, |user| {
        let r: ApiResult = async {
            ensure_auth_enabled(&st.db).await?;
            let uid = user.id.clone();
            let keys = st
                .db
                .call(move |c| {
                    let mut s = c.prepare(&format!(
                        r#"SELECT {API_KEY_COLS} FROM "ApiKey" WHERE "userId" = ?1 AND "drawingId" IS NULL ORDER BY "createdAt" DESC"#
                    ))?;
                    let rows = s.query_map([&uid], api_key_json)?.collect::<Result<Vec<_>, _>>()?;
                    Ok(rows)
                })
                .await?;
            ok(json!({ "apiKeys": keys }))
        }
        .await;
        catch(r, "List API keys error:", "Failed to list API keys")
    })
}

/// normalizeApiKeyScopes
fn normalize_scopes(scopes: Option<Vec<String>>) -> Option<Vec<String>> {
    let Some(scopes) = scopes else {
        return Some(DEFAULT_API_KEY_SCOPES.iter().map(|s| s.to_string()).collect());
    };
    let mut out: Vec<String> = vec![];
    for s in scopes {
        let t = crate::security::js_trim(&s).to_string();
        if !t.is_empty() && !out.contains(&t) {
            out.push(t);
        }
    }
    if out.is_empty() || out.iter().any(|s| !DEFAULT_API_KEY_SCOPES.contains(&s.as_str())) {
        return None;
    }
    Some(out)
}

fn parse_api_key_create(body: &Body) -> V<(String, Option<Vec<String>>)> {
    let o = object(&body.0)?;
    let name = trimmed(&o, "name", 1, 100)?;
    let scopes = match o.get("scopes") {
        None => None,
        Some(Value::Array(a)) => Some(
            a.iter().map(|v| v.as_str().map(str::to_string).ok_or(Invalid)).collect::<V<Vec<String>>>()?,
        ),
        Some(_) => return Err(Invalid),
    };
    Ok((name, scopes))
}

async fn create_api_key(State(st): State<AppState>, ctx: Ctx, body: Body) -> Response {
    guarded!(st, ctx, limited: true, |user| {
        let r: ApiResult = async {
            ensure_auth_enabled(&st.db).await?;
            require_csrf(&ctx)?;
            if user.impersonator_id.is_some() {
                return Err(ApiError::forbidden("API key creation is not allowed while impersonating"));
            }
            let Ok((name, scopes)) = parse_api_key_create(&body) else {
                return Err(ApiError::err(400, "Validation error", "API key name must be between 1 and 100 characters"));
            };
            let Some(scopes) = normalize_scopes(scopes) else {
                return Err(ApiError::err(400, "Validation error", "Select at least one valid API key scope"));
            };
            let generated = tokio::task::spawn_blocking(generate_api_key)
                .await
                .map_err(|e| ApiError::internal(e.to_string()))?;
            let uid = user.id.clone();
            let name = crate::security::sanitize_text(&name, 100);
            let (key_id, token_hash, prefix) =
                (generated.key_id.clone(), generated.token_hash.clone(), generated.prefix.clone());
            let api_key = st
                .db
                .call(move |c| {
                    let id = crate::util::uuid_v4();
                    let now = now_ms();
                    c.execute(
                        r#"INSERT INTO "ApiKey" ("id","userId","name","keyId","tokenHash","prefix","scopes","drawingId","lastUsedAt","revokedAt","createdAt","updatedAt")
                           VALUES (?1,?2,?3,?4,?5,?6,?7,NULL,NULL,NULL,?8,?8)"#,
                        rusqlite::params![id, uid, name, key_id, token_hash, prefix, serialize_scopes(&scopes), now],
                    )?;
                    Ok(c.query_row(&format!(r#"SELECT {API_KEY_COLS} FROM "ApiKey" WHERE "id" = ?1"#), [&id], api_key_json)?)
                })
                .await?;
            let id = api_key["id"].as_str().unwrap_or_default().to_string();
            audit(&st, &ctx, &user.id, "api_key_created", Some(format!("api_key:{id}")), None).await;
            status_json(201, json!({ "apiKey": api_key, "token": generated.token }))
        }
        .await;
        catch(r, "Create API key error:", "Failed to create API key")
    })
}

async fn revoke_api_key(State(st): State<AppState>, ctx: Ctx, Path(id): Path<String>) -> Response {
    guarded!(st, ctx, limited: true, |user| {
        let r: ApiResult = async {
            ensure_auth_enabled(&st.db).await?;
            require_csrf(&ctx)?;
            if user.impersonator_id.is_some() {
                return Err(ApiError::forbidden("API key revocation is not allowed while impersonating"));
            }
            let uid = user.id.clone();
            let found = st
                .db
                .call(move |c| {
                    let row = c
                        .query_row(
                            r#"SELECT "id","revokedAt" FROM "ApiKey" WHERE "id" = ?1 AND "userId" = ?2 LIMIT 1"#,
                            rusqlite::params![id, uid],
                            |r| Ok((r.get::<_, String>(0)?, crate::db::opt_dt(r, 1)?)),
                        )
                        .optional()?;
                    if let Some((id, None)) = &row {
                        let now = now_ms();
                        c.execute(
                            r#"UPDATE "ApiKey" SET "revokedAt" = ?1, "updatedAt" = ?1 WHERE "id" = ?2"#,
                            rusqlite::params![now, id],
                        )?;
                    }
                    Ok(row.map(|r| r.0))
                })
                .await?;
            let Some(key_id) = found else {
                return Err(ApiError::not_found("API key not found"));
            };
            audit(&st, &ctx, &user.id, "api_key_revoked", Some(format!("api_key:{key_id}")), None).await;
            ok(json!({ "success": true }))
        }
        .await;
        catch(r, "Revoke API key error:", "Failed to revoke API key")
    })
}

// ---------------------------------------------------------------------------
// Preferences (userPreferencesSchema, strict, output in shape order)

fn parse_preferences(v: &Value) -> V<Map<String, Value>> {
    const SHAPE: [&str; 7] =
        ["theme", "dashboardSortField", "dashboardSortDirection", "language", "gridStep", "editorAutoHide", "compactSidebar"];
    let Value::Object(o) = v else { return Err(Invalid) };
    if o.keys().any(|k| !SHAPE.contains(&k.as_str())) {
        return Err(Invalid);
    }
    let mut out = Map::new();
    for key in SHAPE {
        let Some(val) = o.get(key) else { continue };
        let parsed = match key {
            "theme" => opt_enum(o, key, &["light", "dark"])?.map(Value::String),
            "dashboardSortField" => opt_enum(o, key, &["name", "createdAt", "updatedAt"])?.map(Value::String),
            "dashboardSortDirection" => opt_enum(o, key, &["asc", "desc"])?.map(Value::String),
            "language" => opt_trimmed(o, key, 1, 35)?.map(Value::String),
            "gridStep" => Some(json!(int_value(val, 1, 100)?)),
            _ => opt_bool(o, key)?.map(Value::Bool),
        };
        if let Some(p) = parsed {
            out.insert(key.to_string(), p);
        }
    }
    Ok(out)
}

fn parse_stored_preferences(raw: Option<&str>) -> Map<String, Value> {
    let Some(raw) = raw.filter(|s| !s.is_empty()) else { return Map::new() };
    serde_json::from_str::<Value>(raw).ok().and_then(|v| parse_preferences(&v).ok()).unwrap_or_default()
}

async fn load_preferences(st: &AppState, user_id: &str) -> Result<Option<Option<String>>, ApiError> {
    let uid = user_id.to_string();
    Ok(st
        .db
        .call(move |c| {
            Ok(c.query_row(r#"SELECT "preferences" FROM "User" WHERE "id" = ?1"#, [&uid], |r| r.get::<_, Option<String>>(0))
                .optional()?)
        })
        .await?)
}

async fn get_preferences(State(st): State<AppState>, ctx: Ctx) -> Response {
    guarded!(st, ctx, limited: false, |user| {
        let r: ApiResult = async {
            ensure_auth_enabled(&st.db).await?;
            let Some(stored) = load_preferences(&st, &user.id).await? else {
                return Err(ApiError::not_found("User not found"));
            };
            ok(json!({ "preferences": parse_stored_preferences(stored.as_deref()) }))
        }
        .await;
        catch(r, "Get preferences error:", "Failed to load preferences")
    })
}

async fn put_preferences(State(st): State<AppState>, ctx: Ctx, body: Body) -> Response {
    guarded!(st, ctx, limited: false, |user| {
        let r: ApiResult = async {
            ensure_auth_enabled(&st.db).await?;
            require_csrf(&ctx)?;
            if user.impersonator_id.is_some() {
                return Err(ApiError::forbidden("Preference updates are not allowed while impersonating"));
            }
            let Ok(parsed) = parse_preferences(&body.value()) else {
                return Err(ApiError::err(400, "Validation error", "Invalid preferences"));
            };
            let Some(stored) = load_preferences(&st, &user.id).await? else {
                return Err(ApiError::not_found("User not found"));
            };
            let mut preferences = parse_stored_preferences(stored.as_deref());
            for (k, v) in &parsed {
                preferences.insert(k.clone(), v.clone());
            }
            let serialized = Value::Object(preferences.clone()).to_string();
            let uid = user.id.clone();
            let changed = st
                .db
                .call(move |c| {
                    Ok(c.execute(
                        r#"UPDATE "User" SET "preferences" = ?1, "updatedAt" = ?2 WHERE "id" = ?3"#,
                        rusqlite::params![serialized, now_ms(), uid],
                    )?)
                })
                .await?;
            if changed == 0 {
                return Err(ApiError::internal("Record to update not found."));
            }
            let fields: Vec<Value> = parsed.keys().map(|k| Value::String(k.clone())).collect();
            let mut details = Map::new();
            details.insert("fields".into(), Value::Array(fields));
            audit(&st, &ctx, &user.id, "preferences_updated", None, Some(details)).await;
            ok(json!({ "preferences": preferences }))
        }
        .await;
        catch(r, "Update preferences error:", "Failed to save preferences")
    })
}

// ---------------------------------------------------------------------------
// Profile / email

async fn put_profile(State(st): State<AppState>, ctx: Ctx, body: Body) -> Response {
    guarded!(st, ctx, limited: false, |user| {
        let r: ApiResult = async {
            ensure_auth_enabled(&st.db).await?;
            require_csrf(&ctx)?;
            if user.impersonator_id.is_some() {
                return Err(ApiError::forbidden("Profile updates are not allowed while impersonating"));
            }
            let Ok(name) = object(&body.0).and_then(|o| trimmed(&o, "name", 1, 100)) else {
                return Err(ApiError::err(400, "Validation error", "Invalid name format"));
            };
            let name = crate::security::sanitize_text(&name, 100);
            let uid = user.id.clone();
            let updated = st
                .db
                .call(move |c| {
                    let n = c.execute(
                        r#"UPDATE "User" SET "name" = ?1, "updatedAt" = ?2 WHERE "id" = ?3"#,
                        rusqlite::params![name, now_ms(), uid],
                    )?;
                    if n == 0 {
                        return Ok(None);
                    }
                    Ok(Some(c.query_row(
                        r#"SELECT "id","email","name","createdAt","updatedAt" FROM "User" WHERE "id" = ?1"#,
                        [&uid],
                        |r| {
                            Ok(json!({
                                "id": r.get::<_, String>(0)?,
                                "email": r.get::<_, String>(1)?,
                                "name": r.get::<_, String>(2)?,
                                "createdAt": crate::db::iso(r, 3)?,
                                "updatedAt": crate::db::iso(r, 4)?,
                            }))
                        },
                    )?))
                })
                .await?;
            let Some(updated) = updated else { return Err(ApiError::internal("Record to update not found.")) };
            let mut details = Map::new();
            details.insert("field".into(), json!("name"));
            audit(&st, &ctx, &user.id, "profile_updated", None, Some(details)).await;
            ok(json!({ "user": updated }))
        }
        .await;
        catch(r, "Update profile error:", "Failed to update profile")
    })
}

/// select { id, username, email, name, role, mustResetPassword, createdAt, updatedAt }
pub(crate) fn user_with_dates_json(u: &crate::models::User) -> Value {
    json!({
        "id": u.id,
        "username": u.username,
        "email": u.email,
        "name": u.name,
        "role": u.role,
        "mustResetPassword": u.must_reset_password,
        "createdAt": u.created_iso(),
        "updatedAt": u.updated_iso(),
    })
}

async fn find_user(st: &AppState, id: &str) -> Result<Option<crate::models::User>, ApiError> {
    let id = id.to_string();
    Ok(st.db.call(move |c| Ok(crate::models::User::find_by_id(c, &id)?)).await?)
}

async fn put_email(State(st): State<AppState>, ctx: Ctx, body: Body) -> Response {
    guarded!(st, ctx, limited: true, |user| {
        let r: ApiResult = async {
            ensure_auth_enabled(&st.db).await?;
            require_csrf(&ctx)?;
            if user.impersonator_id.is_some() {
                return Err(ApiError::forbidden("Email changes are not allowed while impersonating"));
            }
            let parsed = object(&body.0).and_then(|o| Ok((email(&o, "email")?, raw_string(&o, "currentPassword", 1, 100)?)));
            let Ok((new_email, current_password)) = parsed else {
                return Err(ApiError::err(400, "Validation error", "Invalid email update data"));
            };
            let Some(existing) = find_user(&st, &user.id).await?.filter(|u| u.is_active) else {
                return Err(ApiError::unauthorized("User account not found or inactive"));
            };
            if !can_use_local_password(&existing.password_hash) {
                return Err(ApiError::err(400, "Bad request", "Cannot change email for this account"));
            }
            if !bcrypt_verify(current_password, existing.password_hash.clone()).await {
                return Err(ApiError::unauthorized("Current password is incorrect"));
            }
            if new_email != existing.email {
                let e = new_email.clone();
                let other = st
                    .db
                    .call(move |c| Ok(crate::models::User::find_by_email(c, &e)?.map(|u| u.id)))
                    .await?;
                if other.is_some_and(|id| id != existing.id) {
                    return Err(ApiError::err(409, "Conflict", "User with this email already exists"));
                }
            }
            let previous_email = existing.email.clone();
            let (uid, e) = (existing.id.clone(), new_email.clone());
            let updated = st
                .db
                .call(move |c| {
                    c.execute(
                        r#"UPDATE "User" SET "email" = ?1, "updatedAt" = ?2 WHERE "id" = ?3"#,
                        rusqlite::params![e, now_ms(), uid],
                    )?;
                    Ok(crate::models::User::find_by_id(c, &uid)?)
                })
                .await?
                .ok_or_else(|| ApiError::internal("Record to update not found."))?;
            if st.cfg.enable_refresh_token_rotation {
                revoke_refresh_tokens(&st, &updated.id).await;
            }
            let mut res = ok(json!({ "user": user_with_dates_json(&updated) }))?;
            issue_session(&st, &ctx, res.headers_mut(), &updated.id, &updated.email, None).await;
            let mut details = Map::new();
            details.insert("previousEmail".into(), json!(previous_email));
            details.insert("newEmail".into(), json!(updated.email));
            audit(&st, &ctx, &updated.id, "email_updated", None, Some(details)).await;
            Ok(res)
        }
        .await;
        catch(r, "Update email error:", "Failed to update email")
    })
}

// ---------------------------------------------------------------------------
// Password change

async fn change_password(State(st): State<AppState>, ctx: Ctx, body: Body) -> Response {
    guarded!(st, ctx, limited: true, |user| {
        let r: ApiResult = async {
            ensure_auth_enabled(&st.db).await?;
            require_csrf(&ctx)?;
            if user.impersonator_id.is_some() {
                return Err(ApiError::forbidden("Password changes are not allowed while impersonating"));
            }
            let parsed = object(&body.0).and_then(|o| {
                Ok((raw_string(&o, "currentPassword", 0, usize::MAX)?, password_value(o.get("newPassword"))?))
            });
            let Ok((current, new_password)) = parsed else {
                return Err(ApiError::err(400, "Validation error", "Invalid password data"));
            };
            let Some(existing) = find_user(&st, &user.id).await?.filter(|u| u.is_active) else {
                return Err(ApiError::not_found("User not found"));
            };
            if !can_use_local_password(&existing.password_hash) {
                return Err(ApiError::err(400, "Bad request", "Cannot change password for this account"));
            }
            if !bcrypt_verify(current, existing.password_hash.clone()).await {
                return Err(ApiError::unauthorized("Current password is incorrect"));
            }
            let hash = bcrypt_hash(new_password).await?;
            set_password(&st, &existing.id, hash).await?;
            if st.cfg.enable_refresh_token_rotation {
                revoke_refresh_tokens(&st, &existing.id).await;
            }
            let mut details = Map::new();
            details.insert("method".into(), json!("change_password"));
            audit(&st, &ctx, &existing.id, "password_changed", None, Some(details)).await;
            ok(json!({ "message": "Password changed successfully" }))
        }
        .await;
        catch(r, "Change password error:", "Failed to change password")
    })
}

/// `user.update({ data: { passwordHash, mustResetPassword: false } })`
async fn set_password(st: &AppState, user_id: &str, hash: String) -> Result<Option<crate::models::User>, ApiError> {
    let uid = user_id.to_string();
    let user = st
        .db
        .call(move |c| {
            let n = c.execute(
                r#"UPDATE "User" SET "passwordHash" = ?1, "mustResetPassword" = 0, "updatedAt" = ?2 WHERE "id" = ?3"#,
                rusqlite::params![hash, now_ms(), uid],
            )?;
            if n == 0 {
                return Ok(None);
            }
            Ok(crate::models::User::find_by_id(c, &uid)?)
        })
        .await?;
    user.map(Some).ok_or_else(|| ApiError::internal("Record to update not found."))
}

async fn must_reset_password(State(st): State<AppState>, ctx: Ctx, body: Body) -> Response {
    guarded!(st, ctx, limited: true, |user| {
        let r: ApiResult = async {
            ensure_auth_enabled(&st.db).await?;
            require_csrf(&ctx)?;
            if user.impersonator_id.is_some() {
                return Err(ApiError::forbidden("Password changes are not allowed while impersonating"));
            }
            let Ok(new_password) = object(&body.0).and_then(|o| password_value(o.get("newPassword"))) else {
                return Err(ApiError::err(400, "Validation error", "Invalid password data"));
            };
            let Some(existing) = find_user(&st, &user.id).await?.filter(|u| u.is_active) else {
                return Err(ApiError::unauthorized("User account not found or inactive"));
            };
            if !existing.must_reset_password {
                return Err(ApiError::err(409, "Conflict", "Password reset is not required for this account"));
            }
            let hash = bcrypt_hash(new_password).await?;
            let updated = set_password(&st, &existing.id, hash).await?.expect("updated user");
            if st.cfg.enable_refresh_token_rotation {
                revoke_refresh_tokens(&st, &updated.id).await;
            }
            let mut res = ok(json!({ "user": user_with_dates_json(&updated) }))?;
            issue_session(&st, &ctx, res.headers_mut(), &updated.id, &updated.email, None).await;
            audit(&st, &ctx, &updated.id, "password_reset_required_completed", None, None).await;
            Ok(res)
        }
        .await;
        catch(r, "Must reset password error:", "Failed to reset password")
    })
}
