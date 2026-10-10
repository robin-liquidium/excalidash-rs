//! auth/adminRoutes.ts: settings (registration, OIDC JIT, login rate limit),
//! user management, admin password reset and impersonation.
use axum::{
    extract::{Path, State},
    response::Response,
    routing::{get, patch, post},
    Router,
};
use serde_json::{json, Map, Value};

use super::account::common::*;
use super::account::guarded;
use super::helpers::{
    account_action_rate_limit, apply_login_rate_limit_config, count_active_admins, effective_oidc_jit_provisioning,
    ensure_auth_enabled, find_user_by_identifier, generate_temp_password, parse_login_rate_limit_config, require_admin,
    require_csrf, reset_login_attempt_key,
};
use crate::auth::middleware::ensure_system_config;
use crate::auth::{require_auth, AuthUser};
use crate::config::{config, AuthMode};
use crate::http::body::Body;
use crate::http::ctx::Ctx;
use crate::http::error::{ok, status_json, ApiError, ApiResult};
use crate::models::{SystemConfig, User, BOOTSTRAP_USER_ID, DEFAULT_SYSTEM_CONFIG_ID};
use crate::state::AppState;
use crate::util::now_ms;

pub fn router() -> Router<AppState> {
    Router::new()
        // adminSettingsRoutes
        .route("/registration/toggle", post(registration_toggle))
        .route("/oidc/jit-provisioning", post(oidc_jit_toggle))
        .route("/rate-limit/login", get(get_login_rate_limit).put(put_login_rate_limit))
        .route("/rate-limit/login/reset", post(reset_login_rate_limit))
        // adminUserRoutes
        .route("/admins", post(update_admin_role))
        .route("/users", get(list_users).post(create_user))
        .route("/users/{id}", patch(update_user))
        .route("/users/{id}/reset-password", post(reset_user_password))
        // adminImpersonationRoutes
        .route("/impersonation-targets", get(impersonation_targets))
        .route("/impersonate", post(impersonate))
}

fn conflict(message: &str) -> ApiError {
    ApiError::err(409, "Conflict", message)
}

fn bool_num(n: f64) -> Value {
    if n.fract() == 0.0 && n.abs() < 9e15 { json!(n as i64) } else { json!(n) }
}

fn rate_limit_json(cfg: super::helpers::LoginRateLimitConfig) -> Value {
    json!({ "enabled": cfg.enabled, "windowMs": bool_num(cfg.window_ms), "max": bool_num(cfg.max) })
}

/// select { id, username, email, name, role, mustResetPassword, isActive }
fn user_admin_json(u: &User) -> Value {
    json!({
        "id": u.id,
        "username": u.username,
        "email": u.email,
        "name": u.name,
        "role": u.role,
        "mustResetPassword": u.must_reset_password,
        "isActive": u.is_active,
    })
}

/// select { ..., isActive, createdAt, updatedAt }
fn user_full_json(u: &User) -> Value {
    let mut v = user_admin_json(u);
    let m = v.as_object_mut().unwrap();
    m.insert("createdAt".into(), json!(u.created_iso()));
    m.insert("updatedAt".into(), json!(u.updated_iso()));
    v
}

async fn load_user(st: &AppState, id: &str) -> Result<Option<User>, ApiError> {
    let id = id.to_string();
    Ok(st.db.call(move |c| Ok(User::find_by_id(c, &id)?)).await?)
}

async fn load_by_identifier(st: &AppState, identifier: &str) -> Result<Option<User>, ApiError> {
    let ident = identifier.to_string();
    Ok(st.db.call(move |c| Ok(find_user_by_identifier(c, &ident)?)).await?)
}

async fn active_admins(st: &AppState) -> Result<i64, ApiError> {
    Ok(st.db.call(|c| Ok(count_active_admins(c)?)).await?)
}

// ---------------------------------------------------------------------------
// Settings

async fn registration_toggle(State(st): State<AppState>, ctx: Ctx, body: Body) -> Response {
    guarded!(st, ctx, limited: false, |user| {
        let r: ApiResult = async {
            ensure_auth_enabled(&st.db).await?;
            require_csrf(&ctx)?;
            require_admin(&user)?;
            if config().auth_mode == AuthMode::OidcEnforced {
                return Err(conflict(
                    "Local self-sign-up is unavailable in OIDC enforced mode. Use invited users and the OIDC auto-provisioning setting instead.",
                ));
            }
            let Ok(enabled) = object(&body.0).and_then(|o| bool_field(&o, "enabled")) else {
                return Err(ApiError::err(400, "Bad request", "Invalid toggle payload"));
            };
            let sc = upsert_system_config(&st, "registrationEnabled", Some(enabled)).await?;
            ok(json!({ "registrationEnabled": sc.registration_enabled }))
        }
        .await;
        catch(r, "Registration toggle error:", "Failed to update registration setting")
    })
}

/// `systemConfig.upsert({ where: { id: "default" }, update: { col }, create: { id, col } })`
async fn upsert_system_config(st: &AppState, column: &'static str, value: Option<bool>) -> Result<SystemConfig, ApiError> {
    Ok(st
        .db
        .call(move |c| {
            let now = now_ms();
            // Create with schema defaults when missing, then apply the update.
            c.execute(
                r#"INSERT INTO "SystemConfig" ("id","createdAt","updatedAt") VALUES (?1,?2,?2) ON CONFLICT("id") DO NOTHING"#,
                rusqlite::params![DEFAULT_SYSTEM_CONFIG_ID, now],
            )?;
            c.execute(
                &format!(r#"UPDATE "SystemConfig" SET "{column}" = ?1, "updatedAt" = ?2 WHERE "id" = ?3"#),
                rusqlite::params![value, now, DEFAULT_SYSTEM_CONFIG_ID],
            )?;
            Ok(SystemConfig::find(c)?.expect("system config row"))
        })
        .await?)
}

async fn oidc_jit_toggle(State(st): State<AppState>, ctx: Ctx, body: Body) -> Response {
    guarded!(st, ctx, limited: false, |user| {
        let r: ApiResult = async {
            ensure_auth_enabled(&st.db).await?;
            require_csrf(&ctx)?;
            require_admin(&user)?;
            if !config().oidc.enabled {
                return Err(conflict("OIDC is not enabled."));
            }
            let Ok(enabled) = object(&body.0).and_then(|o| bool_field(&o, "enabled")) else {
                return Err(ApiError::err(400, "Bad request", "Invalid OIDC provisioning payload"));
            };
            let sc = upsert_system_config(&st, "oidcJitProvisioningEnabled", Some(enabled)).await?;
            ok(json!({ "oidcJitProvisioningEnabled": effective_oidc_jit_provisioning(&sc) }))
        }
        .await;
        catch(r, "OIDC JIT provisioning toggle error:", "Failed to update OIDC provisioning setting")
    })
}

async fn get_login_rate_limit(State(st): State<AppState>, ctx: Ctx) -> Response {
    guarded!(st, ctx, limited: false, |user| {
        let r: ApiResult = async {
            ensure_auth_enabled(&st.db).await?;
            require_admin(&user)?;
            let sc = ensure_system_config(&st.db).await?;
            ok(json!({ "config": rate_limit_json(parse_login_rate_limit_config(&sc)) }))
        }
        .await;
        catch(r, "Get login rate limit config error:", "Failed to fetch login rate limit config")
    })
}

async fn put_login_rate_limit(State(st): State<AppState>, ctx: Ctx, body: Body) -> Response {
    guarded!(st, ctx, limited: false, |user| {
        let r: ApiResult = async {
            ensure_auth_enabled(&st.db).await?;
            require_csrf(&ctx)?;
            require_admin(&user)?;
            let parsed = object(&body.0).and_then(|o| {
                Ok((
                    bool_field(&o, "enabled")?,
                    int_value(o.get("windowMs").ok_or(Invalid)?, 10_000, 24 * 60 * 60 * 1000)?,
                    int_value(o.get("max").ok_or(Invalid)?, 1, 10_000)?,
                ))
            });
            let Ok((enabled, window_ms, max)) = parsed else {
                return Err(ApiError::err(400, "Validation error", "Invalid rate limit config"));
            };
            let updated = st
                .db
                .call(move |c| {
                    let n = c.execute(
                        r#"UPDATE "SystemConfig" SET "authLoginRateLimitEnabled" = ?1, "authLoginRateLimitWindowMs" = ?2, "authLoginRateLimitMax" = ?3, "updatedAt" = ?4 WHERE "id" = ?5"#,
                        rusqlite::params![enabled, window_ms, max, now_ms(), DEFAULT_SYSTEM_CONFIG_ID],
                    )?;
                    if n == 0 {
                        return Ok(None);
                    }
                    Ok(SystemConfig::find(c)?)
                })
                .await?
                .ok_or_else(|| ApiError::internal("Record to update not found."))?;
            let next = apply_login_rate_limit_config(parse_login_rate_limit_config(&updated));
            let details = rate_limit_json(next).as_object().cloned();
            audit(&st, &ctx, &user.id, "admin_login_rate_limit_updated", Some("system_config".into()), details).await;
            ok(json!({ "config": rate_limit_json(next) }))
        }
        .await;
        catch(r, "Update login rate limit config error:", "Failed to update login rate limit config")
    })
}

async fn reset_login_rate_limit(State(st): State<AppState>, ctx: Ctx, body: Body) -> Response {
    guarded!(st, ctx, limited: false, |user| {
        let r: ApiResult = async {
            ensure_auth_enabled(&st.db).await?;
            require_csrf(&ctx)?;
            require_admin(&user)?;
            let Ok(identifier) = object(&body.0).and_then(|o| trimmed(&o, "identifier", 1, 255)) else {
                return Err(ApiError::err(400, "Validation error", "Invalid reset payload"));
            };
            let identifier = crate::security::js_trim(&identifier).to_lowercase();
            reset_login_attempt_key(&st.db, &identifier).await;
            let mut details = Map::new();
            details.insert("identifier".into(), json!(identifier));
            audit(&st, &ctx, &user.id, "admin_login_rate_limit_reset", Some(format!("rate_limit:login:{identifier}")), Some(details))
                .await;
            ok(json!({ "ok": true }))
        }
        .await;
        catch(r, "Reset login rate limit error:", "Failed to reset login rate limit")
    })
}

// ---------------------------------------------------------------------------
// Users

async fn update_admin_role(State(st): State<AppState>, ctx: Ctx, body: Body) -> Response {
    guarded!(st, ctx, limited: false, |user| {
        let r: ApiResult = async {
            ensure_auth_enabled(&st.db).await?;
            require_csrf(&ctx)?;
            require_admin(&user)?;
            let parsed = object(&body.0).and_then(|o| {
                Ok((trimmed(&o, "identifier", 1, 255)?, opt_enum(&o, "role", &["ADMIN", "USER"])?.ok_or(Invalid)?))
            });
            let Ok((identifier, role)) = parsed else {
                return Err(ApiError::err(400, "Bad request", "Invalid admin update payload"));
            };
            let Some(target) = load_by_identifier(&st, &identifier).await? else {
                return Err(ApiError::not_found("User not found"));
            };
            if target.id == BOOTSTRAP_USER_ID && role != "ADMIN" {
                return Err(conflict("The bootstrap account must remain an admin"));
            }
            if target.id == user.id && role != "ADMIN" {
                return Err(conflict("You cannot change your own role from ADMIN"));
            }
            if target.role == "ADMIN" && role != "ADMIN" && target.is_active && active_admins(&st).await? <= 1 {
                return Err(conflict("There must be at least one active admin"));
            }
            let id = target.id.clone();
            let updated = st
                .db
                .call(move |c| {
                    c.execute(
                        r#"UPDATE "User" SET "role" = ?1, "updatedAt" = ?2 WHERE "id" = ?3"#,
                        rusqlite::params![role, now_ms(), id],
                    )?;
                    Ok(User::find_by_id(c, &id)?)
                })
                .await?
                .ok_or_else(|| ApiError::internal("Record to update not found."))?;
            ok(json!({ "user": user_admin_json(&updated) }))
        }
        .await;
        catch(r, "Admin role update error:", "Failed to update user role")
    })
}

async fn list_users(State(st): State<AppState>, ctx: Ctx) -> Response {
    guarded!(st, ctx, limited: false, |user| {
        let r: ApiResult = async {
            ensure_auth_enabled(&st.db).await?;
            require_admin(&user)?;
            let users = st
                .db
                .call(|c| {
                    let mut s = c.prepare(&format!(
                        r#"SELECT {} FROM "User" ORDER BY "createdAt" ASC"#,
                        crate::models::USER_COLS
                    ))?;
                    let rows = s.query_map([], User::from_row)?.collect::<Result<Vec<_>, _>>()?;
                    Ok(rows.iter().map(user_full_json).collect::<Vec<_>>())
                })
                .await?;
            ok(json!({ "users": users }))
        }
        .await;
        catch(r, "List users error:", "Failed to list users")
    })
}

struct CreateUser {
    username: Option<String>,
    email: String,
    password: Option<String>,
    oidc_only: Option<bool>,
    name: String,
    role: Option<String>,
    must_reset_password: Option<bool>,
    is_active: Option<bool>,
}

fn parse_create_user(body: &Body) -> V<CreateUser> {
    let o = object(&body.0)?;
    let username = opt_trimmed(&o, "username", 3, 50)?;
    let email = email(&o, "email")?;
    let password = match o.get("password") {
        None => None,
        v => Some(password_value(v)?),
    };
    let oidc_only = opt_bool(&o, "oidcOnly")?;
    let name = trimmed(&o, "name", 1, 100)?;
    let role = opt_enum(&o, "role", &["ADMIN", "USER"])?;
    let must_reset_password = opt_bool(&o, "mustResetPassword")?;
    let is_active = opt_bool(&o, "isActive")?;
    if !oidc_only.unwrap_or(false) && password.as_deref().unwrap_or("").is_empty() {
        return Err(Invalid);
    }
    Ok(CreateUser { username, email, password, oidc_only, name, role, must_reset_password, is_active })
}

async fn create_user(State(st): State<AppState>, ctx: Ctx, body: Body) -> Response {
    guarded!(st, ctx, limited: true, |user| {
        let r: ApiResult = async {
            ensure_auth_enabled(&st.db).await?;
            require_csrf(&ctx)?;
            require_admin(&user)?;
            let Ok(data) = parse_create_user(&body) else {
                return Err(ApiError::err(400, "Validation error", "Invalid user payload"));
            };
            let (email, username) = (data.email.clone(), data.username.clone());
            let (email_taken, username_taken) = st
                .db
                .call(move |c| {
                    let e = User::find_by_email(c, &email)?.is_some();
                    let u = match &username {
                        Some(u) if !u.is_empty() => {
                            crate::db::exists(c, r#"SELECT 1 FROM "User" WHERE "username" = ?1"#, [u])?
                        }
                        _ => false,
                    };
                    Ok((e, u))
                })
                .await?;
            if email_taken {
                return Err(conflict("User with this email already exists"));
            }
            if username_taken {
                return Err(conflict("User with this username already exists"));
            }
            let oidc_only = data.oidc_only.unwrap_or(false);
            if oidc_only && !config().oidc.enabled {
                return Err(conflict("OIDC-only invited users require OIDC to be enabled."));
            }
            let password_hash = match (&data.password, oidc_only) {
                (Some(p), false) if !p.is_empty() => bcrypt_hash(p.clone()).await?,
                _ => String::new(),
            };
            let name = crate::security::sanitize_text(&data.name, 100);
            let role = data.role.clone().unwrap_or_else(|| "USER".into());
            let must_reset = if oidc_only { false } else { data.must_reset_password.unwrap_or(false) };
            let is_active = data.is_active.unwrap_or(true);
            let (email, username) = (data.email.clone(), data.username.clone());
            let created = st
                .db
                .call(move |c| {
                    let id = crate::util::uuid_v4();
                    let now = now_ms();
                    c.execute(
                        r#"INSERT INTO "User" ("id","username","email","passwordHash","name","role","mustResetPassword","isActive","preferences","createdAt","updatedAt")
                           VALUES (?1,?2,?3,?4,?5,?6,?7,?8,NULL,?9,?9)"#,
                        rusqlite::params![id, username, email, password_hash, name, role, must_reset, is_active, now],
                    )?;
                    Ok(User::find_by_id(c, &id)?.expect("created user"))
                })
                .await?;
            let mut details = Map::new();
            details.insert("createdUserId".into(), json!(created.id));
            audit(&st, &ctx, &user.id, "admin_user_created", Some(format!("user:{}", created.id)), Some(details)).await;
            status_json(201, json!({ "user": user_full_json(&created) }))
        }
        .await;
        catch(r, "Create user error:", "Failed to create user")
    })
}

async fn update_user(State(st): State<AppState>, ctx: Ctx, Path(id): Path<String>, body: Body) -> Response {
    guarded!(st, ctx, limited: false, |user| {
        let r: ApiResult = async {
            ensure_auth_enabled(&st.db).await?;
            require_csrf(&ctx)?;
            require_admin(&user)?;
            let user_id = crate::security::js_trim(&id).to_string();
            if user_id.is_empty() {
                return Err(ApiError::err(400, "Bad request", "Invalid user id"));
            }
            let parsed = object(&body.0).and_then(|o| {
                let username = match o.get("username") {
                    Some(Value::Null) => Some(None),
                    _ => opt_trimmed(&o, "username", 3, 50)?.map(Some),
                };
                Ok((
                    username,
                    opt_trimmed(&o, "name", 1, 100)?,
                    opt_enum(&o, "role", &["ADMIN", "USER"])?,
                    opt_bool(&o, "mustResetPassword")?,
                    opt_bool(&o, "isActive")?,
                ))
            });
            let Ok((username, name, role, must_reset, is_active)) = parsed else {
                return Err(ApiError::err(400, "Bad request", "Invalid update payload"));
            };
            if user_id == user.id && is_active == Some(false) {
                return Err(conflict("You cannot deactivate your own account"));
            }
            if user_id == user.id && role.as_deref().is_some_and(|r| r != "ADMIN") {
                return Err(conflict("You cannot change your own role from ADMIN"));
            }
            let Some(current) = load_user(&st, &user_id).await? else {
                return Err(ApiError::not_found("User not found"));
            };
            let next_role = role.clone().unwrap_or_else(|| current.role.clone());
            if current.id == BOOTSTRAP_USER_ID && next_role != "ADMIN" {
                return Err(conflict("The bootstrap account must remain an admin"));
            }
            let next_active = is_active.unwrap_or(current.is_active);
            let removing_admin = current.role == "ADMIN" && current.is_active && (next_role != "ADMIN" || !next_active);
            if removing_admin && active_admins(&st).await? <= 1 {
                return Err(conflict("There must be at least one active admin"));
            }
            let mut sets: Vec<(&'static str, rusqlite::types::Value)> = vec![];
            use rusqlite::types::Value as Sql;
            if let Some(u) = username {
                sets.push(("username", u.map(Sql::Text).unwrap_or(Sql::Null)));
            }
            if let Some(n) = name {
                sets.push(("name", Sql::Text(crate::security::sanitize_text(&n, 100))));
            }
            if let Some(r) = role {
                sets.push(("role", Sql::Text(r)));
            }
            if let Some(m) = must_reset {
                sets.push(("mustResetPassword", Sql::Integer(m as i64)));
            }
            if let Some(a) = is_active {
                sets.push(("isActive", Sql::Integer(a as i64)));
            }
            let fields: Vec<Value> = sets.iter().map(|(k, _)| json!(k)).collect();
            let uid = current.id.clone();
            let result = st
                .db
                .call(move |c| {
                    // Prisma skips the write (and @updatedAt) when `data` is empty.
                    if !sets.is_empty() {
                        let cols: Vec<String> = sets.iter().enumerate().map(|(i, (k, _))| format!(r#""{k}" = ?{}"#, i + 1)).collect();
                        let n = sets.len();
                        let sql = format!(
                            r#"UPDATE "User" SET {}, "updatedAt" = ?{} WHERE "id" = ?{}"#,
                            cols.join(", "),
                            n + 1,
                            n + 2
                        );
                        let mut params: Vec<rusqlite::types::Value> = sets.into_iter().map(|(_, v)| v).collect();
                        params.push(Sql::Integer(now_ms()));
                        params.push(Sql::Text(uid.clone()));
                        if let Err(e) = c.execute(&sql, rusqlite::params_from_iter(params)) {
                            if let rusqlite::Error::SqliteFailure(f, _) = &e {
                                if f.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE {
                                    return Ok(Err(()));
                                }
                            }
                            return Err(e.into());
                        }
                    }
                    Ok(Ok(User::find_by_id(c, &uid)?))
                })
                .await?;
            let updated = match result {
                Err(()) => return Err(conflict("User with this username already exists")),
                Ok(u) => u.ok_or_else(|| ApiError::internal("Record to update not found."))?,
            };
            let mut details = Map::new();
            details.insert("updatedUserId".into(), json!(updated.id));
            details.insert("fields".into(), Value::Array(fields));
            audit(&st, &ctx, &user.id, "admin_user_updated", Some(format!("user:{}", updated.id)), Some(details)).await;
            ok(json!({ "user": user_full_json(&updated) }))
        }
        .await;
        catch(r, "Update user error:", "Failed to update user")
    })
}

async fn reset_user_password(State(st): State<AppState>, ctx: Ctx, Path(id): Path<String>) -> Response {
    guarded!(st, ctx, limited: true, |user| {
        let r: ApiResult = async {
            ensure_auth_enabled(&st.db).await?;
            require_csrf(&ctx)?;
            require_admin(&user)?;
            if user.impersonator_id.is_some() {
                return Err(ApiError::forbidden("Password resets are not allowed while impersonating"));
            }
            let user_id = crate::security::js_trim(&id).to_string();
            if user_id.is_empty() {
                return Err(ApiError::err(400, "Bad request", "Invalid user id"));
            }
            if user_id == user.id {
                return Err(conflict("Use Profile -> Change Password for your own account"));
            }
            let Some(target) = load_user(&st, &user_id).await? else {
                return Err(ApiError::not_found("User not found"));
            };
            let temp_password = generate_temp_password();
            let hash = bcrypt_hash(temp_password.clone()).await?;
            let tid = target.id.clone();
            st.db
                .call(move |c| {
                    c.execute(
                        r#"UPDATE "User" SET "passwordHash" = ?1, "mustResetPassword" = 1, "isActive" = 1, "updatedAt" = ?2 WHERE "id" = ?3"#,
                        rusqlite::params![hash, now_ms(), tid],
                    )?;
                    Ok(())
                })
                .await?;
            revoke_refresh_tokens(&st, &target.id).await;
            reset_login_attempt_key(&st.db, &target.email.to_lowercase()).await;
            let mut details = Map::new();
            details.insert("targetUserId".into(), json!(target.id));
            details.insert("targetEmail".into(), json!(target.email));
            audit(&st, &ctx, &user.id, "admin_password_reset_generated", Some(format!("user:{}", target.id)), Some(details)).await;
            ok(json!({
                "user": { "id": target.id, "email": target.email, "username": target.username, "role": target.role },
                "tempPassword": temp_password,
            }))
        }
        .await;
        catch(r, "Reset password error:", "Failed to reset password")
    })
}

// ---------------------------------------------------------------------------
// Impersonation

struct ActingAdmin {
    id: String,
    email: String,
    name: String,
}

/// resolveImpersonationAdmin: the admin itself, or the active admin behind an impersonation.
async fn resolve_impersonation_admin(st: &AppState, user: &AuthUser) -> Result<ActingAdmin, ApiError> {
    if user.role == "ADMIN" {
        return Ok(ActingAdmin { id: user.id.clone(), email: user.email.clone(), name: user.name.clone() });
    }
    let Some(imp_id) = &user.impersonator_id else {
        return Err(ApiError::forbidden("Admin access required"));
    };
    match load_user(st, imp_id).await? {
        Some(u) if u.is_active && u.role == "ADMIN" => Ok(ActingAdmin { id: u.id, email: u.email, name: u.name }),
        _ => Err(ApiError::forbidden("Admin access required")),
    }
}

async fn impersonation_targets(State(st): State<AppState>, ctx: Ctx) -> Response {
    guarded!(st, ctx, limited: false, |user| {
        let r: ApiResult = async {
            ensure_auth_enabled(&st.db).await?;
            let acting = resolve_impersonation_admin(&st, &user).await?;
            let aid = acting.id.clone();
            let users = st
                .db
                .call(move |c| {
                    let mut s = c.prepare(&format!(
                        r#"SELECT {} FROM "User" WHERE "isActive" = 1 AND "id" <> ?1 ORDER BY "name" ASC, "email" ASC"#,
                        crate::models::USER_COLS
                    ))?;
                    let rows = s.query_map([&aid], User::from_row)?.collect::<Result<Vec<_>, _>>()?;
                    Ok(rows
                        .iter()
                        .map(|u| {
                            json!({
                                "id": u.id, "username": u.username, "email": u.email,
                                "name": u.name, "role": u.role, "isActive": u.is_active,
                            })
                        })
                        .collect::<Vec<_>>())
                })
                .await?;
            ok(json!({
                "users": users,
                "impersonator": { "id": acting.id, "email": acting.email, "name": acting.name },
            }))
        }
        .await;
        catch(r, "List impersonation targets error:", "Failed to list impersonation targets")
    })
}

async fn impersonate(State(st): State<AppState>, ctx: Ctx, body: Body) -> Response {
    guarded!(st, ctx, limited: true, |user| {
        let r: ApiResult = async {
            ensure_auth_enabled(&st.db).await?;
            require_csrf(&ctx)?;
            let acting = resolve_impersonation_admin(&st, &user).await?;
            let parsed = object(&body.0).and_then(|o| {
                let user_id = opt_trimmed(&o, "userId", 1, usize::MAX)?;
                let identifier = opt_trimmed(&o, "identifier", 1, usize::MAX)?;
                if user_id.is_none() && identifier.is_none() {
                    return Err(Invalid);
                }
                Ok((user_id, identifier))
            });
            let Ok((user_id, identifier)) = parsed else {
                return Err(ApiError::err(400, "Bad request", "Invalid impersonation payload"));
            };
            let target = match user_id {
                Some(id) => load_user(&st, &id).await?,
                None => load_by_identifier(&st, identifier.as_deref().unwrap_or("")).await?,
            };
            let Some(target) = target else {
                return Err(ApiError::not_found("User not found"));
            };
            if target.id == acting.id {
                return Err(conflict("Already using the admin account. Use stop impersonation to return."));
            }
            if !target.is_active {
                return Err(ApiError::forbidden("Target user is inactive"));
            }
            let mut res = ok(json!({ "user": target.public_json() }))?;
            issue_session(&st, &ctx, res.headers_mut(), &target.id, &target.email, Some(acting.id.clone())).await;
            let mut details = Map::new();
            details.insert("targetUserId".into(), json!(target.id));
            details.insert("initiatedFromImpersonation".into(), json!(user.impersonator_id.is_some()));
            audit(&st, &ctx, &acting.id, "impersonation_started", Some(format!("user:{}", target.id)), Some(details)).await;
            Ok(res)
        }
        .await;
        catch(r, "Impersonation error:", "Failed to impersonate user")
    })
}
