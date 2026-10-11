//! middleware/auth.ts (requireAuth / optionalAuth) and auth/authMode.ts.
use serde_json::json;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use super::api_keys::{api_key_hash_matches, extract_api_key_id, is_api_key_token, parse_scopes};
use super::cookies::{ACCESS_TOKEN_COOKIE_NAME, REFRESH_TOKEN_COOKIE_NAME};
use super::jwt::{verify_access_token, JwtPayload};
use crate::config::{config, AuthMode};
use crate::db::Db;
use crate::http::ctx::Ctx;
use crate::http::error::ApiError;
use crate::models::{bootstrap_acting_user, SystemConfig, User, USER_COLS};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialType {
    Jwt,
    ApiKey,
    Bootstrap,
}

/// `req.user`
#[derive(Debug, Clone)]
pub struct AuthUser {
    pub id: String,
    pub username: Option<String>,
    pub email: String,
    pub name: String,
    pub role: String,
    pub must_reset_password: bool,
    pub impersonator_id: Option<String>,
    pub credential: CredentialType,
    /// `req.apiKeyDrawingId`
    pub api_key_drawing_id: Option<String>,
}

impl AuthUser {
    fn from_user(u: &User, credential: CredentialType, impersonator_id: Option<String>) -> AuthUser {
        AuthUser {
            id: u.id.clone(),
            username: u.username.clone(),
            email: u.email.clone(),
            name: u.name.clone(),
            role: u.role.clone(),
            must_reset_password: u.must_reset_password,
            impersonator_id,
            credential,
            api_key_drawing_id: None,
        }
    }
    pub fn is_admin(&self) -> bool {
        self.role == "ADMIN"
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthErrorCode {
    InvalidAccessToken,
    AccessTokenMissing,
}

impl AuthErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            AuthErrorCode::InvalidAccessToken => "INVALID_ACCESS_TOKEN",
            AuthErrorCode::AccessTokenMissing => "ACCESS_TOKEN_MISSING",
        }
    }
}

// ---------------------------------------------------------------------------
// authMode service

static AUTH_ENABLED_CACHE: Mutex<Option<(bool, Instant)>> = Mutex::new(None);
const AUTH_ENABLED_TTL: Duration = Duration::from_millis(5000);

pub fn clear_auth_enabled_cache() {
    *AUTH_ENABLED_CACHE.lock().unwrap() = None;
}

pub async fn get_auth_enabled(db: &Db) -> Result<bool, ApiError> {
    let mode = config().auth_mode;
    if mode != AuthMode::Local {
        let v = mode.enables_auth();
        *AUTH_ENABLED_CACHE.lock().unwrap() = Some((v, Instant::now()));
        return Ok(v);
    }
    if let Some((v, at)) = *AUTH_ENABLED_CACHE.lock().unwrap() {
        if at.elapsed() < AUTH_ENABLED_TTL {
            return Ok(v);
        }
    }
    let sc = db.call(|c| Ok(SystemConfig::ensure(c)?)).await?;
    *AUTH_ENABLED_CACHE.lock().unwrap() = Some((sc.auth_enabled, Instant::now()));
    Ok(sc.auth_enabled)
}

pub async fn ensure_system_config(db: &Db) -> Result<SystemConfig, ApiError> {
    Ok(db.call(|c| Ok(SystemConfig::ensure(c)?)).await?)
}

pub async fn get_bootstrap_acting_user(db: &Db) -> Result<User, ApiError> {
    Ok(db.call(|c| Ok(bootstrap_acting_user(c)?)).await?)
}

// ---------------------------------------------------------------------------
// helpers

enum Extracted {
    Bearer(String),
    Cookie(String),
}

fn extract_token(ctx: &Ctx) -> Option<Extracted> {
    if let Some(h) = ctx.header("authorization") {
        let parts: Vec<&str> = h.split(' ').collect();
        if parts.len() == 2 && parts[0] == "Bearer" {
            return if parts[1].is_empty() { None } else { Some(Extracted::Bearer(parts[1].to_string())) };
        }
    }
    ctx.cookie(ACCESS_TOKEN_COOKIE_NAME).map(Extracted::Cookie)
}

fn is_allowed_while_must_reset(ctx: &Ctx) -> bool {
    let m = ctx.method.as_str();
    let p = ctx.path.as_str();
    (m == "GET" && p == "/auth/me")
        || (m == "POST" && p == "/auth/change-password")
        || (m == "POST" && p == "/auth/must-reset-password")
}

fn api_key_route_resource(ctx: &Ctx) -> Option<&'static str> {
    let segs: Vec<&str> = ctx.path.split('/').filter(|s| !s.is_empty()).collect();
    let m = ctx.method.as_str();
    match segs.first() {
        Some(&"drawings") => {
            if segs.len() == 1 && ["GET", "HEAD", "POST"].contains(&m) {
                return Some("drawings");
            }
            if segs.len() == 2 && segs[1] != "shared" && ["GET", "HEAD", "PUT", "DELETE"].contains(&m) {
                return Some("drawings");
            }
            None
        }
        Some(&"collections") => {
            if segs.len() == 1 && ["GET", "HEAD", "POST"].contains(&m) {
                return Some("collections");
            }
            if segs.len() == 2 && ["PUT", "DELETE"].contains(&m) {
                return Some("collections");
            }
            None
        }
        _ => None,
    }
}

fn required_api_key_scope(ctx: &Ctx) -> Option<String> {
    let resource = api_key_route_resource(ctx)?;
    let access = if matches!(ctx.method.as_str(), "GET" | "HEAD") { "read" } else { "write" };
    Some(format!("{resource}:{access}"))
}

struct ApiKeyAuth {
    user: User,
    scopes: Vec<String>,
    drawing_id: Option<String>,
}

async fn authenticate_api_key(db: &Db, token: String) -> Result<Option<ApiKeyAuth>, ApiError> {
    let Some(key_id) = extract_api_key_id(&token) else { return Ok(None) };
    let found = db
        .call(move |c| {
            use crate::sql::OptionalExtension;
            let row = c
                .query_row(
                    r#"SELECT "id","tokenHash","scopes","drawingId","revokedAt","userId" FROM "ApiKey" WHERE "keyId" = ?1"#,
                    [&key_id],
                    |r| {
                        Ok((
                            r.get::<_, String>(0)?,
                            r.get::<_, String>(1)?,
                            r.get::<_, Option<String>>(2)?,
                            r.get::<_, Option<String>>(3)?,
                            crate::db::opt_dt(r, 4)?,
                            r.get::<_, String>(5)?,
                        ))
                    },
                )
                .optional()?;
            let Some(row) = row else { return Ok(None) };
            let user = User::find_by_id(c, &row.5)?;
            Ok(Some((row, user)))
        })
        .await?;
    let Some(((id, token_hash, scopes, drawing_id, revoked_at, _), user)) = found else { return Ok(None) };
    if revoked_at.is_some() {
        return Ok(None);
    }
    let matches = tokio::task::spawn_blocking(move || api_key_hash_matches(&token, &token_hash))
        .await
        .unwrap_or(false);
    if !matches {
        return Ok(None);
    }
    let Some(user) = user else { return Ok(None) };
    if !user.is_active {
        return Ok(None);
    }
    let now = crate::util::now_ms();
    if let Err(e) = db
        .call(move |c| {
            c.execute(r#"UPDATE "ApiKey" SET "lastUsedAt" = ?1, "updatedAt" = ?1 WHERE "id" = ?2"#, crate::sql::params![now, id])?;
            Ok(())
        })
        .await
    {
        eprintln!("Failed to update API key lastUsedAt: {e}");
    }
    Ok(Some(ApiKeyAuth { user, scopes: parse_scopes(scopes.as_deref()), drawing_id }))
}

async fn should_reconcile_oidc_role(db: &Db, payload: &JwtPayload, user_id: &str) -> Result<bool, ApiError> {
    if config().oidc.admin_groups.is_empty() || payload.impersonator_id.is_some() {
        return Ok(false);
    }
    match payload.auth_provider.as_deref() {
        Some("oidc") => return Ok(true),
        Some("local") => return Ok(false),
        _ => {}
    }
    let uid = user_id.to_string();
    Ok(db
        .call(move |c| {
            Ok(crate::db::exists(
                c,
                r#"SELECT 1 FROM "AuthIdentity" WHERE "provider" = 'oidc' AND "userId" = ?1"#,
                [&uid],
            )?)
        })
        .await?)
}

async fn reconcile_role(db: &Db, payload: &JwtPayload, user: User) -> Result<User, ApiError> {
    if !should_reconcile_oidc_role(db, payload, &user.id).await? {
        return Ok(user);
    }
    let admin_groups = &config().oidc.admin_groups;
    let groups: Vec<String> = payload
        .oidc_groups
        .clone()
        .unwrap_or_default()
        .into_iter()
        .map(|g| g.trim().to_string())
        .filter(|g| !g.is_empty())
        .collect();
    let expected = if groups.iter().any(|g| admin_groups.contains(g)) { "ADMIN" } else { "USER" };
    if user.role == expected {
        return Ok(user);
    }
    let id = user.id.clone();
    let role = expected.to_string();
    Ok(db
        .call(move |c| {
            c.execute(
                r#"UPDATE "User" SET "role" = ?1, "updatedAt" = ?2 WHERE "id" = ?3"#,
                crate::sql::params![role, crate::util::now_ms(), id],
            )?;
            Ok(c.query_row(&format!(r#"SELECT {USER_COLS} FROM "User" WHERE "id" = ?1"#), [&id], User::from_row)?)
        })
        .await?)
}

fn must_reset_error() -> ApiError {
    ApiError::json(
        403,
        json!({
            "error": "Forbidden",
            "code": "MUST_RESET_PASSWORD",
            "message": "You must reset your password before using the app",
        }),
    )
}

// ---------------------------------------------------------------------------
// requireAuth

pub async fn require_auth(db: &Db, ctx: &Ctx) -> Result<AuthUser, ApiError> {
    match get_auth_enabled(db).await {
        Ok(false) => {
            let u = get_bootstrap_acting_user(db).await?;
            return Ok(AuthUser::from_user(&u, CredentialType::Bootstrap, None));
        }
        Ok(true) => {}
        Err(e) => {
            eprintln!("Error reading auth mode: {e:?}");
            return Err(ApiError::err(500, "Internal server error", "Failed to read authentication mode"));
        }
    }
    let Some(extracted) = extract_token(ctx) else {
        return Err(ApiError::unauthorized("Authentication token required"));
    };
    if let Extracted::Bearer(token) = &extracted {
        if is_api_key_token(token) {
            let result = match authenticate_api_key(db, token.clone()).await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("Error verifying API key: {e:?}");
                    return Err(ApiError::err(500, "Internal server error", "Failed to verify API key"));
                }
            };
            let Some(result) = result else {
                return Err(ApiError::unauthorized("Invalid or revoked API key"));
            };
            if result.drawing_id.is_some() {
                return Err(ApiError::forbidden("Drawing-scoped tokens are not supported in this release"));
            }
            let required = required_api_key_scope(ctx);
            if !required.map(|s| result.scopes.contains(&s)).unwrap_or(false) {
                return Err(ApiError::forbidden("API key is not authorized for this route"));
            }
            if result.user.must_reset_password && !is_allowed_while_must_reset(ctx) {
                return Err(must_reset_error());
            }
            let mut u = AuthUser::from_user(&result.user, CredentialType::ApiKey, None);
            u.api_key_drawing_id = result.drawing_id;
            return Ok(u);
        }
    }
    let token = match extracted {
        Extracted::Bearer(t) | Extracted::Cookie(t) => t,
    };
    let Some(payload) = verify_access_token(&token) else {
        return Err(ApiError::unauthorized("Invalid or expired token"));
    };
    let uid = payload.user_id.clone();
    let user = match db.call(move |c| Ok(User::find_by_id(c, &uid)?)).await {
        Ok(u) => u,
        Err(e) => {
            eprintln!("Error verifying user: {e}");
            return Err(ApiError::err(500, "Internal server error", "Failed to verify user"));
        }
    };
    let Some(user) = user.filter(|u| u.is_active) else {
        return Err(ApiError::unauthorized("User account not found or inactive"));
    };
    let user = match reconcile_role(db, &payload, user).await {
        Ok(u) => u,
        Err(e) => {
            eprintln!("Error verifying user: {e:?}");
            return Err(ApiError::err(500, "Internal server error", "Failed to verify user"));
        }
    };
    if user.must_reset_password && !is_allowed_while_must_reset(ctx) {
        return Err(must_reset_error());
    }
    Ok(AuthUser::from_user(&user, CredentialType::Jwt, payload.impersonator_id.clone()))
}

// ---------------------------------------------------------------------------
// optionalAuth

#[derive(Debug, Clone, Default)]
pub struct OptionalAuth {
    pub user: Option<AuthUser>,
    pub auth_error: Option<AuthErrorCode>,
}

pub async fn optional_auth(db: &Db, ctx: &Ctx) -> OptionalAuth {
    match get_auth_enabled(db).await {
        Ok(false) => {
            return match get_bootstrap_acting_user(db).await {
                Ok(u) => OptionalAuth { user: Some(AuthUser::from_user(&u, CredentialType::Bootstrap, None)), auth_error: None },
                Err(_) => OptionalAuth::default(),
            };
        }
        Ok(true) => {}
        Err(e) => {
            eprintln!("Error reading auth mode: {e:?}");
            return OptionalAuth::default();
        }
    }
    let Some(extracted) = extract_token(ctx) else {
        if ctx.cookie(REFRESH_TOKEN_COOKIE_NAME).is_some() {
            return OptionalAuth { user: None, auth_error: Some(AuthErrorCode::AccessTokenMissing) };
        }
        return OptionalAuth::default();
    };
    let invalid = OptionalAuth { user: None, auth_error: Some(AuthErrorCode::InvalidAccessToken) };
    if let Extracted::Bearer(token) = &extracted {
        if is_api_key_token(token) {
            return match authenticate_api_key(db, token.clone()).await {
                Ok(Some(r)) => {
                    if r.drawing_id.is_some() {
                        return invalid;
                    }
                    let required = required_api_key_scope(ctx);
                    if !required.map(|s| r.scopes.contains(&s)).unwrap_or(false) {
                        return invalid;
                    }
                    OptionalAuth { user: Some(AuthUser::from_user(&r.user, CredentialType::ApiKey, None)), auth_error: None }
                }
                Ok(None) => invalid,
                Err(e) => {
                    eprintln!("Error in optional API key auth: {e:?}");
                    invalid
                }
            };
        }
    }
    let token = match extracted {
        Extracted::Bearer(t) | Extracted::Cookie(t) => t,
    };
    let Some(payload) = verify_access_token(&token) else { return invalid };
    let uid = payload.user_id.clone();
    match db.call(move |c| Ok(User::find_by_id(c, &uid)?)).await {
        Ok(Some(u)) if u.is_active => OptionalAuth {
            user: Some(AuthUser::from_user(&u, CredentialType::Jwt, payload.impersonator_id.clone())),
            auth_error: None,
        },
        Ok(_) => OptionalAuth::default(),
        Err(e) => {
            eprintln!("Error in optional auth: {e}");
            OptionalAuth::default()
        }
    }
}
