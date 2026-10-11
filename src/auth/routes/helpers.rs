//! Shared helpers from auth.ts used by the core/admin/account/oidc route modules.
use serde_json::json;
use std::{
    collections::{HashMap, VecDeque},
    sync::Mutex,
};

use crate::auth::middleware::{ensure_system_config, AuthUser};
use crate::config::{config, AuthMode};
use crate::db::Db;
use crate::http::body::Body;
use crate::http::ctx::Ctx;
use crate::http::error::ApiError;
use crate::http::rate_limit::{apply_headers, RateLimitInfo, RateLimiter};
use crate::models::{SystemConfig, User, USER_COLS};

/// ensureAuthEnabled: 404 when authentication is disabled.
pub async fn ensure_auth_enabled(db: &Db) -> Result<(), ApiError> {
    let sc = ensure_system_config(db).await?;
    let enabled = if config().auth_mode != AuthMode::Local { config().auth_mode.enables_auth() } else { sc.auth_enabled };
    if !enabled {
        return Err(ApiError::err(404, "Not found", "Authentication is disabled"));
    }
    Ok(())
}

/// requireCsrf (auth routes validate CSRF themselves; /auth/* skips the global middleware).
pub fn require_csrf(ctx: &Ctx) -> Result<(), ApiError> {
    crate::http::csrf::check(ctx)
}

/// requireAdmin
pub fn require_admin(user: &AuthUser) -> Result<(), ApiError> {
    if user.role != "ADMIN" {
        return Err(ApiError::forbidden("Admin access required"));
    }
    Ok(())
}

/// generateTempPassword: 18 random bytes → base64 without +/= → first 24 chars.
pub fn generate_temp_password() -> String {
    let b64 = crate::util::b64_std(&crate::util::random_bytes(18));
    b64.chars().filter(|c| !matches!(c, '+' | '/' | '=')).take(24).collect()
}

/// findUserByIdentifier
pub fn find_user_by_identifier(c: &crate::sql::Connection, identifier: &str) -> crate::sql::Result<Option<User>> {
    use crate::sql::OptionalExtension;
    let trimmed = crate::security::js_trim(identifier);
    if trimmed.is_empty() {
        return Ok(None);
    }
    if trimmed.contains('@') {
        return User::find_by_email(c, &trimmed.to_lowercase());
    }
    c.query_row(
        &format!(r#"SELECT {USER_COLS} FROM "User" WHERE "username" = ?1 OR "email" = ?2 LIMIT 1"#),
        crate::sql::params![trimmed, trimmed.to_lowercase()],
        User::from_row,
    )
    .optional()
}

pub fn count_active_admins(c: &crate::sql::Connection) -> crate::sql::Result<i64> {
    c.query_row(r#"SELECT COUNT(*) FROM "User" WHERE "role" = 'ADMIN' AND "isActive" = 1"#, [], |r| r.get(0))
}

/// getRefreshTokenExpiresAt (ms since epoch).
pub fn refresh_token_expires_at_ms() -> i64 {
    crate::util::now_ms()
        + crate::util::duration_ms_or(&config().jwt_refresh_expires_in, 7.0 * 24.0 * 60.0 * 60.0 * 1000.0) as i64
}

// ---------------------------------------------------------------------------
// Login attempt rate limiter (configurable via SystemConfig) and account-action limiter.

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LoginRateLimitConfig {
    pub enabled: bool,
    pub window_ms: f64,
    pub max: f64,
}

pub const DEFAULT_LOGIN_RATE_LIMIT: LoginRateLimitConfig =
    LoginRateLimitConfig { enabled: true, window_ms: 15.0 * 60.0 * 1000.0, max: 20.0 };

struct LoginLimiterState {
    config: LoginRateLimitConfig,
    limiter: Option<RateLimiter>,
    identifier_keys: HashMap<String, VecDeque<String>>,
    identifier_order: VecDeque<String>,
}

static LOGIN: Mutex<Option<LoginLimiterState>> = Mutex::new(None);

fn login_message() -> serde_json::Value {
    json!({"error": "Too many requests", "message": "Too many login attempts, please try again later"})
}

pub fn parse_login_rate_limit_config(sc: &SystemConfig) -> LoginRateLimitConfig {
    let window = sc.auth_login_rate_limit_window_ms as f64;
    let max = sc.auth_login_rate_limit_max as f64;
    LoginRateLimitConfig {
        enabled: sc.auth_login_rate_limit_enabled,
        window_ms: if window > 0.0 { window } else { DEFAULT_LOGIN_RATE_LIMIT.window_ms },
        max: if max > 0.0 { max } else { DEFAULT_LOGIN_RATE_LIMIT.max },
    }
}

/// applyLoginRateLimitConfig: rebuild the limiter (resets all counters).
pub fn apply_login_rate_limit_config(cfg: LoginRateLimitConfig) -> LoginRateLimitConfig {
    *LOGIN.lock().unwrap() = Some(LoginLimiterState {
        config: cfg,
        limiter: Some(RateLimiter::new(cfg.window_ms, cfg.max, login_message())),
        identifier_keys: HashMap::new(),
        identifier_order: VecDeque::new(),
    });
    cfg
}

async fn ensure_login_limiter(db: &Db) -> Result<(), ApiError> {
    if LOGIN.lock().unwrap().is_some() {
        return Ok(());
    }
    let sc = ensure_system_config(db).await?;
    let mut g = LOGIN.lock().unwrap();
    if g.is_none() {
        let cfg = parse_login_rate_limit_config(&sc);
        *g = Some(LoginLimiterState {
            config: cfg,
            limiter: Some(RateLimiter::new(cfg.window_ms, cfg.max, login_message())),
            identifier_keys: HashMap::new(),
            identifier_order: VecDeque::new(),
        });
    }
    Ok(())
}

fn resolve_auth_identifier(body: &Body) -> Option<String> {
    let pick = |k: &str| body.str(k).filter(|s| !s.is_empty()).map(str::to_string);
    let raw = pick("email").or_else(|| pick("username")).or_else(|| pick("identifier"))?;
    let t = crate::security::js_trim(&raw).to_lowercase();
    if t.is_empty() { None } else { Some(crate::util::js_slice(&t, 255)) }
}

/// Rate-limit outcome: headers to apply on success, or the 429 response.
pub struct LimitDecision {
    pub info: Option<RateLimitInfo>,
}

impl LimitDecision {
    pub fn apply(&self, headers: &mut axum::http::HeaderMap) {
        if let Some(info) = &self.info {
            apply_headers(headers, info);
        }
    }
}

/// loginAttemptRateLimiter middleware. Err = 429 response.
pub async fn login_attempt_rate_limit(db: &Db, ctx: &Ctx, body: &Body) -> Result<LimitDecision, axum::response::Response> {
    if let Err(e) = ensure_login_limiter(db).await {
        return Err(axum::response::IntoResponse::into_response(e));
    }
    let mut g = LOGIN.lock().unwrap();
    let st = g.as_mut().unwrap();
    if !st.config.enabled {
        return Ok(LimitDecision { info: None });
    }
    let ip = crate::util::js_slice(&ctx.ip, 255);
    let key = match resolve_auth_identifier(body) {
        Some(identifier) => {
            let key = format!("login:{identifier}:ip:{ip}");
            if !st.identifier_keys.contains_key(&identifier) && st.identifier_keys.len() >= 5000 {
                if let Some(oldest) = st.identifier_order.pop_front() {
                    st.identifier_keys.remove(&oldest);
                }
            }
            if !st.identifier_keys.contains_key(&identifier) {
                st.identifier_order.push_back(identifier.clone());
            }
            let keys = st.identifier_keys.entry(identifier).or_default();
            if !keys.contains(&key) {
                if keys.len() >= 50 {
                    keys.pop_front();
                }
                keys.push_back(key.clone());
            }
            key
        }
        None => format!("login-ip:{ip}"),
    };
    let limiter = st.limiter.as_ref().unwrap();
    let info = limiter.hit(&key);
    if info.exceeded {
        return Err(limiter.limited_response(&info));
    }
    Ok(LimitDecision { info: Some(info) })
}

/// resetLoginAttemptKey(identifier)
pub async fn reset_login_attempt_key(db: &Db, identifier: &str) {
    if ensure_login_limiter(db).await.is_err() {
        return;
    }
    let normalized = crate::security::js_trim(identifier).to_lowercase();
    let mut g = LOGIN.lock().unwrap();
    let st = g.as_mut().unwrap();
    let Some(limiter) = st.limiter.as_ref() else { return };
    match st.identifier_keys.remove(&normalized) {
        Some(keys) if !keys.is_empty() => {
            for k in keys {
                limiter.reset_key(&k);
            }
            st.identifier_order.retain(|i| i != &normalized);
        }
        _ => limiter.reset_key(&format!("login:{normalized}")),
    }
}

pub fn current_login_rate_limit_config() -> Option<LoginRateLimitConfig> {
    LOGIN.lock().unwrap().as_ref().map(|s| s.config)
}

fn account_limiter() -> &'static RateLimiter {
    static L: std::sync::OnceLock<RateLimiter> = std::sync::OnceLock::new();
    L.get_or_init(|| {
        RateLimiter::new(
            5.0 * 60.0 * 1000.0,
            60.0,
            json!({"error": "Too many requests", "message": "Too many requests, please try again later"}),
        )
    })
}

/// accountActionRateLimiter (keyed by IP).
pub fn account_action_rate_limit(ctx: &Ctx) -> Result<LimitDecision, axum::response::Response> {
    let limiter = account_limiter();
    let info = limiter.hit(&crate::http::rate_limit::ip_key(&ctx.ip));
    if info.exceeded {
        return Err(limiter.limited_response(&info));
    }
    Ok(LimitDecision { info: Some(info) })
}

// ---------------------------------------------------------------------------
// auth/accessPolicy.ts

pub fn effective_oidc_jit_provisioning(sc: &SystemConfig) -> bool {
    let cfg = config();
    if !cfg.oidc.enabled {
        return false;
    }
    sc.oidc_jit_provisioning_enabled.unwrap_or(cfg.oidc.jit_provisioning)
}

pub fn effective_registration_enabled(registration_enabled: bool) -> bool {
    config().auth_mode != AuthMode::OidcEnforced && registration_enabled
}

/// auth/localPassword.ts canUseLocalPasswordFlows
pub fn can_use_local_password_flows(password_hash: Option<&str>) -> bool {
    password_hash.map(|h| h.starts_with("$2")).unwrap_or(false)
}
