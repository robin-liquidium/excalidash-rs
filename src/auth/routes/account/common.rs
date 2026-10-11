//! Helpers shared by the account and admin routes: zod-equivalent field
//! validation, bcrypt, session issuing, refresh-token revocation, try/catch.
use axum::{
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use serde_json::{Map, Value};
use std::sync::OnceLock;

use crate::auth::routes::helpers::LimitDecision;
use crate::config::config;
use crate::http::ctx::Ctx;
use crate::http::error::{ApiError, ApiResult};
use crate::state::AppState;
use crate::util;

pub type Obj = Map<String, Value>;

/// Validation failure marker (the route decides the response body).
#[derive(Debug)]
pub struct Invalid;
pub type V<T> = Result<T, Invalid>;

/// `z.object(...)` input: must be a plain object.
pub fn object(body: &Option<Value>) -> V<Obj> {
    match body {
        Some(Value::Object(m)) => Ok(m.clone()),
        _ => Err(Invalid),
    }
}

/// `z.string().trim().min(min).max(max).optional()`
pub fn opt_trimmed(o: &Obj, key: &str, min: usize, max: usize) -> V<Option<String>> {
    match o.get(key) {
        None => Ok(None),
        Some(Value::String(s)) => {
            let t = crate::security::js_trim(s).to_string();
            let n = util::js_len(&t);
            if n < min || n > max { Err(Invalid) } else { Ok(Some(t)) }
        }
        Some(_) => Err(Invalid),
    }
}

/// `z.string().trim().min(min).max(max)`
pub fn trimmed(o: &Obj, key: &str, min: usize, max: usize) -> V<String> {
    opt_trimmed(o, key, min, max)?.ok_or(Invalid)
}

/// `z.string()` (+ optional min/max on the raw value).
pub fn raw_string(o: &Obj, key: &str, min: usize, max: usize) -> V<String> {
    match o.get(key) {
        Some(Value::String(s)) => {
            let n = util::js_len(s);
            if n < min || n > max { Err(Invalid) } else { Ok(s.clone()) }
        }
        _ => Err(Invalid),
    }
}

fn email_regex() -> &'static regex::Regex {
    static R: OnceLock<regex::Regex> = OnceLock::new();
    // zod 4 `regexes.email` minus its two lookaheads (checked separately).
    R.get_or_init(|| {
        regex::Regex::new(r"^([A-Za-z0-9_'+\-\.]*)[A-Za-z0-9_+-]@([A-Za-z0-9][A-Za-z0-9\-]*\.)+[A-Za-z]{2,}$").unwrap()
    })
}

pub fn is_zod_email(s: &str) -> bool {
    !s.starts_with('.') && !s.contains("..") && email_regex().is_match(s)
}

/// `z.string().email().toLowerCase().trim()` (the email check sees the raw value).
pub fn email(o: &Obj, key: &str) -> V<String> {
    match o.get(key) {
        Some(Value::String(s)) if is_zod_email(s) => Ok(crate::security::js_trim(&s.to_lowercase()).to_string()),
        _ => Err(Invalid),
    }
}

/// `z.boolean().optional()`
pub fn opt_bool(o: &Obj, key: &str) -> V<Option<bool>> {
    match o.get(key) {
        None => Ok(None),
        Some(Value::Bool(b)) => Ok(Some(*b)),
        Some(_) => Err(Invalid),
    }
}

/// `z.boolean()`
pub fn bool_field(o: &Obj, key: &str) -> V<bool> {
    opt_bool(o, key)?.ok_or(Invalid)
}

/// `z.enum([...]).optional()`
pub fn opt_enum(o: &Obj, key: &str, allowed: &[&str]) -> V<Option<String>> {
    match o.get(key) {
        None => Ok(None),
        Some(Value::String(s)) if allowed.contains(&s.as_str()) => Ok(Some(s.clone())),
        Some(_) => Err(Invalid),
    }
}

/// `z.number().int().min(min).max(max)` → integer value.
pub fn int_value(v: &Value, min: i64, max: i64) -> V<i64> {
    let n = v.as_f64().ok_or(Invalid)?;
    if !n.is_finite() || n.fract() != 0.0 || n.abs() > 9_007_199_254_740_991.0 {
        return Err(Invalid);
    }
    let n = n as i64;
    if n < min || n > max { Err(Invalid) } else { Ok(n) }
}

/// The policy-checked `passwordSchema`.
pub fn password_value(v: Option<&Value>) -> V<String> {
    match v {
        Some(Value::String(s)) => {
            match crate::config::validate_password_against_policy(s, &config().password_policy) {
                None => Ok(s.clone()),
                Some(_) => Err(Invalid),
            }
        }
        _ => Err(Invalid),
    }
}

// ---------------------------------------------------------------------------
// bcrypt (node `bcrypt` compatible: $2b$, 72-byte truncation)

pub async fn bcrypt_hash(password: String) -> Result<String, ApiError> {
    tokio::task::spawn_blocking(move || bcrypt::hash(password, 10))
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?
        .map_err(|e| ApiError::internal(e.to_string()))
}

pub async fn bcrypt_verify(password: String, hash: String) -> bool {
    tokio::task::spawn_blocking(move || bcrypt::verify(password, &hash).unwrap_or(false)).await.unwrap_or(false)
}

/// auth/localPassword.ts canUseLocalPasswordFlows
pub fn can_use_local_password(hash: &str) -> bool {
    crate::auth::routes::helpers::can_use_local_password_flows(Some(hash))
}

// ---------------------------------------------------------------------------
// Sessions / refresh tokens

/// `refreshToken.updateMany({ where: { userId, revoked: false }, data: { revoked: true } })`
/// inside the upstream try/catch (errors are swallowed).
pub async fn revoke_refresh_tokens(st: &AppState, user_id: &str) {
    let uid = user_id.to_string();
    let r = st
        .db
        .call(move |c| {
            c.execute(r#"UPDATE "RefreshToken" SET "revoked" = 1 WHERE "userId" = ?1 AND "revoked" = 0"#, [&uid])?;
            Ok(())
        })
        .await;
    if r.is_err() && config().is_dev {
        eprintln!("Refresh token revocation skipped (feature disabled or table missing)");
    }
}

/// generateTokens + setAuthCookies + (rotation) refreshToken.create.
pub async fn issue_session(
    st: &AppState,
    ctx: &Ctx,
    headers: &mut HeaderMap,
    user_id: &str,
    email: &str,
    impersonator_id: Option<String>,
) {
    let (access, refresh) = crate::auth::jwt::generate_tokens(
        user_id,
        email,
        crate::auth::jwt::TokenOptions { impersonator_id, ..Default::default() },
    );
    crate::auth::cookies::set_auth_cookies(ctx, headers, &access, &refresh);
    if config().enable_refresh_token_rotation {
        let uid = user_id.to_string();
        let token = util::sha256_hex(refresh.as_bytes());
        let expires = crate::auth::routes::helpers::refresh_token_expires_at_ms();
        let r = st
            .db
            .call(move |c| {
                c.execute(
                    r#"INSERT INTO "RefreshToken" ("id","userId","token","expiresAt","revoked","createdAt") VALUES (?1,?2,?3,?4,0,?5)"#,
                    crate::sql::params![util::uuid_v4(), uid, token, expires, util::now_ms()],
                )?;
                Ok(())
            })
            .await;
        if r.is_err() && config().is_dev {
            eprintln!("Refresh token storage skipped (feature disabled or table missing)");
        }
    }
}

// ---------------------------------------------------------------------------
// Response plumbing

/// The route's try/catch: thrown errors become the route-specific 500 body.
pub fn catch(r: ApiResult, log: &str, message: &str) -> ApiResult {
    match r {
        Err(ApiError::Thrown { message: m, .. }) => {
            eprintln!("{log} {m}");
            Err(ApiError::err(500, "Internal server error", message))
        }
        other => other,
    }
}

/// Apply a rate-limiter decision's headers to whatever the handler produced.
pub fn finish(decision: Option<LimitDecision>, r: ApiResult) -> Response {
    let mut res = match r {
        Ok(r) => r,
        Err(e) => e.into_response(),
    };
    if let Some(d) = decision {
        d.apply(res.headers_mut());
    }
    res
}

/// `req.ip || req.connection.remoteAddress`
pub fn ip_of(ctx: &Ctx) -> Option<String> {
    Some(ctx.ip.clone()).filter(|s| !s.is_empty()).or_else(|| Some(ctx.remote_addr.clone()))
}

pub fn ua_of(ctx: &Ctx) -> Option<String> {
    ctx.user_agent().map(str::to_string)
}

/// logAuditEvent with the request's ip/user agent (no-op unless ENABLE_AUDIT_LOGGING).
pub async fn audit(st: &AppState, ctx: &Ctx, user_id: &str, action: &str, resource: Option<String>, details: Option<Obj>) {
    if !config().enable_audit_logging {
        return;
    }
    crate::audit::log_audit_event(
        &st.db,
        crate::audit::AuditEvent {
            user_id: Some(user_id.to_string()),
            action: action.to_string(),
            resource,
            ip_address: ip_of(ctx),
            user_agent: ua_of(ctx),
            details,
        },
    )
    .await;
}

/// ISO string or null for an optional ms timestamp.
pub fn opt_iso(ms: Option<i64>) -> Value {
    ms.map(|m| Value::String(util::iso_from_ms(m))).unwrap_or(Value::Null)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zod_email_matches_zod4() {
        for (e, ok) in [
            ("A@B.CO", true),
            ("a@b.c", false),
            ("a..b@x.io", false),
            (".a@x.io", false),
            ("a.@x.io", false),
            ("a@x-.io", true),
            ("o'r@x.io", true),
            ("a@b.co ", false),
            ("ä@x.io", false),
        ] {
            assert_eq!(is_zod_email(e), ok, "{e}");
        }
    }

    #[test]
    fn int_value_rules() {
        assert_eq!(int_value(&serde_json::json!(5.0), 1, 100).unwrap(), 5);
        assert!(int_value(&serde_json::json!(5.5), 1, 100).is_err());
        assert!(int_value(&serde_json::json!(0), 1, 100).is_err());
        assert!(int_value(&serde_json::json!("5"), 1, 100).is_err());
        assert!(int_value(&serde_json::json!(1e300), 0, i64::MAX).is_err());
    }
}
