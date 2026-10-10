//! CSRF tokens (security.ts), client ids (security/csrfClient.ts) and the
//! /csrf-token route + middleware (server/csrf.ts).
use axum::{
    http::{header, HeaderValue},
    response::Response,
};
use hmac::{Hmac, KeyInit, Mac};
use serde_json::json;
use sha2::Sha256;
use std::{
    collections::HashMap,
    sync::{Mutex, OnceLock},
};

use super::ctx::{parse_cookie_header, Ctx};
use super::error::{json_response, ApiError};
use crate::config::config;
use crate::util;

pub const CSRF_TOKEN_HEADER: &str = "x-csrf-token";
pub const CSRF_CLIENT_COOKIE_NAME: &str = "excalidash-csrf-client";
const CSRF_TOKEN_EXPIRY_MS: f64 = 24.0 * 60.0 * 60.0 * 1000.0;
const CSRF_TOKEN_FUTURE_SKEW_MS: f64 = 5.0 * 60.0 * 1000.0;
const CSRF_TOKEN_MAX_LENGTH: usize = 2048;
const CSRF_CLIENT_COOKIE_MAX_AGE_SECONDS: u64 = 60 * 60 * 24 * 30;

fn csrf_secret() -> &'static [u8] {
    static SECRET: OnceLock<Vec<u8>> = OnceLock::new();
    SECRET.get_or_init(|| match config().csrf_secret.as_deref() {
        Some(s) if !s.trim().is_empty() => s.as_bytes().to_vec(),
        _ => {
            eprintln!(
                "[SECURITY WARNING] CSRF_SECRET is not set ({}).\nUsing an ephemeral per-process secret.\n  - Tokens will expire on container restart\n  - Horizontal scaling (k8s) will NOT work\n  - Generate a secret: openssl rand -base64 32\n  - Set environment variable: CSRF_SECRET=<generated-secret>",
                config().node_env
            );
            util::random_bytes(32)
        }
    })
}

fn sign(client_id: &str, ts: &str, nonce: &str) -> Vec<u8> {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(csrf_secret()).expect("hmac key");
    mac.update(format!("{client_id}|{ts}|{nonce}").as_bytes());
    mac.finalize().into_bytes().to_vec()
}

pub fn create_csrf_token(client_id: &str) -> String {
    let ts = util::now_ms();
    let nonce = util::b64url(&util::random_bytes(16));
    let payload = format!("{{\"ts\":{ts},\"nonce\":{}}}", serde_json::to_string(&nonce).unwrap());
    let sig = sign(client_id, &ts.to_string(), &nonce);
    format!("{}.{}", util::b64url(payload.as_bytes()), util::b64url(&sig))
}

pub fn validate_csrf_token(client_id: &str, token: &str) -> bool {
    if token.is_empty() || util::js_len(token) > CSRF_TOKEN_MAX_LENGTH {
        return false;
    }
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 2 {
        return false;
    }
    let payload_bytes = util::b64_decode_lenient(parts[0]);
    let Ok(payload) = serde_json::from_slice::<serde_json::Value>(&String::from_utf8_lossy(&payload_bytes).as_bytes())
    else {
        return false;
    };
    let Some(ts) = payload.get("ts").and_then(|v| v.as_f64()) else { return false };
    let Some(nonce) = payload.get("nonce").and_then(|v| v.as_str()) else { return false };
    if !ts.is_finite() || util::js_len(nonce) < 8 {
        return false;
    }
    let now = util::now_ms() as f64;
    if now - ts > CSRF_TOKEN_EXPIRY_MS || ts - now > CSRF_TOKEN_FUTURE_SKEW_MS {
        return false;
    }
    let ts_str = match payload.get("ts") {
        Some(serde_json::Value::Number(n)) if n.is_i64() || n.is_u64() => n.to_string(),
        _ => util::js_num_str(ts),
    };
    let expected = sign(client_id, &ts_str, nonce);
    let provided = util::b64_decode_lenient(parts[1]);
    util::constant_time_eq(&provided, &expected)
}

pub fn get_origin_from_referer(referer: &str) -> Option<String> {
    if referer.trim().is_empty() {
        return None;
    }
    let url = url::Url::parse(referer).ok()?;
    if url.scheme() != "http" && url.scheme() != "https" {
        return None;
    }
    let host = url.host_str()?;
    let host = match url.port() {
        Some(p) => format!("{host}:{p}"),
        None => host.to_string(),
    };
    Some(format!("{}://{}", url.scheme(), host))
}

fn csrf_client_cookie_value(ctx: &Ctx) -> Option<String> {
    let v = parse_cookie_header(ctx.header("cookie")).remove(CSRF_CLIENT_COOKIE_NAME)?;
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    let re = RE.get_or_init(|| regex::Regex::new(r"^[A-Za-z0-9_-]{16,128}$").unwrap());
    re.is_match(&v).then_some(v)
}

fn legacy_client_id(ctx: &Ctx) -> String {
    let ua = ctx.user_agent().unwrap_or("unknown");
    util::js_slice(&format!("{}:{}", ctx.ip, ua), 256)
}

pub fn validation_client_ids(ctx: &Ctx) -> Vec<String> {
    let mut out = vec![];
    if let Some(v) = csrf_client_cookie_value(ctx) {
        out.push(format!("cookie:{v}"));
    }
    let legacy = legacy_client_id(ctx);
    if !out.contains(&legacy) {
        out.push(legacy);
    }
    out
}

/// auth/apiKeys.ts isNonBrowserApiKeyBearerRequest
pub fn is_non_browser_api_key_bearer(ctx: &Ctx) -> bool {
    if !crate::auth::api_keys::has_bearer_api_key(ctx.header("authorization")) {
        return false;
    }
    ctx.header("origin").is_none() && ctx.header("referer").is_none()
}

/// Shared check used by the global middleware and by auth routes' `requireCsrf`.
pub fn check(ctx: &Ctx) -> Result<(), ApiError> {
    if is_non_browser_api_key_bearer(ctx) {
        return Ok(());
    }
    let cfg = config();
    if let Some(origin) = ctx.header("origin") {
        if !cfg.is_allowed_origin(Some(origin)) {
            return Err(ApiError::err(403, "CSRF origin mismatch", "Origin not allowed"));
        }
    } else if let Some(referer) = ctx.header("referer") {
        let ok = get_origin_from_referer(referer).map(|o| cfg.is_allowed_origin(Some(&o))).unwrap_or(false);
        if !ok {
            return Err(ApiError::err(403, "CSRF referer mismatch", "Referer not allowed"));
        }
    }
    let Some(token) = ctx.header(CSRF_TOKEN_HEADER).filter(|t| !t.is_empty()) else {
        return Err(ApiError::err(403, "CSRF token missing", &format!("Missing {CSRF_TOKEN_HEADER} header")));
    };
    if !validation_client_ids(ctx).iter().any(|id| validate_csrf_token(id, token)) {
        return Err(ApiError::err(
            403,
            "CSRF token invalid",
            "Invalid or expired CSRF token. Please refresh and try again.",
        ));
    }
    Ok(())
}

/// Global middleware part: skip safe methods and `/auth/*`.
pub fn middleware_check(ctx: &Ctx) -> Result<(), ApiError> {
    if matches!(ctx.method.as_str(), "GET" | "HEAD" | "OPTIONS") {
        return Ok(());
    }
    if ctx.path.starts_with("/auth/") {
        return Ok(());
    }
    check(ctx)
}

struct IssueLimit {
    count: f64,
    reset_ms: i64,
}

fn issue_limits() -> &'static Mutex<(HashMap<String, IssueLimit>, u64)> {
    static M: OnceLock<Mutex<(HashMap<String, IssueLimit>, u64)>> = OnceLock::new();
    M.get_or_init(|| Mutex::new((HashMap::new(), 0)))
}

/// GET /csrf-token
pub fn issue_token(ctx: &Ctx) -> Response {
    let cfg = config();
    let now = util::now_ms();
    {
        let mut guard = issue_limits().lock().unwrap();
        let (map, counter) = &mut *guard;
        let ip = ctx.ip.clone();
        match map.get_mut(&ip) {
            Some(l) if now < l.reset_ms => {
                if l.count >= cfg.csrf_max_requests {
                    return json_response(
                        axum::http::StatusCode::TOO_MANY_REQUESTS,
                        &json!({"error": "Rate limit exceeded", "message": "Too many CSRF token requests"}),
                    );
                }
                l.count += 1.0;
            }
            _ => {
                map.insert(ip, IssueLimit { count: 1.0, reset_ms: now + cfg.csrf_rate_limit_window_ms as i64 });
            }
        }
        *counter += 1;
        if *counter % 100 == 0 {
            map.retain(|_, l| now <= l.reset_ms);
        }
    }
    let mut set_cookie = None;
    let client_id = match csrf_client_cookie_value(ctx) {
        Some(v) => format!("cookie:{v}"),
        None => {
            let generated = util::random_hex_uuid();
            let secure = if ctx.secure { "; Secure" } else { "" };
            set_cookie = Some(format!(
                "{CSRF_CLIENT_COOKIE_NAME}={}; Path=/; HttpOnly; SameSite=Lax; Max-Age={CSRF_CLIENT_COOKIE_MAX_AGE_SECONDS}{secure}",
                generated
            ));
            format!("cookie:{generated}")
        }
    };
    if cfg.debug_csrf {
        println!(
            "[CSRF DEBUG] getClientId {{ method: '{}', path: '{}', ip: '{}', hasCsrfCookie: {}, strategy: 'cookie' }}",
            ctx.method,
            ctx.path,
            ctx.ip,
            csrf_client_cookie_value(ctx).is_some()
        );
    }
    let token = create_csrf_token(&client_id);
    let mut res = json_response(axum::http::StatusCode::OK, &json!({ "token": token, "header": CSRF_TOKEN_HEADER }));
    if let Some(c) = set_cookie {
        if let Ok(v) = HeaderValue::from_str(&c) {
            res.headers_mut().append(header::SET_COOKIE, v);
        }
    }
    res
}
