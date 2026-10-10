//! auth/cookies.ts — Express `res.cookie` / `res.clearCookie` formatting.
use axum::http::{header, HeaderMap, HeaderValue};

use crate::config::config;
use crate::http::ctx::Ctx;
use crate::util;

pub const ACCESS_TOKEN_COOKIE_NAME: &str = "excalidash-access-token";
pub const REFRESH_TOKEN_COOKIE_NAME: &str = "excalidash-refresh-token";

const DEFAULT_ACCESS_TTL_MS: f64 = 15.0 * 60.0 * 1000.0;
const DEFAULT_REFRESH_TTL_MS: f64 = 7.0 * 24.0 * 60.0 * 60.0 * 1000.0;

pub fn access_max_age_ms() -> f64 {
    util::duration_ms_or(&config().jwt_access_expires_in, DEFAULT_ACCESS_TTL_MS)
}
pub fn refresh_max_age_ms() -> f64 {
    util::duration_ms_or(&config().jwt_refresh_expires_in, DEFAULT_REFRESH_TTL_MS)
}

fn http_date(ms: i64) -> String {
    use chrono::TimeZone;
    chrono::Utc
        .timestamp_millis_opt(ms)
        .single()
        .map(|d| d.format("%a, %d %b %Y %H:%M:%S GMT").to_string())
        .unwrap_or_default()
}

fn encode_component(v: &str) -> String {
    // encodeURIComponent
    const SET: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
        .remove(b'-')
        .remove(b'_')
        .remove(b'.')
        .remove(b'!')
        .remove(b'~')
        .remove(b'*')
        .remove(b'\'')
        .remove(b'(')
        .remove(b')');
    percent_encoding::utf8_percent_encode(v, SET).to_string()
}

/// Express `res.cookie(name, value, { httpOnly, secure, sameSite: "lax", path: "/", maxAge })`.
pub fn serialize_cookie(name: &str, value: &str, max_age_ms: f64, secure: bool) -> String {
    let expires = util::now_ms() + max_age_ms as i64;
    let mut s = format!(
        "{name}={}; Max-Age={}; Path=/; Expires={}; HttpOnly",
        encode_component(value),
        (max_age_ms / 1000.0).floor() as i64,
        http_date(expires)
    );
    if secure {
        s.push_str("; Secure");
    }
    s.push_str("; SameSite=Lax");
    s
}

/// Express 5 `res.clearCookie(name, { httpOnly, secure, sameSite: "lax", path: "/" })`.
pub fn serialize_clear_cookie(name: &str, secure: bool) -> String {
    let mut s = format!("{name}=; Path=/; Expires={}; HttpOnly", http_date(1));
    if secure {
        s.push_str("; Secure");
    }
    s.push_str("; SameSite=Lax");
    s
}

fn append(headers: &mut HeaderMap, v: String) {
    if let Ok(v) = HeaderValue::from_str(&v) {
        headers.append(header::SET_COOKIE, v);
    }
}

pub fn set_auth_cookies(ctx: &Ctx, headers: &mut HeaderMap, access: &str, refresh: &str) {
    append(headers, serialize_cookie(ACCESS_TOKEN_COOKIE_NAME, access, access_max_age_ms(), ctx.secure));
    append(headers, serialize_cookie(REFRESH_TOKEN_COOKIE_NAME, refresh, refresh_max_age_ms(), ctx.secure));
}

pub fn set_access_token_cookie(ctx: &Ctx, headers: &mut HeaderMap, access: &str) {
    append(headers, serialize_cookie(ACCESS_TOKEN_COOKIE_NAME, access, access_max_age_ms(), ctx.secure));
}

pub fn clear_auth_cookies(ctx: &Ctx, headers: &mut HeaderMap) {
    append(headers, serialize_clear_cookie(ACCESS_TOKEN_COOKIE_NAME, ctx.secure));
    append(headers, serialize_clear_cookie(REFRESH_TOKEN_COOKIE_NAME, ctx.secure));
}

pub fn read_refresh_token(ctx: &Ctx) -> Option<String> {
    ctx.cookie(REFRESH_TOKEN_COOKIE_NAME)
}
