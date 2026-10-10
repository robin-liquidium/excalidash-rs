//! OpenID Connect login: auth/oidcRoutes.ts, oidcCallbackRoute.ts and
//! oidcRouteHelpers.ts. The protocol side lives in `crate::auth::oidc_client`.
use axum::{
    body::Body as AxumBody,
    extract::State,
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use hmac::{Hmac, KeyInit, Mac};
use rusqlite::OptionalExtension;
use serde_json::{json, Map, Value};
use sha2::Sha256;

use crate::auth::cookies::{serialize_clear_cookie, serialize_cookie, set_auth_cookies};
use crate::auth::jwt::{generate_tokens, TokenOptions};
use crate::auth::oidc_client::{self, Checks, OidcError};
use crate::auth::routes::helpers;
use crate::config::config;
use crate::db::DbError;
use crate::http::ctx::Ctx;
use crate::http::error::ApiError;
use crate::models::{SystemConfig, User, USER_COLS};
use crate::state::AppState;
use crate::util;

pub const OIDC_FLOW_COOKIE_NAME: &str = "excalidash-oidc-flow";
pub const OIDC_PROVIDER_KEY: &str = "oidc";
pub const OIDC_FLOW_TTL_MS: i64 = 10 * 60 * 1000;

pub fn router() -> Router<AppState> {
    if !config().oidc.enabled {
        return Router::new();
    }
    Router::new().route("/oidc/start", get(start)).route("/oidc/callback", get(callback))
}

// ---------------------------------------------------------------------------
// oidcRouteHelpers.ts

#[derive(Debug, Clone, PartialEq)]
pub struct FlowPayload {
    pub state: String,
    pub nonce: String,
    pub code_verifier: String,
    pub return_to: String,
    pub expires_at: f64,
}

/// requestUsesHttps: req.secure, or a first-hop `X-Forwarded-Proto: https` (regardless of trust proxy).
fn request_uses_https(ctx: &Ctx) -> bool {
    if ctx.secure {
        return true;
    }
    let first = ctx
        .headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .split(',')
        .next()
        .unwrap_or("");
    crate::security::js_trim(first).to_lowercase() == "https"
}

pub fn normalize_email(value: &str) -> String {
    crate::security::js_trim(value).to_lowercase()
}

/// sanitizeReturnTo
pub fn sanitize_return_to(raw: Option<&Value>) -> String {
    let Some(Value::String(raw)) = raw else { return "/".into() };
    let value = crate::security::js_trim(raw);
    if !value.starts_with('/') || value.starts_with("//") || value.contains(['\r', '\n']) || util::js_len(value) > 2048 {
        return "/".into();
    }
    value.to_string()
}

fn sign_flow_payload(encoded: &str, secret: &str) -> String {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(secret.as_bytes()).expect("hmac key");
    mac.update(encoded.as_bytes());
    util::b64url(&mac.finalize().into_bytes())
}

/// encodeFlowPayload
pub fn encode_flow_payload(p: &FlowPayload, secret: &str) -> String {
    let body = json!({
        "state": p.state,
        "nonce": p.nonce,
        "codeVerifier": p.code_verifier,
        "returnTo": p.return_to,
        "expiresAt": p.expires_at as i64,
    });
    let encoded = util::b64url(body.to_string().as_bytes());
    let sig = sign_flow_payload(&encoded, secret);
    format!("{encoded}.{sig}")
}

/// decodeFlowPayload
pub fn decode_flow_payload(cookie: Option<&str>, secret: &str) -> Option<FlowPayload> {
    let cookie = cookie.filter(|c| !c.is_empty())?;
    let mut parts = cookie.split('.');
    let encoded = parts.next().filter(|s| !s.is_empty())?;
    let provided = parts.next().filter(|s| !s.is_empty())?;
    let expected = sign_flow_payload(encoded, secret);
    if !util::constant_time_eq(expected.as_bytes(), provided.as_bytes()) {
        return None;
    }
    let bytes = util::b64_decode_lenient(encoded);
    let parsed: Value = serde_json::from_str(&String::from_utf8_lossy(&bytes)).ok()?;
    let s = |k: &str| parsed.get(k).and_then(|v| v.as_str()).map(str::to_string);
    let (state, nonce, code_verifier, return_to) = (s("state")?, s("nonce")?, s("codeVerifier")?, s("returnTo")?);
    let expires_at = parsed.get("expiresAt").and_then(|v| v.as_f64())?;
    if (util::now_ms() as f64) > expires_at {
        return None;
    }
    Some(FlowPayload {
        state,
        nonce,
        code_verifier,
        return_to: sanitize_return_to(Some(&Value::String(return_to))),
        expires_at,
    })
}

/// readStringClaim
pub fn read_string_claim(claims: &Map<String, Value>, key: &str) -> Option<String> {
    let Some(Value::String(v)) = claims.get(key) else { return None };
    let t = crate::security::js_trim(v);
    (!t.is_empty()).then(|| t.to_string())
}

/// readBooleanClaim
pub fn read_boolean_claim(claims: &Map<String, Value>, key: &str) -> Option<bool> {
    match claims.get(key) {
        Some(Value::Bool(b)) => Some(*b),
        Some(Value::String(s)) => match crate::security::js_trim(s).to_lowercase().as_str() {
            "true" | "1" => Some(true),
            "false" | "0" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

/// readClaimByPath (dotted paths; arrays index like JS property access).
pub fn read_claim_by_path(claims: &Map<String, Value>, key_path: &str) -> Option<Value> {
    let segments: Vec<&str> = key_path.split('.').map(crate::security::js_trim).filter(|s| !s.is_empty()).collect();
    if segments.is_empty() {
        return None;
    }
    let mut current = Value::Object(claims.clone());
    for seg in segments {
        current = match &current {
            Value::Object(m) => m.get(seg)?.clone(),
            Value::Array(a) => {
                if seg == "length" {
                    Value::from(a.len())
                } else if seg == "0" || (!seg.starts_with('0') && seg.chars().all(|c| c.is_ascii_digit())) {
                    a.get(seg.parse::<usize>().ok()?)?.clone()
                } else {
                    return None;
                }
            }
            _ => return None,
        };
    }
    Some(current)
}

/// normalizeClaimGroups
pub fn normalize_claim_groups(value: Option<&Value>) -> Vec<String> {
    let trim = |s: &str| crate::security::js_trim(s).to_string();
    match value {
        Some(Value::Array(a)) => a.iter().filter_map(|v| v.as_str()).map(trim).filter(|s| !s.is_empty()).collect(),
        Some(Value::String(s)) => s.split(',').map(trim).filter(|s| !s.is_empty()).collect(),
        _ => vec![],
    }
}

/// getOidcErrorMessage
pub fn oidc_error_message(code: &str) -> &'static str {
    match code {
        "missing_flow" => "Missing or expired OIDC login flow. Please try again.",
        "provider_error" => "OIDC provider returned an error.",
        "missing_subject" => "OIDC response is missing required subject claim.",
        "missing_email" => "OIDC response is missing required email claim.",
        "unverified_email" => "OIDC account email is not verified.",
        "account_inactive" => "Your account is inactive.",
        "provisioning_disabled" => {
            "No account found. Ask an admin to create your account or enable OIDC auto-provisioning."
        }
        "callback_failed" => "OIDC callback validation failed.",
        _ => "OIDC sign-in failed.",
    }
}

// ---------------------------------------------------------------------------
// Express res.redirect

/// encodeurl
fn encode_url(url: &str) -> String {
    let bytes = url.as_bytes();
    let mut out = String::with_capacity(url.len());
    let allowed = |c: char| {
        matches!(c, '\x21' | '\x23'..='\x3B' | '\x3D' | '\x3F'..='\x5F' | '\x61'..='\x7A' | '\x7C' | '\x7E')
    };
    for (i, c) in url.char_indices() {
        if c == '%' {
            let hex = |j: usize| bytes.get(j).map(|b| b.is_ascii_hexdigit()).unwrap_or(false);
            if hex(i + 1) && hex(i + 2) {
                out.push('%');
            } else {
                out.push_str("%25");
            }
        } else if allowed(c) {
            out.push(c);
        } else {
            let mut buf = [0u8; 4];
            for b in c.encode_utf8(&mut buf).bytes() {
                out.push_str(&format!("%{b:02X}"));
            }
        }
    }
    out
}

/// req.accepts(["text", "html"]) via `negotiator`.
fn negotiate_redirect_format(accept: Option<&str>) -> Option<&'static str> {
    let accept = match accept {
        Some(a) if !a.trim().is_empty() => a,
        _ => return Some("text"),
    };
    struct Spec {
        ty: String,
        sub: String,
        params: Vec<(String, String)>,
        q: f64,
        i: usize,
    }
    let specs: Vec<Spec> = accept
        .split(',')
        .enumerate()
        .filter_map(|(i, raw)| {
            let mut parts = raw.split(';');
            let full = parts.next()?.trim();
            let (ty, sub) = full.split_once('/')?;
            let mut q = 1.0;
            let mut params = vec![];
            for p in parts {
                let (k, v) = p.split_once('=')?;
                let k = k.trim().to_lowercase();
                let v = v.trim().trim_matches('"').to_string();
                if k == "q" {
                    q = v.parse().unwrap_or(0.0);
                } else {
                    params.push((k, v));
                }
            }
            Some(Spec { ty: ty.trim().to_string(), sub: sub.trim().to_string(), params, q, i })
        })
        .collect();
    let candidates = [("text", "text", "plain"), ("html", "text", "html")];
    let mut ranked: Vec<(f64, i32, i64, usize, &'static str)> = vec![];
    for (idx, (name, ty, sub)) in candidates.iter().enumerate() {
        let mut best: (i32, f64, i64) = (0, 0.0, -1);
        for spec in &specs {
            let mut s = 0;
            if spec.ty.to_lowercase() == *ty {
                s |= 4;
            } else if spec.ty != "*" {
                continue;
            }
            if spec.sub.to_lowercase() == *sub {
                s |= 2;
            } else if spec.sub != "*" {
                continue;
            }
            if !spec.params.is_empty() {
                if spec.params.iter().all(|(_, v)| v == "*" || v.is_empty()) {
                    s |= 1;
                } else {
                    continue;
                }
            }
            let cand = (s, spec.q, spec.i as i64);
            let diff = if best.0 != cand.0 {
                (best.0 - cand.0) as f64
            } else if best.1 != cand.1 {
                best.1 - cand.1
            } else {
                (best.2 - cand.2) as f64
            };
            if diff < 0.0 {
                best = cand;
            }
        }
        if best.1 > 0.0 {
            ranked.push((best.1, best.0, best.2, idx, name));
        }
    }
    ranked.sort_by(|a, b| {
        b.0.partial_cmp(&a.0)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(b.1.cmp(&a.1))
            .then(a.2.cmp(&b.2))
            .then(a.3.cmp(&b.3))
    });
    ranked.first().map(|r| r.4)
}

/// res.redirect(url) (302) carrying the cookies collected in `headers`.
fn express_redirect(ctx: &Ctx, url: &str, headers: HeaderMap) -> Response {
    let address = encode_url(url);
    let (content_type, body) = match negotiate_redirect_format(ctx.header("accept")) {
        Some("text") => (Some("text/plain; charset=utf-8"), format!("Found. Redirecting to {address}")),
        Some(_) => (
            Some("text/html; charset=utf-8"),
            format!("<p>Found. Redirecting to {}</p>", crate::http::error::escape_html(&address)),
        ),
        None => (None, String::new()),
    };
    let len = body.len();
    let mut res = Response::new(AxumBody::from(body));
    *res.status_mut() = StatusCode::FOUND;
    let h = res.headers_mut();
    h.extend(headers);
    if let Ok(v) = HeaderValue::from_str(&address) {
        h.insert(header::LOCATION, v);
    }
    h.insert(header::VARY, HeaderValue::from_static("Accept"));
    if let Some(ct) = content_type {
        h.insert(header::CONTENT_TYPE, HeaderValue::from_static(ct));
    }
    h.insert(header::CONTENT_LENGTH, HeaderValue::from(len));
    res
}

fn append_cookie(headers: &mut HeaderMap, cookie: String) {
    if let Ok(v) = HeaderValue::from_str(&cookie) {
        headers.append(header::SET_COOKIE, v);
    }
}

fn clear_flow_cookie(ctx: &Ctx, headers: &mut HeaderMap) {
    append_cookie(headers, serialize_clear_cookie(OIDC_FLOW_COOKIE_NAME, request_uses_https(ctx)));
}

/// redirectToLoginWithError
fn redirect_to_login_with_error(ctx: &Ctx, mut headers: HeaderMap, code: &str, return_to: Option<&str>) -> Response {
    let mut search = url::form_urlencoded::Serializer::new(String::new());
    search.append_pair("oidcError", code);
    search.append_pair("oidcErrorMessage", oidc_error_message(code));
    if let Some(r) = return_to.filter(|r| !r.is_empty()) {
        search.append_pair("returnTo", &sanitize_return_to(Some(&Value::String(r.to_string()))));
    }
    clear_flow_cookie(ctx, &mut headers);
    express_redirect(ctx, &format!("/login?{}", search.finish()), headers)
}

fn with_headers(resp: impl IntoResponse, headers: HeaderMap) -> Response {
    let mut r = resp.into_response();
    for (k, v) in headers.iter() {
        r.headers_mut().append(k.clone(), v.clone());
    }
    r
}

// ---------------------------------------------------------------------------
// GET /oidc/start

async fn start(State(st): State<AppState>, ctx: Ctx) -> Response {
    let mut headers = HeaderMap::new();
    let result: Result<Response, String> = async {
        match helpers::ensure_auth_enabled(&st.db).await {
            Ok(()) => {}
            Err(e @ ApiError::Json(..)) => return Ok(e.into_response()),
            Err(e) => return Err(format!("{e:?}")),
        }
        let client = oidc_client::get_client().await.map_err(|e| e.to_string())?;
        let state = oidc_client::random();
        let nonce = oidc_client::random();
        let code_verifier = oidc_client::random();
        let challenge = oidc_client::code_challenge(&code_verifier);
        let query = ctx.query.as_deref().map(crate::http::body::parse_query_values).unwrap_or_default();
        let return_to = sanitize_return_to(query.get("returnTo"));
        let payload = FlowPayload {
            state: state.clone(),
            nonce: nonce.clone(),
            code_verifier,
            return_to,
            expires_at: (util::now_ms() + OIDC_FLOW_TTL_MS) as f64,
        };
        append_cookie(
            &mut headers,
            serialize_cookie(
                OIDC_FLOW_COOKIE_NAME,
                &encode_flow_payload(&payload, &config().jwt_secret),
                OIDC_FLOW_TTL_MS as f64,
                request_uses_https(&ctx),
            ),
        );
        let url = client
            .authorization_url(&[
                ("scope", &config().oidc.scopes),
                ("response_type", "code"),
                ("state", &state),
                ("nonce", &nonce),
                ("code_challenge", &challenge),
                ("code_challenge_method", "S256"),
            ])
            .map_err(|e| e.to_string())?;
        Ok(express_redirect(&ctx, &url, std::mem::take(&mut headers)))
    }
    .await;
    match result {
        Ok(r) => r,
        Err(e) => {
            eprintln!("OIDC start error: {e}");
            redirect_to_login_with_error(&ctx, headers, "callback_failed", None)
        }
    }
}

// ---------------------------------------------------------------------------
// GET /oidc/callback

/// The callback's own cookie parser: first `excalidash-oidc-flow` wins.
fn read_flow_cookie(ctx: &Ctx) -> Option<String> {
    let header = ctx.header("cookie")?;
    for part in header.split(';') {
        let mut it = part.split('=');
        let key = it.next().unwrap_or("");
        let rest: Vec<&str> = it.collect();
        if key.is_empty() || rest.is_empty() {
            continue;
        }
        if crate::security::js_trim(key) != OIDC_FLOW_COOKIE_NAME {
            continue;
        }
        let raw = crate::security::js_trim(&rest.join("=")).to_string();
        return Some(
            percent_encoding::percent_decode_str(&raw)
                .decode_utf8()
                .map(|v| v.into_owned())
                .unwrap_or(raw),
        );
    }
    None
}

enum Fail {
    /// redirectToLoginWithError(code) without a log line.
    Code(&'static str),
    /// Thrown error: logged, then callback_failed (or provisioning_disabled).
    Thrown(String),
    /// A response that was sent directly (ensureAuthEnabled 404).
    Sent(Response),
}

impl From<OidcError> for Fail {
    fn from(e: OidcError) -> Self {
        Fail::Thrown(e.to_string())
    }
}

enum TxOutcome {
    User(User),
    ProvisioningDisabled,
}

async fn callback(State(st): State<AppState>, ctx: Ctx) -> Response {
    let cookie = read_flow_cookie(&ctx);
    let flow = decode_flow_payload(cookie.as_deref(), &config().jwt_secret);
    let mut headers = HeaderMap::new();
    clear_flow_cookie(&ctx, &mut headers);
    let Some(flow) = flow else {
        return redirect_to_login_with_error(&ctx, headers, "missing_flow", None);
    };
    match run_callback(&st, &ctx, &flow, &mut headers).await {
        Ok(r) => r,
        Err(Fail::Sent(r)) => with_headers(r, headers),
        Err(Fail::Code(code)) => redirect_to_login_with_error(&ctx, headers, code, Some(&flow.return_to)),
        Err(Fail::Thrown(e)) => {
            eprintln!("OIDC callback error: {e}");
            redirect_to_login_with_error(&ctx, headers, "callback_failed", Some(&flow.return_to))
        }
    }
}

async fn run_callback(st: &AppState, ctx: &Ctx, flow: &FlowPayload, headers: &mut HeaderMap) -> Result<Response, Fail> {
    let cfg = config();
    match helpers::ensure_auth_enabled(&st.db).await {
        Ok(()) => {}
        Err(e @ ApiError::Json(..)) => return Err(Fail::Sent(e.into_response())),
        Err(e) => return Err(Fail::Thrown(format!("{e:?}"))),
    }
    let query = ctx.query.as_deref().map(crate::http::body::parse_query_values).unwrap_or_default();
    if matches!(query.get("error"), Some(Value::String(_))) {
        return Err(Fail::Code("provider_error"));
    }
    let client = oidc_client::get_client().await?;
    let checks = Checks { state: flow.state.clone(), nonce: flow.nonce.clone(), code_verifier: flow.code_verifier.clone() };
    let token_set = match client.callback(&query, &checks).await {
        Ok(ts) => ts,
        Err(error) => {
            let mismatch = oidc_client::parse_jwt_alg_mismatch_error(&error.message);
            let can_retry = cfg.oidc.id_token_signed_response_alg.is_none()
                && mismatch
                    .as_ref()
                    .map(|(_, got)| oidc_client::can_use_id_token_signing_alg(got, cfg.oidc.client_secret.is_some()))
                    .unwrap_or(false);
            let Some((expected, got)) = mismatch.filter(|_| can_retry) else { return Err(error.into()) };
            eprintln!("OIDC callback id_token alg mismatch (expected {expected}, got {got}); retrying once with {got}.");
            let retry = oidc_client::build_client(Some(&got)).await?;
            retry.callback(&query, &checks).await?
        }
    };
    let id_token_claims = oidc_client::token_set_claims(&token_set)?;
    let mut userinfo_claims = Map::new();
    let email_missing = read_string_claim(&id_token_claims, &cfg.oidc.email_claim).is_none()
        && read_string_claim(&id_token_claims, "email").is_none();
    if email_missing {
        match client.userinfo(&token_set).await {
            Ok(m) => userinfo_claims = m,
            Err(e) => eprintln!("OIDC: userinfo request failed, falling back to ID token claims only: {e}"),
        }
    }
    let mut claims = userinfo_claims;
    for (k, v) in &id_token_claims {
        claims.insert(k.clone(), v.clone());
    }
    let issuer = client.issuer.clone();
    let Some(subject) = read_string_claim(&claims, "sub") else { return Err(Fail::Code("missing_subject")) };
    let Some(raw_email) = read_string_claim(&claims, &cfg.oidc.email_claim).or_else(|| read_string_claim(&claims, "email")) else {
        return Err(Fail::Code("missing_email"));
    };
    let normalized_email = normalize_email(&raw_email);
    let system_config = st.db.call(|c| Ok(SystemConfig::ensure(c)?)).await.map_err(|e| Fail::Thrown(e.to_string()))?;
    let jit = helpers::effective_oidc_jit_provisioning(&system_config);
    // Email verification is trusted only from the signed ID token.
    let email_verified = read_boolean_claim(&id_token_claims, &cfg.oidc.email_verified_claim);
    if cfg.oidc.require_email_verified && email_verified != Some(true) {
        return Err(Fail::Code("unverified_email"));
    }
    let mut oidc_groups: Vec<String> = vec![];
    for g in normalize_claim_groups(read_claim_by_path(&claims, &cfg.oidc.groups_claim).as_ref()) {
        if !oidc_groups.contains(&g) {
            oidc_groups.push(g);
        }
    }
    let admin_groups = cfg.oidc.admin_groups.clone();
    let should_be_admin = !admin_groups.is_empty() && oidc_groups.iter().any(|g| admin_groups.contains(g));
    let Some(issuer) = issuer else { return Err(Fail::Thrown("OIDC issuer is not a string".into())) };

    let default_name = read_string_claim(&claims, "name")
        .or_else(|| read_string_claim(&claims, "preferred_username"))
        .unwrap_or_else(|| normalized_email.split('@').next().unwrap_or("").to_string());
    let sanitized_name = {
        let n = crate::security::sanitize_text(&default_name, 100);
        if n.is_empty() { "User".to_string() } else { n }
    };
    let tx_issuer = issuer.clone();
    let tx_email = normalized_email.clone();
    let first_user_admin = cfg.oidc.first_user_admin;
    let outcome = st
        .db
        .tx(move |tx| {
            let now = util::now_ms();
            let linked: Option<(String, String)> = tx
                .query_row(
                    r#"SELECT "id","userId" FROM "AuthIdentity" WHERE "issuer" = ?1 AND "subject" = ?2"#,
                    rusqlite::params![tx_issuer, subject],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            if let Some((identity_id, user_id)) = linked {
                tx.execute(
                    r#"UPDATE "AuthIdentity" SET "lastLoginAt" = ?1, "emailAtLink" = ?2, "updatedAt" = ?1 WHERE "id" = ?3"#,
                    rusqlite::params![now, tx_email, identity_id],
                )?;
                let user = User::find_by_id(tx, &user_id)?.ok_or_else(|| DbError::from(rusqlite::Error::QueryReturnedNoRows))?;
                return Ok(TxOutcome::User(user));
            }
            let existing = User::find_by_email(tx, &tx_email)?;
            if let Some(u) = &existing {
                if !u.is_active {
                    return Ok(TxOutcome::User(u.clone()));
                }
            }
            let mut resolved = match existing {
                Some(u) => u,
                None => {
                    if !jit {
                        return Ok(TxOutcome::ProvisioningDisabled);
                    }
                    let active: i64 = tx.query_row(r#"SELECT COUNT(*) FROM "User" WHERE "isActive" = 1"#, [], |r| r.get(0))?;
                    let role = if active == 0 && first_user_admin { "ADMIN" } else { "USER" };
                    let id = util::uuid_v4();
                    tx.execute(
                        r#"INSERT INTO "User" ("id","username","email","passwordHash","name","role","mustResetPassword","isActive","createdAt","updatedAt")
                           VALUES (?1, NULL, ?2, '', ?3, ?4, 0, 1, ?5, ?5)"#,
                        rusqlite::params![id, tx_email, sanitized_name, role, now],
                    )?;
                    crate::trash::ensure_trash_collection(tx, &id)?;
                    User::find_by_id(tx, &id)?.ok_or_else(|| DbError::from(rusqlite::Error::QueryReturnedNoRows))?
                }
            };
            let provider_identity: Option<String> = tx
                .query_row(
                    r#"SELECT "id" FROM "AuthIdentity" WHERE "provider" = ?1 AND "userId" = ?2"#,
                    rusqlite::params![OIDC_PROVIDER_KEY, resolved.id],
                    |r| r.get(0),
                )
                .optional()?;
            match provider_identity {
                Some(identity_id) => {
                    tx.execute(
                        r#"UPDATE "AuthIdentity" SET "issuer" = ?1, "subject" = ?2, "emailAtLink" = ?3, "lastLoginAt" = ?4, "updatedAt" = ?4 WHERE "id" = ?5"#,
                        rusqlite::params![tx_issuer, subject, tx_email, now, identity_id],
                    )?;
                }
                None => {
                    tx.execute(
                        r#"INSERT INTO "AuthIdentity" ("id","userId","provider","issuer","subject","emailAtLink","lastLoginAt","createdAt","updatedAt")
                           VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7, ?7)"#,
                        rusqlite::params![util::uuid_v4(), resolved.id, OIDC_PROVIDER_KEY, tx_issuer, subject, tx_email, now],
                    )?;
                }
            }
            if !admin_groups.is_empty() {
                let next = if should_be_admin { "ADMIN" } else { "USER" };
                if resolved.role != next {
                    tx.execute(
                        r#"UPDATE "User" SET "role" = ?1, "updatedAt" = ?2 WHERE "id" = ?3"#,
                        rusqlite::params![next, now, resolved.id],
                    )?;
                    resolved = tx.query_row(
                        &format!(r#"SELECT {USER_COLS} FROM "User" WHERE "id" = ?1"#),
                        [&resolved.id],
                        User::from_row,
                    )?;
                }
            }
            Ok(TxOutcome::User(resolved))
        })
        .await;
    let user = match outcome {
        Ok(TxOutcome::User(u)) => u,
        Ok(TxOutcome::ProvisioningDisabled) => return Err(Fail::Code("provisioning_disabled")),
        Err(e) if e.is_unique_violation() => return Err(Fail::Code("callback_failed")),
        Err(e) => return Err(Fail::Thrown(e.to_string())),
    };
    if !user.is_active {
        return Err(Fail::Code("account_inactive"));
    }
    let (access, refresh) = generate_tokens(
        &user.id,
        &user.email,
        TokenOptions { auth_provider: Some("oidc".into()), oidc_groups: Some(oidc_groups), ..Default::default() },
    );
    set_auth_cookies(ctx, headers, &access, &refresh);
    if cfg.enable_refresh_token_rotation {
        let expires_at = helpers::refresh_token_expires_at_ms();
        let token = crate::authz::hash_token_for_storage(&refresh);
        let uid = user.id.clone();
        let r = st
            .db
            .call(move |c| {
                c.execute(
                    r#"INSERT INTO "RefreshToken" ("id","userId","token","expiresAt","revoked","createdAt") VALUES (?1, ?2, ?3, ?4, 0, ?5)"#,
                    rusqlite::params![util::uuid_v4(), uid, token, expires_at, util::now_ms()],
                )?;
                Ok(())
            })
            .await;
        if let Err(e) = r {
            let msg = e.to_string();
            if regex::Regex::new(r"(?i)no such table:\s*RefreshToken").unwrap().is_match(&msg) {
                return Err(Fail::Code("callback_failed"));
            }
            if e.is_unique_violation() {
                return Err(Fail::Code("callback_failed"));
            }
            return Err(Fail::Thrown(msg));
        }
    }
    if cfg.enable_audit_logging {
        let mut details = Map::new();
        details.insert("provider".into(), Value::String(cfg.oidc.provider_name.clone()));
        details.insert("issuer".into(), Value::String(issuer));
        crate::audit::log_audit_event(
            &st.db,
            crate::audit::AuditEvent {
                user_id: Some(user.id.clone()),
                action: "oidc_login".into(),
                ip_address: Some(ctx.ip.clone()),
                user_agent: ctx.user_agent().map(str::to_string),
                details: Some(details),
                ..Default::default()
            },
        )
        .await;
    }
    let target = if flow.return_to.is_empty() { "/".to_string() } else { flow.return_to.clone() };
    Ok(express_redirect(ctx, &target, std::mem::take(headers)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn return_to_sanitizing() {
        let s = |v: &str| sanitize_return_to(Some(&Value::String(v.into())));
        assert_eq!(s(" /drawings/1 "), "/drawings/1");
        assert_eq!(s("//evil.test"), "/");
        assert_eq!(s("https://evil.test"), "/");
        assert_eq!(s("/a\nb"), "/");
        assert_eq!(s(&format!("/{}", "a".repeat(2048))), "/");
        assert_eq!(sanitize_return_to(Some(&json!(["/x"]))), "/");
        assert_eq!(sanitize_return_to(None), "/");
    }

    #[test]
    fn flow_payload_round_trip_and_tamper() {
        let p = FlowPayload {
            state: "s".into(),
            nonce: "n".into(),
            code_verifier: "v".into(),
            return_to: "/x".into(),
            expires_at: (util::now_ms() + 60_000) as f64,
        };
        let enc = encode_flow_payload(&p, "secret");
        assert_eq!(decode_flow_payload(Some(&enc), "secret"), Some(p.clone()));
        assert_eq!(decode_flow_payload(Some(&enc), "other"), None);
        let (body, sig) = enc.split_once('.').unwrap();
        assert_eq!(decode_flow_payload(Some(&format!("{body}x.{sig}")), "secret"), None);
        assert_eq!(decode_flow_payload(Some(&format!("{enc}.extra")), "secret"), Some(p.clone()));
        let expired = FlowPayload { expires_at: (util::now_ms() - 1) as f64, ..p };
        assert_eq!(decode_flow_payload(Some(&encode_flow_payload(&expired, "secret")), "secret"), None);
        assert_eq!(decode_flow_payload(None, "secret"), None);
    }

    #[test]
    fn claim_readers() {
        let claims = json!({
            "email": "  A@B.test ", "blank": "  ", "ev": "TRUE", "ev0": "0", "evx": "yes",
            "realm_access": {"roles": ["admin", " ops ", 3, ""]}, "csv": "a, b,,c", "arr": [["x"]],
        });
        let m = claims.as_object().unwrap();
        assert_eq!(read_string_claim(m, "email").as_deref(), Some("A@B.test"));
        assert_eq!(read_string_claim(m, "blank"), None);
        assert_eq!(read_boolean_claim(m, "ev"), Some(true));
        assert_eq!(read_boolean_claim(m, "ev0"), Some(false));
        assert_eq!(read_boolean_claim(m, "evx"), None);
        assert_eq!(
            normalize_claim_groups(read_claim_by_path(m, "realm_access.roles").as_ref()),
            vec!["admin".to_string(), "ops".to_string()]
        );
        assert_eq!(normalize_claim_groups(read_claim_by_path(m, "csv").as_ref()), vec!["a", "b", "c"]);
        assert_eq!(normalize_claim_groups(read_claim_by_path(m, "arr.0").as_ref()), vec!["x"]);
        assert_eq!(read_claim_by_path(m, " . "), None);
        assert_eq!(read_claim_by_path(m, "email.x"), None);
    }

    #[test]
    fn redirect_helpers() {
        assert_eq!(encode_url("/login?a=b c&d=%zz%41"), "/login?a=b%20c&d=%25zz%41");
        assert_eq!(negotiate_redirect_format(None), Some("text"));
        assert_eq!(negotiate_redirect_format(Some("text/html,application/xhtml+xml,*/*;q=0.8")), Some("html"));
        assert_eq!(negotiate_redirect_format(Some("application/json")), None);
        assert_eq!(negotiate_redirect_format(Some("*/*")), Some("text"));
    }
}
