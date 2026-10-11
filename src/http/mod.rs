//! HTTP front door: reproduces the Express middleware chain from index.ts and,
//! when a frontend dist is configured, the nginx routing in front of it.
pub mod body;
pub mod csrf;
pub mod ctx;
pub mod error;
pub mod express_routes;
pub mod rate_limit;
pub mod static_files;

use axum::{
    body::Body as AxumBody,
    extract::ConnectInfo,
    http::{header, HeaderMap, HeaderValue, Method, Request, Response, StatusCode, Uri},
    Router,
};
use base64::Engine;
use sha1::{Digest, Sha1};
use std::{
    net::SocketAddr,
    sync::Mutex,
    time::{Duration, Instant},
};
use tower::ServiceExt;

use self::body::{is_json_type, is_urlencoded_type, parse_json_body, parse_urlencoded_body, BodyError, ParsedBody};
use self::ctx::{build_ctx, Ctx};
use self::error::{error_handler_body, json_response, EtagEligible, FinalHandler};
use crate::config::config;
use crate::state::AppState;

const HELMET_HEADERS: [(&str, &str); 12] = [
    (
        "content-security-policy",
        "default-src 'none';base-uri 'none';form-action 'none';frame-ancestors 'none';object-src 'none';img-src 'self' data:;connect-src 'self';font-src 'self' https: data:;script-src 'self';script-src-attr 'none';style-src 'self' https: 'unsafe-inline';upgrade-insecure-requests",
    ),
    ("cross-origin-opener-policy", "same-origin"),
    ("cross-origin-resource-policy", "same-origin"),
    ("origin-agent-cluster", "?1"),
    ("referrer-policy", "no-referrer"),
    ("strict-transport-security", "max-age=31536000; includeSubDomains; preload"),
    ("x-content-type-options", "nosniff"),
    ("x-dns-prefetch-control", "off"),
    ("x-download-options", "noopen"),
    ("x-frame-options", "SAMEORIGIN"),
    ("x-permitted-cross-domain-policies", "none"),
    ("x-xss-protection", "0"),
];

const CORS_ALLOWED_HEADERS: &str = "Content-Type,Authorization,x-csrf-token,x-imported-file";
const CORS_EXPOSED_HEADERS: &str = "x-csrf-token,x-request-id";

/// Express-style weak ETag: W/"<len hex>-<sha1 base64 [0..27]>".
pub fn express_etag(body: &[u8]) -> String {
    let hash = base64::engine::general_purpose::STANDARD.encode(Sha1::digest(body));
    format!("W/\"{:x}-{}\"", body.len(), &hash[..27])
}

fn set(h: &mut HeaderMap, k: &'static str, v: &str) {
    if let Ok(v) = HeaderValue::from_str(v) {
        h.insert(k, v);
    }
}

/// HTTPS redirect policy (server/httpsRedirectPolicy.ts).
fn https_redirect_url(ctx: &Ctx, full_path: &str) -> Option<String> {
    let cfg = config();
    if !(cfg.node_env == "production" && cfg.enforce_https_redirect) {
        return None;
    }
    let parsed: Vec<(String, String)> = cfg
        .allowed_origins
        .iter()
        .filter_map(|o| url::Url::parse(o).ok())
        .filter(|u| u.scheme() == "http" || u.scheme() == "https")
        .map(|u| {
            let host = match u.port() {
                Some(p) => format!("{}:{}", u.host_str().unwrap_or(""), p),
                None => u.host_str().unwrap_or("").to_string(),
            };
            (host.to_lowercase(), u.scheme().to_string())
        })
        .collect();
    let canonical = parsed.iter().find(|(_, s)| s == "https").map(|(h, _)| h.clone())?;
    if ctx.path == "/health" {
        return None;
    }
    let forwarded = ctx
        .header("x-forwarded-proto")
        .map(|v| v.split(',').next().unwrap_or("").trim().to_lowercase())
        .filter(|v| !v.is_empty());
    if ctx.secure || forwarded.as_deref() == Some("https") {
        return None;
    }
    let host = ctx.header("host").map(|h| h.trim().to_lowercase()).unwrap_or_default();
    let protocols: Vec<&str> =
        parsed.iter().filter(|(h, _)| !host.is_empty() && *h == host).map(|(_, s)| s.as_str()).collect();
    let target = if protocols.contains(&"https") {
        host
    } else if !protocols.is_empty() {
        return None;
    } else {
        canonical
    };
    let path = if full_path.starts_with('/') { full_path } else { "/" };
    Some(format!("https://{target}{path}"))
}

fn apply_helmet(h: &mut HeaderMap) {
    for (k, v) in HELMET_HEADERS {
        h.insert(k, HeaderValue::from_static(v));
    }
}

/// cors(): returns false when the origin is not allowed (no CORS headers at all).
fn apply_cors(h: &mut HeaderMap, origin: Option<&str>) -> bool {
    if !config().is_allowed_origin(origin) {
        return false;
    }
    if let Some(o) = origin {
        set(h, "access-control-allow-origin", o);
    }
    h.append(header::VARY, HeaderValue::from_static("Origin"));
    h.insert("access-control-allow-credentials", HeaderValue::from_static("true"));
    true
}

struct OnboardingGateCache {
    required: bool,
    at: Instant,
}
static ONBOARDING_GATE: Mutex<Option<OnboardingGateCache>> = Mutex::new(None);

async fn onboarding_required(st: &AppState) -> Result<bool, error::ApiError> {
    if let Some(c) = &*ONBOARDING_GATE.lock().unwrap() {
        if c.at.elapsed() < Duration::from_millis(5000) {
            return Ok(c.required);
        }
    }
    let sc = crate::auth::middleware::ensure_system_config(&st.db).await?;
    let required = if sc.auth_enabled || sc.auth_onboarding_completed {
        false
    } else {
        !st.db
            .call(|c| Ok(crate::db::exists(c, r#"SELECT 1 FROM "User" WHERE "isActive" = 1 LIMIT 1"#, [])?))
            .await?
    };
    *ONBOARDING_GATE.lock().unwrap() = Some(OnboardingGateCache { required, at: Instant::now() });
    Ok(required)
}

pub fn clear_onboarding_gate_cache() {
    *ONBOARDING_GATE.lock().unwrap() = None;
}

fn onboarding_gate_enabled() -> bool {
    let cfg = config();
    cfg.auth_mode == crate::config::AuthMode::Local && cfg.node_env == "production" && !cfg.disable_onboarding_gate
}

fn gate_bypass(path: &str) -> bool {
    path == "/health" || path == "/csrf-token" || path == "/auth" || path.starts_with("/auth/")
}

/// The Express application: everything index.ts does for one request.
/// `path` is the backend path (prefix already stripped).
pub async fn handle_backend(st: AppState, router: Router, mut req: Request<AxumBody>, peer: Option<SocketAddr>) -> Response<AxumBody> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let query = req.uri().query().map(str::to_string);
    let ctx = build_ctx(method.clone(), path.clone(), query.clone(), req.headers().clone(), peer);
    let mut base = HeaderMap::new();
    set(&mut base, "x-request-id", &ctx.request_id);

    // HTTPS redirect (before helmet).
    if let Some(url) = https_redirect_url(&ctx, &ctx.original_url) {
        let mut r = Response::new(AxumBody::from(format!("Found. Redirecting to {url}")));
        *r.status_mut() = StatusCode::FOUND;
        let h = r.headers_mut();
        h.extend(base);
        set(h, "location", &url);
        set(h, "content-type", "text/plain; charset=utf-8");
        set(h, "vary", "Accept");
        return r;
    }

    apply_helmet(&mut base);
    let origin = ctx.header("origin").map(str::to_string);
    let cors_ok = apply_cors(&mut base, origin.as_deref());
    if cors_ok && method == Method::OPTIONS {
        let mut r = Response::new(AxumBody::empty());
        *r.status_mut() = StatusCode::NO_CONTENT;
        let h = r.headers_mut();
        h.extend(base);
        set(h, "access-control-allow-methods", "GET,HEAD,PUT,PATCH,POST,DELETE");
        set(h, "access-control-allow-headers", CORS_ALLOWED_HEADERS);
        set(h, "access-control-expose-headers", CORS_EXPOSED_HEADERS);
        set(h, "content-length", "0");
        return r;
    }
    if cors_ok {
        set(&mut base, "access-control-expose-headers", CORS_EXPOSED_HEADERS);
    }

    // Body parsers.
    let content_type = ctx.header("content-type").unwrap_or("").to_string();
    let wants_json = is_json_type(&content_type);
    let wants_form = is_urlencoded_type(&content_type);
    let mut parsed = ParsedBody(None);
    if wants_json || wants_form {
        let limit = config().body_limit_bytes;
        let declared = ctx.header("content-length").and_then(|v| v.parse::<usize>().ok());
        let has_body = declared.map(|n| n > 0).unwrap_or(false) || ctx.header("transfer-encoding").is_some();
        if has_body {
            let result = if declared.map(|n| n > limit).unwrap_or(false) {
                Err(BodyError::TooLarge)
            } else {
                let body = std::mem::take(req.body_mut());
                match axum::body::to_bytes(body, limit).await {
                    Ok(bytes) => {
                        if wants_json {
                            parse_json_body(&content_type, &bytes)
                        } else {
                            parse_urlencoded_body(&bytes)
                        }
                    }
                    Err(_) => Err(BodyError::TooLarge),
                }
            };
            match result {
                Ok(v) => parsed = ParsedBody(Some(v)),
                Err(e) => {
                    let (status, msg) = match e {
                        BodyError::Parse(m) => (400u16, m),
                        BodyError::TooLarge => (413, "request entity too large".to_string()),
                        BodyError::Charset(cs) => (415, format!("unsupported charset \"{}\"", cs.to_uppercase())),
                    };
                    eprintln!("Error: {{ message: {msg:?}, statusCode: {status}, path: {:?}, method: {:?} }}", ctx.path, ctx.method.as_str());
                    let mut r = json_response(
                        StatusCode::from_u16(status).unwrap(),
                        &error_handler_body(status, &msg, false),
                    );
                    r.headers_mut().extend(base);
                    return finish(&ctx, r);
                }
            }
        }
    }

    // Request logging (req.user is never set at this point upstream).
    if let Some(len) = ctx.header("content-length").and_then(|v| v.parse::<f64>().ok()) {
        let mb = len / 1024.0 / 1024.0;
        if mb > 10.0 {
            println!(
                "[LARGE REQUEST] {} {} - {:.2}MB - User: anonymous - RequestID: {}",
                ctx.method, ctx.path, mb, ctx.request_id
            );
        }
    }
    println!(
        "[REQUEST] {} {} - User: anonymous - IP: {} - RequestID: {}",
        ctx.method, ctx.path, ctx.ip, ctx.request_id
    );

    // General rate limiter.
    let info = st.general_limiter.hit(&rate_limit::ip_key(&ctx.ip));
    rate_limit::apply_headers(&mut base, &info);
    if info.exceeded {
        let mut r = st.general_limiter.limited_response(&info);
        merge_base(r.headers_mut(), base);
        return finish(&ctx, r);
    }

    // Express routes match case-insensitively; registered-before-the-gate routes
    // (/csrf-token, /health, /auth/*) are recognised by their canonical spelling.
    let trimmed = if path.len() > 1 && path.ends_with('/') { path.trim_end_matches('/') } else { path.as_str() };
    let canonical = express_canonical_path(trimmed).unwrap_or_else(|| trimmed.to_string());

    // GET /csrf-token
    if (method == Method::GET || method == Method::HEAD) && canonical == "/csrf-token" {
        let mut r = csrf::issue_token(&ctx);
        merge_base(r.headers_mut(), base);
        return finish(&ctx, r);
    }
    if let Err(e) = csrf::middleware_check(&ctx) {
        let mut r = axum::response::IntoResponse::into_response(e);
        merge_base(r.headers_mut(), base);
        return finish(&ctx, r);
    }

    // Onboarding gate (applies after /auth and /health are registered).
    if onboarding_gate_enabled() && !gate_bypass(&canonical) {
        match onboarding_required(&st).await {
            Ok(true) => {
                let mut r = json_response(
                    StatusCode::CONFLICT,
                    &serde_json::json!({
                        "error": "Authentication onboarding required",
                        "code": "AUTH_ONBOARDING_REQUIRED",
                        "message": "Authentication onboarding is required before using the app. Refresh the page to load the latest UI and complete setup.",
                        "redirectTo": "/auth-setup",
                    }),
                );
                set(r.headers_mut(), "clear-site-data", "\"cache\"");
                merge_base(r.headers_mut(), base);
                return finish(&ctx, r);
            }
            Ok(false) => {}
            Err(e) => eprintln!("Auth onboarding gate error: {e:?}"),
        }
    }

    // Route. Express (non-strict routing) ignores one trailing slash.
    let mut routed_path = if path.len() > 1 && path.ends_with('/') { path.trim_end_matches('/').to_string() } else { path.clone() };
    // Express's automatic OPTIONS reply (reached when cors did not answer the preflight).
    if method == Method::OPTIONS {
        if let Some(allow) = express_allow(&routed_path) {
            let mut r = Response::new(AxumBody::from(allow.clone()));
            set(r.headers_mut(), "allow", &allow);
            set(r.headers_mut(), "content-type", "text/plain");
            merge_base(r.headers_mut(), base);
            return r;
        }
    }
    // Express matches literal path segments case-insensitively (parameters keep their case).
    if let Some(canonical) = express_canonical_path(&routed_path) {
        routed_path = canonical;
    }
    let uri: Uri = match &query {
        Some(q) => format!("{routed_path}?{q}"),
        None => routed_path,
    }
    .parse()
    .unwrap_or_else(|_| Uri::from_static("/"));
    *req.uri_mut() = uri;
    req.extensions_mut().insert(ctx.clone());
    req.extensions_mut().insert(parsed);
    let mut r = match router.oneshot(req).await {
        Ok(r) => r,
        Err(never) => match never {},
    };
    if r.extensions().get::<FinalHandler>().is_some() {
        // finalhandler keeps existing headers but overrides CSP.
        let csp = r.headers().get("content-security-policy").cloned();
        merge_base(r.headers_mut(), base);
        if let Some(csp) = csp {
            r.headers_mut().insert("content-security-policy", csp);
        }
    } else {
        merge_base(r.headers_mut(), base);
    }
    finish(&ctx, r)
}

/// Base headers were set before the handler ran; handler headers win.
fn merge_base(h: &mut HeaderMap, base: HeaderMap) {
    let mut last: Option<header::HeaderName> = None;
    for (k, v) in base {
        let k = match k {
            Some(k) => {
                last = Some(k.clone());
                k
            }
            None => last.clone().unwrap(),
        };
        if k == header::VARY {
            if !h.get_all(header::VARY).iter().any(|x| x == v) {
                h.append(k, v);
            }
            continue;
        }
        if !h.contains_key(&k) {
            h.insert(k, v);
        }
    }
}

/// res.send post-processing: ETag + freshness (304) for buffered bodies.
fn finish(ctx: &Ctx, r: Response<AxumBody>) -> Response<AxumBody> {
    if r.extensions().get::<EtagEligible>().is_none() || r.headers().contains_key(header::ETAG) {
        return strip_empty(ctx, r);
    }
    let (mut parts, body) = r.into_parts();
    // Buffered bodies are already in memory; this does not allocate a copy.
    let bytes = match futures_util::FutureExt::now_or_never(axum::body::to_bytes(body, usize::MAX)) {
        Some(Ok(b)) => b,
        _ => return Response::from_parts(parts, AxumBody::empty()),
    };
    let etag = express_etag(&bytes);
    parts.headers.insert(header::ETAG, HeaderValue::from_str(&etag).unwrap());
    let status = parts.status.as_u16();
    let fresh_eligible = (ctx.method == Method::GET || ctx.method == Method::HEAD) && ((200..300).contains(&status) || status == 304);
    if fresh_eligible && is_fresh(&ctx.headers, &etag) {
        parts.status = StatusCode::NOT_MODIFIED;
        parts.headers.remove(header::CONTENT_TYPE);
        parts.headers.remove(header::CONTENT_LENGTH);
        parts.headers.remove(header::TRANSFER_ENCODING);
        return Response::from_parts(parts, AxumBody::empty());
    }
    strip_empty(ctx, Response::from_parts(parts, AxumBody::from(bytes)))
}

fn strip_empty(ctx: &Ctx, mut r: Response<AxumBody>) -> Response<AxumBody> {
    if r.status() == StatusCode::NO_CONTENT || r.status() == StatusCode::NOT_MODIFIED {
        r.headers_mut().remove(header::CONTENT_TYPE);
        r.headers_mut().remove(header::CONTENT_LENGTH);
        *r.body_mut() = AxumBody::empty();
    }
    let _ = ctx;
    r
}

/// `fresh` package semantics.
fn is_fresh(req: &HeaderMap, etag: &str) -> bool {
    let inm = req.get(header::IF_NONE_MATCH).and_then(|v| v.to_str().ok());
    let ims = req.get(header::IF_MODIFIED_SINCE);
    if inm.is_none() && ims.is_none() {
        return false;
    }
    if let Some(cc) = req.get(header::CACHE_CONTROL).and_then(|v| v.to_str().ok()) {
        if cc.contains("no-cache") {
            return false;
        }
    }
    if let Some(inm) = inm {
        if inm.trim() == "*" {
            return true;
        }
        let strip = |t: &str| t.trim().trim_start_matches("W/").to_string();
        let target = strip(etag);
        return inm.split(',').any(|t| strip(t) == target);
    }
    false
}

// ---------------------------------------------------------------------------
// Top-level service

#[derive(Clone)]
pub struct Frontdoor {
    pub st: AppState,
    pub backend: Router,
}

/// Dispatch one request: /socket.io is handled by the Socket.IO layer before this;
/// `/api/*` (or everything, in backend-only mode) goes to the Express pipeline;
/// the rest is static frontend.
pub async fn dispatch(fd: Frontdoor, req: Request<AxumBody>) -> Response<AxumBody> {
    let peer = req.extensions().get::<ConnectInfo<SocketAddr>>().map(|c| c.0);
    let cfg = config();
    let Some(dist) = cfg.frontend_dist_dir.clone() else {
        return handle_backend(fd.st, fd.backend, req, peer).await;
    };
    let path = req.uri().path().to_string();
    if path == "/api" || path.starts_with("/api/") {
        // nginx `location /api/ { proxy_pass http://backend/; }` strips the prefix.
        let stripped = path.strip_prefix("/api").unwrap_or("");
        let stripped = if stripped.is_empty() { "/".to_string() } else { stripped.to_string() };
        if path == "/api" {
            // `/api` (no slash) is not matched by `location /api/`; nginx serves the SPA.
            return static_files::serve(dist, req).await;
        }
        let new_uri = match req.uri().query() {
            Some(q) => format!("{stripped}?{q}"),
            None => stripped,
        };
        let mut req = req;
        *req.uri_mut() = new_uri.parse().unwrap_or_else(|_| Uri::from_static("/"));
        // nginx sets X-Forwarded-For/Proto/Real-IP for the backend.
        let remote = peer.map(|p| p.ip().to_string()).unwrap_or_default();
        let h = req.headers_mut();
        let xff = match h.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            Some(prev) => format!("{prev}, {remote}"),
            None => remote.clone(),
        };
        set(h, "x-forwarded-for", &xff);
        set(h, "x-real-ip", &remote);
        let proto = forwarded_proto(h);
        set(h, "x-forwarded-proto", &proto);
        let accepts_gzip = static_files::accepts_gzip(req.headers());
        let mut r = handle_backend(fd.st, fd.backend, req, peer).await;
        let status = r.status();
        static_files::apply_server_headers(status, r.headers_mut());
        return maybe_gzip(r, accepts_gzip).await;
    }
    static_files::serve(dist, req).await
}

/// nginx `map $http_x_forwarded_proto $forwarded_proto`.
fn forwarded_proto(h: &HeaderMap) -> String {
    let incoming = h.get("x-forwarded-proto").and_then(|v| v.to_str().ok()).unwrap_or("").to_lowercase();
    let first = incoming.split(',').next().unwrap_or("");
    if first == "https" {
        "https".into()
    } else if first == "http" {
        "http".into()
    } else {
        "http".into()
    }
}

/// nginx `gzip on` for proxied JSON/text responses.
async fn maybe_gzip(r: Response<AxumBody>, accepts: bool) -> Response<AxumBody> {
    let ct = r.headers().get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    // ngx_http_gzip_filter: only 200/403/404, gzip_types, and >= gzip_min_length (20) when known.
    if !static_files::gzip_type(&ct) || !matches!(r.status().as_u16(), 200 | 403 | 404) {
        return r;
    }
    let known_len = r
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .or_else(|| axum::body::HttpBody::size_hint(r.body()).exact());
    if known_len.map(|n| n < 20).unwrap_or(false) {
        return r;
    }
    let (mut parts, body) = r.into_parts();
    parts.headers.append(header::VARY, HeaderValue::from_static("Accept-Encoding"));
    if !accepts || parts.headers.contains_key(header::CONTENT_ENCODING) {
        return Response::from_parts(parts, body);
    }
    let bytes = match axum::body::to_bytes(body, usize::MAX).await {
        Ok(b) => b,
        Err(_) => return Response::from_parts(parts, AxumBody::empty()),
    };
    if bytes.len() < 20 {
        return Response::from_parts(parts, AxumBody::from(bytes));
    }
    let gz = static_files::gzip_bytes(&bytes);
    parts.headers.remove(header::CONTENT_LENGTH);
    parts.headers.insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
    if let Some(etag) = parts.headers.get(header::ETAG).and_then(|v| v.to_str().ok()).map(str::to_string) {
        if !etag.starts_with("W/") {
            parts.headers.insert(header::ETAG, HeaderValue::from_str(&format!("W/{etag}")).unwrap());
        }
    }
    Response::from_parts(parts, AxumBody::from(gz))
}

// ---------------------------------------------------------------------------
// Outermost layer (also wraps Socket.IO): socket.io's `cors` option for the
// engine endpoints, nginx's server-level headers on /socket.io, and nginx's
// `Server` header on everything in bundled mode.

/// Header-name spellings as Express/helmet/cors/nginx/engine.io emit them.
pub fn canonical_header_name(name: &str, socket: bool) -> String {
    const EXACT: [&str; 12] = [
        "X-Request-ID", "ETag", "X-DNS-Prefetch-Control", "X-XSS-Protection", "RateLimit-Policy", "RateLimit-Limit",
        "RateLimit-Remaining", "RateLimit-Reset", "WWW-Authenticate", "Content-MD5", "X-Cache", "Origin-Agent-Cluster",
    ];
    if socket && name == "cache-control" {
        return name.to_string(); // engine.io sets it lowercase
    }
    if let Some(e) = EXACT.iter().find(|e| e.eq_ignore_ascii_case(name)) {
        return e.to_string();
    }
    name.split('-')
        .map(|part| {
            let mut c = part.chars();
            match c.next() {
                Some(f) => f.to_ascii_uppercase().to_string() + c.as_str(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join("-")
}

fn apply_header_case(r: &mut Response<AxumBody>, socket: bool) {
    let mut map = hyper::ext::HeaderCaseMap::new();
    let names: Vec<header::HeaderName> = r.headers().keys().cloned().collect();
    for name in names {
        let spelling = bytes::Bytes::from(canonical_header_name(name.as_str(), socket));
        for _ in r.headers().get_all(&name).iter() {
            map.push(name.clone(), spelling.clone());
        }
    }
    // Headers hyper writes itself also take their spelling from the map.
    for (name, spelling) in [
        (header::DATE, "Date"),
        (header::CONTENT_LENGTH, "Content-Length"),
        (header::TRANSFER_ENCODING, "Transfer-Encoding"),
        (header::CONNECTION, "Connection"),
    ] {
        if !r.headers().contains_key(&name) {
            map.push(name, bytes::Bytes::from_static(spelling.as_bytes()));
        }
    }
    r.extensions_mut().insert(map);
}

pub async fn outer_layer(bundled: bool, req: Request<AxumBody>, next: axum::middleware::Next) -> Response<AxumBody> {
    let is_socket = req.uri().path().starts_with("/socket.io");
    let wants_close = req
        .headers()
        .get(header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_ascii_lowercase().contains("close"))
        .unwrap_or(false)
        || req.version() == axum::http::Version::HTTP_10;
    let origin = req.headers().get(header::ORIGIN).and_then(|v| v.to_str().ok()).map(str::to_string);
    let cors_ok = is_socket && config().is_allowed_origin(origin.as_deref());
    let accepts_gzip = static_files::accepts_gzip(req.headers());
    let polling = is_socket && req.uri().query().map(|q| q.contains("transport=polling")).unwrap_or(false);
    let mut r = if is_socket && cors_ok && req.method() == Method::OPTIONS {
        // engine.io + cors: preflight answered with 204.
        let mut r = Response::new(AxumBody::empty());
        *r.status_mut() = StatusCode::NO_CONTENT;
        let h = r.headers_mut();
        set(h, "access-control-allow-methods", "GET,HEAD,PUT,PATCH,POST,DELETE");
        if let Some(req_headers) = req.headers().get("access-control-request-headers") {
            h.insert("access-control-allow-headers", req_headers.clone());
            // cors builds one combined Vary value.
            h.insert(header::VARY, HeaderValue::from_static("Origin, Access-Control-Request-Headers"));
        }
        set(h, "content-length", "0");
        r
    } else {
        next.run(req).await
    };
    let status = r.status();
    let h = r.headers_mut();
    if polling && status == StatusCode::OK && !h.contains_key(header::CACHE_CONTROL) {
        // engine.io polling responses
        set(h, "cache-control", "no-store");
    }
    if cors_ok {
        if let Some(o) = &origin {
            set(h, "access-control-allow-origin", o);
        }
        if !h.get_all(header::VARY).iter().any(|v| v.to_str().map(|s| s.contains("Origin")).unwrap_or(false)) {
            h.append(header::VARY, HeaderValue::from_static("Origin"));
        }
        set(h, "access-control-allow-credentials", "true");
    }
    if bundled {
        if is_socket {
            static_files::apply_server_headers(status, h);
        }
        h.insert(header::SERVER, HeaderValue::from_static(static_files::NGINX_SERVER));
    }
    if !wants_close {
        // nginx and Node announce persistent connections explicitly.
        h.insert(header::CONNECTION, HeaderValue::from_static("keep-alive"));
        if !bundled {
            h.insert("keep-alive", HeaderValue::from_static("timeout=5"));
        }
    }
    let mut r = if bundled && is_socket {
        // nginx gzip on the proxied engine.io text/plain responses.
        maybe_gzip(r, accepts_gzip).await
    } else {
        r
    };
    apply_header_case(&mut r, is_socket);
    r
}

// ---------------------------------------------------------------------------
// Express routing semantics on top of axum's (case-sensitive) router.

fn template_matches(template: &str, path: &str, case_sensitive: bool) -> bool {
    let t: Vec<&str> = template.split('/').collect();
    let p: Vec<&str> = path.split('/').collect();
    t.len() == p.len()
        && t.iter().zip(&p).all(|(ts, ps)| {
            if ts.starts_with(':') {
                !ps.is_empty()
            } else if case_sensitive {
                ts == ps
            } else {
                ts.eq_ignore_ascii_case(ps)
            }
        })
}

/// The `Allow` value Express computes for OPTIONS (sorted, HEAD implied by GET).
pub fn express_allow(path: &str) -> Option<String> {
    let mut methods: Vec<&str> = express_routes::ROUTES
        .iter()
        .filter(|(_, t)| template_matches(t, path, false))
        .flat_map(|(m, _)| if *m == "GET" { vec!["GET", "HEAD"] } else { vec![*m] })
        .collect();
    if methods.is_empty() {
        return None;
    }
    methods.sort_unstable();
    methods.dedup();
    Some(methods.join(", "))
}

/// When no route matches exactly but one matches ignoring case, rewrite the literal
/// segments to the registered spelling (parameter values are kept as sent).
pub fn express_canonical_path(path: &str) -> Option<String> {
    if express_routes::ROUTES.iter().any(|(_, t)| template_matches(t, path, true)) {
        return None;
    }
    let (_, template) = express_routes::ROUTES.iter().find(|(_, t)| template_matches(t, path, false))?;
    let out: Vec<String> = template
        .split('/')
        .zip(path.split('/'))
        .map(|(t, p)| if t.starts_with(':') { p.to_string() } else { t.to_string() })
        .collect();
    Some(out.join("/"))
}

#[cfg(test)]
mod express_routing_tests {
    use super::*;

    #[test]
    fn allow_and_case_folding_match_upstream() {
        // Values captured from upstream 0.6.5 (OPTIONS with a disallowed Origin).
        assert_eq!(express_allow("/drawings").as_deref(), Some("GET, HEAD, POST"));
        assert_eq!(express_allow("/drawings/abc").as_deref(), Some("DELETE, GET, HEAD, PUT"));
        assert_eq!(express_allow("/drawings/shared").as_deref(), Some("DELETE, GET, HEAD, PUT"));
        assert_eq!(express_allow("/Drawings/ABC").as_deref(), Some("DELETE, GET, HEAD, PUT"));
        assert_eq!(express_allow("/drawings/a/history/b/restore").as_deref(), Some("POST"));
        assert_eq!(express_allow("/collections/x/shares/y").as_deref(), Some("DELETE, PATCH"));
        assert_eq!(express_allow("/auth/users").as_deref(), Some("GET, HEAD, POST"));
        assert_eq!(express_allow("/auth/USERS/abc").as_deref(), Some("PATCH"));
        assert_eq!(express_allow("/library").as_deref(), Some("GET, HEAD, PUT"));
        assert_eq!(express_allow("/health").as_deref(), Some("GET, HEAD"));
        assert_eq!(express_allow("/nope"), None);
        assert_eq!(express_canonical_path("/DRAWINGS/AbC/HISTORY").as_deref(), Some("/drawings/AbC/history"));
        assert_eq!(express_canonical_path("/Auth/Status").as_deref(), Some("/auth/status"));
        assert_eq!(express_canonical_path("/drawings/AbC"), None);
    }
}
