//! auth/oidcClient.ts plus the parts of `openid-client` v5.7.1 it relies on:
//! discovery, authorization URL, code exchange, ID token validation (with the
//! issuer JWKS cache), and userinfo. Error messages match openid-client so
//! upstream's alg-mismatch retry and log lines behave the same.
use serde_json::{Map, Value};
use sha2::Digest;
use std::collections::{HashSet, VecDeque};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use crate::config::config;

pub type TokenSet = Map<String, Value>;

#[derive(Debug, Clone)]
pub struct OidcError {
    pub name: &'static str,
    pub message: String,
}

impl std::fmt::Display for OidcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.name, self.message)
    }
}

fn rp(message: impl Into<String>) -> OidcError {
    OidcError { name: "RPError", message: message.into() }
}
fn op(message: impl Into<String>) -> OidcError {
    OidcError { name: "OPError", message: message.into() }
}
fn type_err(message: impl Into<String>) -> OidcError {
    OidcError { name: "TypeError", message: message.into() }
}
fn plain(message: impl Into<String>) -> OidcError {
    OidcError { name: "Error", message: message.into() }
}

// ---------------------------------------------------------------------------
// JS value helpers

fn truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64().map(|f| f != 0.0 && !f.is_nan()).unwrap_or(true),
        Some(Value::String(s)) => !s.is_empty(),
        Some(_) => true,
    }
}

/// `util.format("%s", v)` / `String(v)` for the values we print.
fn js_str(v: Option<&Value>) -> String {
    match v {
        None => "undefined".into(),
        Some(Value::Null) => "null".into(),
        Some(Value::String(s)) => s.clone(),
        Some(Value::Array(a)) => a.iter().map(|x| if x.is_null() { String::new() } else { js_str(Some(x)) }).collect::<Vec<_>>().join(","),
        Some(Value::Object(_)) => "[object Object]".into(),
        Some(other) => other.to_string(),
    }
}

fn is_str(v: Option<&Value>, s: &str) -> bool {
    matches!(v, Some(Value::String(x)) if x == s)
}

fn now_secs() -> f64 {
    (crate::util::now_ms() / 1000) as f64
}

// ---------------------------------------------------------------------------
// openid-client helpers/generators.js

pub fn random() -> String {
    crate::util::b64url(&crate::util::random_bytes(32))
}

pub fn code_challenge(verifier: &str) -> String {
    crate::util::b64url(&sha2::Sha256::digest(verifier.as_bytes()))
}

// ---------------------------------------------------------------------------
// auth/oidcRouteHelpers.ts (client-related parts)

/// canonicalizeIssuerUrl
pub fn canonicalize_issuer_url(issuer: &str) -> String {
    let trimmed = crate::security::js_trim(issuer);
    if trimmed.is_empty() {
        return trimmed.to_string();
    }
    match url::Url::parse(trimmed) {
        Ok(mut u) => {
            let path = u.path().trim_end_matches('/').to_string();
            u.set_path(&path);
            u.as_str().trim_end_matches('/').to_string()
        }
        Err(_) => trimmed.trim_end_matches('/').to_string(),
    }
}

fn is_hs(alg: &str) -> bool {
    alg.len() >= 2 && alg[..2].eq_ignore_ascii_case("hs")
}

/// resolveIdTokenSignedResponseAlg
pub fn resolve_id_token_signed_response_alg(
    configured: Option<&str>,
    has_client_secret: bool,
    metadata: &Map<String, Value>,
) -> Result<String, OidcError> {
    if let Some(c) = configured.filter(|c| !c.is_empty()) {
        return Ok(c.to_string());
    }
    if let Some(Value::Array(advertised)) = metadata.get("id_token_signing_alg_values_supported") {
        let supported: Vec<String> = advertised
            .iter()
            .filter_map(|v| v.as_str())
            .filter(|s| !crate::security::js_trim(s).is_empty())
            .map(|s| crate::security::js_trim(s).to_string())
            .collect();
        if !supported.is_empty() {
            for c in ["RS256", "PS256", "ES256", "EdDSA", "RS384", "PS384", "ES384", "RS512", "PS512", "ES512"] {
                if supported.iter().any(|s| s == c) {
                    return Ok(c.to_string());
                }
            }
            if let Some(a) = supported.iter().find(|a| !is_hs(a) && a.to_lowercase() != "none") {
                return Ok(a.clone());
            }
            let hs: Vec<&String> = supported.iter().filter(|a| is_hs(a)).collect();
            if !hs.is_empty() {
                if !has_client_secret {
                    return Err(plain(
                        "OIDC provider only advertises HS* ID token signing algorithms, but OIDC_CLIENT_SECRET is not configured. \
Fix: set OIDC_CLIENT_SECRET for a confidential client, or configure your provider/client to sign ID tokens with an asymmetric algorithm (for example RS256).",
                    ));
                }
                for c in ["HS256", "HS384", "HS512"] {
                    if hs.iter().any(|s| *s == c) {
                        return Ok(c.to_string());
                    }
                }
                return Ok(hs[0].clone());
            }
        }
    }
    Ok("RS256".into())
}

/// parseJwtAlgMismatchError → (expected, got), both upper-cased.
pub fn parse_jwt_alg_mismatch_error(message: &str) -> Option<(String, String)> {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    let re = RE.get_or_init(|| regex::Regex::new(r"(?i)expected\s+([A-Za-z0-9_-]+)\s*,\s*got:\s*([A-Za-z0-9_-]+)").unwrap());
    let c = re.captures(message)?;
    Some((c[1].to_uppercase(), c[2].to_uppercase()))
}

/// canUseIdTokenSigningAlg
pub fn can_use_id_token_signing_alg(alg: &str, has_client_secret: bool) -> bool {
    if alg.to_lowercase() == "none" {
        return false;
    }
    if is_hs(alg) {
        return has_client_secret;
    }
    true
}

/// selectTokenEndpointAuthMethod (oidcClient.ts)
fn select_token_endpoint_auth_method(
    has_client_secret: bool,
    supported: Option<&Value>,
    configured: Option<&str>,
) -> Result<String, OidcError> {
    let supported: Option<Vec<Value>> = match supported {
        None | Some(Value::Null) => None,
        Some(Value::Array(a)) => Some(a.iter().filter(|v| truthy(Some(v))).cloned().collect()),
        Some(_) => return Err(type_err("opts.supported?.filter is not a function")),
    };
    let includes = |s: &Vec<Value>, m: &str| s.iter().any(|v| v.as_str() == Some(m));
    let listed = |s: &Vec<Value>| s.iter().map(|v| js_str(Some(v))).collect::<Vec<_>>().join(", ");
    if let Some(configured) = configured {
        if let Some(s) = &supported {
            if !s.is_empty() && !includes(s, configured) {
                return Err(plain(format!(
                    "OIDC_TOKEN_ENDPOINT_AUTH_METHOD={configured} is configured, but provider does not advertise support for it. Supported methods: {}",
                    listed(s)
                )));
            }
        }
        return Ok(configured.to_string());
    }
    if !has_client_secret {
        if let Some(s) = &supported {
            if !s.is_empty() && !includes(s, "none") {
                return Err(plain(
                    "OIDC is configured without OIDC_CLIENT_SECRET (public client), but the provider does not advertise support for token endpoint auth method \"none\". \
Fix: configure the client as public at your IdP (token endpoint auth = none), or set OIDC_CLIENT_SECRET for a confidential client.",
                ));
            }
        }
        return Ok("none".into());
    }
    for candidate in ["client_secret_basic", "client_secret_post"] {
        match &supported {
            None => return Ok(candidate.into()),
            Some(s) if s.is_empty() || includes(s, candidate) => return Ok(candidate.into()),
            _ => {}
        }
    }
    Err(plain(
        "OIDC provider does not advertise support for client_secret-based token endpoint auth methods (tried: client_secret_basic, client_secret_post). \
If your provider requires JWT-based client auth (private_key_jwt/client_secret_jwt), ExcaliDash currently does not expose configuration for that.",
    ))
}

// ---------------------------------------------------------------------------
// HTTP (openid-client helpers/request.js + process_response.js)

fn http() -> &'static reqwest::Client {
    static C: OnceLock<reqwest::Client> = OnceLock::new();
    C.get_or_init(|| {
        reqwest::Client::builder()
            .use_preconfigured_tls(crate::net::rustls_client_config())
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_millis(3500))
            .user_agent("openid-client/5.7.1 (https://github.com/panva/node-openid-client)")
            .build()
            .expect("oidc http client")
    })
}

struct HttpResponse {
    status: u16,
    headers: reqwest::header::HeaderMap,
    body: Vec<u8>,
}

fn check_url(raw: &str) -> Result<url::Url, OidcError> {
    match url::Url::parse(raw) {
        Ok(u) if u.scheme() == "http" || u.scheme() == "https" => Ok(u),
        _ => Err(type_err("only valid absolute URLs can be requested")),
    }
}

async fn send(rb: reqwest::RequestBuilder) -> Result<HttpResponse, OidcError> {
    let r = rb.header("Accept-Encoding", "identity").send().await.map_err(|e| {
        if e.is_timeout() {
            rp("outgoing request timed out after 3500ms")
        } else {
            plain(e.to_string())
        }
    })?;
    let status = r.status().as_u16();
    let headers = r.headers().clone();
    let body = r.bytes().await.map_err(|e| plain(e.to_string()))?.to_vec();
    Ok(HttpResponse { status, headers, body })
}

fn status_text(code: u16) -> String {
    reqwest::StatusCode::from_u16(code)
        .ok()
        .and_then(|s| s.canonical_reason())
        .map(str::to_string)
        .unwrap_or_else(|| "undefined".into())
}

fn op_error_from_body(body: &Map<String, Value>) -> OidcError {
    let error = js_str(body.get("error"));
    match body.get("error_description") {
        Some(d) if truthy(Some(d)) => op(format!("{error} ({})", js_str(Some(d)))),
        _ => op(error),
    }
}

/// processResponse(response, { bearer }) → JSON body.
fn process_response(res: &HttpResponse, bearer: bool) -> Result<Value, OidcError> {
    if res.status != 200 {
        if bearer {
            if let Some(www) = res.headers.get("www-authenticate").and_then(|v| v.to_str().ok()) {
                let mut m = Map::new();
                for (k, v) in parse_www_authenticate(www) {
                    m.insert(k, Value::String(v));
                }
                if truthy(m.get("error")) {
                    return Err(op_error_from_body(&m));
                }
            }
        }
        if let Ok(Value::Object(m)) = serde_json::from_slice::<Value>(&res.body) {
            if matches!(m.get("error"), Some(Value::String(s)) if !s.is_empty()) {
                return Err(op_error_from_body(&m));
            }
        }
        return Err(op(format!(
            "expected 200 OK, got: {} {}",
            res.status,
            status_text(res.status)
        )));
    }
    if res.body.is_empty() {
        return Err(op("expected 200 OK with body but no body was returned"));
    }
    serde_json::from_slice::<Value>(&res.body).map_err(|e| OidcError { name: "SyntaxError", message: e.to_string() })
}

fn parse_www_authenticate(header: &str) -> Vec<(String, String)> {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    let re = RE.get_or_init(|| regex::Regex::new(r#"(\w+)=("[^"]*")"#).unwrap());
    re.captures_iter(header)
        .map(|c| (c[1].to_string(), c[2].trim_matches('"').to_string()))
        .collect()
}

// ---------------------------------------------------------------------------
// Issuer + client

const ISSUER_DEFAULTS: &[(&str, &str)] = &[
    ("claim_types_supported", r#"["normal"]"#),
    ("claims_parameter_supported", "false"),
    ("grant_types_supported", r#"["authorization_code","implicit"]"#),
    ("request_parameter_supported", "false"),
    ("request_uri_parameter_supported", "true"),
    ("require_request_uri_registration", "false"),
    ("response_modes_supported", r#"["query","fragment"]"#),
    ("token_endpoint_auth_methods_supported", r#"["client_secret_basic"]"#),
];

/// issuer.js resolveWellKnownUri
fn resolve_well_known_uri(uri: &str) -> String {
    let Ok(mut u) = url::Url::parse(uri) else { return uri.to_string() };
    if u.path().contains("/.well-known/") {
        return uri.to_string();
    }
    let path = if u.path().ends_with('/') {
        format!("{}.well-known/openid-configuration", u.path())
    } else {
        format!("{}/.well-known/openid-configuration", u.path())
    };
    u.set_path(&path);
    u.to_string()
}

/// Issuer.discover
async fn discover(uri: &str) -> Result<Map<String, Value>, OidcError> {
    let well_known = resolve_well_known_uri(uri);
    let url = check_url(&well_known)?;
    let res = send(http().get(url).header("Accept", "application/json")).await?;
    let body = process_response(&res, false)?;
    let mut meta = Map::new();
    for (k, v) in ISSUER_DEFAULTS {
        meta.insert(k.to_string(), serde_json::from_str(v).unwrap());
    }
    if let Value::Object(m) = body {
        for (k, v) in m {
            meta.insert(k, v);
        }
    }
    Ok(meta)
}

struct KeyEntry {
    jwk: Map<String, Value>,
    algorithms: Result<HashSet<String>, ()>,
}

#[derive(Default)]
struct JwksCache {
    keys: Option<Arc<Vec<KeyEntry>>>,
    throttle_until: Option<Instant>,
    seen: VecDeque<String>,
}

pub struct Client {
    pub metadata: Map<String, Value>,
    /// `client.issuer.issuer`
    pub issuer: Option<String>,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub redirect_uri: String,
    pub token_endpoint_auth_method: String,
    pub id_token_signed_response_alg: String,
    jwks: tokio::sync::Mutex<JwksCache>,
}

/// buildOidcClient(idTokenSignedResponseAlgOverride)
pub async fn build_client(alg_override: Option<&str>) -> Result<Client, OidcError> {
    let cfg = &config().oidc;
    let (Some(issuer_url), Some(client_id), Some(redirect_uri)) = (&cfg.issuer_url, &cfg.client_id, &cfg.redirect_uri) else {
        return Err(plain("OIDC is enabled but provider configuration is incomplete"));
    };
    let discovery_url = cfg.discovery_url.as_deref().unwrap_or(issuer_url);
    let metadata = discover(discovery_url).await?;
    let expected = canonicalize_issuer_url(issuer_url);
    // openid-client exposes `issuer` as a read-only accessor, so upstream's
    // override only takes effect when discovery returned no `issuer` at all.
    let issuer = match metadata.get("issuer") {
        Some(Value::String(raw)) => {
            if canonicalize_issuer_url(raw) != expected {
                eprintln!(
                    "[OIDC] Issuer mismatch between discovery ({raw}) and configured OIDC_ISSUER_URL ({issuer_url}); using configured issuer for token validation."
                );
            }
            Some(raw.clone())
        }
        None => Some(expected),
        Some(_) => None,
    };
    let method = select_token_endpoint_auth_method(
        cfg.client_secret.is_some(),
        metadata.get("token_endpoint_auth_methods_supported"),
        cfg.token_endpoint_auth_method.as_deref(),
    )?;
    let default_alg = resolve_id_token_signed_response_alg(
        cfg.id_token_signed_response_alg.as_deref(),
        cfg.client_secret.is_some(),
        &metadata,
    )?;
    let alg = alg_override.filter(|a| !a.is_empty()).map(str::to_string).unwrap_or(default_alg);
    if client_id.is_empty() {
        return Err(type_err("client_id is required"));
    }
    Ok(Client {
        metadata,
        issuer,
        client_id: client_id.clone(),
        client_secret: cfg.client_secret.clone(),
        redirect_uri: redirect_uri.clone(),
        token_endpoint_auth_method: method,
        id_token_signed_response_alg: alg,
        jwks: tokio::sync::Mutex::new(JwksCache::default()),
    })
}

/// getOidcClient: build once, cache, retry on the next call after a failure.
pub async fn get_client() -> Result<Arc<Client>, OidcError> {
    static CACHE: tokio::sync::Mutex<Option<Arc<Client>>> = tokio::sync::Mutex::const_new(None);
    let mut g = CACHE.lock().await;
    if let Some(c) = g.as_ref() {
        return Ok(c.clone());
    }
    let c = Arc::new(build_client(None).await?);
    *g = Some(c.clone());
    Ok(c)
}

/// Callback checks (state / nonce / PKCE verifier).
pub struct Checks {
    pub state: String,
    pub nonce: String,
    pub code_verifier: String,
}

/// openid-client pickCb
pub fn pick_callback_params(input: &Map<String, Value>) -> Map<String, Value> {
    const KEYS: &[&str] = &[
        "access_token",
        "code",
        "error_description",
        "error_uri",
        "error",
        "expires_in",
        "id_token",
        "iss",
        "response",
        "session_state",
        "state",
        "token_type",
    ];
    let mut out = Map::new();
    for k in KEYS {
        if let Some(v) = input.get(*k) {
            out.insert(k.to_string(), v.clone());
        }
    }
    out
}

/// querystring.escape (also used by querystring.stringify for form bodies).
fn qs_escape(s: &str) -> String {
    const SET: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
        .remove(b'-')
        .remove(b'.')
        .remove(b'_')
        .remove(b'~')
        .remove(b'!')
        .remove(b'*')
        .remove(b'\'')
        .remove(b'(')
        .remove(b')');
    percent_encoding::utf8_percent_encode(s, SET).to_string()
}

/// encodeURIComponent(value).replace(/%20/g, "+")
fn form_url_encode(s: &str) -> String {
    qs_escape(s).replace("%20", "+")
}

fn decode_segment(seg: &str) -> Result<Value, ()> {
    let bytes = crate::util::b64_decode_lenient(seg);
    serde_json::from_str::<Value>(&String::from_utf8_lossy(&bytes)).map_err(|_| ())
}

/// TokenSet#claims()
pub fn token_set_claims(ts: &TokenSet) -> Result<Map<String, Value>, OidcError> {
    if !truthy(ts.get("id_token")) {
        return Err(type_err("id_token not present in TokenSet"));
    }
    let tok = js_str(ts.get("id_token"));
    let part = tok.split('.').nth(1).unwrap_or("");
    match decode_segment(part) {
        Ok(Value::Object(m)) => Ok(m),
        Ok(_) => Ok(Map::new()),
        Err(_) => Err(OidcError { name: "SyntaxError", message: "Unexpected token in JSON".into() }),
    }
}

struct ValidatedJwt {
    header: Map<String, Value>,
    payload: Map<String, Value>,
    crv: Option<String>,
}

fn kty_from_alg(alg: &str) -> Option<&'static str> {
    match alg.get(..2) {
        Some("RS") | Some("PS") => Some("RSA"),
        Some("ES") => Some("EC"),
        Some("Ed") => Some("OKP"),
        _ => None,
    }
}

fn algorithms_for(use_: Option<&str>, alg: Option<&str>, kty: &str, crv: Option<&str>) -> Result<HashSet<String>, ()> {
    if let Some(a) = alg {
        return Ok([a.to_string()].into());
    }
    let mut out: Vec<&str> = vec![];
    match kty {
        "EC" => {
            if use_ == Some("enc") || use_.is_none() {
                out.extend(["ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"]);
            }
            if use_ == Some("sig") || use_.is_none() {
                match crv {
                    Some("P-256") => out.push("ES256"),
                    Some("P-384") => out.push("ES384"),
                    Some("P-521") => out.push("ES512"),
                    Some("secp256k1") => out.push("ES256K"),
                    _ => {}
                }
            }
        }
        "OKP" => out.extend(["ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"]),
        "RSA" => {
            if use_ == Some("enc") || use_.is_none() {
                out.extend(["RSA-OAEP", "RSA-OAEP-256", "RSA-OAEP-384", "RSA-OAEP-512", "RSA1_5"]);
            }
            if use_ == Some("sig") || use_.is_none() {
                out.extend(["PS256", "PS384", "PS512", "RS256", "RS384", "RS512"]);
            }
        }
        _ => return Err(()),
    }
    Ok(out.into_iter().map(str::to_string).collect())
}

/// KeyStore.fromJWKS(jwks, { onlyPublic: true })
fn keystore_from_jwks(jwks: &Value) -> Result<Vec<KeyEntry>, OidcError> {
    let bad = || type_err("jwks must be a JSON Web Key Set formatted object");
    let Value::Object(set) = jwks else { return Err(bad()) };
    let Some(Value::Array(keys)) = set.get("keys") else { return Err(bad()) };
    if keys.iter().any(|k| !matches!(k, Value::Object(m) if m.contains_key("kty"))) {
        return Err(bad());
    }
    let mut out = vec![];
    for k in keys {
        let mut jwk = k.as_object().cloned().unwrap_or_default();
        let Some(kty) = jwk.get("kty").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).map(str::to_string) else {
            continue;
        };
        let crv = jwk.get("crv").and_then(|v| v.as_str()).map(str::to_string);
        let mut use_ = match jwk.get("use") {
            None => None,
            Some(Value::String(s)) if s == "sig" || s == "enc" => Some(s.clone()),
            Some(_) => continue,
        };
        let mut alg = match jwk.get("alg") {
            None => None,
            Some(Value::String(s)) => Some(s.clone()),
            Some(_) => continue,
        };
        if !matches!(jwk.get("kid"), None | Some(Value::String(_))) {
            continue;
        }
        if kty == "EC" && use_.as_deref() == Some("sig") {
            match crv.as_deref() {
                Some("P-256") => alg = Some("ES256".into()),
                Some("P-384") => alg = Some("ES384".into()),
                Some("P-521") => alg = Some("ES512".into()),
                _ => {}
            }
        }
        if crv.as_deref() == Some("secp256k1") {
            use_ = Some("sig".into());
            alg = Some("ES256K".into());
        }
        if kty == "OKP" {
            match crv.as_deref() {
                Some("Ed25519") | Some("Ed448") => {
                    use_ = Some("sig".into());
                    alg = Some("EdDSA".into());
                }
                Some("X25519") | Some("X448") => use_ = Some("enc".into()),
                _ => {}
            }
        }
        if let (Some(a), None) = (&alg, &use_) {
            if a.starts_with("ECDH") || a.starts_with("RSA") {
                use_ = Some("enc".into());
            }
        }
        if jwk.contains_key("d") && truthy(jwk.get("d")) || jwk.contains_key("k") && truthy(jwk.get("k")) {
            continue;
        }
        match &alg {
            Some(a) => jwk.insert("alg".into(), Value::String(a.clone())),
            None => jwk.remove("alg"),
        };
        match &use_ {
            Some(u) => jwk.insert("use".into(), Value::String(u.clone())),
            None => jwk.remove("use"),
        };
        let algorithms = algorithms_for(use_.as_deref(), alg.as_deref(), &kty, crv.as_deref());
        out.push(KeyEntry { jwk, algorithms });
    }
    Ok(out)
}

/// KeyStore#all({ alg, kid, use: "sig" }) → indexes, sorted by key score.
fn keystore_all(keys: &[KeyEntry], alg: &str, kid: Option<&str>) -> Result<Vec<usize>, OidcError> {
    let kty = kty_from_alg(alg);
    let mut out = vec![];
    for (i, key) in keys.iter().enumerate() {
        let jwk_str = |k: &str| key.jwk.get(k).and_then(|v| v.as_str());
        let mut candidate = true;
        if kty.is_some() && jwk_str("kty") != kty {
            candidate = false;
        }
        if candidate && kid.is_some() && jwk_str("kid") != kid {
            candidate = false;
        }
        if candidate && jwk_str("use").is_some() && jwk_str("use") != Some("sig") {
            candidate = false;
        }
        let key_alg = jwk_str("alg").filter(|a| !a.is_empty());
        if candidate && key_alg.is_some() && key_alg != Some(alg) {
            candidate = false;
        } else {
            match &key.algorithms {
                Ok(set) if set.contains(alg) => {}
                Ok(_) => candidate = false,
                Err(()) => return Err(plain("unreachable")),
            }
        }
        if candidate {
            out.push(i);
        }
    }
    let score = |i: &usize| {
        let k = &keys[*i];
        k.jwk.get("alg").map(|v| truthy(Some(v))).unwrap_or(false) as i32
            + k.jwk.get("use").map(|v| truthy(Some(v))).unwrap_or(false) as i32
    };
    out.sort_by_key(|i| std::cmp::Reverse(score(i)));
    Ok(out)
}

/// Build a verification key the way jose would accept it (incl. its key checks).
fn decoding_key(jwk: &Map<String, Value>, alg: &str) -> Option<jsonwebtoken::DecodingKey> {
    let s = |k: &str| jwk.get(k).and_then(|v| v.as_str());
    match s("kty")? {
        "RSA" => {
            let n = crate::util::b64_decode_lenient(s("n")?);
            let first = n.iter().position(|b| *b != 0)?;
            let bits = (n.len() - first) * 8 - n[first].leading_zeros() as usize;
            if bits < 2048 {
                return None;
            }
            jsonwebtoken::DecodingKey::from_rsa_components(s("n")?, s("e")?).ok()
        }
        "EC" => {
            let want = match alg {
                "ES256" => "P-256",
                "ES384" => "P-384",
                "ES512" => "P-521",
                _ => return None,
            };
            if s("crv")? != want {
                return None;
            }
            jsonwebtoken::DecodingKey::from_ec_components(s("x")?, s("y")?).ok()
        }
        "OKP" => {
            if alg != "EdDSA" || s("crv")? != "Ed25519" {
                return None;
            }
            jsonwebtoken::DecodingKey::from_ed_components(s("x")?).ok()
        }
        _ => None,
    }
}

fn verify_signature(jwt: &str, alg: &str, key: &jsonwebtoken::DecodingKey) -> bool {
    use std::str::FromStr;
    let Ok(a) = jsonwebtoken::Algorithm::from_str(alg) else { return false };
    let Some((message, signature)) = jwt.rsplit_once('.') else { return false };
    jsonwebtoken::crypto::verify(signature, message.as_bytes(), key, a).unwrap_or(false)
}

/// oidc-token-hash validate
fn validate_token_hash(claim: &str, source_name: &str, actual: Option<&Value>, source: &str, alg: &str, crv: Option<&str>) -> Result<(), OidcError> {
    let actual = match actual {
        Some(Value::String(s)) if !s.is_empty() => s.clone(),
        _ => return Err(rp(format!("{claim} must be a non-empty string"))),
    };
    if source.is_empty() {
        return Err(rp(format!("{source_name} must be a non-empty string")));
    }
    let digest: Result<Vec<u8>, String> = match alg {
        "HS256" | "RS256" | "PS256" | "ES256" | "ES256K" => Ok(sha2::Sha256::digest(source.as_bytes()).to_vec()),
        "HS384" | "RS384" | "PS384" | "ES384" => Ok(sha2::Sha384::digest(source.as_bytes()).to_vec()),
        "HS512" | "RS512" | "PS512" | "ES512" | "Ed25519" => Ok(sha2::Sha512::digest(source.as_bytes()).to_vec()),
        "EdDSA" => match crv {
            Some("Ed25519") => Ok(sha2::Sha512::digest(source.as_bytes()).to_vec()),
            _ => Err("unrecognized or invalid EdDSA curve provided".into()),
        },
        _ => Err("unrecognized or invalid JWS algorithm provided".into()),
    };
    match digest {
        Ok(d) => {
            let expected = crate::util::b64url(&d[..d.len() / 2]);
            if expected != actual {
                return Err(rp(format!("{claim} mismatch, expected {expected}, got: {actual}")));
            }
            Ok(())
        }
        Err(e) => Err(rp(format!("{claim} could not be validated ({e})"))),
    }
}

impl Client {
    fn meta_str(&self, key: &str) -> Option<&str> {
        self.metadata.get(key).and_then(|v| v.as_str()).filter(|s| !s.is_empty())
    }

    fn require_endpoint(&self, key: &str) -> Result<&str, OidcError> {
        if !truthy(self.metadata.get(key)) {
            return Err(type_err(format!("{key} must be configured on the issuer")));
        }
        self.meta_str(key).ok_or_else(|| type_err("only valid absolute URLs can be requested"))
    }

    /// client.authorizationUrl(params)
    pub fn authorization_url(&self, params: &[(&str, &str)]) -> Result<String, OidcError> {
        let endpoint = self.require_endpoint("authorization_endpoint")?;
        let mut target = url::Url::parse(endpoint).map_err(|_| type_err("Invalid URL"))?;
        let mut all: Vec<(String, String)> = vec![
            ("client_id".into(), self.client_id.clone()),
            ("scope".into(), "openid".into()),
            ("response_type".into(), "code".into()),
            ("redirect_uri".into(), self.redirect_uri.clone()),
        ];
        for (k, v) in params {
            match all.iter_mut().find(|(ek, _)| ek == k) {
                Some(e) => e.1 = v.to_string(),
                None => all.push((k.to_string(), v.to_string())),
            }
        }
        // URLSearchParams#set on the endpoint's existing query.
        let mut pairs: Vec<(String, String)> = target.query_pairs().map(|(k, v)| (k.into_owned(), v.into_owned())).collect();
        for (k, v) in all {
            match pairs.iter().position(|(pk, _)| *pk == k) {
                Some(i) => {
                    pairs[i].1 = v;
                    let mut j = i + 1;
                    while j < pairs.len() {
                        if pairs[j].0 == k {
                            pairs.remove(j);
                        } else {
                            j += 1;
                        }
                    }
                }
                None => pairs.push((k, v)),
            }
        }
        let query = url::form_urlencoded::Serializer::new(String::new()).extend_pairs(pairs).finish();
        target.set_query(if query.is_empty() { None } else { Some(&query) });
        Ok(target.as_str().replace('+', "%20"))
    }

    /// client.callback(redirectUri, params, checks)
    pub async fn callback(&self, params: &Map<String, Value>, checks: &Checks) -> Result<TokenSet, OidcError> {
        let params = pick_callback_params(params);
        if params.contains_key("response") {
            return Err(rp("JWT-secured authorization responses are not supported"));
        }
        if !truthy(params.get("state")) {
            return Err(rp("state missing from the response"));
        }
        if !is_str(params.get("state"), &checks.state) {
            return Err(rp(format!("state mismatch, expected {}, got: {}", checks.state, js_str(params.get("state")))));
        }
        if params.contains_key("iss") {
            let Some(issuer) = self.issuer.as_deref().filter(|s| !s.is_empty()) else {
                return Err(type_err("issuer must be configured on the issuer"));
            };
            if !is_str(params.get("iss"), issuer) {
                return Err(rp(format!("iss mismatch, expected {issuer}, got: {}", js_str(params.get("iss")))));
            }
        } else if truthy(self.metadata.get("authorization_response_iss_parameter_supported")) && !params.contains_key("id_token") {
            return Err(rp("iss missing from the response"));
        }
        if truthy(params.get("error")) {
            return Err(op_error_from_body(&params));
        }
        if truthy(params.get("id_token")) {
            let ts = params.clone();
            self.validate_id_token(&ts, &checks.nonce, true, Some(&checks.state)).await?;
            if !truthy(params.get("code")) {
                return Ok(ts);
            }
        }
        if truthy(params.get("code")) {
            let code = js_str(params.get("code"));
            let ts = self.grant(&code, &checks.code_verifier).await?;
            self.validate_id_token(&ts, &checks.nonce, false, None).await?;
            let mut ts = ts;
            if truthy(params.get("session_state")) {
                ts.insert("session_state".into(), params["session_state"].clone());
            }
            return Ok(ts);
        }
        Ok(params)
    }

    /// client.grant({ grant_type: "authorization_code", ... }) via authenticatedPost.
    async fn grant(&self, code: &str, code_verifier: &str) -> Result<TokenSet, OidcError> {
        let endpoint = self.require_endpoint("token_endpoint")?;
        let mut form: Vec<(&str, String)> = vec![
            ("grant_type", "authorization_code".into()),
            ("code", code.into()),
            ("redirect_uri", self.redirect_uri.clone()),
            ("code_verifier", code_verifier.into()),
        ];
        let mut basic: Option<String> = None;
        match self.token_endpoint_auth_method.as_str() {
            "none" | "self_signed_tls_client_auth" | "tls_client_auth" => form.push(("client_id", self.client_id.clone())),
            "client_secret_post" => {
                let Some(secret) = &self.client_secret else {
                    return Err(type_err("client_secret_post client authentication method requires a client_secret"));
                };
                form.push(("client_id", self.client_id.clone()));
                form.push(("client_secret", secret.clone()));
            }
            "client_secret_basic" => {
                let Some(secret) = &self.client_secret else {
                    return Err(type_err("client_secret_basic client authentication method requires a client_secret"));
                };
                let encoded = format!("{}:{}", form_url_encode(&self.client_id), form_url_encode(secret));
                basic = Some(format!("Basic {}", crate::util::b64_std(encoded.as_bytes())));
            }
            _ => return Err(type_err("missing, or unsupported, token_endpoint_auth_method")),
        }
        let body = form.iter().map(|(k, v)| format!("{}={}", qs_escape(k), qs_escape(v))).collect::<Vec<_>>().join("&");
        let url = check_url(endpoint)?;
        let mut rb = http()
            .post(url)
            .header("Accept", "application/json")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(body);
        if let Some(b) = basic {
            rb = rb.header("Authorization", b);
        }
        let res = send(rb).await?;
        match process_response(&res, false)? {
            Value::Object(m) => Ok(m),
            _ => Ok(Map::new()),
        }
    }

    /// client.validateIdToken(tokenSet, nonce, returnedBy, undefined, state)
    async fn validate_id_token(&self, ts: &TokenSet, nonce: &str, by_authorization: bool, state: Option<&str>) -> Result<(), OidcError> {
        if !truthy(ts.get("id_token")) {
            return Err(type_err("id_token not present in TokenSet"));
        }
        let id_token = js_str(ts.get("id_token"));
        let ValidatedJwt { header, payload, crv } = self.validate_jwt(&id_token).await?;
        let header_alg = js_str(header.get("alg"));
        if !is_str(payload.get("nonce"), nonce) {
            return Err(rp(format!("nonce mismatch, expected {nonce}, got: {}", js_str(payload.get("nonce")))));
        }
        if by_authorization {
            if !truthy(payload.get("at_hash")) && truthy(ts.get("access_token")) {
                return Err(rp("missing required property at_hash"));
            }
            if !truthy(payload.get("c_hash")) && truthy(ts.get("code")) {
                return Err(rp("missing required property c_hash"));
            }
            if truthy(payload.get("s_hash")) {
                let Some(state) = state else {
                    return Err(type_err("cannot verify s_hash, \"checks.state\" property not provided"));
                };
                validate_token_hash("s_hash", "state", payload.get("s_hash"), state, &header_alg, crv.as_deref())?;
            }
        }
        if truthy(ts.get("access_token")) && payload.contains_key("at_hash") {
            let source = js_str(ts.get("access_token"));
            validate_token_hash("at_hash", "access_token", payload.get("at_hash"), &source, &header_alg, crv.as_deref())?;
        }
        if truthy(ts.get("code")) && payload.contains_key("c_hash") {
            let source = js_str(ts.get("code"));
            validate_token_hash("c_hash", "code", payload.get("c_hash"), &source, &header_alg, crv.as_deref())?;
        }
        Ok(())
    }

    /// client.validateJWT(jwt, expectedAlg)
    async fn validate_jwt(&self, jwt: &str) -> Result<ValidatedJwt, OidcError> {
        let expected_alg = &self.id_token_signed_response_alg;
        let timestamp = now_secs();
        let parts: Vec<&str> = jwt.split('.').collect();
        let decoded = if jwt.is_empty() {
            Err("TypeError: JWT must be a string".to_string())
        } else if parts.len() == 5 {
            Err("TypeError: encrypted JWTs cannot be decoded".to_string())
        } else if parts.len() != 3 {
            Err("Error: JWTs must have three components".to_string())
        } else {
            match (decode_segment(parts[0]), decode_segment(parts[1])) {
                (Ok(h), Ok(p)) => Ok((h, p)),
                _ => Err("Error: JWT is malformed".to_string()),
            }
        };
        let (header, payload) = decoded.map_err(|e| rp(format!("failed to decode JWT ({e})")))?;
        let header = header.as_object().cloned().unwrap_or_default();
        let payload = payload.as_object().cloned().unwrap_or_default();
        if !is_str(header.get("alg"), expected_alg) {
            return Err(rp(format!(
                "unexpected JWT alg received, expected {expected_alg}, got: {}",
                js_str(header.get("alg"))
            )));
        }
        for prop in ["iss", "sub", "aud", "exp", "iat"] {
            if !payload.contains_key(prop) {
                return Err(rp(format!("missing required JWT property {prop}")));
            }
        }
        if let Some(iss) = payload.get("iss") {
            let expected = self.issuer.as_deref();
            if expected.is_none() || !is_str(Some(iss), expected.unwrap_or_default()) {
                return Err(rp(format!(
                    "unexpected iss value, expected {}, got: {}",
                    expected.unwrap_or("undefined"),
                    js_str(Some(iss))
                )));
            }
        }
        if let Some(iat) = payload.get("iat") {
            if !iat.is_number() {
                return Err(rp("JWT iat claim must be a JSON numeric value"));
            }
        }
        if let Some(nbf) = payload.get("nbf") {
            let Some(n) = nbf.as_f64() else { return Err(rp("JWT nbf claim must be a JSON numeric value")) };
            if n > timestamp {
                return Err(rp(format!("JWT not active yet, now {timestamp}, nbf {}", js_str(Some(nbf)))));
            }
        }
        if let Some(exp) = payload.get("exp") {
            let Some(e) = exp.as_f64() else { return Err(rp("JWT exp claim must be a JSON numeric value")) };
            if timestamp >= e {
                return Err(rp(format!("JWT expired, now {timestamp}, exp {}", js_str(Some(exp)))));
            }
        }
        if let Some(aud) = payload.get("aud") {
            match aud {
                Value::Array(a) => {
                    if a.len() > 1 && !truthy(payload.get("azp")) {
                        return Err(rp("missing required JWT property azp"));
                    }
                    if !a.iter().any(|v| v.as_str() == Some(self.client_id.as_str())) {
                        return Err(rp(format!(
                            "aud is missing the client_id, expected {} to be included in {}",
                            self.client_id, aud
                        )));
                    }
                }
                other => {
                    if other.as_str() != Some(self.client_id.as_str()) {
                        return Err(rp(format!("aud mismatch, expected {}, got: {}", self.client_id, js_str(Some(other)))));
                    }
                }
            }
        }
        if let Some(azp) = payload.get("azp") {
            if azp.as_str() != Some(self.client_id.as_str()) {
                return Err(rp(format!("azp mismatch, got: {}", js_str(Some(azp)))));
            }
        }
        let alg = expected_alg.as_str();
        if alg.starts_with("HS") {
            let Some(secret) = &self.client_secret else { return Err(type_err("client_secret is required")) };
            let key = jsonwebtoken::DecodingKey::from_secret(secret.as_bytes());
            if verify_signature(jwt, alg, &key) {
                return Ok(ValidatedJwt { header, payload, crv: None });
            }
            return Err(rp("failed to validate JWT signature"));
        }
        if alg == "none" {
            return Ok(ValidatedJwt { header, payload, crv: None });
        }
        let kid = header.get("kid").and_then(|v| v.as_str()).map(str::to_string);
        let kty = header.get("kty").map(|v| v.to_string());
        let (keys, idxs) = self.query_keystore(alg, kid.as_deref(), kty.as_deref()).await?;
        for i in idxs {
            let jwk = &keys[i].jwk;
            if let Some(key) = decoding_key(jwk, alg) {
                if verify_signature(jwt, alg, &key) {
                    let crv = jwk.get("crv").and_then(|v| v.as_str()).map(str::to_string);
                    return Ok(ValidatedJwt { header, payload, crv });
                }
            }
        }
        Err(rp("failed to validate JWT signature"))
    }

    /// helpers/issuer.js queryKeyStore (+ getKeyStore with its 60s refresh throttle).
    async fn query_keystore(&self, alg: &str, kid: Option<&str>, kty: Option<&str>) -> Result<(Arc<Vec<KeyEntry>>, Vec<usize>), OidcError> {
        let def_hash = format!("{kid:?}|{kty:?}|{alg}|sig");
        let mut cache = self.jwks.lock().await;
        let throttled = cache.throttle_until.map(|t| Instant::now() < t).unwrap_or(false);
        let fresh = cache.seen.contains(&def_hash) || throttled;
        if !fresh || cache.keys.is_none() {
            let uri = self.require_endpoint("jwks_uri")?.to_string();
            cache.seen.clear();
            cache.throttle_until = None;
            let url = check_url(&uri)?;
            let res = send(http().get(url).header("Accept", "application/json, application/jwk-set+json")).await?;
            let jwks = process_response(&res, false)?;
            let keys = keystore_from_jwks(&jwks)?;
            cache.throttle_until = Some(Instant::now() + Duration::from_secs(60));
            cache.keys = Some(Arc::new(keys));
        }
        let keys = cache.keys.clone().unwrap();
        let idxs = keystore_all(&keys, alg, kid)?;
        let mut def = Map::new();
        if let Some(k) = kid {
            def.insert("kid".into(), Value::String(k.into()));
        }
        def.insert("alg".into(), Value::String(alg.into()));
        if idxs.is_empty() {
            return Err(rp(format!("no valid key found in issuer's jwks_uri for key parameters {}", Value::Object(def))));
        }
        if idxs.len() > 1 && kid.is_none() {
            return Err(rp(format!(
                "multiple matching keys found in issuer's jwks_uri for key parameters {}, kid must be provided in this case",
                Value::Object(def)
            )));
        }
        if !cache.seen.contains(&def_hash) {
            if cache.seen.len() >= 100 {
                cache.seen.pop_front();
            }
            cache.seen.push_back(def_hash);
        }
        Ok((keys, idxs))
    }

    /// client.userinfo(tokenSet)
    pub async fn userinfo(&self, ts: &TokenSet) -> Result<Map<String, Value>, OidcError> {
        let endpoint = self.require_endpoint("userinfo_endpoint")?.to_string();
        if !truthy(ts.get("access_token")) {
            return Err(type_err("access_token not present in TokenSet"));
        }
        let Some(Value::String(access_token)) = ts.get("access_token") else {
            return Err(type_err("invalid access token provided"));
        };
        let token_type = js_str(ts.get("token_type"));
        let url = check_url(&endpoint)?;
        let res = send(
            http()
                .get(url)
                .header("Accept", "application/json")
                .header("Authorization", format!("{token_type} {access_token}")),
        )
        .await?;
        process_response(&res, true)?;
        let parsed: Value =
            serde_json::from_slice(&res.body).map_err(|e| OidcError { name: "SyntaxError", message: e.to_string() })?;
        if truthy(ts.get("id_token")) {
            let claims = token_set_claims(ts)?;
            let expected = claims.get("sub");
            let got = parsed.get("sub");
            if expected != got {
                return Err(rp(format!("userinfo sub mismatch, expected {}, got: {}", js_str(expected), js_str(got))));
            }
        }
        Ok(parsed.as_object().cloned().unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn canonicalizes_issuers() {
        assert_eq!(canonicalize_issuer_url(" https://id.example.test/realms/x/ "), "https://id.example.test/realms/x");
        assert_eq!(canonicalize_issuer_url("https://id.example.test/"), "https://id.example.test");
        assert_eq!(canonicalize_issuer_url("not a url//"), "not a url");
    }

    #[test]
    fn well_known_resolution() {
        assert_eq!(resolve_well_known_uri("https://id.test/realms/a"), "https://id.test/realms/a/.well-known/openid-configuration");
        assert_eq!(resolve_well_known_uri("https://id.test/"), "https://id.test/.well-known/openid-configuration");
        assert_eq!(resolve_well_known_uri("https://id.test/x/.well-known/custom"), "https://id.test/x/.well-known/custom");
    }

    #[test]
    fn alg_resolution_matches_upstream() {
        let m = |v: Value| v.as_object().unwrap().clone();
        assert_eq!(resolve_id_token_signed_response_alg(Some("PS384"), false, &Map::new()).unwrap(), "PS384");
        assert_eq!(resolve_id_token_signed_response_alg(None, false, &Map::new()).unwrap(), "RS256");
        assert_eq!(
            resolve_id_token_signed_response_alg(None, false, &m(json!({"id_token_signing_alg_values_supported": ["HS256", "ES256", "RS256"]}))).unwrap(),
            "RS256"
        );
        assert_eq!(
            resolve_id_token_signed_response_alg(None, false, &m(json!({"id_token_signing_alg_values_supported": ["ES512K", "HS256"]}))).unwrap(),
            "ES512K"
        );
        assert!(resolve_id_token_signed_response_alg(None, false, &m(json!({"id_token_signing_alg_values_supported": ["HS256"]}))).is_err());
        assert_eq!(
            resolve_id_token_signed_response_alg(None, true, &m(json!({"id_token_signing_alg_values_supported": ["HS512", "HS384"]}))).unwrap(),
            "HS384"
        );
    }

    #[test]
    fn alg_mismatch_parsing() {
        assert_eq!(
            parse_jwt_alg_mismatch_error("unexpected JWT alg received, expected RS256, got: HS256"),
            Some(("RS256".into(), "HS256".into()))
        );
        assert_eq!(parse_jwt_alg_mismatch_error("expected 200 OK, got: 400 Bad Request"), None);
        assert!(can_use_id_token_signing_alg("RS256", false));
        assert!(!can_use_id_token_signing_alg("HS256", false));
        assert!(!can_use_id_token_signing_alg("NONE", true));
    }

    #[test]
    fn token_endpoint_auth_selection() {
        let basic = json!(["client_secret_basic"]);
        assert_eq!(select_token_endpoint_auth_method(true, Some(&basic), None).unwrap(), "client_secret_basic");
        let post = json!(["client_secret_post"]);
        assert_eq!(select_token_endpoint_auth_method(true, Some(&post), None).unwrap(), "client_secret_post");
        assert!(select_token_endpoint_auth_method(false, Some(&basic), None).is_err());
        assert_eq!(select_token_endpoint_auth_method(false, None, None).unwrap(), "none");
        assert!(select_token_endpoint_auth_method(true, Some(&basic), Some("client_secret_post")).is_err());
        assert_eq!(select_token_endpoint_auth_method(true, Some(&json!([])), Some("none")).unwrap(), "none");
    }

    #[test]
    fn token_hashes() {
        // RFC-style example: at_hash for "jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y" with RS256.
        let src = "jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y";
        let d = sha2::Sha256::digest(src.as_bytes());
        let expected = crate::util::b64url(&d[..16]);
        assert!(validate_token_hash("at_hash", "access_token", Some(&json!(expected)), src, "RS256", None).is_ok());
        assert!(validate_token_hash("at_hash", "access_token", Some(&json!("nope")), src, "RS256", None).is_err());
        assert!(validate_token_hash("at_hash", "access_token", Some(&json!("x")), src, "EdDSA", None).is_err());
    }

    #[test]
    fn keystore_filters_like_openid_client() {
        let jwks = json!({"keys": [
            {"kty": "RSA", "kid": "a", "use": "enc", "n": "x", "e": "AQAB"},
            {"kty": "RSA", "kid": "b", "n": "x", "e": "AQAB"},
            {"kty": "RSA", "kid": "c", "alg": "RS256", "use": "sig", "n": "x", "e": "AQAB"},
            {"kty": "EC", "kid": "d", "crv": "P-256", "use": "sig", "x": "x", "y": "y"},
            {"kty": "oct", "kid": "e", "k": "secret"}
        ]});
        let keys = keystore_from_jwks(&jwks).unwrap();
        assert_eq!(keys.len(), 4);
        let idx = keystore_all(&keys, "RS256", None).unwrap();
        let kids: Vec<&str> = idx.iter().map(|i| keys[*i].jwk["kid"].as_str().unwrap()).collect();
        assert_eq!(kids, vec!["c", "b"]);
        let idx = keystore_all(&keys, "ES256", None).unwrap();
        assert_eq!(idx.len(), 1);
        assert!(keystore_from_jwks(&json!({"keys": [{"kid": "x"}]})).is_err());
    }

    #[test]
    fn form_encoding() {
        assert_eq!(form_url_encode("a b+c:d"), "a+b%2Bc%3Ad");
        assert_eq!(qs_escape("a b!*'()~"), "a%20b!*'()~");
    }
}
