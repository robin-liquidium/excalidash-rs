//! JWT signing/verification compatible with node `jsonwebtoken` (HS256).
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde_json::{Map, Value};

use crate::config::config;

/// Payload carried by access/refresh tokens (middleware/auth.ts JwtPayload).
#[derive(Debug, Clone)]
pub struct JwtPayload {
    pub user_id: String,
    pub email: String,
    pub token_type: String,
    pub impersonator_id: Option<String>,
    pub auth_provider: Option<String>,
    pub oidc_groups: Option<Vec<String>>,
    pub raw: Map<String, Value>,
}

pub fn decode_any(token: &str, secret: &str) -> Option<Map<String, Value>> {
    let mut v = Validation::new(Algorithm::HS256);
    v.algorithms = vec![Algorithm::HS256, Algorithm::HS384, Algorithm::HS512];
    v.leeway = 0;
    v.validate_exp = true;
    v.validate_nbf = true;
    v.required_spec_claims.clear();
    v.validate_aud = false;
    decode::<Map<String, Value>>(token, &DecodingKey::from_secret(secret.as_bytes()), &v)
        .ok()
        .map(|d| d.claims)
}

/// `isJwtPayload` from middleware/auth.ts (`check_impersonator` is false for auth.ts' variant).
pub fn parse_payload(claims: Map<String, Value>, check_impersonator: bool) -> Option<JwtPayload> {
    let user_id = claims.get("userId")?.as_str()?.to_string();
    let email = claims.get("email")?.as_str()?.to_string();
    let token_type = claims.get("type")?.as_str()?.to_string();
    if token_type != "access" && token_type != "refresh" {
        return None;
    }
    let impersonator_id = match claims.get("impersonatorId") {
        None => None,
        Some(Value::String(s)) => Some(s.clone()),
        Some(_) if check_impersonator => return None,
        Some(_) => None,
    };
    let auth_provider = match claims.get("authProvider") {
        None => None,
        Some(Value::String(s)) if s == "local" || s == "oidc" => Some(s.clone()),
        Some(_) => return None,
    };
    let oidc_groups = match claims.get("oidcGroups") {
        None => None,
        Some(Value::Array(a)) => {
            let mut out = vec![];
            for g in a {
                out.push(g.as_str()?.to_string());
            }
            Some(out)
        }
        Some(_) => return None,
    };
    Some(JwtPayload { user_id, email, token_type, impersonator_id, auth_provider, oidc_groups, raw: claims })
}

/// middleware/auth.ts verifyToken: valid signature + access type.
pub fn verify_access_token(token: &str) -> Option<JwtPayload> {
    let claims = decode_any(token, &config().jwt_secret)?;
    let p = parse_payload(claims, true)?;
    (p.token_type == "access").then_some(p)
}

pub struct TokenOptions {
    pub impersonator_id: Option<String>,
    pub auth_provider: Option<String>,
    pub oidc_groups: Option<Vec<String>>,
}

impl Default for TokenOptions {
    fn default() -> Self {
        TokenOptions { impersonator_id: None, auth_provider: None, oidc_groups: None }
    }
}

fn sign(claims: &Map<String, Value>) -> String {
    let mut header = Header::new(Algorithm::HS256);
    header.typ = Some("JWT".into());
    encode(&header, claims, &EncodingKey::from_secret(config().jwt_secret.as_bytes())).expect("jwt encode")
}

fn expires_seconds(expires_in: &str) -> Option<i64> {
    // jsonwebtoken `timespan`: strings go through `ms`, numbers are seconds.
    if let Ok(n) = expires_in.trim().parse::<f64>() {
        if expires_in.trim().chars().all(|c| c.is_ascii_digit()) {
            // A purely numeric string is treated by `ms` as milliseconds.
            return Some((n / 1000.0).floor() as i64);
        }
    }
    crate::util::parse_ms(expires_in).map(|ms| (ms / 1000.0).floor() as i64)
}

/// auth.ts generateTokens
pub fn generate_tokens(user_id: &str, email: &str, opts: TokenOptions) -> (String, String) {
    let cfg = config();
    let auth_provider = opts.auth_provider.unwrap_or_else(|| "local".into());
    let groups: Option<Vec<String>> = if auth_provider == "oidc" {
        let mut seen = vec![];
        for g in opts.oidc_groups.unwrap_or_default() {
            let t = g.trim().to_string();
            if !t.is_empty() && !seen.contains(&t) {
                seen.push(t);
            }
        }
        seen.truncate(100);
        Some(seen)
    } else {
        None
    };
    let now = chrono::Utc::now().timestamp();
    let build = |kind: &str, expires_in: &str| {
        let mut m = Map::new();
        m.insert("userId".into(), Value::String(user_id.into()));
        m.insert("email".into(), Value::String(email.into()));
        if let Some(i) = &opts.impersonator_id {
            m.insert("impersonatorId".into(), Value::String(i.clone()));
        }
        m.insert("authProvider".into(), Value::String(auth_provider.clone()));
        if let Some(g) = &groups {
            m.insert("oidcGroups".into(), Value::Array(g.iter().cloned().map(Value::String).collect()));
        }
        m.insert("type".into(), Value::String(kind.into()));
        m.insert("iat".into(), Value::from(now));
        if let Some(secs) = expires_seconds(expires_in) {
            m.insert("exp".into(), Value::from(now + secs));
        }
        m.insert("jti".into(), Value::String(crate::util::uuid_v4()));
        sign(&m)
    };
    (build("access", &cfg.jwt_access_expires_in), build("refresh", &cfg.jwt_refresh_expires_in))
}

/// Sign arbitrary claims with the app secret (used by OIDC state cookies etc.).
pub fn sign_claims(claims: &Map<String, Value>) -> String {
    sign(claims)
}
