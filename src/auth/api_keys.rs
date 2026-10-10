//! auth/apiKeys.ts — scrypt-hashed API keys with a server-side pepper.
use crate::config::config;
use crate::util;

pub const API_KEY_PREFIX: &str = "exd_";
pub const DEFAULT_API_KEY_SCOPES: [&str; 4] =
    ["drawings:read", "drawings:write", "collections:read", "collections:write"];

pub struct GeneratedApiKey {
    pub token: String,
    pub key_id: String,
    pub prefix: String,
    pub token_hash: String,
}

pub fn generate_api_key() -> GeneratedApiKey {
    let key_id = util::b64url(&util::random_bytes(12));
    let secret = util::b64url(&util::random_bytes(32));
    let token = format!("{API_KEY_PREFIX}{key_id}_{secret}");
    GeneratedApiKey {
        prefix: util::js_slice(&token, 16),
        token_hash: hash_api_key(&token),
        key_id,
        token,
    }
}

/// scrypt(token, pepper, N=2^14, r=8, p=1, keylen=32) → hex. CPU/memory heavy (16 MiB);
/// call from a blocking context.
pub fn hash_api_key(token: &str) -> String {
    let params = scrypt::Params::new(14, 8, 1).expect("scrypt params");
    let mut out = [0u8; 32];
    scrypt::scrypt(token.as_bytes(), config().api_key_hash_pepper.as_bytes(), &params, &mut out)
        .expect("scrypt");
    hex::encode(out)
}

pub fn is_api_key_token(token: &str) -> bool {
    token.starts_with(API_KEY_PREFIX)
}

pub fn extract_api_key_id(token: &str) -> Option<String> {
    let rest = token.strip_prefix(API_KEY_PREFIX)?;
    let chars: Vec<char> = rest.chars().collect();
    let sep = if chars.get(16) == Some(&'_') { Some(16) } else { chars.iter().position(|c| *c == '_') };
    let sep = sep.filter(|i| *i > 0)?;
    let key_id: String = chars[..sep].iter().collect();
    let ok = (8..=64).contains(&key_id.len())
        && key_id.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    ok.then_some(key_id)
}

pub fn api_key_hash_matches(token: &str, stored_hash: &str) -> bool {
    let computed = hex::decode(hash_api_key(token)).unwrap_or_default();
    // Buffer.from(hex) stops at the first invalid pair.
    let stored = decode_hex_lenient(stored_hash);
    util::constant_time_eq(&computed, &stored)
}

fn decode_hex_lenient(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = vec![];
    let mut i = 0;
    while i + 1 < b.len() {
        match u8::from_str_radix(&s[i..i + 2], 16) {
            Ok(v) => out.push(v),
            Err(_) => break,
        }
        i += 2;
    }
    out
}

pub fn serialize_scopes(scopes: &[String]) -> String {
    scopes.join(",")
}

pub fn parse_scopes(raw: Option<&str>) -> Vec<String> {
    raw.unwrap_or("").split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()
}

pub fn has_bearer_api_key(authorization: Option<&str>) -> bool {
    let Some(h) = authorization else { return false };
    let mut parts = h.split(' ');
    let scheme = parts.next();
    let token = parts.next();
    scheme == Some("Bearer") && token.map(is_api_key_token).unwrap_or(false)
}
