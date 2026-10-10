//! In-test mock OpenID Provider (discovery, JWKS, token, userinfo) and helpers
//! to drive /auth/oidc/start → /auth/oidc/callback.
#![allow(dead_code)]

use serde_json::{json, Map, Value};
use sha2::Digest;
use std::{
    collections::HashMap,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{Arc, Mutex},
};

use crate::common::{Resp, TestClient};

pub const CLIENT_ID: &str = "excalidash-test";
pub const CLIENT_SECRET: &str = "test-only-oidc-secret";
pub const REDIRECT_URI: &str = "https://app.example.test/auth/oidc/callback";
pub const KID: &str = "test-key";

pub const RSA_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCZUrLKrXO8HQe9
jrTV6/s1yhMVHcAZMsQNW5IaHJwowvBV6MCOxlBldg6Wj1dyNMAQJmT9t55c9eac
0MBvoroqP5DFKQtpXc4EJWHVF2vczrV0MK66jK1hp8tSNcizO1ejfAjpCxDa8dmh
W7pvTg7ZQtby4mCv4oY5CXqe191UsKY+LYP8o6CTCmY+jKIhy3uWLbmsU+FCS5Bn
JS3abR+EXE7kDe/X4Sb8Do7CmQ8OgR4ovCvpSSVFcC6Ygs2pVQi0Gken8JjOeRC4
fmGhQnSHo28FxkIVdx7G0DBmrqtavnATs5eg56TUhTtUErJlqJHYC61GBXN1cPVq
2+iU620NAgMBAAECggEAAPnx1ts76BrB4zHMHQCfsjv92x3mt0Jc1T5Gs+aIErUL
FWuiA5wSWahizLqk8pPmFTQ+uGQ5nJtEQ1i2S6pcR8tCf2mU1QWakOmGsfYFjdET
KWZAoUImvdR1Cv+krjTWiLKlgTZnfmgZMVna2hKZLZurWr3uTQXC7Qy5Edc2EEVS
gy6uB5OPaxUztrbJdh2mEYsBEf8SS/GQROi3o0lElCD4oN5nch5c25DU2EMsJ65z
dAhGGjOLYIlEM5K8UOkVHQ3AnTWN21p39g1TDTzZCRP0IdPn7eRkGNJTDZ/ExvVK
O7gZ73xNxsA/QbKhLUKfjmWbIiCTdrclSmB2ZjEjgQKBgQDOiI1kGtJeUgrb8/LA
4zUx9Qe5P1YXG6ov+zic6f8gHI+6NdGJLaZH9rF0ypJjZeJpIM1cGytuwVNjJWto
0NiUyNiKXYGBrz1/KK1SjN5pSKe7Sy7YhQwNsn7efQ8y7sGjJsjN1Sh5Y+B5ZwDc
Idlv9aie+KoZEMHcpvWQOQIi6QKBgQC+C5czw2Xp76V+ExYXfUrttB6sYxb269P0
lDaop+ZPhRxFCMwoL0E5cRtrFkcHJctncZu2kWZa3N4ut6DeHFTFNzLP691Cu0AU
GuMxfsdAC6rOccaXFLhdN6Mvl70TyMboHWBeFm/gxhlNaQzNVezkvA0Odz9jAcEW
Mg7DgqK6hQKBgARQc+uoZ8aSnil0EhkXZfASN0QWX50B9e8kp00X0j2Aezwfja34
5yVPsOtIpAAxi6Y4ijGnW6Pno+9JQ9IfsraA740MYP0thPJYDi7QRIEchGx0KJlb
RiIvHVlWcW/V7vOShtVN45eNj43ZqfnvNxSQpCIV/a+iWvpZ/n0xw6qpAoGAC50f
t10YjExF28eE0RiqDI62VSiVDa/puweXs4TXMULcMGfSOh5xKPZ9i3TIEGrB3Gd3
8Zc/HwxiU46LOSeYEplF9KjgU6SnzNK70ZmCyaos3QLc9PyiK6grw8vNFTlu1l59
NiK+4YiZoT5rNt0qZewMDDdDW2SPDTEv78i68xUCgYEAxF5veSwZehR7ExvJ3MfR
kGJNLdQPaaRu4boBUYlmH+jO66THzkDQxy53neamDDXxMh0dinaM4HwnZCs6GBCy
fPEr8dniSYTZRvCWk/ZNIARK03uqYRy5X02+IeKdqvVqgDzKnKbvWGaKr7mxUWyO
R2RQRotucpUnS1DF1e44s5s=
-----END PRIVATE KEY-----
";

pub const RSA_N: &str = "mVKyyq1zvB0HvY601ev7NcoTFR3AGTLEDVuSGhycKMLwVejAjsZQZXYOlo9XcjTAECZk_beeXPXmnNDAb6K6Kj-QxSkLaV3OBCVh1Rdr3M61dDCuuoytYafLUjXIsztXo3wI6QsQ2vHZoVu6b04O2ULW8uJgr-KGOQl6ntfdVLCmPi2D_KOgkwpmPoyiIct7li25rFPhQkuQZyUt2m0fhFxO5A3v1-Em_A6OwpkPDoEeKLwr6UklRXAumILNqVUItBpHp_CYznkQuH5hoUJ0h6NvBcZCFXcextAwZq6rWr5wE7OXoOek1IU7VBKyZaiR2AutRgVzdXD1atvolOttDQ";

pub struct CodeEntry {
    pub challenge: String,
    /// Claims to put in the ID token (iss/aud/exp/iat/nonce defaults are added).
    pub claims: Value,
    pub nonce: String,
}

#[derive(Default)]
pub struct IdpState {
    pub discovery_overrides: Map<String, Value>,
    pub codes: HashMap<String, CodeEntry>,
    /// Raw requests seen by the token endpoint: (headers lowercased, body).
    pub token_requests: Vec<(HashMap<String, String>, String)>,
    pub userinfo: Option<Value>,
    pub userinfo_requests: Vec<HashMap<String, String>>,
    pub discovery_hits: usize,
    pub jwks_hits: usize,
    /// When set, the ID token is HS256-signed with this secret instead of RS256.
    pub hs_secret: Option<String>,
}

pub struct MockIdp {
    pub issuer: String,
    pub state: Arc<Mutex<IdpState>>,
}

fn b64url(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

pub fn pkce_challenge(verifier: &str) -> String {
    b64url(&sha2::Sha256::digest(verifier.as_bytes()))
}

impl MockIdp {
    pub fn start() -> MockIdp {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let issuer = format!("http://127.0.0.1:{port}");
        let state = Arc::new(Mutex::new(IdpState::default()));
        let st = state.clone();
        let iss = issuer.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let st = st.clone();
                let iss = iss.clone();
                std::thread::spawn(move || handle(stream, &iss, &st));
            }
        });
        MockIdp { issuer, state }
    }

    pub fn register_code(&self, code: &str, challenge: &str, nonce: &str, claims: Value) {
        self.state
            .lock()
            .unwrap()
            .codes
            .insert(code.into(), CodeEntry { challenge: challenge.into(), claims, nonce: nonce.into() });
    }
}

fn respond(mut s: TcpStream, status: &str, ctype: &str, body: &str) {
    let _ = write!(
        s,
        "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
}

fn form_decode(body: &str) -> HashMap<String, String> {
    url::form_urlencoded::parse(body.as_bytes()).into_owned().collect()
}

fn handle(mut s: TcpStream, issuer: &str, state: &Arc<Mutex<IdpState>>) {
    let mut buf = vec![];
    let mut tmp = [0u8; 4096];
    let header_end = loop {
        let n = match s.read(&mut tmp) {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        buf.extend_from_slice(&tmp[..n]);
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i;
        }
    };
    let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or("").to_string();
    let mut headers = HashMap::new();
    for l in lines {
        if let Some((k, v)) = l.split_once(':') {
            headers.insert(k.trim().to_lowercase(), v.trim().to_string());
        }
    }
    let len: usize = headers.get("content-length").and_then(|v| v.parse().ok()).unwrap_or(0);
    let mut body = buf[header_end + 4..].to_vec();
    while body.len() < len {
        let n = match s.read(&mut tmp) {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        body.extend_from_slice(&tmp[..n]);
    }
    let body = String::from_utf8_lossy(&body).to_string();
    let mut parts = request_line.split(' ');
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("").split('?').next().unwrap_or("").to_string();
    match (method, path.as_str()) {
        ("GET", "/.well-known/openid-configuration") => {
            let mut g = state.lock().unwrap();
            g.discovery_hits += 1;
            let mut doc = json!({
                "issuer": issuer,
                "authorization_endpoint": format!("{issuer}/authorize"),
                "token_endpoint": format!("{issuer}/token"),
                "userinfo_endpoint": format!("{issuer}/userinfo"),
                "jwks_uri": format!("{issuer}/jwks"),
                "id_token_signing_alg_values_supported": ["RS256"],
                "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
            });
            for (k, v) in &g.discovery_overrides {
                if v.is_null() {
                    doc.as_object_mut().unwrap().remove(k);
                } else {
                    doc[k] = v.clone();
                }
            }
            respond(s, "200 OK", "application/json", &doc.to_string());
        }
        ("GET", "/jwks") => {
            state.lock().unwrap().jwks_hits += 1;
            let doc = json!({"keys": [{"kty": "RSA", "kid": KID, "use": "sig", "alg": "RS256", "n": RSA_N, "e": "AQAB"}]});
            respond(s, "200 OK", "application/json", &doc.to_string());
        }
        ("POST", "/token") => {
            let form = form_decode(&body);
            let mut g = state.lock().unwrap();
            g.token_requests.push((headers.clone(), body.clone()));
            let code = form.get("code").cloned().unwrap_or_default();
            let Some(entry) = g.codes.remove(&code) else {
                return respond(s, "400 Bad Request", "application/json", r#"{"error":"invalid_grant"}"#);
            };
            let verifier = form.get("code_verifier").cloned().unwrap_or_default();
            if pkce_challenge(&verifier) != entry.challenge {
                return respond(
                    s,
                    "400 Bad Request",
                    "application/json",
                    r#"{"error":"invalid_grant","error_description":"PKCE verification failed"}"#,
                );
            }
            let now = chrono::Utc::now().timestamp();
            let mut claims = json!({
                "iss": issuer, "aud": CLIENT_ID, "exp": now + 300, "iat": now, "nonce": entry.nonce, "sub": "subject-1",
            });
            for (k, v) in entry.claims.as_object().cloned().unwrap_or_default() {
                if v.is_null() {
                    claims.as_object_mut().unwrap().remove(&k);
                } else {
                    claims[&k] = v;
                }
            }
            let access_token = format!("at-{code}");
            let id_token = match &g.hs_secret {
                Some(secret) => jsonwebtoken::encode(
                    &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
                    &claims,
                    &jsonwebtoken::EncodingKey::from_secret(secret.as_bytes()),
                )
                .unwrap(),
                None => {
                    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
                    header.kid = Some(KID.into());
                    jsonwebtoken::encode(&header, &claims, &jsonwebtoken::EncodingKey::from_rsa_pem(RSA_PEM.as_bytes()).unwrap())
                        .unwrap()
                }
            };
            let doc = json!({"access_token": access_token, "token_type": "Bearer", "expires_in": 300, "id_token": id_token});
            respond(s, "200 OK", "application/json", &doc.to_string());
        }
        ("GET", "/userinfo") => {
            let mut g = state.lock().unwrap();
            g.userinfo_requests.push(headers.clone());
            match &g.userinfo {
                Some(v) => respond(s, "200 OK", "application/json", &v.to_string()),
                None => respond(s, "401 Unauthorized", "application/json", r#"{"error":"invalid_token"}"#),
            }
        }
        _ => respond(s, "404 Not Found", "text/plain", "not found"),
    }
}

/// Server env for an OIDC-enabled backend talking to `idp`.
pub fn oidc_env(idp: &MockIdp, mode: &str) -> Vec<(String, String)> {
    vec![
        ("AUTH_MODE".into(), mode.into()),
        ("OIDC_ISSUER_URL".into(), idp.issuer.clone()),
        ("OIDC_CLIENT_ID".into(), CLIENT_ID.into()),
        ("OIDC_CLIENT_SECRET".into(), CLIENT_SECRET.into()),
        ("OIDC_REDIRECT_URI".into(), REDIRECT_URI.into()),
    ]
}

pub fn query_param(url: &str, key: &str) -> Option<String> {
    let parsed = url::Url::parse(url).unwrap_or_else(|_| url::Url::parse(&format!("http://x{url}")).unwrap());
    parsed.query_pairs().find(|(k, _)| k == key).map(|(_, v)| v.into_owned())
}

pub struct Started {
    pub location: String,
    pub state: String,
    pub nonce: String,
    pub challenge: String,
}

/// GET /auth/oidc/start and parse the authorization redirect.
pub fn oidc_start(c: &TestClient, return_to: &str) -> Started {
    let r = c.get(&format!("/auth/oidc/start?returnTo={}", url::form_urlencoded::byte_serialize(return_to.as_bytes()).collect::<String>()));
    assert_eq!(r.status, 302, "start: {}", r.text());
    let location = r.header("location").unwrap();
    Started {
        state: query_param(&location, "state").unwrap(),
        nonce: query_param(&location, "nonce").unwrap(),
        challenge: query_param(&location, "code_challenge").unwrap(),
        location,
    }
}

/// Full login round-trip with the given extra ID token claims; returns the callback response.
pub fn oidc_login(c: &TestClient, idp: &MockIdp, claims: Value) -> Resp {
    let s = oidc_start(c, "/dashboard");
    let code = uuid::Uuid::new_v4().to_string();
    idp.register_code(&code, &s.challenge, &s.nonce, claims);
    c.get(&format!("/auth/oidc/callback?code={code}&state={}", s.state))
}

pub fn decode_jwt_claims(token: &str) -> Value {
    use base64::Engine;
    let part = token.split('.').nth(1).unwrap();
    serde_json::from_slice(&base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(part).unwrap()).unwrap()
}

/// Value of a cookie set by the response.
pub fn set_cookie_value(r: &Resp, name: &str) -> Option<String> {
    r.header_all("set-cookie")
        .into_iter()
        .find(|c| c.starts_with(&format!("{name}=")))
        .map(|c| c.split(';').next().unwrap().splitn(2, '=').nth(1).unwrap().to_string())
}

/// Assert a `/login?oidcError=...` redirect and return the parsed location.
pub fn assert_login_error(r: &Resp, code: &str) -> String {
    assert_eq!(r.status, 302, "body: {}", r.text());
    let loc = r.header("location").unwrap();
    assert!(loc.starts_with("/login?"), "location: {loc}");
    assert_eq!(query_param(&loc, "oidcError").as_deref(), Some(code), "location: {loc}");
    loc
}
