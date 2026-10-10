//! Per-request context (what Express exposes as req.ip, req.path, cookies, ...).
use axum::{
    extract::FromRequestParts,
    http::{request::Parts, HeaderMap, Method},
};
use std::{collections::HashMap, convert::Infallible, net::SocketAddr, sync::Arc};

use crate::config::{config, TrustProxy};

#[derive(Clone, Debug)]
pub struct Ctx(pub Arc<CtxInner>);

#[derive(Debug)]
pub struct CtxInner {
    pub request_id: String,
    pub method: Method,
    /// Path as the backend sees it (after the `/api` prefix strip), no query.
    pub path: String,
    /// Path + query as the backend sees it (Express `req.originalUrl`).
    pub original_url: String,
    pub query: Option<String>,
    pub headers: HeaderMap,
    pub ip: String,
    pub remote_addr: String,
    pub secure: bool,
}

impl std::ops::Deref for Ctx {
    type Target = CtxInner;
    fn deref(&self) -> &CtxInner {
        &self.0
    }
}

impl CtxInner {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }
    pub fn user_agent(&self) -> Option<&str> {
        self.header("user-agent")
    }
    pub fn cookies(&self) -> HashMap<String, String> {
        parse_cookie_header(self.header("cookie"))
    }
    pub fn cookie(&self, name: &str) -> Option<String> {
        self.cookies().remove(name).filter(|v| !v.trim().is_empty())
    }
    pub fn query_map(&self) -> HashMap<String, String> {
        crate::http::body::parse_query_flat(self.query.as_deref().unwrap_or(""))
    }
}

impl<S: Send + Sync> FromRequestParts<S> for Ctx {
    type Rejection = Infallible;
    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(parts.extensions.get::<Ctx>().cloned().expect("Ctx middleware not installed"))
    }
}

/// Cookie header parser shared by cookies.ts / csrfClient.ts.
pub fn parse_cookie_header(header: Option<&str>) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let Some(header) = header else { return out };
    for part in header.split(';') {
        let mut it = part.splitn(2, '=');
        let raw_key = it.next().unwrap_or("");
        let Some(raw_value) = it.next() else { continue };
        let key = raw_key.trim();
        if key.is_empty() {
            continue;
        }
        let raw_value = raw_value.trim();
        let value = percent_encoding::percent_decode_str(raw_value)
            .decode_utf8()
            .map(|v| v.into_owned())
            .unwrap_or_else(|_| raw_value.to_string());
        out.insert(key.to_string(), value);
    }
    out
}

fn first_forwarded(headers: &HeaderMap, name: &str) -> Option<String> {
    headers.get(name).and_then(|v| v.to_str().ok()).map(|v| v.split(',').next().unwrap_or("").trim().to_lowercase())
}

/// Express `req.ip` (proxy-addr) for the configured trust-proxy setting.
pub fn resolve_ip(headers: &HeaderMap, remote: &str) -> String {
    let trust = config().trust_proxy;
    let xff: Vec<String> = headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(',').map(|s| s.trim().to_string()).collect::<Vec<_>>())
        .filter(|s| !s.is_empty())
        .collect();
    // addrs = [remote, ...xff reversed]
    let mut addrs = vec![remote.to_string()];
    addrs.extend(xff.into_iter().rev());
    match trust {
        TrustProxy::Off => remote.to_string(),
        TrustProxy::All => addrs.last().cloned().unwrap_or_default(),
        TrustProxy::Hops(n) => {
            let idx = (n as usize).min(addrs.len() - 1);
            addrs[idx].clone()
        }
    }
}

pub fn request_is_secure(headers: &HeaderMap) -> bool {
    if !config().trust_proxy.trusts_headers() {
        return false;
    }
    first_forwarded(headers, "x-forwarded-proto").as_deref() == Some("https")
}

pub fn build_ctx(method: Method, path: String, query: Option<String>, headers: HeaderMap, peer: Option<SocketAddr>) -> Ctx {
    let remote = match peer {
        Some(SocketAddr::V4(a)) => a.ip().to_string(),
        Some(SocketAddr::V6(a)) => match a.ip().to_ipv4_mapped() {
            Some(v4) => format!("::ffff:{v4}"),
            None => a.ip().to_string(),
        },
        None => "unknown".to_string(),
    };
    let ip = resolve_ip(&headers, &remote);
    let secure = request_is_secure(&headers);
    let original_url = match &query {
        Some(q) => format!("{path}?{q}"),
        None => path.clone(),
    };
    Ctx(Arc::new(CtxInner {
        request_id: crate::util::uuid_v4(),
        method,
        path,
        original_url,
        query,
        headers,
        ip,
        remote_addr: remote,
        secure,
    }))
}
