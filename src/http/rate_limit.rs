//! express-rate-limit v8 (MemoryStore, standardHeaders draft-6) equivalent.
use axum::{http::HeaderMap, http::HeaderValue, response::Response};
use serde_json::Value;
use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

use super::error::json_response;

pub struct RateLimiter {
    pub window_ms: f64,
    pub max: f64,
    message: Value,
    hits: Mutex<HashMap<String, (u64, Instant)>>,
}

#[derive(Clone, Copy, Debug)]
pub struct RateLimitInfo {
    pub limit: f64,
    pub total_hits: u64,
    pub reset_secs: u64,
    pub window_secs: u64,
    pub exceeded: bool,
}

impl RateLimiter {
    pub fn new(window_ms: f64, max: f64, message: Value) -> Self {
        RateLimiter { window_ms, max, message, hits: Mutex::new(HashMap::new()) }
    }

    /// Count a hit for `key` and report whether the limit is exceeded.
    pub fn hit(&self, key: &str) -> RateLimitInfo {
        let now = Instant::now();
        let window = Duration::from_millis(self.window_ms.max(0.0) as u64);
        let mut map = self.hits.lock().unwrap();
        if map.len() > 10_000 {
            map.retain(|_, (_, reset)| *reset > now);
        }
        let entry = map.entry(key.to_string()).or_insert((0, now + window));
        if entry.1 <= now {
            *entry = (0, now + window);
        }
        entry.0 += 1;
        let remaining_ms = entry.1.saturating_duration_since(now).as_millis() as f64;
        RateLimitInfo {
            limit: self.max,
            total_hits: entry.0,
            reset_secs: (remaining_ms / 1000.0).ceil().max(0.0) as u64,
            window_secs: (self.window_ms / 1000.0).ceil() as u64,
            exceeded: entry.0 as f64 > self.max,
        }
    }

    pub fn reset_key(&self, key: &str) {
        self.hits.lock().unwrap().remove(key);
    }

    pub fn reset_all(&self) {
        self.hits.lock().unwrap().clear();
    }

    /// The 429 response (headers must be applied by the caller).
    pub fn limited_response(&self, info: &RateLimitInfo) -> Response {
        let mut res = json_response(axum::http::StatusCode::TOO_MANY_REQUESTS, &self.message);
        apply_headers(res.headers_mut(), info);
        res
    }
}

pub fn apply_headers(h: &mut HeaderMap, info: &RateLimitInfo) {
    let limit = crate::util::js_num_str(info.limit);
    let remaining = (info.limit - info.total_hits as f64).max(0.0);
    let set = |h: &mut HeaderMap, k: &'static str, v: String| {
        if let Ok(v) = HeaderValue::from_str(&v) {
            h.insert(k, v);
        }
    };
    set(h, "ratelimit-policy", format!("{limit};w={}", info.window_secs));
    set(h, "ratelimit-limit", limit);
    set(h, "ratelimit-remaining", crate::util::js_num_str(remaining));
    set(h, "ratelimit-reset", info.reset_secs.to_string());
    if info.exceeded {
        set(h, "retry-after", info.reset_secs.to_string());
    }
}

/// express-rate-limit v8 default key generator: IPv6 addresses are bucketed by /56.
pub fn ip_key(ip: &str) -> String {
    if let Ok(std::net::IpAddr::V6(v6)) = ip.parse::<std::net::IpAddr>() {
        if v6.to_ipv4_mapped().is_none() {
            let seg = v6.segments();
            // keep first 56 bits
            let masked = [seg[0], seg[1], seg[2], seg[3] & 0xff00, 0, 0, 0, 0];
            let addr = std::net::Ipv6Addr::new(
                masked[0], masked[1], masked[2], masked[3], masked[4], masked[5], masked[6], masked[7],
            );
            return format!("{addr}/56");
        }
    }
    ip.to_string()
}
