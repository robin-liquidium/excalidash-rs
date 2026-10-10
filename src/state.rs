//! Shared application state.
//!
//! Feature modules keep their own singletons (module-level `OnceLock`/`Mutex`)
//! rather than adding fields here, so modules stay independent.
use socketioxide::SocketIo;
use std::sync::{Arc, OnceLock};

use crate::config::{config, Config};
use crate::db::Db;
use crate::drawings_cache::DrawingsCache;
use crate::http::rate_limit::RateLimiter;

#[derive(Clone)]
pub struct AppState(pub Arc<Inner>);

pub struct Inner {
    pub cfg: &'static Config,
    pub db: Db,
    pub drawings_cache: DrawingsCache,
    pub general_limiter: RateLimiter,
    io: OnceLock<SocketIo>,
    http: OnceLock<reqwest::Client>,
}

impl std::ops::Deref for AppState {
    type Target = Inner;
    fn deref(&self) -> &Inner {
        &self.0
    }
}

impl AppState {
    pub fn new(db: Db) -> AppState {
        let cfg = config();
        AppState(Arc::new(Inner {
            cfg,
            db,
            drawings_cache: DrawingsCache::new(cfg.drawings_cache_ttl_ms),
            general_limiter: RateLimiter::new(
                cfg.rate_limit_window_ms,
                cfg.rate_limit_max_requests,
                serde_json::json!({
                    "error": "Rate limit exceeded",
                    "message": "Too many requests, please try again later",
                }),
            ),
            io: OnceLock::new(),
            http: OnceLock::new(),
        }))
    }

    pub fn set_io(&self, io: SocketIo) {
        let _ = self.io.set(io);
    }

    /// The Socket.IO server handle (`io` in index.ts).
    pub fn io(&self) -> Option<&SocketIo> {
        self.io.get()
    }

    /// Shared outbound HTTP client (rustls + webpki roots), created lazily.
    pub fn http(&self) -> &reqwest::Client {
        self.http.get_or_init(crate::net::build_http_client)
    }
}
