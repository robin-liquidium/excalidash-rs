//! Authentication: tokens, cookies, API keys, auth mode and the /auth router.
pub mod api_keys;
pub mod cookies;
pub mod jwt;
pub mod middleware;
pub mod routes;

pub use middleware::{optional_auth, require_auth, AuthUser, OptionalAuth};
