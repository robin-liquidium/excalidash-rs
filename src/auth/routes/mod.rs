//! The /auth router (auth.ts createAuthRouter).
pub mod account;
pub mod admin;
pub mod core;
pub mod helpers;
pub mod oidc;

use axum::Router;

use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .merge(oidc::router())
        .merge(core::router())
        .merge(admin::router())
        .merge(account::router())
}
