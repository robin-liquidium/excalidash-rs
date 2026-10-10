//! STUB — routes/dashboard/* (drawings, collections, library, sharing, history).
use axum::Router;

use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
}
