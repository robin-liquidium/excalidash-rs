//! STUB — routes/importExport/* (.excalidash export/import, legacy SQLite import).
use axum::Router;

use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
}
