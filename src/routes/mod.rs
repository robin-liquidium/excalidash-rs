//! Backend routes (everything index.ts registers on the Express app).
pub mod dashboard;
pub mod files;
pub mod import_export;
pub mod storage;
pub mod system;

use axum::{extract::State, routing::get, Router};
use serde_json::json;

use crate::http::error::{json_response, ApiResult};
use crate::state::AppState;

async fn health(State(st): State<AppState>) -> ApiResult {
    let ok = st.db.call(|c| Ok(c.query_row("SELECT 1", [], |_| Ok(()))?)).await;
    Ok(match ok {
        Ok(()) => json_response(axum::http::StatusCode::OK, &json!({"status": "ok", "database": "ok"})),
        Err(e) => {
            eprintln!("Health check failed {e}");
            json_response(
                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                &json!({"status": "error", "database": "unavailable"}),
            )
        }
    })
}

async fn not_found(ctx: crate::http::ctx::Ctx) -> axum::response::Response {
    crate::http::error::express_not_found(ctx.method.as_str(), &ctx.path)
}

pub fn router(st: AppState) -> Router {
    Router::new()
        .nest("/auth", crate::auth::routes::router())
        .route("/health", get(health))
        .merge(system::router())
        .merge(dashboard::router())
        .merge(files::router())
        .merge(storage::router())
        .merge(import_export::router())
        .fallback(not_found)
        .with_state(st)
}
