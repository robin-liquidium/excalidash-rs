//! library.ts — per-user Excalidraw library.
use axum::extract::State;
use rusqlite::OptionalExtension;
use serde_json::{json, Value};

use super::{err_only, parse_json_field};
use crate::http::body::Body;
use crate::http::ctx::Ctx;
use crate::http::error::{ok, ApiError, ApiResult};
use crate::state::AppState;

/// GET /library
pub async fn get_library(State(st): State<AppState>, ctx: Ctx) -> ApiResult {
    let user = crate::auth::require_auth(&st.db, &ctx).await?;
    let id = format!("user_{}", user.id);
    let items: Option<String> = st
        .db
        .call(move |c| Ok(c.query_row(r#"SELECT "items" FROM "Library" WHERE "id" = ?1"#, [&id], |r| r.get(0)).optional()?))
        .await?;
    match items {
        None => ok(json!({ "items": [] })),
        Some(raw) => ok(json!({ "items": parse_json_field(Some(&raw), json!([])) })),
    }
}

/// PUT /library
pub async fn put_library(State(st): State<AppState>, ctx: Ctx, body: Body) -> ApiResult {
    let user = crate::auth::require_auth(&st.db, &ctx).await?;
    let Some(b) = &body.0 else {
        return Err(ApiError::internal("Cannot destructure property 'items' of 'req.body' as it is undefined."));
    };
    let Some(Value::Array(items)) = b.get("items") else {
        return Err(err_only(400, "Items must be an array"));
    };
    let raw = Value::Array(items.clone()).to_string();
    let id = format!("user_{}", user.id);
    let stored: String = st
        .db
        .call(move |c| {
            let now = crate::util::now_ms();
            c.execute(
                r#"INSERT INTO "Library" ("id","items","createdAt","updatedAt") VALUES (?1,?2,?3,?3)
                   ON CONFLICT("id") DO UPDATE SET "items" = excluded."items", "updatedAt" = excluded."updatedAt""#,
                rusqlite::params![id, raw, now],
            )?;
            Ok(c.query_row(r#"SELECT "items" FROM "Library" WHERE "id" = ?1"#, [&id], |r| r.get(0))?)
        })
        .await?;
    ok(json!({ "items": parse_json_field(Some(&stored), json!([])) }))
}
