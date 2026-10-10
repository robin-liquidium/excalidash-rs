//! routes/dashboard/* — drawings, collections, library, sharing, history —
//! plus the dashboard-specific parts of index.ts (schemas, parseJsonField, MAX_PAGE_SIZE).
mod collections;
mod drawings;
mod history;
mod library;
mod list;
pub mod scene;
pub mod schema;
mod sharing;

use axum::{
    routing::{get, patch, post, put, MethodRouter},
    Router,
};
use rusqlite::{Connection, OptionalExtension, Row};
use serde_json::{json, Map, Value};

use crate::auth::middleware::OptionalAuth;
use crate::http::ctx::Ctx;
use crate::http::error::ApiError;
use crate::state::AppState;

/// index.ts MAX_PAGE_SIZE
pub const MAX_PAGE_SIZE: f64 = 200.0;

async fn not_found(ctx: Ctx) -> axum::response::Response {
    crate::http::error::express_not_found(ctx.method.as_str(), &ctx.path)
}

/// Express answers unknown methods on a known path with its default 404.
fn r(m: MethodRouter<AppState>) -> MethodRouter<AppState> {
    m.fallback(not_found)
}

pub fn router() -> Router<AppState> {
    Router::new()
        // drawings (registration order mirrors drawings.ts; `/drawings/shared`
        // is dispatched inside the `/drawings/{id}` GET handler like Express does)
        .route("/drawings", r(get(list::list_drawings).post(drawings::create_drawing)))
        .route(
            "/drawings/{id}",
            r(get(drawings::get_drawing_or_shared).put(drawings::update_drawing).delete(drawings::delete_drawing)),
        )
        .route("/drawings/{id}/preview", r(get(list::drawing_preview)))
        .route("/drawings/{id}/duplicate", r(post(drawings::duplicate_drawing)))
        .route("/drawings/{id}/share-resolve", r(get(sharing::share_resolve)))
        .route("/drawings/{id}/sharing", r(get(sharing::get_sharing)))
        .route("/drawings/{id}/permissions", r(post(sharing::upsert_permission)))
        .route("/drawings/{id}/permissions/{perm_id}", r(axum::routing::delete(sharing::delete_permission)))
        .route("/drawings/{id}/link-shares", r(post(sharing::create_link_share)))
        .route("/drawings/{id}/link-shares/{share_id}", r(axum::routing::delete(sharing::revoke_link_share)))
        .route("/drawings/{id}/shared-visibility", r(patch(sharing::shared_visibility)))
        .route("/drawings/{id}/history", r(get(history::list_history)))
        .route("/drawings/{id}/history/{snapshot_id}", r(get(history::get_snapshot)))
        .route("/drawings/{id}/history/{snapshot_id}/restore", r(post(history::restore_snapshot)))
        // collections
        .route("/collections", r(get(collections::list_collections).post(collections::create_collection)))
        .route(
            "/collections/{id}",
            r(put(collections::rename_collection).delete(collections::delete_collection)),
        )
        .route(
            "/collections/{id}/shares",
            r(get(collections::list_shares).post(collections::upsert_share)),
        )
        .route(
            "/collections/{id}/shares/{user_id}",
            r(patch(collections::update_share).delete(collections::delete_share)),
        )
        .route("/collections/{id}/share-resolve", r(get(collections::share_resolve)))
        // library
        .route("/library", r(get(library::get_library).put(library::put_library)))
}

// ---------------------------------------------------------------------------
// Shared helpers

/// index.ts parseJsonField(rawValue, fallback)
pub fn parse_json_field(raw: Option<&str>, fallback: Value) -> Value {
    let Some(raw) = raw.filter(|s| !s.is_empty()) else { return fallback };
    match serde_json::from_str::<Value>(raw) {
        Ok(v) => v,
        Err(e) => {
            eprintln!(
                "Failed to parse JSON field {{ error: {:?}, valuePreview: {:?} }}",
                e.to_string(),
                crate::util::js_slice(raw, 50)
            );
            fallback
        }
    }
}

/// `req.query` (Express 5 simple parser: strings or arrays of strings).
pub fn query(ctx: &Ctx) -> Map<String, Value> {
    crate::http::body::parse_query_values(ctx.query.as_deref().unwrap_or(""))
}

/// JS `String(value)` for query values (strings / arrays of strings).
pub fn js_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Array(a) => a.iter().map(js_string).collect::<Vec<_>>().join(","),
        Value::Null => "null".into(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::Object(_) => "[object Object]".into(),
    }
}

/// JS truthiness of a JSON value (`undefined` = None).
pub fn truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64().map(|f| f != 0.0 && !f.is_nan()).unwrap_or(true),
        Some(Value::String(s)) => !s.is_empty(),
        Some(_) => true,
    }
}

/// JS number → JSON value (integers print without a fraction).
pub fn js_num(n: f64) -> Value {
    if n.is_finite() && n == n.trunc() && n.abs() < 9.007_199_254_740_992e15 {
        json!(n as i64)
    } else {
        serde_json::Number::from_f64(n).map(Value::Number).unwrap_or(Value::Null)
    }
}

/// respondWithAuthErrorIfPresent
pub fn auth_error(opt: &OptionalAuth) -> Option<ApiError> {
    opt.auth_error.map(|_| ApiError::err(401, "Unauthorized", "Invalid or expired token"))
}

pub fn principal(opt: &OptionalAuth) -> Option<String> {
    opt.user.as_ref().map(|u| u.id.clone())
}

/// `{ error: msg }` with a status.
pub fn err_only(status: u16, msg: &str) -> ApiError {
    ApiError::json(status, json!({ "error": msg }))
}

/// Audit event with the request context (req.ip / user-agent).
pub async fn audit(st: &AppState, ctx: &Ctx, user_id: &str, action: &str, resource: String, details: Value) {
    if !st.cfg.enable_audit_logging {
        return;
    }
    crate::audit::log_audit_event(
        &st.db,
        crate::audit::AuditEvent {
            user_id: Some(user_id.to_string()),
            action: action.to_string(),
            resource: Some(resource),
            ip_address: Some(ctx.ip.clone()),
            user_agent: ctx.user_agent().map(str::to_string),
            details: match details {
                Value::Object(m) => Some(m),
                _ => None,
            },
        },
    )
    .await;
}

// ---------------------------------------------------------------------------
// Drawing model

pub const DRAWING_COLS: &str =
    r#""id","name","elements","appState","files","preview","version","userId","collectionId","createdAt","updatedAt""#;

#[derive(Debug, Clone)]
pub struct DrawingRow {
    pub id: String,
    pub name: String,
    pub elements: String,
    pub app_state: String,
    pub files: String,
    pub preview: Option<String>,
    pub version: i64,
    pub user_id: String,
    pub collection_id: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

impl DrawingRow {
    /// Reads DRAWING_COLS starting at column `o`.
    pub fn from_row_at(r: &Row<'_>, o: usize) -> rusqlite::Result<DrawingRow> {
        Ok(DrawingRow {
            id: r.get(o)?,
            name: r.get(o + 1)?,
            elements: r.get(o + 2)?,
            app_state: r.get(o + 3)?,
            files: r.get(o + 4)?,
            preview: r.get(o + 5)?,
            version: r.get(o + 6)?,
            user_id: r.get(o + 7)?,
            collection_id: r.get(o + 8)?,
            created_at: crate::db::dt(r, o + 9)?,
            updated_at: crate::db::dt(r, o + 10)?,
        })
    }

    pub fn find(c: &Connection, id: &str) -> rusqlite::Result<Option<DrawingRow>> {
        c.query_row(&format!(r#"SELECT {DRAWING_COLS} FROM "Drawing" WHERE "id" = ?1"#), [id], |r| {
            DrawingRow::from_row_at(r, 0)
        })
        .optional()
    }

    /// Prisma model object (schema field order, raw JSON strings).
    pub fn to_map(&self) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("id".into(), json!(self.id));
        m.insert("name".into(), json!(self.name));
        m.insert("elements".into(), json!(self.elements));
        m.insert("appState".into(), json!(self.app_state));
        m.insert("files".into(), json!(self.files));
        m.insert("preview".into(), json!(self.preview));
        m.insert("version".into(), json!(self.version));
        m.insert("userId".into(), json!(self.user_id));
        m.insert("collectionId".into(), json!(self.collection_id));
        m.insert("createdAt".into(), json!(crate::util::iso_from_ms(self.created_at)));
        m.insert("updatedAt".into(), json!(crate::util::iso_from_ms(self.updated_at)));
        m
    }

    /// `{...drawing, collectionId, elements, appState, files}` with parsed scene fields.
    pub fn to_json_with(&self, collection_id: Value) -> Map<String, Value> {
        let mut m = self.to_map();
        m.insert("collectionId".into(), collection_id);
        m.insert("elements".into(), parse_json_field(Some(&self.elements), json!([])));
        m.insert("appState".into(), parse_json_field(Some(&self.app_state), json!({})));
        m.insert("files".into(), parse_json_field(Some(&self.files), json!({})));
        m
    }
}

pub fn opt_str_json(v: Option<String>) -> Value {
    v.map(Value::String).unwrap_or(Value::Null)
}

/// Owner-only lookup used by the sharing routes: `findUnique({select:{userId}})`.
pub async fn drawing_owner(st: &AppState, id: &str) -> Result<Option<String>, ApiError> {
    let id = id.to_string();
    Ok(st
        .db
        .call(move |c| {
            Ok(c.query_row(r#"SELECT "userId" FROM "Drawing" WHERE "id" = ?1"#, [&id], |r| r.get::<_, String>(0))
                .optional()?)
        })
        .await?)
}

/// Placeholders `?N,?N+1,...` for an IN list.
pub fn placeholders(start: usize, n: usize) -> String {
    (0..n).map(|i| format!("?{}", start + i)).collect::<Vec<_>>().join(",")
}