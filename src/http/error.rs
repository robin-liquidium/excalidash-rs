//! Errors and JSON responses with Express semantics.
//!
//! Handlers return `ApiResult`. `ApiError::Json` is an explicit
//! `res.status(x).json(body)`; the other variants go through the equivalent
//! of middleware/errorHandler.ts.
use axum::{
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use serde_json::{json, Value};

use crate::config::config;

pub type ApiResult<T = Response> = Result<T, ApiError>;

#[derive(Debug)]
pub enum ApiError {
    /// Explicit `res.status(status).json(body)`.
    Json(StatusCode, Value),
    /// Thrown error reaching errorHandler (statusCode, message, isOperational).
    Thrown { status: u16, message: String, operational: bool },
}

impl ApiError {
    pub fn json(status: u16, body: Value) -> Self {
        ApiError::Json(StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR), body)
    }
    pub fn err(status: u16, error: &str, message: &str) -> Self {
        Self::json(status, json!({ "error": error, "message": message }))
    }
    /// Unhandled exception → errorHandler 500.
    pub fn internal(message: impl Into<String>) -> Self {
        ApiError::Thrown { status: 500, message: message.into(), operational: false }
    }
    pub fn operational(status: u16, message: impl Into<String>) -> Self {
        ApiError::Thrown { status, message: message.into(), operational: true }
    }
    pub fn bad_request() -> Self {
        Self::err(400, "Bad request", "Invalid request")
    }
    pub fn unauthorized(message: &str) -> Self {
        Self::err(401, "Unauthorized", message)
    }
    pub fn forbidden(message: &str) -> Self {
        Self::err(403, "Forbidden", message)
    }
    pub fn not_found(message: &str) -> Self {
        Self::err(404, "Not found", message)
    }
}

impl From<crate::db::DbError> for ApiError {
    fn from(e: crate::db::DbError) -> Self {
        ApiError::internal(e.to_string())
    }
}
impl From<rusqlite::Error> for ApiError {
    fn from(e: rusqlite::Error) -> Self {
        ApiError::internal(e.to_string())
    }
}

/// The JSON body errorHandler.ts produces for a thrown error.
pub fn error_handler_body(status: u16, message: &str, operational: bool) -> Value {
    let cfg = config();
    if cfg.node_env != "development" {
        if status >= 500 {
            return json!({
                "error": "Internal server error",
                "message": "An error occurred while processing your request",
            });
        }
        return json!({
            "error": "Request error",
            "message": if operational { message } else { "Invalid request" },
        });
    }
    json!({ "error": message, "stack": format!("Error: {message}"), "statusCode": status })
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        match self {
            ApiError::Json(status, body) => json_response(status, &body),
            ApiError::Thrown { status, message, operational } => {
                eprintln!(
                    "Error: {{ message: {:?}, statusCode: {}, timestamp: {:?} }}",
                    message,
                    status,
                    crate::util::iso_now()
                );
                json_response(
                    StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                    &error_handler_body(status, &message, operational),
                )
            }
        }
    }
}

/// Marker: response body is a fully buffered `res.send` body (gets an Express ETag).
#[derive(Clone, Copy)]
pub struct EtagEligible;

pub fn json_response(status: StatusCode, body: &Value) -> Response {
    json_bytes(status, serde_json::to_vec(body).unwrap_or_default())
}

pub fn json_bytes(status: StatusCode, bytes: Vec<u8>) -> Response {
    let mut res = (status, bytes).into_response();
    res.headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json; charset=utf-8"));
    res.extensions_mut().insert(EtagEligible);
    res
}

/// `res.json(body)` with status 200.
pub fn ok(body: Value) -> ApiResult {
    Ok(json_response(StatusCode::OK, &body))
}

/// `res.status(status).json(body)`.
pub fn status_json(status: u16, body: Value) -> ApiResult {
    Ok(json_response(StatusCode::from_u16(status).unwrap_or(StatusCode::OK), &body))
}

/// `res.status(204).end()` / `res.sendStatus(204)`-like empty response.
pub fn no_content() -> ApiResult {
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// Express `res.send(text)` with text/html content type.
pub fn html(status: StatusCode, body: String) -> Response {
    let mut res = (status, body).into_response();
    res.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"));
    res.extensions_mut().insert(EtagEligible);
    res
}

/// Express default 404 (finalhandler).
pub fn express_not_found(method: &str, path: &str) -> Response {
    let body = format!(
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<title>Error</title>\n</head>\n<body>\n<pre>Cannot {} {}</pre>\n</body>\n</html>\n",
        method,
        escape_html(&encode_url_for_html(path))
    );
    let mut res = (StatusCode::NOT_FOUND, body).into_response();
    let h = res.headers_mut();
    h.insert("content-security-policy", HeaderValue::from_static("default-src 'none'"));
    h.insert("x-content-type-options", HeaderValue::from_static("nosniff"));
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"));
    res.extensions_mut().insert(FinalHandler);
    res
}

/// Marker: response produced by Express's finalhandler (overrides helmet CSP).
#[derive(Clone, Copy)]
pub struct FinalHandler;

fn encode_url_for_html(path: &str) -> String {
    // encodeurl: percent-encode chars not allowed in URLs, keep existing escapes.
    let mut out = String::new();
    for c in path.chars() {
        if c.is_ascii_alphanumeric() || "-._~:/?#[]@!$&'()*+,;=%".contains(c) {
            out.push(c);
        } else {
            let mut buf = [0u8; 4];
            for b in c.encode_utf8(&mut buf).bytes() {
                out.push_str(&format!("%{b:02X}"));
            }
        }
    }
    out
}

pub fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&#39;")
}
