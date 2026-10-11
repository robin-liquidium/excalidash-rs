//! routes/files.ts
//!   GET  /files/config                     – report whether S3 is configured
//!   PUT  /drawings/:drawingId/files/:fileId – upload raw image bytes (edit access)
//!   GET  /files/:drawingId/:fileId         – serve an image (db bytes w/ ETag, or 302 to S3)
use axum::{
    body::Body as RawBody,
    extract::{Path, State},
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, put},
    Router,
};
use serde_json::json;

use crate::auth::middleware::{optional_auth, require_auth};
use crate::authz::get_drawing_access;
use crate::files::{
    cleanup_unused_s3_upload, find_drawing_file, is_valid_file_id, mime_ext, store_drawing_file_once, FileContent,
    MIME_TO_EXT,
};
use crate::http::ctx::Ctx;
use crate::http::error::{ok, status_json, ApiResult};
use crate::s3;
use crate::state::AppState;

const DOWNLOAD_EXPIRES_IN: u64 = 3600;

async fn files_config(State(st): State<AppState>, ctx: Ctx) -> ApiResult {
    require_auth(&st.db, &ctx).await?;
    ok(json!({ "s3Enabled": s3::is_s3_enabled() }))
}

fn too_large() -> ApiResult {
    let cfg = crate::config::config();
    status_json(
        413,
        json!({
            "error": "File too large",
            "message": format!(
                "Uploaded file exceeds the {}MB limit. Raise FILE_UPLOAD_MAX_MB to accept larger images.",
                crate::util::js_num_str(cfg.file_upload_max_mb)
            ),
        }),
    )
}

/// express.raw({ type: "*/*", limit }) for a body the JSON/urlencoded parsers left alone.
/// Ok(None) = no body / already consumed; Err = 413 response.
async fn read_raw_body(ctx: &Ctx, body: RawBody) -> Result<Option<Vec<u8>>, Response> {
    let limit = crate::config::config().file_upload_max_bytes;
    let declared = ctx.header("content-length").and_then(|v| v.trim().parse::<u64>().ok());
    let has_body = declared.is_some() || ctx.header("transfer-encoding").is_some();
    if !has_body {
        return Ok(None);
    }
    let ct = ctx.header("content-type").unwrap_or("");
    if crate::http::body::is_json_type(ct) || crate::http::body::is_urlencoded_type(ct) {
        // The global parsers already consumed it (req._body) – raw() skips.
        return Ok(None);
    }
    if declared.is_some_and(|n| n as f64 > limit) {
        return Err(too_large().into_response());
    }
    let cap = if limit.is_finite() { limit.floor().max(0.0) as usize } else { usize::MAX };
    match axum::body::to_bytes(body, cap).await {
        Ok(b) => Ok(Some(b.to_vec())),
        Err(_) => Err(too_large().into_response()),
    }
}

async fn upload_file(
    State(st): State<AppState>,
    ctx: Ctx,
    Path((drawing_id, file_id)): Path<(String, String)>,
    body: RawBody,
) -> ApiResult {
    // requireAuth runs before the raw-body parser.
    let user = require_auth(&st.db, &ctx).await?;
    let body = match read_raw_body(&ctx, body).await {
        Ok(b) => b,
        Err(r) => return Ok(r),
    };
    if !is_valid_file_id(&drawing_id) || !is_valid_file_id(&file_id) {
        return status_json(400, json!({ "error": "Invalid id segment" }));
    }
    let (uid, did) = (user.id.clone(), drawing_id.clone());
    let access = st.db.call(move |c| Ok(get_drawing_access(c, Some(&uid), &did, None)?)).await?;
    if !access.can_edit() {
        return status_json(404, json!({ "error": "Drawing not found" }));
    }

    let mime_type = ctx
        .header("content-type")
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_lowercase();
    if mime_type.is_empty() || mime_ext(&mime_type).is_none() {
        let allowed: Vec<&str> = MIME_TO_EXT.iter().map(|(m, _)| *m).collect();
        return status_json(
            415,
            json!({
                "error": "Unsupported media type",
                "message": format!("Content-Type must be one of: {}", allowed.join(", ")),
            }),
        );
    }

    let Some(body) = body.filter(|b| !b.is_empty()) else {
        return status_json(
            400,
            json!({ "error": "Empty request body", "message": "Send the raw image bytes as the request body." }),
        );
    };

    let response_url = format!("/api/files/{drawing_id}/{file_id}");
    let done = || ok(json!({ "url": response_url, "fileId": file_id }));

    let (did, fid) = (drawing_id.clone(), file_id.clone());
    let existing = st.db.call(move |c| Ok(find_drawing_file(c, &did, &fid)?)).await?;
    if existing.is_some_and(|r| r.has_content()) {
        return done();
    }

    let size_bytes = body.len() as i64;
    if let Some(s3c) = s3::client() {
        // Storage listing and cleanup use the drawing owner's namespace.
        let did = drawing_id.clone();
        let owner: Option<String> = st
            .db
            .call(move |c| {
                use crate::sql::OptionalExtension;
                Ok(c.query_row(r#"SELECT "userId" FROM "Drawing" WHERE "id" = ?1"#, [&did], |r| r.get(0))
                    .optional()?)
            })
            .await?;
        let Some(owner) = owner else {
            return status_json(404, json!({ "error": "Drawing not found" }));
        };
        let ext = mime_ext(&mime_type).unwrap_or("bin");
        let key = s3c.build_key(&owner, &drawing_id, &file_id, ext, Some(&crate::util::uuid_v4()));
        s3c.upload_buffer(st.http(), &key, body, &mime_type).await?;
        let content = FileContent {
            drawing_id: drawing_id.clone(),
            file_id: file_id.clone(),
            mime_type,
            size_bytes,
            storage: "s3",
            s3_key: Some(key.clone()),
            data: None,
        };
        let stored = st.db.call(move |c| store_drawing_file_once(c, &content)).await?;
        cleanup_unused_s3_upload(st.http(), s3c, &key, &stored).await;
        return done();
    }

    let content = FileContent {
        drawing_id: drawing_id.clone(),
        file_id: file_id.clone(),
        mime_type,
        size_bytes,
        storage: "db",
        s3_key: None,
        data: Some(body),
    };
    st.db.call(move |c| store_drawing_file_once(c, &content)).await?;
    done()
}

fn header_value(v: &str) -> HeaderValue {
    HeaderValue::from_str(v).unwrap_or_else(|_| HeaderValue::from_static(""))
}

/// Quality of `ty` ("text/plain") in an Accept header (negotiator rules, simplified).
fn accept_quality(accept: &str, ty: &str) -> Option<(f32, u8)> {
    let (main, _) = ty.split_once('/').unwrap_or((ty, ""));
    let mut best: Option<(f32, u8)> = None;
    for part in accept.split(',') {
        let mut it = part.split(';');
        let range = it.next().unwrap_or("").trim().to_ascii_lowercase();
        let q = it
            .filter_map(|p| p.trim().strip_prefix("q=").and_then(|v| v.trim().parse::<f32>().ok()))
            .next()
            .unwrap_or(1.0);
        let specificity = if range == ty {
            2
        } else if range == format!("{main}/*") {
            1
        } else if range == "*/*" {
            0
        } else {
            continue;
        };
        if best.is_none_or(|(_, s)| specificity > s) {
            best = Some((q, specificity));
        }
    }
    best.filter(|(q, _)| *q > 0.0)
}

/// Express 5 `res.redirect(302, url)` (body negotiated via res.format: text, html, default).
fn express_redirect(ctx: &Ctx, url: &str) -> Response {
    let accept = ctx.header("accept").unwrap_or("*/*");
    let text = accept_quality(accept, "text/plain");
    let html = accept_quality(accept, "text/html");
    let (body, ct) = match (text, html) {
        (Some((tq, _)), Some((hq, _))) if hq > tq => (
            format!("<p>Found. Redirecting to {}</p>", crate::http::error::escape_html(url)),
            Some("text/html; charset=utf-8"),
        ),
        (Some(_), _) => (format!("Found. Redirecting to {url}"), Some("text/plain; charset=utf-8")),
        (None, Some(_)) => (
            format!("<p>Found. Redirecting to {}</p>", crate::http::error::escape_html(url)),
            Some("text/html; charset=utf-8"),
        ),
        (None, None) => (String::new(), None),
    };
    let len = body.len();
    let body = if ctx.method == axum::http::Method::HEAD { String::new() } else { body };
    let mut r = (StatusCode::FOUND, body).into_response();
    let h = r.headers_mut();
    h.insert(header::LOCATION, header_value(url));
    h.insert(header::VARY, HeaderValue::from_static("Accept"));
    match ct {
        Some(ct) => {
            h.insert(header::CONTENT_TYPE, HeaderValue::from_static(ct));
        }
        None => {
            h.remove(header::CONTENT_TYPE);
        }
    }
    h.insert(header::CONTENT_LENGTH, HeaderValue::from(len));
    r
}

async fn serve_file(
    State(st): State<AppState>,
    ctx: Ctx,
    Path((drawing_id, file_id)): Path<(String, String)>,
) -> ApiResult {
    let opt = optional_auth(&st.db, &ctx).await;
    if !is_valid_file_id(&drawing_id) || !is_valid_file_id(&file_id) {
        return status_json(400, json!({ "error": "Invalid id segment" }));
    }
    let principal = opt.user.map(|u| u.id);
    let (did, fid) = (drawing_id.clone(), file_id.clone());
    let (access, record) = st
        .db
        .call(move |c| {
            let access = get_drawing_access(c, principal.as_deref(), &did, None)?;
            if !access.can_view() {
                return Ok((access, None));
            }
            Ok((access, find_drawing_file(c, &did, &fid)?))
        })
        .await?;
    let not_found = || status_json(404, json!({ "error": "File not found" }));
    if !access.can_view() {
        return not_found();
    }
    let Some(record) = record else { return not_found() };

    if record.storage == "db" {
        let Some(data) = record.data else { return not_found() };
        let etag = format!("\"{file_id}\"");
        let fresh = ctx.header("if-none-match") == Some(etag.as_str());
        let mut r = if fresh {
            StatusCode::NOT_MODIFIED.into_response()
        } else {
            let len = data.len();
            let mut r = (StatusCode::OK, data).into_response();
            r.headers_mut().insert(header::CONTENT_TYPE, header_value(&record.mime_type));
            r.headers_mut().insert(header::CONTENT_LENGTH, HeaderValue::from(len));
            r
        };
        let h = r.headers_mut();
        h.insert(header::ETAG, header_value(&etag));
        h.insert(header::CACHE_CONTROL, HeaderValue::from_static("private, max-age=31536000, immutable"));
        if fresh {
            h.remove(header::CONTENT_TYPE);
        }
        return Ok(r);
    }

    let (Some(s3c), Some(key)) = (s3::client(), record.s3_key.filter(|k| !k.is_empty())) else {
        return not_found();
    };
    // The redirect bypasses our CSP/nosniff headers: pin the stored type and
    // force scriptable types to download.
    let scriptable = record.mime_type == "image/svg+xml" || record.mime_type == "text/html";
    let disposition = if scriptable { "attachment".to_string() } else { format!("inline; filename=\"{file_id}\"") };
    let url = s3c
        .presigned_download_url(st.http(), &key, DOWNLOAD_EXPIRES_IN, Some(&record.mime_type), Some(&disposition))
        .await
        .map_err(|e| crate::http::error::ApiError::internal(e.to_string()))?;
    Ok(express_redirect(&ctx, &url))
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/files/config", get(files_config))
        .route("/drawings/{id}/files/{fileId}", put(upload_file))
        .route("/files/{drawingId}/{fileId}", get(serve_file))
}

#[cfg(test)]
mod tests {
    use super::accept_quality;

    #[test]
    fn accept_negotiation() {
        assert_eq!(accept_quality("*/*", "text/plain"), Some((1.0, 0)));
        assert_eq!(accept_quality("text/html,*/*;q=0.8", "text/html"), Some((1.0, 2)));
        assert_eq!(accept_quality("text/html,*/*;q=0.8", "text/plain"), Some((0.8, 0)));
        assert_eq!(accept_quality("image/png", "text/plain"), None);
    }
}
