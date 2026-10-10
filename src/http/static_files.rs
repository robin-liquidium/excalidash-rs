//! nginx emulation for the frontend container (frontend/nginx.conf.template):
//! SPA fallback, per-location headers, caching, gzip, ETag/Last-Modified, 304s.
//!
//! To keep the image small, compressible assets may be stored only as `<file>.gz`;
//! they are sent compressed to gzip-capable clients and inflated otherwise.
use axum::{
    body::Body,
    http::{header, HeaderMap, HeaderValue, Method, Request, Response, StatusCode},
};
use std::{
    io::Read,
    path::{Component, Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

pub const NGINX_SECURITY_HEADERS: [(&str, &str); 5] = [
    ("x-frame-options", "DENY"),
    ("x-content-type-options", "nosniff"),
    ("referrer-policy", "strict-origin-when-cross-origin"),
    ("permissions-policy", "camera=(), microphone=(), geolocation=()"),
    (
        "content-security-policy",
        "default-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; frame-src https:; script-src 'self'; style-src 'self' 'unsafe-inline'; font-src 'self' data:; img-src 'self' data: blob: https:; connect-src 'self' https: ws: wss:;",
    ),
];

/// nginx `add_header` (without `always`) only applies to these statuses.
fn add_header_applies(status: StatusCode) -> bool {
    matches!(status.as_u16(), 200 | 201 | 204 | 206 | 301 | 302 | 303 | 304 | 307 | 308)
}

/// Server-level headers nginx appends to proxied `/api` and `/socket.io` responses.
pub fn apply_server_headers(status: StatusCode, h: &mut HeaderMap) {
    if !add_header_applies(status) {
        return;
    }
    for (k, v) in NGINX_SECURITY_HEADERS {
        h.append(k, HeaderValue::from_static(v));
    }
}

/// `gzip_types` from the nginx config (text/html is always included by nginx).
pub fn gzip_type(content_type: &str) -> bool {
    let ess = content_type.split(';').next().unwrap_or("").trim();
    matches!(
        ess,
        "text/html"
            | "text/plain"
            | "text/css"
            | "application/json"
            | "application/javascript"
            | "text/xml"
            | "application/xml"
            | "application/xml+rss"
            | "text/javascript"
    )
}

pub fn accepts_gzip(headers: &HeaderMap) -> bool {
    headers
        .get_all(header::ACCEPT_ENCODING)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|enc| {
            let mut parts = enc.trim().split(';');
            let name = parts.next().unwrap_or("").trim();
            let q_zero = parts.any(|p| {
                let p = p.trim();
                p == "q=0" || p == "q=0.0" || p == "q=0.00" || p == "q=0.000"
            });
            (name.eq_ignore_ascii_case("gzip") || name == "*") && !q_zero
        })
}

pub fn gzip_bytes(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::new(1));
    let _ = enc.write_all(data);
    enc.finish().unwrap_or_default()
}

fn mime_for(path: &Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()).map(|e| e.to_ascii_lowercase()).as_deref() {
        Some("html" | "htm" | "shtml") => "text/html",
        Some("js") => "application/javascript",
        Some("css") => "text/css",
        Some("svg" | "svgz") => "image/svg+xml",
        Some("woff2") => "font/woff2",
        Some("woff") => "font/woff",
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("webp") => "image/webp",
        Some("ico") => "image/x-icon",
        Some("json") => "application/json",
        Some("txt") => "text/plain",
        Some("wasm") => "application/wasm",
        Some("xml") => "text/xml",
        _ => "application/octet-stream",
    }
}

enum Location {
    IndexHtml,
    Asset,
    Default,
}

fn location_for(uri_path: &str) -> Location {
    if uri_path == "/index.html" {
        return Location::IndexHtml;
    }
    let lower = uri_path.to_ascii_lowercase();
    const EXT: [&str; 13] = [".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".woff", ".woff2", ".ttf", ".eot", ""];
    if EXT[..12].iter().any(|e| lower.ends_with(e)) {
        return Location::Asset;
    }
    Location::Default
}

fn http_date(t: SystemTime) -> String {
    let dt: chrono::DateTime<chrono::Utc> = t.into();
    dt.format("%a, %d %b %Y %H:%M:%S GMT").to_string()
}

struct Found {
    path: PathBuf,
    gz_only: bool,
}

fn safe_join(root: &Path, uri_path: &str) -> Option<PathBuf> {
    let decoded = percent_encoding::percent_decode_str(uri_path).decode_utf8().ok()?;
    let mut p = root.to_path_buf();
    for c in Path::new(decoded.trim_start_matches('/')).components() {
        match c {
            Component::Normal(s) => p.push(s),
            Component::CurDir => {}
            _ => return None,
        }
    }
    Some(p)
}

fn find_file(root: &Path, uri_path: &str) -> Option<Found> {
    let p = safe_join(root, uri_path)?;
    if p.is_file() {
        return Some(Found { path: p, gz_only: false });
    }
    let mut gz = p.clone().into_os_string();
    gz.push(".gz");
    let gz = PathBuf::from(gz);
    if gz.is_file() {
        return Some(Found { path: gz, gz_only: true });
    }
    None
}

pub async fn serve(root: PathBuf, req: Request<Body>) -> Response<Body> {
    let method = req.method().clone();
    let headers = req.headers().clone();
    let uri_path = req.uri().path().to_string();
    tokio::task::spawn_blocking(move || serve_blocking(&root, &method, &headers, &uri_path))
        .await
        .unwrap_or_else(|_| simple(StatusCode::INTERNAL_SERVER_ERROR))
}

fn simple(status: StatusCode) -> Response<Body> {
    let body = format!(
        "<html>\r\n<head><title>{0} {1}</title></head>\r\n<body>\r\n<center><h1>{0} {1}</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n",
        status.as_u16(),
        status.canonical_reason().unwrap_or("")
    );
    let mut r = Response::new(Body::from(body));
    *r.status_mut() = status;
    r.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html"));
    r
}

fn serve_blocking(root: &Path, method: &Method, headers: &HeaderMap, uri_path: &str) -> Response<Body> {
    if method != Method::GET && method != Method::HEAD {
        // nginx static handler: 405 for other methods on files.
        let mut r = simple(StatusCode::METHOD_NOT_ALLOWED);
        apply_server_headers(StatusCode::OK, r.headers_mut()); // location / inherits server headers
        return r;
    }
    // try_files $uri $uri/ /index.html
    let (served_path, found) = match find_file(root, uri_path) {
        Some(f) => (uri_path.to_string(), f),
        None => match find_file(root, "/index.html") {
            Some(f) => ("/index.html".to_string(), f),
            None => return simple(StatusCode::NOT_FOUND),
        },
    };
    let location = location_for(&served_path);
    let logical = if found.gz_only { found.path.with_extension("") } else { found.path.clone() };
    let content_type = mime_for(&logical);

    let meta = match std::fs::metadata(&found.path) {
        Ok(m) => m,
        Err(_) => return simple(StatusCode::NOT_FOUND),
    };
    let mtime = meta.modified().unwrap_or(UNIX_EPOCH);
    let mtime_secs = mtime.duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);

    let client_gzip = accepts_gzip(headers);
    let compress = gzip_type(content_type) && client_gzip;
    // Body bytes for the representation we will send.
    let raw = match std::fs::read(&found.path) {
        Ok(b) => b,
        Err(_) => return simple(StatusCode::NOT_FOUND),
    };
    let (body_bytes, gzipped, plain_len) = if found.gz_only {
        if client_gzip {
            let plain_len = gz_plain_len(&raw);
            (raw, true, plain_len)
        } else {
            let mut out = vec![];
            let _ = flate2::read::GzDecoder::new(&raw[..]).read_to_end(&mut out);
            let n = out.len() as u64;
            (out, false, n)
        }
    } else if compress && raw.len() >= 20 {
        let n = raw.len() as u64;
        (gzip_bytes(&raw), true, n)
    } else {
        let n = raw.len() as u64;
        (raw, false, n)
    };

    let etag_strong = format!("\"{:x}-{:x}\"", mtime_secs, plain_len);
    let etag = if gzipped { format!("W/{etag_strong}") } else { etag_strong.clone() };
    let last_modified = http_date(mtime);

    let mut builder = Response::builder().status(StatusCode::OK);
    let h = builder.headers_mut().unwrap();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    h.insert(header::LAST_MODIFIED, HeaderValue::from_str(&last_modified).unwrap());
    if gzip_type(content_type) {
        h.insert(header::VARY, HeaderValue::from_static("Accept-Encoding"));
    }
    h.insert(header::ETAG, HeaderValue::from_str(&etag).unwrap());
    let now = SystemTime::now();
    match location {
        Location::IndexHtml => {
            h.insert(header::EXPIRES, HeaderValue::from_str(&http_date(now - std::time::Duration::from_secs(1))).unwrap());
            h.append(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
            h.append(
                header::CACHE_CONTROL,
                HeaderValue::from_static("no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0"),
            );
        }
        Location::Asset => {
            h.insert(
                header::EXPIRES,
                HeaderValue::from_str(&http_date(now + std::time::Duration::from_secs(31_536_000))).unwrap(),
            );
            h.append(header::CACHE_CONTROL, HeaderValue::from_static("max-age=31536000"));
            h.append(header::CACHE_CONTROL, HeaderValue::from_static("public, immutable"));
        }
        Location::Default => {
            for (k, v) in NGINX_SECURITY_HEADERS {
                h.append(k, HeaderValue::from_static(v));
            }
        }
    }
    if gzipped {
        h.insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
    } else {
        h.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    }

    // Conditional requests (nginx ngx_http_not_modified_filter).
    let inm = headers.get(header::IF_NONE_MATCH).and_then(|v| v.to_str().ok());
    let ims = headers.get(header::IF_MODIFIED_SINCE).and_then(|v| v.to_str().ok());
    let not_modified = match inm {
        Some(v) => v.split(',').map(|t| t.trim()).any(|t| {
            t == "*" || t == etag || t == etag_strong || t.trim_start_matches("W/") == etag_strong
        }),
        None => ims.map(|v| v == last_modified).unwrap_or(false),
    };
    if not_modified {
        let mut r = builder.status(StatusCode::NOT_MODIFIED).body(Body::empty()).unwrap();
        r.headers_mut().remove(header::CONTENT_TYPE);
        r.headers_mut().remove(header::CONTENT_ENCODING);
        return r;
    }

    // Single byte-range support for uncompressed bodies.
    if !gzipped {
        if let Some(range) = headers.get(header::RANGE).and_then(|v| v.to_str().ok()) {
            if let Some((start, end)) = parse_range(range, body_bytes.len() as u64) {
                let slice = body_bytes[start as usize..=end as usize].to_vec();
                let total = body_bytes.len();
                let h = builder.headers_mut().unwrap();
                h.insert(
                    header::CONTENT_RANGE,
                    HeaderValue::from_str(&format!("bytes {start}-{end}/{total}")).unwrap(),
                );
                h.insert(header::CONTENT_LENGTH, HeaderValue::from(slice.len()));
                let body = if method == Method::HEAD { Body::empty() } else { Body::from(slice) };
                return builder.status(StatusCode::PARTIAL_CONTENT).body(body).unwrap();
            }
        }
    }

    if !gzipped {
        builder.headers_mut().unwrap().insert(header::CONTENT_LENGTH, HeaderValue::from(body_bytes.len()));
    }
    let body = if method == Method::HEAD { Body::empty() } else { Body::from(body_bytes) };
    builder.body(body).unwrap()
}

fn gz_plain_len(gz: &[u8]) -> u64 {
    // ISIZE trailer (mod 2^32) — fine for our asset sizes.
    if gz.len() >= 4 {
        let n = gz.len();
        u32::from_le_bytes([gz[n - 4], gz[n - 3], gz[n - 2], gz[n - 1]]) as u64
    } else {
        0
    }
}

fn parse_range(v: &str, len: u64) -> Option<(u64, u64)> {
    let spec = v.strip_prefix("bytes=")?;
    if spec.contains(',') || len == 0 {
        return None;
    }
    let (a, b) = spec.split_once('-')?;
    let (start, end) = if a.is_empty() {
        let n: u64 = b.parse().ok()?;
        (len.saturating_sub(n), len - 1)
    } else {
        let s: u64 = a.parse().ok()?;
        let e: u64 = if b.is_empty() { len - 1 } else { b.parse::<u64>().ok()?.min(len - 1) };
        (s, e)
    };
    (start <= end && start < len).then_some((start, end))
}
