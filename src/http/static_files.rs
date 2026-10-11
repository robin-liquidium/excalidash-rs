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

/// `Server` header of the upstream frontend image (nginx in zimengxiong/excalidash-frontend:0.6.5).
pub const NGINX_SERVER: &str = "nginx/1.31.6";

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

/// Deliberate deviation from upstream: nginx drops the server-level `add_header` set inside
/// `location = /index.html` (it defines its own), so upstream serves the app document without
/// CSP or frame protection (reported upstream as GHSA-r343-6gfx-3pcp). We send the same
/// headers on the HTML shell; the CSP's `script-src` additionally allows the shell's own
/// inline scripts by hash, so upstream's inline `EXCALIDRAW_ASSET_PATH` setup keeps working.
fn apply_document_headers(h: &mut HeaderMap, hashes: &[String]) {
    for (k, v) in NGINX_SECURITY_HEADERS {
        if k == "content-security-policy" {
            // Excalidraw's font subsetting (used when exporting) is Emscripten-compiled
            // HarfBuzz: it compiles WebAssembly and its embind glue builds functions with
            // `new Function`. Without these, subsetting fails and Excalidraw falls back to
            // fetching every font from the esm.sh CDN (blocked by font-src).
            let mut sources = ["'self'", "'unsafe-eval'", "'wasm-unsafe-eval'"].map(String::from).to_vec();
            sources.extend(hashes.iter().cloned());
            let csp = v.replacen("script-src 'self'", &format!("script-src {}", sources.join(" ")), 1);
            if let Ok(val) = HeaderValue::from_str(&csp) {
                h.append(k, val);
            }
        } else {
            h.append(k, HeaderValue::from_static(v));
        }
    }
}

/// `'sha256-…'` sources for every inline `<script>` (no `src`) in an HTML document.
pub fn inline_script_hashes(html: &[u8]) -> Vec<String> {
    use base64::Engine;
    use sha2::{Digest, Sha256};
    let s = String::from_utf8_lossy(html);
    let mut out = vec![];
    let mut rest = &s[..];
    while let Some(open) = rest.find("<script") {
        let after = &rest[open..];
        let Some(tag_end) = after.find('>') else { break };
        let tag = &after[..tag_end];
        let body = &after[tag_end + 1..];
        let Some(close) = body.find("</script>") else { break };
        if !tag.contains("src=") {
            let digest = Sha256::digest(body[..close].as_bytes());
            out.push(format!("'sha256-{}'", base64::engine::general_purpose::STANDARD.encode(digest)));
        }
        rest = &body[close..];
    }
    out
}

/// Server-level headers nginx appends (`add_header ... always`) to proxied
/// `/api` and `/socket.io` responses, for every status.
pub fn apply_server_headers(_status: StatusCode, h: &mut HeaderMap) {
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

/// nginx's built-in error page.
fn simple(status: StatusCode) -> Response<Body> {
    let body = format!(
        "<html>\r\n<head><title>{0} {1}</title></head>\r\n<body>\r\n<center><h1>{0} {1}</h1></center>\r\n<hr><center>{2}</center>\r\n</body>\r\n</html>\r\n",
        status.as_u16(),
        status.canonical_reason().unwrap_or(""),
        NGINX_SERVER
    );
    let mut r = Response::new(Body::from(body));
    *r.status_mut() = status;
    r.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html"));
    r
}

fn serve_blocking(root: &Path, method: &Method, headers: &HeaderMap, uri_path: &str) -> Response<Body> {
    if method != Method::GET && method != Method::HEAD {
        // nginx static handler: 405 for other methods on files. Only `location /`
        // inherits the server-level add_header set; the asset location defines its own.
        let mut r = simple(StatusCode::METHOD_NOT_ALLOWED);
        if !matches!(location_for(uri_path), Location::Asset) {
            apply_server_headers(StatusCode::OK, r.headers_mut());
        }
        return r;
    }
    let request_location = location_for(uri_path);
    let (served_path, found) = match request_location {
        // `location ~* \.(js|css|...)$` has no try_files: a missing file is nginx's 404.
        Location::Asset => match find_file(root, uri_path) {
            Some(f) => (uri_path.to_string(), f),
            None => {
                let mut r = simple(StatusCode::NOT_FOUND);
                r.headers_mut().insert(header::VARY, HeaderValue::from_static("Accept-Encoding"));
                return r;
            }
        },
        // try_files $uri $uri/ /index.html
        _ => match find_file(root, uri_path) {
            Some(f) => (uri_path.to_string(), f),
            None => {
                if let Some(dir) = safe_join(root, uri_path).filter(|p| p.is_dir() && uri_path != "/") {
                    let mut r = if !uri_path.ends_with('/') {
                        // Directory without trailing slash: 301 to the slash form.
                        let mut r = simple(StatusCode::MOVED_PERMANENTLY);
                        // absolute_redirect + port_in_redirect: Host name with the listen port.
                        let host = headers.get(header::HOST).and_then(|v| v.to_str().ok()).unwrap_or("localhost");
                        let name = host.rsplit_once(':').map(|(h, _)| h).unwrap_or(host);
                        let port = crate::config::config().port;
                        let authority = if port == 80 { name.to_string() } else { format!("{name}:{port}") };
                        if let Ok(v) = HeaderValue::from_str(&format!("http://{authority}{uri_path}/")) {
                            r.headers_mut().insert(header::LOCATION, v);
                        }
                        r
                    } else if dir.join("index.html").is_file() {
                        return serve_blocking(root, method, headers, &format!("{uri_path}index.html"));
                    } else {
                        // No index file and autoindex off.
                        let mut r = simple(StatusCode::FORBIDDEN);
                        r.headers_mut().insert(header::VARY, HeaderValue::from_static("Accept-Encoding"));
                        r
                    };
                    apply_server_headers(r.status(), r.headers_mut());
                    return r;
                }
                match find_file(root, "/index.html") {
                    Some(f) => ("/index.html".to_string(), f),
                    None => return simple(StatusCode::NOT_FOUND),
                }
            }
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
    let raw = if served_path == "/index.html" && !found.gz_only && crate::config::config().theme_follow_system {
        super::theme::inject(&raw)
    } else {
        raw
    };
    let document_hashes =
        if matches!(location_for(&served_path), Location::IndexHtml) { inline_script_hashes(&raw) } else { vec![] };
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
            apply_document_headers(h, &document_hashes);
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
        for h in [header::CONTENT_TYPE, header::CONTENT_ENCODING, header::ACCEPT_RANGES, header::VARY, header::CONTENT_LENGTH] {
            r.headers_mut().remove(h);
        }
        return r;
    }

    // ngx_http_range_filter: single ranges, multipart/byteranges, 416 (not with gzip).
    if !gzipped {
        if let Some(range) = headers.get(header::RANGE).and_then(|v| v.to_str().ok()) {
            let total = body_bytes.len() as u64;
            match parse_ranges(range, total) {
                RangeResult::Ignore => {}
                RangeResult::Unsatisfiable => {
                    // The range filter turns the prepared 200 into nginx's 416 page; the
                    // location's caching/security headers computed for the 200 remain.
                    let reason = "Requested Range Not Satisfiable";
                    let body = format!(
                        "<html>\r\n<head><title>416 {reason}</title></head>\r\n<body>\r\n<center><h1>416 {reason}</h1></center>\r\n<hr><center>{NGINX_SERVER}</center>\r\n</body>\r\n</html>\r\n"
                    );
                    let mut r = Response::new(Body::from(body));
                    *r.status_mut() = StatusCode::RANGE_NOT_SATISFIABLE;
                    r.extensions_mut().insert(hyper::ext::ReasonPhrase::from_static(b"Requested Range Not Satisfiable"));
                    let h = r.headers_mut();
                    for (k, v) in builder.headers_ref().unwrap() {
                        if [header::CONTENT_TYPE, header::LAST_MODIFIED, header::ETAG, header::ACCEPT_RANGES, header::VARY].contains(k) {
                            continue;
                        }
                        h.append(k.clone(), v.clone());
                    }
                    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html"));
                    if gzip_type(content_type) {
                        h.insert(header::VARY, HeaderValue::from_static("Accept-Encoding"));
                    }
                    h.insert(header::CONTENT_RANGE, HeaderValue::from_str(&format!("bytes */{total}")).unwrap());
                    if matches!(location, Location::IndexHtml) {
                        // `add_header Cache-Control ... always` runs again for the error response.
                        h.append(
                            header::CACHE_CONTROL,
                            HeaderValue::from_static("no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0"),
                        );
                    }
                    return r;
                }
                RangeResult::Ranges(ranges) if ranges.len() == 1 => {
                    let (start, end) = ranges[0];
                    let slice = body_bytes[start as usize..=end as usize].to_vec();
                    let h = builder.headers_mut().unwrap();
                    h.insert(header::CONTENT_RANGE, HeaderValue::from_str(&format!("bytes {start}-{end}/{total}")).unwrap());
                    h.insert(header::CONTENT_LENGTH, HeaderValue::from(slice.len()));
                    h.remove(header::ACCEPT_RANGES);
                    let body = if method == Method::HEAD { Body::empty() } else { Body::from(slice) };
                    return builder.status(StatusCode::PARTIAL_CONTENT).body(body).unwrap();
                }
                RangeResult::Ranges(ranges) => {
                    static BOUNDARY: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
                    let boundary = format!("{:020}", BOUNDARY.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1);
                    let mut out = Vec::new();
                    for (start, end) in &ranges {
                        out.extend_from_slice(
                            format!("\r\n--{boundary}\r\nContent-Type: {content_type}\r\nContent-Range: bytes {start}-{end}/{total}\r\n\r\n").as_bytes(),
                        );
                        out.extend_from_slice(&body_bytes[*start as usize..=*end as usize]);
                    }
                    out.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
                    let h = builder.headers_mut().unwrap();
                    h.insert(
                        header::CONTENT_TYPE,
                        HeaderValue::from_str(&format!("multipart/byteranges; boundary={boundary}")).unwrap(),
                    );
                    h.insert(header::CONTENT_LENGTH, HeaderValue::from(out.len()));
                    h.remove(header::ACCEPT_RANGES);
                    let body = if method == Method::HEAD { Body::empty() } else { Body::from(out) };
                    return builder.status(StatusCode::PARTIAL_CONTENT).body(body).unwrap();
                }
            }
        }
    }

    if !gzipped {
        builder.headers_mut().unwrap().insert(header::CONTENT_LENGTH, HeaderValue::from(body_bytes.len()));
    }
    let body = if method == Method::HEAD {
        Body::empty()
    } else if gzipped {
        // nginx's gzip filter streams the compressed body (chunked, no Content-Length).
        Body::from_stream(futures_util::stream::iter([Ok::<_, std::io::Error>(bytes::Bytes::from(body_bytes))]))
    } else {
        Body::from(body_bytes)
    };
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

enum RangeResult {
    Ignore,
    Unsatisfiable,
    Ranges(Vec<(u64, u64)>),
}

/// ngx_http_range_parse: `bytes=` list of `a-b`, `a-`, `-n`; ranges starting past the end
/// are dropped; malformed or inverted ranges make the whole header unsatisfiable.
fn parse_ranges(v: &str, len: u64) -> RangeResult {
    let Some(spec) = v.strip_prefix("bytes=") else { return RangeResult::Ignore };
    let mut out = vec![];
    for part in spec.split(',') {
        let part = part.trim_matches(' ');
        let Some((a, b)) = part.split_once('-') else { return RangeResult::Unsatisfiable };
        let (a, b) = (a.trim_matches(' '), b.trim_matches(' '));
        let num = |x: &str| if !x.is_empty() && x.bytes().all(|c| c.is_ascii_digit()) { x.parse::<u64>().ok() } else { None };
        let (start, end) = if a.is_empty() {
            let Some(n) = num(b) else { return RangeResult::Unsatisfiable };
            if n == 0 {
                continue;
            }
            (len.saturating_sub(n), len.saturating_sub(1))
        } else {
            let Some(s) = num(a) else { return RangeResult::Unsatisfiable };
            let e = if b.is_empty() {
                len.saturating_sub(1)
            } else {
                match num(b) {
                    Some(e) => e,
                    None => return RangeResult::Unsatisfiable,
                }
            };
            if s > e {
                return RangeResult::Unsatisfiable;
            }
            (s, e.min(len.saturating_sub(1)))
        };
        if start < len {
            out.push((start, end));
        }
    }
    if out.is_empty() { RangeResult::Unsatisfiable } else { RangeResult::Ranges(out) }
}

#[cfg(test)]
mod document_header_tests {
    use super::*;

    #[test]
    fn hashes_only_inline_scripts() {
        let html = b"<head><script src=\"/a.js\"></script><script type=\"module\" src=\"/b.js\"></script></head><body><script>\n  x();\n</script></body>";
        // sha256("\n  x();\n")
        use base64::Engine;
        use sha2::{Digest, Sha256};
        let want = format!("'sha256-{}'", base64::engine::general_purpose::STANDARD.encode(Sha256::digest(b"\n  x();\n")));
        assert_eq!(inline_script_hashes(html), vec![want.clone()]);
        let mut h = HeaderMap::new();
        apply_document_headers(&mut h, &inline_script_hashes(html));
        let csp = h.get("content-security-policy").unwrap().to_str().unwrap();
        assert!(csp.contains(&format!("script-src 'self' 'unsafe-eval' 'wasm-unsafe-eval' {want};")), "{csp}");
        assert_eq!(h.get("x-frame-options").unwrap(), "DENY");
    }
}

