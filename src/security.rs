//! security.ts — XSS sanitization and drawing-payload validation.
//!
//! DOMPurify is replaced by `ammonia` (html5ever) configured with the same
//! allow/forbid lists; zod schemas are reproduced by hand, including output key
//! order (known keys in schema order, then passthrough/catchall keys).
use serde_json::{Map, Value};
use std::collections::HashSet;
use std::sync::{atomic::AtomicU64, atomic::Ordering, OnceLock};

use crate::util::{js_len, js_slice};

/// DrawingSanitizationError (400 bad dataURL / 413 too large), carries the file id.
#[derive(Debug, Clone)]
pub struct DrawingSanitizationError {
    pub status: u16,
    pub file_id: String,
    pub message: String,
}

#[derive(Debug, Clone)]
pub enum SanitizeFailure {
    Drawing(DrawingSanitizationError),
    /// "Invalid or malicious drawing data detected"
    Invalid,
}

static MAX_DATA_URL_SIZE: AtomicU64 = AtomicU64::new(10 * 1024 * 1024);

pub fn configure_max_data_url_size(bytes: u64) {
    MAX_DATA_URL_SIZE.store(bytes, Ordering::Relaxed);
}
pub fn reset_security_settings() {
    MAX_DATA_URL_SIZE.store(10 * 1024 * 1024, Ordering::Relaxed);
}
pub fn max_data_url_size() -> u64 {
    MAX_DATA_URL_SIZE.load(Ordering::Relaxed)
}

/// fileProcessing.ts MIME_TO_EXT (ordered).
pub const MIME_TO_EXT: [(&str, &str); 7] = [
    ("image/png", "png"),
    ("image/jpeg", "jpg"),
    ("image/gif", "gif"),
    ("image/webp", "webp"),
    ("image/avif", "avif"),
    ("image/bmp", "bmp"),
    ("image/svg+xml", "svg"),
];

pub fn mime_to_ext(mime: &str) -> Option<&'static str> {
    MIME_TO_EXT.iter().find(|(m, _)| *m == mime).map(|(_, e)| *e)
}

fn re(cell: &'static OnceLock<regex::Regex>, pat: &str) -> &'static regex::Regex {
    cell.get_or_init(|| regex::Regex::new(pat).unwrap())
}

fn safe_image_dataurl() -> &'static regex::Regex {
    static R: OnceLock<regex::Regex> = OnceLock::new();
    R.get_or_init(|| {
        let mimes: Vec<String> = MIME_TO_EXT.iter().map(|(m, _)| regex::escape(m)).collect();
        regex::Regex::new(&format!(r"(?i)^data:(?:{});base64,[A-Za-z0-9+/=\s]+$", mimes.join("|"))).unwrap()
    })
}

pub fn api_file_ref() -> &'static regex::Regex {
    static R: OnceLock<regex::Regex> = OnceLock::new();
    re(&R, r"^/api/files/[A-Za-z0-9_-]{1,200}/[A-Za-z0-9_-]{1,200}$")
}

fn valid_file_id() -> &'static regex::Regex {
    static R: OnceLock<regex::Regex> = OnceLock::new();
    re(&R, r"^[A-Za-z0-9_-]{1,200}$")
}

/// JS `String.prototype.trim` (also strips U+FEFF).
pub fn js_trim(s: &str) -> &str {
    s.trim_matches(|c: char| c.is_whitespace() || c == '\u{FEFF}')
}

fn strip_controls(s: &str) -> String {
    s.chars()
        .filter(|c| {
            let u = *c as u32;
            !((u <= 0x08) || u == 0x0B || u == 0x0C || (0x0E..=0x1F).contains(&u) || u == 0x7F)
        })
        .collect()
}

const PURIFY_FORBID_CONTENTS: [&str; 26] = [
    "annotation-xml", "audio", "colgroup", "desc", "foreignobject", "foreignObject", "head", "iframe", "math", "mi",
    "mn", "mo", "ms", "mtext", "noembed", "noframes", "noscript", "plaintext", "script", "style", "svg", "template",
    "thead", "title", "video", "xmp",
];

fn text_cleaner() -> &'static ammonia::Builder<'static> {
    static B: OnceLock<ammonia::Builder<'static>> = OnceLock::new();
    B.get_or_init(|| {
        let mut b = ammonia::Builder::empty();
        b.tag_attributes(std::collections::HashMap::new());
        b.generic_attributes(HashSet::new());
        b.tags(["b", "i", "u", "em", "strong", "br", "span"].into_iter().collect());
        let content: HashSet<&str> = PURIFY_FORBID_CONTENTS.iter().copied().collect();
        b.clean_content_tags(content);
        b.strip_comments(true);
        b.link_rel(None);
        b
    })
}

/// sanitizeText(input, maxLength)
pub fn sanitize_text_value(input: &Value, max_length: usize) -> String {
    match input {
        Value::String(s) => sanitize_text(s, max_length),
        _ => String::new(),
    }
}

pub fn sanitize_text(input: &str, max_length: usize) -> String {
    let cleaned = strip_controls(input);
    let truncated = js_slice(&cleaned, max_length);
    let out = text_cleaner().clean(&truncated).to_string();
    js_trim(&out).to_string()
}

/// sanitizeElementText: strip control chars + truncate, no HTML processing.
pub fn sanitize_element_text(input: &str, max_length: usize) -> String {
    js_slice(&strip_controls(input), max_length)
}

/// sanitizeUrl
pub fn sanitize_url(url: &str) -> String {
    let trimmed = js_trim(url);
    static BAD: OnceLock<regex::Regex> = OnceLock::new();
    static GOOD: OnceLock<regex::Regex> = OnceLock::new();
    if re(&BAD, r"(?i)^(javascript|data|vbscript):").is_match(trimmed) {
        return String::new();
    }
    if re(&GOOD, r"(?i)^(https?://|mailto:|/|\./|\.\./)").is_match(trimmed) {
        return trimmed.to_string();
    }
    String::new()
}

const SVG_TAGS: [&str; 18] = [
    "svg", "defs", "pattern", "g", "image", "symbol", "use", "clipPath", "mask", "rect", "circle", "ellipse", "line",
    "polyline", "polygon", "path", "text", "tspan",
];
const SVG_ATTRS: [&str; 55] = [
    "xmlns", "xmlns:xlink", "version", "id", "viewBox", "preserveAspectRatio", "x", "y", "width", "height", "cx", "cy",
    "r", "rx", "ry", "x1", "y1", "x2", "y2", "points", "d", "fill", "fill-opacity", "fill-rule", "stroke",
    "stroke-width", "stroke-opacity", "stroke-linecap", "stroke-linejoin", "stroke-miterlimit", "stroke-dasharray",
    "stroke-dashoffset", "opacity", "transform", "clip-path", "mask", "clipPathUnits", "maskUnits",
    "maskContentUnits", "vector-effect", "patternUnits", "patternContentUnits", "font-size", "font-family",
    "font-weight", "letter-spacing", "text-anchor", "dominant-baseline", "href", "xlink:href", "xlink", "viewbox",
    "preserveaspectratio", "clippathunits", "maskunits",
];

fn svg_cleaner() -> &'static ammonia::Builder<'static> {
    static B: OnceLock<ammonia::Builder<'static>> = OnceLock::new();
    B.get_or_init(|| {
        let mut b = ammonia::Builder::empty();
        b.tag_attributes(std::collections::HashMap::new());
        b.tags(SVG_TAGS.into_iter().collect());
        b.generic_attributes(SVG_ATTRS.into_iter().collect());
        let content: HashSet<&str> = ["script", "style", "foreignObject", "foreignobject", "iframe", "title", "desc", "noscript", "template", "math"]
            .into_iter()
            .collect();
        b.clean_content_tags(content);
        b.strip_comments(true);
        b.link_rel(None);
        // Image/use hrefs are validated by the post-pass below (same as upstream).
        b.url_relative(ammonia::UrlRelative::PassThrough);
        b.url_schemes(["http", "https", "data", "mailto"].into_iter().collect());
        b
    })
}

/// sanitizeSvg
pub fn sanitize_svg(svg: &str) -> String {
    let sanitized = svg_cleaner().clean(svg).to_string();
    let sanitized = js_trim(&sanitized).to_string();
    // Crop/frame masks only refer to local SVG geometry.
    static ATTR: OnceLock<regex::Regex> = OnceLock::new();
    static LOCAL: OnceLock<regex::Regex> = OnceLock::new();
    let attr_re = re(&ATTR, r#"(?i)\s(?:clip-path|mask)="([^"]*)""#);
    let local_re = re(&LOCAL, r"^url\(#[A-Za-z0-9_-]+\)$");
    let local_refs = attr_re.replace_all(&sanitized, |caps: &regex::Captures<'_>| {
        if local_re.is_match(&caps[1]) { caps[0].to_string() } else { String::new() }
    });
    js_trim(&sanitize_svg_image_tags(&local_refs)).to_string()
}

fn sanitize_svg_image_tags(content: &str) -> String {
    static TAG: OnceLock<regex::Regex> = OnceLock::new();
    static H1: OnceLock<regex::Regex> = OnceLock::new();
    static H2: OnceLock<regex::Regex> = OnceLock::new();
    static H3: OnceLock<regex::Regex> = OnceLock::new();
    static H4: OnceLock<regex::Regex> = OnceLock::new();
    static XLINK_ANY: OnceLock<regex::Regex> = OnceLock::new();
    static HREF_EQ: OnceLock<regex::Regex> = OnceLock::new();
    static HREF_ANY: OnceLock<regex::Regex> = OnceLock::new();
    static OPEN: OnceLock<regex::Regex> = OnceLock::new();
    static USE_REF: OnceLock<regex::Regex> = OnceLock::new();
    static SAFE_IMG: OnceLock<regex::Regex> = OnceLock::new();
    let tag_re = re(&TAG, r"(?i)<(image|use)\b[^>]*>");
    let h = [
        re(&H1, r#"(?i)\shref\s*=\s*"([^"]*)""#),
        re(&H2, r#"(?i)\shref\s*=\s*'([^']*)'"#),
        re(&H3, r#"(?i)\sxlink:href\s*=\s*"([^"]*)""#),
        re(&H4, r#"(?i)\sxlink:href\s*=\s*'([^']*)'"#),
    ];
    let xlink_any = re(&XLINK_ANY, r#"(?i)\sxlink:href\s*=\s*(?:"[^"]*"|'[^']*')"#);
    let href_eq = re(&HREF_EQ, r"(?i)\shref\s*=");
    let href_any = re(&HREF_ANY, r#"(?i)\shref\s*=\s*(?:"[^"]*"|'[^']*')"#);
    let open = re(&OPEN, r"(?i)<(image|use)\b");
    let use_ref = re(&USE_REF, r"^#[A-Za-z0-9_-]+$");
    let safe_img = re(&SAFE_IMG, r"(?i)^data:image/(?:png|jpe?g|gif|webp|avif|bmp|svg\+xml);base64,[a-z0-9+/=\s]+$");
    tag_re
        .replace_all(content, |caps: &regex::Captures<'_>| {
            let image_tag = &caps[0];
            let tag = caps[1].to_lowercase();
            let href = h.iter().find_map(|r| r.captures(image_tag).map(|c| c[1].to_string()));
            let href_value = href.map(|v| js_trim(&v).to_string());
            let safe = match &href_value {
                Some(v) if !v.is_empty() => {
                    if tag == "use" {
                        use_ref.is_match(v)
                    } else {
                        safe_img.is_match(v) || api_file_ref().is_match(v)
                    }
                }
                _ => false,
            };
            if !safe {
                return String::new();
            }
            let hv = href_value.unwrap();
            let without_xlink = xlink_any.replace_all(image_tag, "").to_string();
            if href_eq.is_match(&without_xlink) {
                return href_any.replacen(&without_xlink, 1, format!(" href=\"{hv}\"").as_str()).to_string();
            }
            open.replacen(&without_xlink, 1, |c: &regex::Captures<'_>| format!("<{} href=\"{hv}\"", &c[1])).to_string()
        })
        .to_string()
}

// ---------------------------------------------------------------------------
// zod schema emulation

fn is_num(v: &Value) -> bool {
    v.is_number()
}

/// `.optional().nullable()` wrapper: absent → skip, null → keep null.
fn opt_null<F: Fn(&Value) -> bool>(v: Option<&Value>, check: F) -> bool {
    match v {
        None | Some(Value::Null) => true,
        Some(v) => check(v),
    }
}

fn num_in(v: &Value, min: Option<f64>, max: Option<f64>) -> bool {
    match v.as_f64() {
        Some(n) if n.is_finite() => min.map(|m| n >= m).unwrap_or(true) && max.map(|m| n <= m).unwrap_or(true),
        _ => false,
    }
}

fn str_max(v: &Value, max: usize) -> bool {
    v.as_str().map(|s| js_len(s) <= max).unwrap_or(false)
}

fn is_record(v: &Value) -> bool {
    v.is_object()
}

const ELEMENT_KEYS: [&str; 29] = [
    "id", "type", "x", "y", "width", "height", "angle", "strokeColor", "backgroundColor", "fillStyle", "strokeWidth",
    "strokeStyle", "roundness", "boundElements", "groupIds", "frameId", "seed", "version", "versionNonce", "isDeleted",
    "opacity", "link", "locked", "text", "fontSize", "fontFamily", "textAlign", "verticalAlign", "customData",
];

fn element_field_ok(key: &str, v: &Value) -> bool {
    match key {
        "id" => v.as_str().map(|s| { let n = js_len(s); n >= 1 && n <= 200 }).unwrap_or(false),
        "type" | "strokeColor" | "backgroundColor" | "fillStyle" | "strokeStyle" | "frameId" | "link" | "text"
        | "textAlign" | "verticalAlign" => v.is_string(),
        "x" | "y" | "width" | "height" | "angle" | "strokeWidth" | "seed" | "version" | "versionNonce" | "opacity"
        | "fontSize" => is_num(v),
        "roundness" => true,
        "boundElements" => v.is_array(),
        "groupIds" => v.as_array().map(|a| a.iter().all(|x| x.is_string())).unwrap_or(false),
        "isDeleted" | "locked" => v.is_boolean(),
        "fontFamily" => is_num(v) || str_max(v, 200),
        "customData" => is_record(v),
        _ => true,
    }
}

/// elementSchema.parse (passthrough + text/link transform).
pub fn sanitize_element(el: &Value) -> Option<Value> {
    let obj = el.as_object()?;
    let mut out = Map::new();
    for key in ELEMENT_KEYS {
        if let Some(v) = obj.get(key) {
            if !opt_null(Some(v), |v| element_field_ok(key, v)) {
                return None;
            }
            out.insert(key.to_string(), v.clone());
        }
    }
    for (k, v) in obj {
        if !out.contains_key(k) {
            out.insert(k.clone(), v.clone());
        }
    }
    if let Some(Value::String(t)) = out.get("text") {
        let s = sanitize_element_text(t, 5000);
        out.insert("text".into(), Value::String(s));
    }
    if let Some(Value::String(l)) = out.get("link") {
        let s = sanitize_url(l);
        out.insert("link".into(), Value::String(s));
    }
    Some(Value::Object(out))
}

pub fn sanitize_elements(elements: &Value) -> Option<Vec<Value>> {
    elements.as_array()?.iter().map(sanitize_element).collect()
}

const APPSTATE_KEYS: [&str; 26] = [
    "gridSize", "gridStep", "viewBackgroundColor", "currentItemStrokeColor", "currentItemBackgroundColor",
    "currentItemFillStyle", "currentItemStrokeWidth", "currentItemStrokeStyle", "currentItemRoundness",
    "currentItemFontSize", "currentItemFontFamily", "currentItemTextAlign", "currentItemVerticalAlign", "scrollX",
    "scrollY", "zoom", "selection", "selectedElementIds", "selectedGroupIds", "activeEmbeddable", "activeTool",
    "cursorX", "cursorY", "collaborators", "", "",
];

fn enum_of(v: &Value, allowed: &[&str]) -> bool {
    v.as_str().map(|s| allowed.contains(&s)).unwrap_or(false)
}

/// Returns the parsed (possibly stripped) value or None on validation failure.
fn appstate_field(key: &str, v: &Value) -> Option<Value> {
    if v.is_null() {
        return Some(Value::Null);
    }
    let ok = |b: bool| if b { Some(v.clone()) } else { None };
    match key {
        "gridSize" => ok(num_in(v, Some(0.0), Some(1000.0))),
        "gridStep" => ok(num_in(v, Some(1.0), Some(1000.0))),
        "viewBackgroundColor" | "currentItemStrokeColor" | "currentItemBackgroundColor" => ok(v.is_string()),
        "currentItemFillStyle" => ok(enum_of(v, &["solid", "hachure", "cross-hatch", "dots"])),
        "currentItemStrokeWidth" => ok(num_in(v, Some(0.0), Some(50.0))),
        "currentItemStrokeStyle" => ok(enum_of(v, &["solid", "dashed", "dotted"])),
        "currentItemRoundness" => {
            if enum_of(v, &["sharp", "round"]) {
                return Some(v.clone());
            }
            let o = v.as_object()?;
            let t = o.get("type")?;
            let val = o.get("value")?;
            if enum_of(t, &["round", "sharp"]) && num_in(val, Some(0.0), Some(1.0)) {
                let mut m = Map::new();
                m.insert("type".into(), t.clone());
                m.insert("value".into(), val.clone());
                Some(Value::Object(m))
            } else {
                None
            }
        }
        "currentItemFontSize" => ok(num_in(v, Some(1.0), Some(500.0))),
        "currentItemFontFamily" => ok(num_in(v, Some(0.0), None) || str_max(v, 200)),
        "currentItemTextAlign" => ok(enum_of(v, &["left", "center", "right"])),
        "currentItemVerticalAlign" => ok(enum_of(v, &["top", "middle", "bottom"])),
        "scrollX" | "scrollY" => ok(num_in(v, Some(-10000000.0), Some(10000000.0))),
        "zoom" => {
            let o = v.as_object()?;
            let val = o.get("value")?;
            if !num_in(val, Some(0.01), Some(100.0)) {
                return None;
            }
            let mut m = Map::new();
            m.insert("value".into(), val.clone());
            Some(Value::Object(m))
        }
        "selection" => ok(v.as_array().map(|a| a.iter().all(|x| x.is_string())).unwrap_or(false)),
        "selectedElementIds" | "selectedGroupIds" => {
            ok(v.as_object().map(|o| o.values().all(|x| x.is_boolean())).unwrap_or(false))
        }
        "activeEmbeddable" => {
            let o = v.as_object()?;
            let (e, s) = (o.get("elementId")?, o.get("state")?);
            if !(e.is_string() && s.is_string()) {
                return None;
            }
            let mut m = Map::new();
            m.insert("elementId".into(), e.clone());
            m.insert("state".into(), s.clone());
            Some(Value::Object(m))
        }
        "activeTool" => {
            let o = v.as_object()?;
            let t = o.get("type")?;
            if !t.is_string() {
                return None;
            }
            let mut m = Map::new();
            m.insert("type".into(), t.clone());
            if let Some(ct) = o.get("customType") {
                if !(ct.is_null() || ct.is_string()) {
                    return None;
                }
                m.insert("customType".into(), ct.clone());
            }
            Some(Value::Object(m))
        }
        "cursorX" | "cursorY" => ok(num_in(v, None, None)),
        "collaborators" => ok(is_record(v)),
        _ => Some(v.clone()),
    }
}

/// appStateSchema.parse — None on failure.
pub fn sanitize_app_state(app_state: &Value) -> Option<Value> {
    let obj = app_state.as_object()?;
    let mut out = Map::new();
    for key in APPSTATE_KEYS.iter().filter(|k| !k.is_empty()) {
        if let Some(v) = obj.get(*key) {
            out.insert((*key).to_string(), appstate_field(key, v)?);
        }
    }
    for (k, v) in obj {
        if out.contains_key(k) {
            continue;
        }
        // catchall(z.any().refine(val => typeof val === "string" ? sanitizeText(val, 1000) : true))
        if let Value::String(s) = v {
            if sanitize_text(s, 1000).is_empty() {
                return None;
            }
        }
        out.insert(k.clone(), v.clone());
    }
    Some(Value::Object(out))
}

/// Node `Buffer.byteLength(str, "base64")`.
pub fn base64_byte_length(s: &str) -> u64 {
    let b = s.as_bytes();
    let mut n = b.len();
    if n > 0 && b[n - 1] == b'=' {
        n -= 1;
    }
    if n > 1 && b[n - 1] == b'=' {
        n -= 1;
    }
    ((n as u64) * 3) >> 2
}

/// The `files` part of sanitizeDrawingData.
pub fn sanitize_files(files: &Value) -> Result<Value, SanitizeFailure> {
    let Value::Object(map) = files else { return Ok(files.clone()) };
    let max = max_data_url_size();
    let mut out = Map::new();
    for (file_id, file) in map {
        if !valid_file_id().is_match(file_id) {
            continue;
        }
        let Value::Object(fobj) = file else {
            out.insert(file_id.clone(), file.clone());
            continue;
        };
        let mut fo = Map::new();
        for (key, value) in fobj {
            let Value::String(s) = value else {
                fo.insert(key.clone(), Value::String(sanitize_text_value(value, 1000)));
                continue;
            };
            if key != "dataURL" {
                fo.insert(key.clone(), Value::String(sanitize_text(s, 1000)));
                continue;
            }
            if s.is_empty() {
                fo.insert(key.clone(), Value::String(String::new()));
                continue;
            }
            if s.starts_with("data:") {
                if !safe_image_dataurl().is_match(s) {
                    return Err(SanitizeFailure::Drawing(DrawingSanitizationError {
                        status: 400,
                        file_id: file_id.clone(),
                        message: format!("Image file \"{file_id}\" has an invalid or unsupported image data URL and was rejected."),
                    }));
                }
                let b64: String = s[s.find(',').map(|i| i + 1).unwrap_or(0)..].chars().filter(|c| !c.is_whitespace()).collect();
                if base64_byte_length(&b64) > max {
                    return Err(SanitizeFailure::Drawing(DrawingSanitizationError {
                        status: 413,
                        file_id: file_id.clone(),
                        message: format!("Image file \"{file_id}\" exceeds the maximum allowed size of {max} bytes."),
                    }));
                }
                fo.insert(key.clone(), value.clone());
            } else if s.len() >= 7 && (s[..7].eq_ignore_ascii_case("http://") || s.get(..8).map(|p| p.eq_ignore_ascii_case("https://")).unwrap_or(false)) {
                if js_len(s) > 2048 {
                    return Err(SanitizeFailure::Drawing(DrawingSanitizationError {
                        status: 400,
                        file_id: file_id.clone(),
                        message: format!("Image file \"{file_id}\" has an invalid image URL and was rejected."),
                    }));
                }
                fo.insert(key.clone(), value.clone());
            } else if api_file_ref().is_match(s) {
                fo.insert(key.clone(), value.clone());
            } else {
                return Err(SanitizeFailure::Drawing(DrawingSanitizationError {
                    status: 400,
                    file_id: file_id.clone(),
                    message: format!("Image file \"{file_id}\" has an invalid image reference and was rejected."),
                }));
            }
        }
        out.insert(file_id.clone(), Value::Object(fo));
    }
    Ok(Value::Object(out))
}

#[derive(Debug, Clone)]
pub struct SanitizedDrawing {
    pub elements: Vec<Value>,
    pub app_state: Value,
    /// `None` when the input had no files (undefined).
    pub files: Option<Value>,
    /// `None` = undefined; `Some(Null)` = null.
    pub preview: Option<Value>,
}

/// sanitizeDrawingData({ elements, appState, files?, preview? })
pub fn sanitize_drawing_data(
    elements: &Value,
    app_state: &Value,
    files: Option<&Value>,
    preview: Option<&Value>,
) -> Result<SanitizedDrawing, SanitizeFailure> {
    let Some(elements) = sanitize_elements(elements) else {
        eprintln!("Data sanitization failed: invalid elements");
        return Err(SanitizeFailure::Invalid);
    };
    let Some(app_state) = sanitize_app_state(app_state) else {
        eprintln!("Data sanitization failed: invalid appState");
        return Err(SanitizeFailure::Invalid);
    };
    let preview = preview.map(|p| match p {
        Value::String(s) => Value::String(sanitize_svg(s)),
        other => other.clone(),
    });
    let files = match files {
        Some(f) if f.is_object() => Some(sanitize_files(f)?),
        Some(f) => Some(f.clone()),
        None => None,
    };
    Ok(SanitizedDrawing { elements, app_state, files, preview })
}

/// validateImportedDrawing
pub fn validate_imported_drawing(data: &Value) -> bool {
    let Some(obj) = data.as_object() else { return false };
    let Some(elements) = obj.get("elements").and_then(|e| e.as_array()) else { return false };
    let Some(app_state) = obj.get("appState") else { return false };
    // typeof null === "object" passes this check upstream.
    if !(app_state.is_object() || app_state.is_null()) {
        return false;
    }
    if elements.len() > 10000 {
        eprintln!("Imported drawing validation failed: Drawing contains too many elements (max 10,000)");
        return false;
    }
    match sanitize_drawing_data(&Value::Array(elements.clone()), app_state, obj.get("files"), obj.get("preview")) {
        Ok(s) => s.elements.len() == elements.len(),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn text_sanitizer_matches_dompurify_basics() {
        assert_eq!(sanitize_text("<b>hi</b><script>x</script>", 1000), "<b>hi</b>");
        assert_eq!(sanitize_text("  a & b < c  ", 1000), "a &amp; b &lt; c");
        assert_eq!(sanitize_text("<a href=x>link</a>", 1000), "link");
        assert_eq!(sanitize_text("\u{0001}abc", 2), "ab");
    }

    #[test]
    fn element_text_keeps_brackets() {
        let el = sanitize_element(&json!({"id":"a","type":"text","text":"3 < 4 & ok","link":"javascript:alert(1)"})).unwrap();
        assert_eq!(el["text"], "3 < 4 & ok");
        assert_eq!(el["link"], "");
    }

    #[test]
    fn element_type_errors_rejected() {
        assert!(sanitize_element(&json!({"x":"1"})).is_none());
        assert!(sanitize_element(&json!({"id":""})).is_none());
        assert!(sanitize_element(&json!({"x":null,"extra":1})).is_some());
    }

    #[test]
    fn appstate_strips_nested_unknown_keys() {
        let s = sanitize_app_state(&json!({"activeTool":{"type":"selection","locked":false},"zoom":{"value":1,"x":2},"foo":1})).unwrap();
        assert_eq!(s["activeTool"], json!({"type":"selection"}));
        assert_eq!(s["zoom"], json!({"value":1}));
        assert_eq!(s["foo"], 1);
        assert!(sanitize_app_state(&json!({"bar":""})).is_none());
        assert!(sanitize_app_state(&json!({"gridSize": 5000})).is_none());
    }

    #[test]
    fn files_rules() {
        let files = json!({"ok":{"id":"ok","mimeType":"image/png","dataURL":"data:image/png;base64,AAAA","created":1},"bad id!":{}});
        let out = sanitize_files(&files).unwrap();
        assert!(out.get("bad id!").is_none());
        assert_eq!(out["ok"]["created"], "");
        assert_eq!(out["ok"]["dataURL"], "data:image/png;base64,AAAA");
        let err = sanitize_files(&json!({"f":{"dataURL":"data:text/html;base64,AAAA"}})).unwrap_err();
        assert!(matches!(err, SanitizeFailure::Drawing(e) if e.status == 400 && e.file_id == "f"));
        configure_max_data_url_size(2);
        let err = sanitize_files(&json!({"f":{"dataURL":"data:image/png;base64,AAAAAAAA"}})).unwrap_err();
        assert!(matches!(err, SanitizeFailure::Drawing(e) if e.status == 413));
        reset_security_settings();
    }

    #[test]
    fn svg_keeps_safe_images_and_drops_scripts() {
        let svg = r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10"><script>alert(1)</script><style>.a{}</style><rect width="1" height="1" onclick="x"/><image href="data:image/png;base64,AAAA"/><image href="https://evil/x.png"/><g clip-path="url(#c)"><path d="M0 0"/></g></svg>"#;
        let out = sanitize_svg(svg);
        assert!(!out.contains("script"));
        assert!(!out.contains("style"));
        assert!(!out.contains("onclick"));
        assert!(out.contains(r#"<image href="data:image/png;base64,AAAA">"#), "{out}");
        assert!(!out.contains("evil"));
        assert!(out.contains(r#"clip-path="url(#c)""#));
        assert!(out.contains("viewBox"), "{out}");
    }

    #[test]
    fn base64_len() {
        assert_eq!(base64_byte_length("AAAA"), 3);
        assert_eq!(base64_byte_length("AA=="), 1);
    }
}
