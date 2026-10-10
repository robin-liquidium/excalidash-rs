//! Small helpers that reproduce Node/JS behaviour (number formatting, dates,
//! `ms` durations, base64url, hashing).
use base64::Engine;
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use sha2::{Digest, Sha256};

pub fn random_bytes(n: usize) -> Vec<u8> {
    use rand::Rng;
    let mut buf = vec![0u8; n];
    rand::rng().fill_bytes(&mut buf);
    buf
}

pub fn uuid_v4() -> String {
    uuid::Uuid::new_v4().to_string()
}

pub fn now_ms() -> i64 {
    Utc::now().timestamp_millis()
}

/// JavaScript `Date.prototype.toISOString()`.
pub fn iso_from_ms(ms: i64) -> String {
    match Utc.timestamp_millis_opt(ms).single() {
        Some(dt) => dt.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
        None => String::new(),
    }
}

pub fn iso_now() -> String {
    iso_from_ms(now_ms())
}

/// Parse a JS-style date string (ISO 8601 or `YYYY-MM-DD HH:MM:SS`) to ms.
pub fn parse_date_ms(s: &str) -> Option<i64> {
    let s = s.trim();
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Some(dt.timestamp_millis());
    }
    for fmt in ["%Y-%m-%d %H:%M:%S%.f", "%Y-%m-%dT%H:%M:%S%.f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"] {
        if let Ok(n) = NaiveDateTime::parse_from_str(s, fmt) {
            return Some(n.and_utc().timestamp_millis());
        }
    }
    if let Ok(d) = chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d") {
        return Some(d.and_hms_opt(0, 0, 0)?.and_utc().timestamp_millis());
    }
    None
}

/// Format an f64 the way JavaScript's `String(number)` does for typical values.
pub fn js_num_str(n: f64) -> String {
    if n.is_nan() {
        return "NaN".into();
    }
    if n.is_infinite() {
        return if n > 0.0 { "Infinity".into() } else { "-Infinity".into() };
    }
    if n == n.trunc() && n.abs() < 1e21 {
        return format!("{}", n as i64);
    }
    let s = format!("{}", n);
    s
}

/// vercel/ms string → milliseconds. Returns None for invalid input.
pub fn parse_ms(input: &str) -> Option<f64> {
    if input.is_empty() || input.len() > 100 {
        return None;
    }
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let re = RE.get_or_init(|| {
        regex::Regex::new(
            r"(?i)^(?P<value>-?\d*\.?\d+) *(?P<type>milliseconds?|msecs?|ms|seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h|days?|d|weeks?|w|years?|yrs?|y)?$",
        )
        .unwrap()
    });
    let caps = re.captures(input)?;
    let n: f64 = caps.name("value")?.as_str().parse().ok()?;
    let unit = caps.name("type").map(|m| m.as_str().to_lowercase()).unwrap_or_else(|| "ms".into());
    let s = 1000.0;
    let m = s * 60.0;
    let h = m * 60.0;
    let d = h * 24.0;
    let w = d * 7.0;
    let y = d * 365.25;
    let mult = match unit.as_str() {
        "years" | "year" | "yrs" | "yr" | "y" => y,
        "weeks" | "week" | "w" => w,
        "days" | "day" | "d" => d,
        "hours" | "hour" | "hrs" | "hr" | "h" => h,
        "minutes" | "minute" | "mins" | "min" | "m" => m,
        "seconds" | "second" | "secs" | "sec" | "s" => s,
        "milliseconds" | "millisecond" | "msecs" | "msec" | "ms" => 1.0,
        _ => return None,
    };
    Some(n * mult)
}

/// Positive duration in ms with fallback (cookies.ts / auth.ts `resolveExpiresAt`).
pub fn duration_ms_or(value: &str, fallback_ms: f64) -> f64 {
    match parse_ms(value) {
        Some(v) if v.is_finite() && v > 0.0 => v,
        _ => fallback_ms,
    }
}

pub fn b64url(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

/// Lenient base64url/base64 decode (Node's Buffer.from(x, "base64") ignores junk).
pub fn b64_decode_lenient(input: &str) -> Vec<u8> {
    let cleaned: String = input
        .chars()
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            c => c,
        })
        .filter(|c| c.is_ascii_alphanumeric() || *c == '+' || *c == '/')
        .collect();
    let mut cleaned = cleaned;
    // Node drops a trailing partial sextet (length % 4 == 1).
    if cleaned.len() % 4 == 1 {
        cleaned.pop();
    }
    base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(cleaned.as_bytes())
        .or_else(|_| {
            base64::engine::GeneralPurpose::new(
                &base64::alphabet::STANDARD,
                base64::engine::GeneralPurposeConfig::new()
                    .with_decode_allow_trailing_bits(true)
                    .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent),
            )
            .decode(cleaned.as_bytes())
        })
        .unwrap_or_default()
}

pub fn b64_std(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

pub fn sha256_hex(data: impl AsRef<[u8]>) -> String {
    hex::encode(Sha256::digest(data.as_ref()))
}

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.len() == b.len() && a.ct_eq(b).into()
}

/// `crypto.randomUUID().replace(/-/g, "")`
pub fn random_hex_uuid() -> String {
    uuid_v4().replace('-', "")
}

/// JS `String.prototype.slice(0, n)` on UTF-16 code units, clamped to char boundaries.
pub fn js_slice(s: &str, max: usize) -> String {
    let mut units = 0usize;
    let mut end = 0usize;
    for (i, c) in s.char_indices() {
        let w = c.len_utf16();
        if units + w > max {
            return s[..i].to_string();
        }
        units += w;
        end = i + c.len_utf8();
    }
    s[..end].to_string()
}

pub fn js_len(s: &str) -> usize {
    s.encode_utf16().count()
}
