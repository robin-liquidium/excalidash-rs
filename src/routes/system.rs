//! routes/system/update.ts + utils/semver.ts — GET /system/update.
use axum::{extract::State, routing::get, Router};
use serde_json::{json, Map, Value};
use std::cmp::Ordering;
use std::time::Duration;

use crate::http::ctx::Ctx;
use crate::http::error::{status_json, ApiError, ApiResult};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/system/update", get(system_update))
}

// ---------------------------------------------------------------------------
// utils/semver.ts

#[derive(Debug, Clone, PartialEq)]
pub struct ParsedSemver {
    pub major: f64,
    pub minor: f64,
    pub patch: f64,
    pub prerelease: Vec<String>,
    pub raw: String,
}

fn semver_re() -> &'static regex::Regex {
    static R: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    R.get_or_init(|| {
        regex::Regex::new(
            r"^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$",
        )
        .unwrap()
    })
}

pub fn parse_semver(input: &str) -> Option<ParsedSemver> {
    let trimmed = crate::security::js_trim(input);
    let caps = semver_re().captures(trimmed)?;
    let num = |i: usize| caps.get(i).map(|m| m.as_str().parse::<f64>().unwrap_or(f64::INFINITY)).unwrap_or(f64::NAN);
    let (major, minor, patch) = (num(1), num(2), num(3));
    if !major.is_finite() || !minor.is_finite() || !patch.is_finite() {
        return None;
    }
    let prerelease = match caps.get(4).map(|m| m.as_str()).filter(|s| !s.is_empty()) {
        Some(p) => p.split('.').map(str::to_string).collect(),
        None => Vec::new(),
    };
    Some(ParsedSemver { major, minor, patch, prerelease, raw: trimmed.to_string() })
}

fn is_numeric_identifier(id: &str) -> bool {
    !id.is_empty() && id.bytes().all(|b| b.is_ascii_digit())
}

fn cmp_f64(a: f64, b: f64) -> i32 {
    if a < b { -1 } else if a > b { 1 } else { 0 }
}

pub fn compare_semver(a: &ParsedSemver, b: &ParsedSemver) -> i32 {
    for (x, y) in [(a.major, b.major), (a.minor, b.minor), (a.patch, b.patch)] {
        if x != y {
            return cmp_f64(x, y);
        }
    }
    let (ap, bp) = (&a.prerelease, &b.prerelease);
    if ap.is_empty() && bp.is_empty() {
        return 0;
    }
    if ap.is_empty() {
        return 1;
    }
    if bp.is_empty() {
        return -1;
    }
    for i in 0..ap.len().max(bp.len()) {
        let (Some(ai), Some(bi)) = (ap.get(i), bp.get(i)) else {
            return if ap.get(i).is_none() { -1 } else { 1 };
        };
        if ai == bi {
            continue;
        }
        let (an, bn) = (is_numeric_identifier(ai), is_numeric_identifier(bi));
        if an && bn {
            let (x, y) = (ai.parse::<f64>().unwrap_or(0.0), bi.parse::<f64>().unwrap_or(0.0));
            if x != y {
                return cmp_f64(x, y);
            }
            continue;
        }
        if an && !bn {
            return -1;
        }
        if !an && bn {
            return 1;
        }
        // JS string comparison (UTF-16 code units; identifiers are ASCII).
        return if ai.encode_utf16().cmp(bi.encode_utf16()) == Ordering::Less { -1 } else { 1 };
    }
    0
}

// ---------------------------------------------------------------------------
// routes/system/update.ts

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    Stable,
    Prerelease,
}

impl Channel {
    fn as_str(self) -> &'static str {
        match self {
            Channel::Stable => "stable",
            Channel::Prerelease => "prerelease",
        }
    }
}

fn parse_channel(raw: Option<&str>) -> Channel {
    match raw.map(|s| crate::security::js_trim(s).to_lowercase()) {
        Some(s) if s == "prerelease" => Channel::Prerelease,
        _ => Channel::Stable,
    }
}

const UPDATE_CHECK_TTL_MS: i64 = 10 * 60 * 1000;

struct Cache {
    channel: Channel,
    fetched_at: i64,
    etag: Option<String>,
    response: Map<String, Value>,
}

static CACHE: tokio::sync::Mutex<Option<Cache>> = tokio::sync::Mutex::const_new(None);

fn same_dev_version(a: &ParsedSemver, b: &ParsedSemver) -> bool {
    let hash = |s: &str| (7..=40).contains(&s.len()) && s.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c));
    a.major == b.major
        && a.minor == b.minor
        && a.patch == b.patch
        && [a, b].iter().all(|v| v.prerelease.len() == 2 && v.prerelease[0] == "dev" && hash(&v.prerelease[1]))
}

fn truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64().map(|f| f != 0.0 && !f.is_nan()).unwrap_or(true),
        Some(Value::String(s)) => !s.is_empty(),
        Some(_) => true,
    }
}

fn tag_of(r: &Value) -> &str {
    r.get("tag_name").and_then(|v| v.as_str()).unwrap_or("")
}

fn published_ms(r: &Value) -> i64 {
    r.get("published_at").and_then(|v| v.as_str()).and_then(crate::util::parse_date_ms).unwrap_or(0)
}

/// pickLatestRelease
pub fn pick_latest_release(releases: &[Value], channel: Channel) -> Option<Value> {
    let candidates: Vec<(&Value, ParsedSemver)> = releases
        .iter()
        .filter(|r| truthy(Some(r)) && !truthy(r.get("draft")))
        .filter(|r| {
            if channel == Channel::Prerelease {
                return true;
            }
            if truthy(r.get("prerelease")) {
                return false;
            }
            parse_semver(tag_of(r)).map(|p| p.prerelease.is_empty()).unwrap_or(false)
        })
        .filter_map(|r| parse_semver(tag_of(r)).map(|p| (r, p)))
        .collect();
    let mut best = candidates.first()?;
    for c in candidates.iter().skip(1) {
        let order = if same_dev_version(&c.1, &best.1) {
            (published_ms(c.0) - published_ms(best.0)).signum() as i32
        } else {
            compare_semver(&c.1, &best.1)
        };
        if order > 0 {
            best = c;
        }
    }
    Some(best.0.clone())
}

fn normalize_version(raw: &str) -> Option<String> {
    let p = parse_semver(raw)?;
    let base = format!("{}.{}.{}", crate::util::js_num_str(p.major), crate::util::js_num_str(p.minor), crate::util::js_num_str(p.patch));
    Some(if p.prerelease.is_empty() { base } else { format!("{base}-{}", p.prerelease.join(".")) })
}

/// computeIsUpdateAvailable
pub fn compute_is_update_available(current: Option<&str>, latest: Option<&str>) -> Option<bool> {
    let (c, l) = (current.filter(|s| !s.is_empty())?, latest.filter(|s| !s.is_empty())?);
    let (cp, lp) = (parse_semver(c)?, parse_semver(l)?);
    if same_dev_version(&cp, &lp) {
        return Some(cp.prerelease[1] != lp.prerelease[1]);
    }
    Some(compare_semver(&lp, &cp) > 0)
}

fn base_response(channel: Channel, outbound: bool) -> Map<String, Value> {
    let v = json!({
        "channel": channel.as_str(),
        "outboundEnabled": outbound,
        "latestVersion": null,
        "latestUrl": null,
        "publishedAt": null,
        "isUpdateAvailable": null,
    });
    v.as_object().cloned().unwrap_or_default()
}

/// GitHub API base; overridable for tests only (Rust-specific, undocumented).
fn github_api_base() -> String {
    std::env::var("EXCALIDASH_GITHUB_API_URL")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "https://api.github.com".into())
        .trim_end_matches('/')
        .to_string()
}

/// fetchLatest(channel)
async fn fetch_latest(st: &AppState, channel: Channel) -> Result<Map<String, Value>, String> {
    let now = crate::util::now_ms();
    // Like upstream's module-level `cache`: read it, do the fetch without holding it
    // (concurrent misses each fetch), then write the result.
    let prior_etag = {
        let mut cache = CACHE.lock().await;
        if let Some(c) = cache.as_ref() {
            if c.channel == channel && now - c.fetched_at < UPDATE_CHECK_TTL_MS {
                return Ok(c.response.clone());
            }
        }
        if !st.cfg.update_check.outbound {
            let response = base_response(channel, false);
            *cache = Some(Cache { channel, fetched_at: now, etag: None, response: response.clone() });
            return Ok(response);
        }
        cache.as_ref().filter(|c| c.channel == channel).and_then(|c| c.etag.clone())
    };
    let url = format!(
        "{}/repos/ZimengXiong/ExcaliDash/releases{}",
        github_api_base(),
        if channel == Channel::Stable { "/latest" } else { "?per_page=100" }
    );
    let mut req = st
        .http()
        .get(&url)
        .timeout(Duration::from_secs(10))
        .header("Accept", "application/vnd.github+json")
        .header("User-Agent", "ExcaliDash-UpdateCheck");
    if let Some(token) = &st.cfg.update_check.github_token {
        req = req.header("Authorization", format!("Bearer {token}"));
    }
    if let Some(etag) = &prior_etag {
        req = req.header("If-None-Match", etag);
    }
    let resp = req.send().await.map_err(|e| format!("fetch failed: {e}"))?;
    let status = resp.status().as_u16();
    let mut cache = CACHE.lock().await;
    if status == 304 {
        if let Some(c) = cache.as_mut() {
            if c.channel == channel {
                c.fetched_at = now;
                return Ok(c.response.clone());
            }
        }
    }
    if !(200..300).contains(&status) {
        let mut response = base_response(channel, true);
        response.insert("error".into(), Value::String(format!("GitHub API error: HTTP {status}")));
        *cache = Some(Cache { channel, fetched_at: now, etag: None, response: response.clone() });
        return Ok(response);
    }
    let etag = resp.headers().get("etag").and_then(|v| v.to_str().ok()).map(str::to_string);
    drop(cache);
    let body = resp.bytes().await.map_err(|e| e.to_string())?;
    let json: Value = serde_json::from_slice(&body).map_err(|e| format!("SyntaxError: {e}"))?;
    let releases: Vec<Value> = match json {
        Value::Array(a) => a,
        Value::Object(o) if channel == Channel::Stable => vec![Value::Object(o)],
        _ => Vec::new(),
    };
    let latest = pick_latest_release(&releases, channel);
    let mut response = base_response(channel, true);
    if let Some(l) = &latest {
        let tag = l.get("tag_name").and_then(|v| v.as_str()).filter(|s| !s.is_empty());
        response.insert("latestVersion".into(), tag.and_then(normalize_version).map(Value::String).unwrap_or(Value::Null));
        if let Some(u) = l.get("html_url").and_then(|v| v.as_str()) {
            response.insert("latestUrl".into(), Value::String(u.into()));
        }
        if let Some(p) = l.get("published_at").and_then(|v| v.as_str()) {
            response.insert("publishedAt".into(), Value::String(p.into()));
        }
    }
    *CACHE.lock().await = Some(Cache { channel, fetched_at: now, etag, response: response.clone() });
    Ok(response)
}

async fn system_update(State(st): State<AppState>, ctx: Ctx) -> ApiResult {
    let q = crate::http::body::parse_query_values(ctx.query.as_deref().unwrap_or(""));
    let channel = parse_channel(q.get("channel").and_then(|v| v.as_str()));
    let current = crate::backend_version();
    let current = if current.is_empty() { None } else { Some(current) };
    let mut payload = fetch_latest(&st, channel).await.map_err(ApiError::internal)?;
    let latest = payload.get("latestVersion").and_then(|v| v.as_str()).map(str::to_string);
    payload.insert("currentVersion".into(), current.clone().map(Value::String).unwrap_or(Value::Null));
    payload.insert(
        "isUpdateAvailable".into(),
        compute_is_update_available(current.as_deref(), latest.as_deref()).map(Value::Bool).unwrap_or(Value::Null),
    );
    status_json(200, Value::Object(payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rel(tag: &str, published: &str, prerelease: bool) -> Value {
        json!({"tag_name": format!("v{tag}"), "published_at": published, "prerelease": prerelease, "draft": false,
               "html_url": format!("https://github.com/ZimengXiong/ExcaliDash/releases/tag/v{tag}")})
    }

    #[test]
    fn semver_parse_and_compare() {
        let p = parse_semver(" v1.2.3-dev.abc1234 ").unwrap();
        assert_eq!((p.major, p.minor, p.patch), (1.0, 2.0, 3.0));
        assert_eq!(p.prerelease, vec!["dev", "abc1234"]);
        assert!(parse_semver("01.2.3").is_none());
        assert!(parse_semver("1.2").is_none());
        let c = |a: &str, b: &str| compare_semver(&parse_semver(a).unwrap(), &parse_semver(b).unwrap());
        assert_eq!(c("1.0.0", "1.0.0-rc.1"), 1);
        assert_eq!(c("1.0.0-alpha", "1.0.0-alpha.1"), -1);
        assert_eq!(c("1.0.0-alpha.1", "1.0.0-alpha.beta"), -1);
        assert_eq!(c("1.0.0-beta.11", "1.0.0-beta.2"), 1);
        assert_eq!(c("1.0.0-rc.1", "1.0.0-beta"), 1);
        assert_eq!(c("2.0.0", "10.0.0"), -1);
        assert_eq!(c("1.0.0", "v1.0.0"), 0);
    }

    #[test]
    fn dev_builds_pick_by_publication_time() {
        let v = "0.6.5";
        let releases = vec![
            rel(&format!("{v}-dev.fffffff"), "2026-10-01T12:00:00Z", true),
            rel(&format!("{v}-dev.0000000"), "2026-10-02T12:00:00Z", true),
        ];
        let latest = pick_latest_release(&releases, Channel::Prerelease).unwrap();
        assert_eq!(latest["tag_name"], format!("v{v}-dev.0000000"));
        assert_eq!(compute_is_update_available(Some("0.6.5-dev.1234567"), Some("0.6.5-dev.0000000")), Some(true));
        assert_eq!(compute_is_update_available(Some("0.6.5-dev.1234567"), Some("0.6.5-dev.1234567")), Some(false));
    }

    #[test]
    fn stable_preferred_over_same_version_dev() {
        let releases = vec![rel("0.6.5", "2026-10-01T12:00:00Z", false), rel("0.6.5-dev.fffffff", "2026-10-02T12:00:00Z", true)];
        let latest = pick_latest_release(&releases, Channel::Prerelease).unwrap();
        assert_eq!(normalize_version(tag_of(&latest)).unwrap(), "0.6.5");
        assert_eq!(compute_is_update_available(Some("0.6.5-dev.1234567"), Some("0.6.5")), Some(true));
        // Stable channel ignores prereleases and drafts.
        let releases = vec![rel("0.7.0-dev.abcdef0", "2026-10-03T12:00:00Z", true), json!({"tag_name": "v9.9.9", "draft": true})];
        assert!(pick_latest_release(&releases, Channel::Stable).is_none());
    }

    #[test]
    fn update_availability_edge_cases() {
        assert_eq!(compute_is_update_available(None, Some("1.0.0")), None);
        assert_eq!(compute_is_update_available(Some("unknown"), Some("1.0.0")), None);
        assert_eq!(compute_is_update_available(Some("1.0.0"), Some("1.0.0")), Some(false));
        assert_eq!(compute_is_update_available(Some("1.0.0"), Some("1.0.1")), Some(true));
        assert_eq!(parse_channel(Some(" PreRelease ")), Channel::Prerelease);
        assert_eq!(parse_channel(Some("beta")), Channel::Stable);
        assert_eq!(parse_channel(None), Channel::Stable);
    }
}
