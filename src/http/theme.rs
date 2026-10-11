//! Rust-only `EXCALIDASH_THEME_FOLLOW_SYSTEM=true`: the bundled frontend follows the OS
//! light/dark setting without modifying upstream's build.
//!
//! `index.html` gets one extra `<script>` (first in `<head>`, so it runs before the app).
//! It writes the OS theme into a cookie and into the app's own localStorage preference
//! mirror (correct first paint), and `GET /auth/preferences` answers with the cookie's
//! theme instead of the stored one. When the OS theme changes, non-editor pages reload;
//! open editors pick it up on their next load. A manual toggle in the app lasts until
//! the next load.
use serde_json::{Map, Value};

pub const SCRIPT_PATH: &str = "/excalidash-rs-theme.js";
pub const COOKIE: &str = "excalidash-system-theme";
pub const TAG: &str = "<script src=\"/excalidash-rs-theme.js\"></script>";

pub const SCRIPT: &str = r#"(function () {
  var mq = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)");
  function apply() {
    var theme = mq && mq.matches ? "dark" : "light";
    document.cookie = "excalidash-system-theme=" + theme + "; path=/; max-age=31536000; SameSite=Lax";
    try {
      var key = "excalidash-preferences";
      var prefs = JSON.parse(localStorage.getItem(key) || "{}");
      if (prefs.theme !== theme) {
        prefs.theme = theme;
        localStorage.setItem(key, JSON.stringify(prefs));
      }
    } catch (e) {}
  }
  apply();
  if (mq && mq.addEventListener) {
    mq.addEventListener("change", function () {
      apply();
      if (!/^\/(editor|shared)\//.test(location.pathname)) location.reload();
    });
  }
})();
"#;

/// Insert the script tag right after `<head>` (no-op when absent).
pub fn inject(html: &[u8]) -> Vec<u8> {
    let s = String::from_utf8_lossy(html);
    match s.find("<head>") {
        Some(i) => {
            let at = i + "<head>".len();
            format!("{}\n    {}{}", &s[..at], TAG, &s[at..]).into_bytes()
        }
        None => html.to_vec(),
    }
}

/// Override `theme` (kept first, as in the schema order) with the OS theme cookie.
pub fn override_preferences(prefs: Map<String, Value>, cookie: Option<String>) -> Map<String, Value> {
    let Some(theme) = cookie.filter(|t| t == "light" || t == "dark") else { return prefs };
    let mut out = Map::new();
    out.insert("theme".into(), Value::String(theme));
    out.extend(prefs.into_iter().filter(|(k, _)| k != "theme"));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn injects_first_in_head() {
        let out = String::from_utf8(inject(b"<html><head><title>x</title></head></html>")).unwrap();
        assert_eq!(out, format!("<html><head>\n    {TAG}<title>x</title></head></html>"));
        assert_eq!(inject(b"no head"), b"no head".to_vec());
    }

    #[test]
    fn overrides_theme_in_schema_order() {
        let prefs = json!({"theme": "light", "language": "de"}).as_object().unwrap().clone();
        let out = override_preferences(prefs.clone(), Some("dark".into()));
        assert_eq!(Value::Object(out), json!({"theme": "dark", "language": "de"}));
        let only = json!({"language": "de"}).as_object().unwrap().clone();
        assert_eq!(Value::Object(override_preferences(only, Some("dark".into()))), json!({"theme": "dark", "language": "de"}));
        assert_eq!(override_preferences(prefs.clone(), Some("blue".into())), prefs);
        assert_eq!(override_preferences(prefs.clone(), None), prefs);
    }
}
