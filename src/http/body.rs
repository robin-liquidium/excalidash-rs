//! body-parser (express.json / express.urlencoded) equivalents.
use axum::{extract::FromRequestParts, http::request::Parts};
use serde_json::{Map, Value};
use std::{collections::HashMap, convert::Infallible};

/// Parsed request body as Express would expose it on `req.body`.
/// `None` when no parser matched (Express 5 leaves `req.body` undefined).
#[derive(Clone, Debug, Default)]
pub struct ParsedBody(pub Option<Value>);

/// Extractor for the already-parsed body. Use `.object()` for `req.body || {}` access.
#[derive(Clone, Debug, Default)]
pub struct Body(pub Option<Value>);

impl<S: Send + Sync> FromRequestParts<S> for Body {
    type Rejection = Infallible;
    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(Body(parts.extensions.get::<ParsedBody>().and_then(|b| b.0.clone())))
    }
}

impl Body {
    /// `req.body` as a value (`Value::Null` when undefined).
    pub fn value(&self) -> Value {
        self.0.clone().unwrap_or(Value::Null)
    }
    /// `(req.body || {})` as an object map (non-objects become empty).
    pub fn object(&self) -> Map<String, Value> {
        match &self.0 {
            Some(Value::Object(m)) => m.clone(),
            _ => Map::new(),
        }
    }
    pub fn get(&self, key: &str) -> Option<&Value> {
        match &self.0 {
            Some(Value::Object(m)) => m.get(key),
            _ => None,
        }
    }
    pub fn str(&self, key: &str) -> Option<&str> {
        self.get(key).and_then(|v| v.as_str())
    }
}

#[derive(Debug)]
pub enum BodyError {
    /// 400 entity.parse.failed
    Parse(String),
    /// 413 entity.too.large
    TooLarge,
    /// 415 charset.unsupported
    Charset(String),
}

pub fn mime_essence(content_type: &str) -> String {
    content_type.split(';').next().unwrap_or("").trim().to_ascii_lowercase()
}

fn charset_of(content_type: &str) -> Option<String> {
    content_type.split(';').skip(1).find_map(|p| {
        let mut kv = p.splitn(2, '=');
        let k = kv.next()?.trim().to_ascii_lowercase();
        let v = kv.next()?.trim().trim_matches('"').to_ascii_lowercase();
        (k == "charset").then_some(v)
    })
}

pub fn is_json_type(content_type: &str) -> bool {
    mime_essence(content_type) == "application/json"
}

pub fn is_urlencoded_type(content_type: &str) -> bool {
    mime_essence(content_type) == "application/x-www-form-urlencoded"
}

/// express.json({ strict: true })
pub fn parse_json_body(content_type: &str, bytes: &[u8]) -> Result<Value, BodyError> {
    if let Some(cs) = charset_of(content_type) {
        if !cs.starts_with("utf-") {
            return Err(BodyError::Charset(cs));
        }
    }
    let text = std::str::from_utf8(bytes).map_err(|e| BodyError::Parse(e.to_string()))?;
    if text.is_empty() {
        return Ok(Value::Object(Map::new()));
    }
    let first = text.trim_start_matches([' ', '\t', '\n', '\r']).chars().next();
    if !matches!(first, Some('{') | Some('[')) {
        return Err(BodyError::Parse("Unexpected token in JSON".into()));
    }
    serde_json::from_str(text).map_err(|e| BodyError::Parse(e.to_string()))
}

/// express.urlencoded({ extended: true }) — qs-style nesting for `a[b]=c` and `a[]=x`.
pub fn parse_urlencoded_body(bytes: &[u8]) -> Result<Value, BodyError> {
    let text = std::str::from_utf8(bytes).map_err(|e| BodyError::Parse(e.to_string()))?;
    let mut root = Map::new();
    for (k, v) in url::form_urlencoded::parse(text.as_bytes()) {
        insert_qs(&mut root, &k, Value::String(v.into_owned()));
    }
    Ok(Value::Object(root))
}

fn insert_qs(root: &mut Map<String, Value>, key: &str, value: Value) {
    let (head, rest) = match key.find('[') {
        Some(i) if key.ends_with(']') => (&key[..i], Some(&key[i..])),
        _ => (key, None),
    };
    let Some(rest) = rest else {
        match root.get_mut(head) {
            Some(Value::Array(a)) => a.push(value),
            Some(existing) => {
                let prev = existing.take();
                *existing = Value::Array(vec![prev, value]);
            }
            None => {
                root.insert(head.to_string(), value);
            }
        }
        return;
    };
    let segments: Vec<&str> = rest.trim_start_matches('[').trim_end_matches(']').split("][").collect();
    let mut cur = root.entry(head.to_string()).or_insert_with(|| {
        if segments.first() == Some(&"") { Value::Array(vec![]) } else { Value::Object(Map::new()) }
    });
    for (i, seg) in segments.iter().enumerate() {
        let last = i == segments.len() - 1;
        if seg.is_empty() {
            if let Value::Array(a) = cur {
                if last {
                    a.push(value);
                    return;
                }
                a.push(Value::Object(Map::new()));
                cur = a.last_mut().unwrap();
                continue;
            }
            return;
        }
        if let Value::Array(a) = cur {
            let m: Map<String, Value> = a.drain(..).enumerate().map(|(i, v)| (i.to_string(), v)).collect();
            *cur = Value::Object(m);
        }
        let Value::Object(m) = cur else { return };
        if last {
            m.insert(seg.to_string(), value);
            return;
        }
        cur = m.entry(seg.to_string()).or_insert_with(|| Value::Object(Map::new()));
    }
}

/// Node `querystring` parse, keeping the first value of repeated keys.
pub fn parse_query_flat(q: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for (k, v) in url::form_urlencoded::parse(q.as_bytes()) {
        out.entry(k.into_owned()).or_insert_with(|| v.into_owned());
    }
    out
}

/// Node `querystring` parse as Express 5's "simple" parser: string or array of strings.
pub fn parse_query_values(q: &str) -> Map<String, Value> {
    let mut out = Map::new();
    for (k, v) in url::form_urlencoded::parse(q.as_bytes()) {
        let v = Value::String(v.into_owned());
        match out.get_mut(k.as_ref()) {
            Some(Value::Array(a)) => a.push(v),
            Some(existing) => {
                let prev = existing.take();
                *existing = Value::Array(vec![prev, v]);
            }
            None => {
                out.insert(k.into_owned(), v);
            }
        }
    }
    out
}
