//! index.ts drawingCreateSchema / drawingUpdateSchema (+ sanitizeDrawingUpdateData),
//! respondWithValidationErrors and collectionNameSchema.
use serde_json::{json, Map, Value};

use crate::http::error::ApiError;
use crate::security::{
    js_trim, sanitize_app_state, sanitize_drawing_data, sanitize_element, sanitize_svg, SanitizeFailure,
};
use crate::util::js_len;

/// Parsed drawing payload. `Option<Option<_>>`: outer None = key absent, inner None = null.
#[derive(Debug, Clone, Default)]
pub struct DrawingInput {
    pub name: Option<String>,
    pub collection_id: Option<Option<String>>,
    pub preview: Option<Option<String>>,
    pub elements: Option<Vec<Value>>,
    pub app_state: Option<Value>,
    pub files: Option<Map<String, Value>>,
    pub version: Option<i64>,
}

#[derive(Debug)]
pub enum SchemaError {
    /// zod issues → respondWithValidationErrors
    Issues(Vec<Value>),
    /// Error thrown out of a refinement (DrawingSanitizationError) → errorHandler.
    Thrown(ApiError),
}

fn type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn invalid_type(path: &[Value], expected: &str, got: &Value) -> Value {
    json!({
        "expected": expected,
        "code": "invalid_type",
        "path": path,
        "message": format!("Invalid input: expected {expected}, received {}", type_name(got)),
    })
}

fn custom(message: &str) -> Value {
    json!({ "code": "custom", "path": [], "message": message })
}

fn string_len_issue(path: &str, min: bool, n: usize) -> Value {
    if min {
        json!({"origin": "string", "code": "too_small", "minimum": n, "inclusive": true, "path": [path],
               "message": format!("Too small: expected string to have >={n} characters")})
    } else {
        json!({"origin": "string", "code": "too_big", "maximum": n, "inclusive": true, "path": [path],
               "message": format!("Too big: expected string to have <={n} characters")})
    }
}

struct Parsed {
    input: DrawingInput,
    issues: Vec<Value>,
    /// Any zod-aborting issue (type/enum/union) — outer refinements are skipped then.
    aborted: bool,
}

/// drawingBaseSchema + the scene fields shared by create/update.
fn parse_base(body: Option<&Value>, create: bool) -> Parsed {
    let mut input = DrawingInput::default();
    let mut issues = vec![];
    let Some(Value::Object(obj)) = body else {
        let got = body.cloned().unwrap_or(Value::Null);
        let mut issue = invalid_type(&[], "object", &got);
        if body.is_none() {
            issue["message"] = json!("Invalid input: expected object, received undefined");
        }
        return Parsed { input, issues: vec![issue], aborted: true };
    };
    let mut aborted = false;
    let mut push = |issues: &mut Vec<Value>, list: Vec<crate::zodlike::Issue>| {
        for i in list {
            aborted |= i.aborted;
            issues.push(i.value);
        }
    };

    if let Some(v) = obj.get("name") {
        match v {
            Value::String(s) => {
                let t = js_trim(s);
                if js_len(t) < 1 {
                    issues.push(string_len_issue("name", true, 1));
                } else if js_len(t) > 255 {
                    issues.push(string_len_issue("name", false, 255));
                } else {
                    input.name = Some(t.to_string());
                }
            }
            other => push(&mut issues, vec![crate::zodlike::invalid_type(vec![json!("name")], "string", Some(other))]),
        }
    }
    if let Some(v) = obj.get("collectionId") {
        match v {
            Value::Null => input.collection_id = Some(None),
            Value::String(s) if js_len(js_trim(s)) >= 1 => input.collection_id = Some(Some(js_trim(s).to_string())),
            other => {
                // z.union([z.string().trim().min(1), z.null()])
                use crate::zodlike::{invalid_type as it, too_small, union};
                let string_branch = match other {
                    Value::String(_) => vec![too_small(vec![], "string", 1.0)],
                    o => vec![it(vec![], "string", Some(o))],
                };
                let null_branch = vec![it(vec![], "null", Some(other))];
                push(&mut issues, union(vec![json!("collectionId")], vec![string_branch, null_branch]));
            }
        }
    }
    if let Some(v) = obj.get("preview") {
        match v {
            Value::Null => input.preview = Some(None),
            Value::String(s) => input.preview = Some(Some(s.clone())),
            other => push(&mut issues, vec![crate::zodlike::invalid_type(vec![json!("preview")], "string", Some(other))]),
        }
    }
    match obj.get("elements") {
        None if create => input.elements = Some(vec![]),
        None => {}
        Some(Value::Array(a)) => {
            let mut out = Vec::with_capacity(a.len());
            for (i, el) in a.iter().enumerate() {
                match sanitize_element(el) {
                    Some(v) => out.push(v),
                    None => push(&mut issues, crate::zodlike::element_issues(&vec![json!("elements"), json!(i)], el)),
                }
            }
            input.elements = Some(out);
        }
        Some(other) => push(&mut issues, vec![crate::zodlike::invalid_type(vec![json!("elements")], "array", Some(other))]),
    }
    match obj.get("appState") {
        None if create => input.app_state = Some(json!({})),
        None => {}
        Some(v) => match sanitize_app_state(v) {
            Some(s) => input.app_state = Some(s),
            None => push(&mut issues, crate::zodlike::app_state_issues(&vec![json!("appState")], v)),
        },
    }
    match obj.get("files") {
        None | Some(Value::Null) => {}
        Some(Value::Object(m)) => input.files = Some(m.clone()),
        Some(other) => {
            use crate::zodlike::{invalid_type as it, union};
            push(&mut issues, union(vec![json!("files")], vec![vec![it(vec![], "record", Some(other))], vec![it(vec![], "null", Some(other))]]));
        }
    }
    if !create {
        if let Some(v) = obj.get("version") {
            match v.as_f64() {
                Some(n) if n.fract() == 0.0 && n.abs() <= 9_007_199_254_740_991.0 && n > 0.0 => {
                    input.version = Some(n as i64)
                }
                Some(n) => {
                    // z.number().int().positive()
                    if n.fract() != 0.0 || n.abs() > 9_007_199_254_740_991.0 {
                        push(&mut issues, vec![crate::zodlike::Issue {
                            value: json!({"expected": "int", "format": "safeint", "code": "invalid_type", "path": ["version"],
                                          "message": "Invalid input: expected int, received number"}),
                            aborted: true,
                        }]);
                    } else {
                        push(&mut issues, vec![crate::zodlike::Issue {
                            value: json!({"origin": "number", "code": "too_small", "minimum": 0, "inclusive": false, "path": ["version"],
                                          "message": "Too small: expected number to be >0"}),
                            aborted: false,
                        }]);
                    }
                }
                None => push(&mut issues, vec![crate::zodlike::invalid_type(vec![json!("version")], "number", Some(v))]),
            }
        }
    }
    Parsed { input, issues, aborted }
}

/// The schema-level `.refine` still runs when only non-aborting issues exist; a
/// sanitisation failure then adds its custom issue (DrawingSanitizationError escapes).
fn refine_after_issues(body: Option<&Value>, mut issues: Vec<Value>, aborted: bool, update: bool) -> SchemaError {
    if aborted {
        return SchemaError::Issues(issues);
    }
    let obj = body.and_then(|b| b.as_object()).cloned().unwrap_or_default();
    let has_scene = obj.get("elements").is_some() || obj.get("appState").is_some() || obj.get("files").is_some();
    if update && !has_scene {
        return SchemaError::Issues(issues);
    }
    let elements = obj.get("elements").cloned().unwrap_or(json!([]));
    let app_state = match obj.get("appState") {
        Some(v @ Value::Object(_)) => v.clone(),
        Some(v) if !update => v.clone(),
        _ => json!({}),
    };
    let files = match obj.get("files") {
        Some(Value::Null) | None => if update { Some(json!({})) } else { None },
        Some(v) => Some(v.clone()),
    };
    let preview = obj.get("preview").cloned();
    match sanitize_drawing_data(&elements, &app_state, files.as_ref(), preview.as_ref()) {
        Ok(_) => SchemaError::Issues(issues),
        Err(SanitizeFailure::Drawing(e)) => SchemaError::Thrown(ApiError::operational(e.status, e.message)),
        Err(SanitizeFailure::Invalid) => {
            eprintln!("Sanitization failed: Error: Invalid or malicious drawing data detected");
            issues.push(custom("Invalid or malicious drawing data detected"));
            SchemaError::Issues(issues)
        }
    }
}

fn thrown(f: SanitizeFailure) -> Result<(), SchemaError> {
    match f {
        SanitizeFailure::Drawing(e) => Err(SchemaError::Thrown(ApiError::operational(e.status, e.message))),
        SanitizeFailure::Invalid => {
            eprintln!("Sanitization failed: Error: Invalid or malicious drawing data detected");
            Err(SchemaError::Issues(vec![custom("Invalid or malicious drawing data detected")]))
        }
    }
}

/// drawingCreateSchema.safeParse(req.body)
pub fn parse_create(body: Option<&Value>) -> Result<DrawingInput, SchemaError> {
    let Parsed { mut input, issues, aborted } = parse_base(body, true);
    if !issues.is_empty() {
        return Err(refine_after_issues(body, issues, aborted, false));
    }
    let elements = Value::Array(input.elements.clone().unwrap_or_default());
    let app_state = input.app_state.clone().unwrap_or(json!({}));
    let files = input.files.clone().map(Value::Object);
    let preview = input.preview.clone().map(|p| p.map(Value::String).unwrap_or(Value::Null));
    match sanitize_drawing_data(&elements, &app_state, files.as_ref(), preview.as_ref()) {
        Ok(s) => {
            input.elements = Some(s.elements);
            input.app_state = Some(s.app_state);
            input.files = s.files.and_then(|f| match f {
                Value::Object(m) => Some(m),
                _ => None,
            });
            input.preview = s.preview.map(|p| p.as_str().map(str::to_string));
            Ok(input)
        }
        Err(f) => thrown(f).map(|_| input),
    }
}

/// drawingUpdateSchema.safeParse(req.body) (refine = sanitizeDrawingUpdateData)
pub fn parse_update(body: Option<&Value>) -> Result<DrawingInput, SchemaError> {
    let Parsed { mut input, issues, aborted } = parse_base(body, false);
    if !issues.is_empty() {
        return Err(refine_after_issues(body, issues, aborted, true));
    }
    let has_scene = input.elements.is_some() || input.app_state.is_some() || input.files.is_some();
    if has_scene {
        let elements = Value::Array(input.elements.clone().unwrap_or_default());
        let app_state = match &input.app_state {
            Some(v @ Value::Object(_)) => v.clone(),
            _ => json!({}),
        };
        let files = Value::Object(input.files.clone().unwrap_or_default());
        let preview = input.preview.clone().map(|p| p.map(Value::String).unwrap_or(Value::Null));
        match sanitize_drawing_data(&elements, &app_state, Some(&files), preview.as_ref()) {
            Ok(s) => {
                if input.elements.is_some() {
                    input.elements = Some(s.elements);
                }
                if input.app_state.is_some() {
                    input.app_state = Some(s.app_state);
                }
                if input.files.is_some() {
                    input.files = s.files.and_then(|f| match f {
                        Value::Object(m) => Some(m),
                        _ => None,
                    });
                }
                if input.preview.is_some() {
                    input.preview = s.preview.map(|p| p.as_str().map(str::to_string));
                }
            }
            Err(f) => thrown(f)?,
        }
    } else if let Some(Some(p)) = &input.preview {
        input.preview = Some(Some(sanitize_svg(p)));
    }
    Ok(input)
}

/// respondWithValidationErrors
pub fn validation_error(issues: Vec<Value>) -> ApiError {
    if crate::config::config().node_env == "production" {
        ApiError::err(400, "Validation error", "Invalid request data")
    } else {
        ApiError::json(400, json!({ "error": "Invalid drawing payload", "details": issues }))
    }
}

pub fn schema_error(e: SchemaError) -> ApiError {
    match e {
        SchemaError::Issues(i) => validation_error(i),
        SchemaError::Thrown(e) => e,
    }
}

/// collectionNameSchema = z.string().trim().min(1).max(100)
pub fn collection_name(v: Option<&Value>) -> Option<String> {
    let s = v?.as_str()?;
    let t = js_trim(s);
    let n = js_len(t);
    (1..=100).contains(&n).then(|| t.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_defaults_and_trims() {
        let p = parse_create(Some(&json!({"name": "  hi  ", "collectionId": " c1 "}))).unwrap();
        assert_eq!(p.name.as_deref(), Some("hi"));
        assert_eq!(p.collection_id, Some(Some("c1".into())));
        assert_eq!(p.elements, Some(vec![]));
        assert_eq!(p.app_state, Some(json!({})));
        assert!(p.files.is_none());
        assert!(p.preview.is_none());
    }

    #[test]
    fn create_rejects_bad_shapes() {
        assert!(matches!(parse_create(None), Err(SchemaError::Issues(_))));
        assert!(matches!(parse_create(Some(&json!([]))), Err(SchemaError::Issues(_))));
        assert!(matches!(parse_create(Some(&json!({"name": "   "}))), Err(SchemaError::Issues(_))));
        assert!(matches!(parse_create(Some(&json!({"collectionId": ""}))), Err(SchemaError::Issues(_))));
        assert!(matches!(parse_create(Some(&json!({"elements": {}}))), Err(SchemaError::Issues(_))));
        assert!(matches!(parse_create(Some(&json!({"files": []}))), Err(SchemaError::Issues(_))));
        assert!(matches!(parse_create(Some(&json!({"name": "x".repeat(256)}))), Err(SchemaError::Issues(_))));
    }

    #[test]
    fn create_bad_data_url_is_thrown_operational() {
        let r = parse_create(Some(&json!({"files": {"f": {"dataURL": "data:text/html;base64,AAAA"}}})));
        match r {
            Err(SchemaError::Thrown(ApiError::Thrown { status, operational, .. })) => {
                assert_eq!(status, 400);
                assert!(operational);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn update_version_and_null_files() {
        let p = parse_update(Some(&json!({"version": 3, "files": null}))).unwrap();
        assert_eq!(p.version, Some(3));
        assert!(p.files.is_none());
        assert!(matches!(parse_update(Some(&json!({"version": 0}))), Err(SchemaError::Issues(_))));
        assert!(matches!(parse_update(Some(&json!({"version": 1.5}))), Err(SchemaError::Issues(_))));
        assert!(matches!(parse_update(Some(&json!({"version": "1"}))), Err(SchemaError::Issues(_))));
    }

    #[test]
    fn update_preview_only_is_svg_sanitized() {
        let p = parse_update(Some(&json!({"preview": "<svg><script>x</script></svg>"}))).unwrap();
        assert_eq!(p.preview, Some(Some("<svg></svg>".into())));
        let p = parse_update(Some(&json!({"preview": null}))).unwrap();
        assert_eq!(p.preview, Some(None));
    }

    #[test]
    fn collection_names() {
        assert_eq!(collection_name(Some(&json!("  a "))).as_deref(), Some("a"));
        assert!(collection_name(Some(&json!("  "))).is_none());
        assert!(collection_name(Some(&json!(5))).is_none());
        assert!(collection_name(Some(&json!("x".repeat(101)))).is_none());
        assert!(collection_name(None).is_none());
    }
}
