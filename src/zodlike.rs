//! zod 4 issue objects for the drawing schemas (security.ts elementSchema /
//! appStateSchema and index.ts drawingBaseSchema), exactly as `safeParse` reports
//! them in `error.issues`: shapes, messages, union resolution and abort semantics.
use serde_json::{json, Value};

/// An issue plus whether zod treats it as aborting (type/enum/union failures do;
/// size checks and custom refinements don't — then outer refinements still run).
#[derive(Debug, Clone)]
pub struct Issue {
    pub value: Value,
    pub aborted: bool,
}

pub type Path = Vec<Value>;

fn p(base: &Path, seg: impl Into<Value>) -> Path {
    let mut v = base.clone();
    v.push(seg.into());
    v
}

pub fn received(v: Option<&Value>) -> &'static str {
    match v {
        None => "undefined",
        Some(Value::Null) => "null",
        Some(Value::Bool(_)) => "boolean",
        Some(Value::Number(_)) => "number",
        Some(Value::String(_)) => "string",
        Some(Value::Array(_)) => "array",
        Some(Value::Object(_)) => "object",
    }
}

pub fn invalid_type(path: Path, expected: &str, got: Option<&Value>) -> Issue {
    Issue {
        value: json!({
            "expected": expected,
            "code": "invalid_type",
            "path": path,
            "message": format!("Invalid input: expected {expected}, received {}", received(got)),
        }),
        aborted: true,
    }
}

fn num_lit(n: f64) -> Value {
    if n.fract() == 0.0 && n.abs() < 9e15 { json!(n as i64) } else { json!(n) }
}

pub fn too_small(path: Path, origin: &str, min: f64) -> Issue {
    let unit = if origin == "string" { format!("to have >={} characters", crate::util::js_num_str(min)) } else { format!("to be >={}", crate::util::js_num_str(min)) };
    Issue {
        value: json!({"origin": origin, "code": "too_small", "minimum": num_lit(min), "inclusive": true, "path": path,
                      "message": format!("Too small: expected {origin} {unit}")}),
        aborted: false,
    }
}

pub fn too_big(path: Path, origin: &str, max: f64) -> Issue {
    let unit = if origin == "string" { format!("to have <={} characters", crate::util::js_num_str(max)) } else { format!("to be <={}", crate::util::js_num_str(max)) };
    Issue {
        value: json!({"origin": origin, "code": "too_big", "maximum": num_lit(max), "inclusive": true, "path": path,
                      "message": format!("Too big: expected {origin} {unit}")}),
        aborted: false,
    }
}

pub fn invalid_value(path: Path, values: &[&str]) -> Issue {
    let list = values.iter().map(|v| format!("\"{v}\"")).collect::<Vec<_>>().join("|");
    Issue {
        value: json!({"code": "invalid_value", "values": values, "path": path, "message": format!("Invalid option: expected one of {list}")}),
        aborted: true,
    }
}

pub fn custom(path: Path, message: &str) -> Issue {
    Issue { value: json!({"code": "custom", "path": path, "message": message}), aborted: false }
}

/// z.union([...]) result handling (zod 4 `handleUnionResults`).
pub fn union(path: Path, branches: Vec<Vec<Issue>>) -> Vec<Issue> {
    if branches.iter().any(|b| b.is_empty()) {
        return vec![];
    }
    let non_aborted: Vec<&Vec<Issue>> = branches.iter().filter(|b| !b.iter().any(|i| i.aborted)).collect();
    if non_aborted.len() == 1 {
        return non_aborted[0]
            .iter()
            .map(|i| {
                let mut v = i.value.clone();
                let mut full = path.clone();
                full.extend(v["path"].as_array().cloned().unwrap_or_default());
                v["path"] = Value::Array(full);
                Issue { value: v, aborted: i.aborted }
            })
            .collect();
    }
    let errors: Vec<Value> = branches.iter().map(|b| Value::Array(b.iter().map(|i| i.value.clone()).collect())).collect();
    vec![Issue { value: json!({"code": "invalid_union", "errors": errors, "path": path, "message": "Invalid input"}), aborted: true }]
}

// --- primitives (relative path []) ---------------------------------------------------------

fn string(path: &Path, v: &Value, min: Option<usize>, max: Option<usize>) -> Vec<Issue> {
    let Value::String(s) = v else { return vec![invalid_type(path.clone(), "string", Some(v))] };
    let n = crate::util::js_len(s);
    let mut out = vec![];
    if let Some(m) = min {
        if n < m {
            out.push(too_small(path.clone(), "string", m as f64));
        }
    }
    if let Some(m) = max {
        if n > m {
            out.push(too_big(path.clone(), "string", m as f64));
        }
    }
    out
}

fn number(path: &Path, v: &Value, min: Option<f64>, max: Option<f64>) -> Vec<Issue> {
    let Some(n) = v.as_f64() else { return vec![invalid_type(path.clone(), "number", Some(v))] };
    let mut out = vec![];
    if let Some(m) = min {
        if n < m {
            out.push(too_small(path.clone(), "number", m));
        }
    }
    if let Some(m) = max {
        if n > m {
            out.push(too_big(path.clone(), "number", m));
        }
    }
    out
}

fn boolean(path: &Path, v: &Value) -> Vec<Issue> {
    if v.is_boolean() { vec![] } else { vec![invalid_type(path.clone(), "boolean", Some(v))] }
}

fn enumv(path: &Path, v: &Value, values: &[&str]) -> Vec<Issue> {
    match v.as_str() {
        Some(s) if values.contains(&s) => vec![],
        _ => vec![invalid_value(path.clone(), values)],
    }
}

fn array_of(path: &Path, v: &Value, item: impl Fn(&Path, &Value) -> Vec<Issue>) -> Vec<Issue> {
    let Value::Array(a) = v else { return vec![invalid_type(path.clone(), "array", Some(v))] };
    a.iter().enumerate().flat_map(|(i, x)| item(&p(path, i), x)).collect()
}

fn record_of(path: &Path, v: &Value, item: impl Fn(&Path, &Value) -> Vec<Issue>) -> Vec<Issue> {
    let Value::Object(m) = v else { return vec![invalid_type(path.clone(), "record", Some(v))] };
    m.iter().flat_map(|(k, x)| item(&p(path, k.as_str()), x)).collect()
}

/// `.optional().nullable()` field of an object.
fn opt_field(out: &mut Vec<Issue>, obj: &serde_json::Map<String, Value>, base: &Path, key: &str, check: impl Fn(&Path, &Value) -> Vec<Issue>) {
    if let Some(v) = obj.get(key) {
        if !v.is_null() {
            out.extend(check(&p(base, key), v));
        }
    }
}

// --- security.ts elementSchema ----------------------------------------------------------------

pub fn element_issues(path: &Path, el: &Value) -> Vec<Issue> {
    let Value::Object(o) = el else { return vec![invalid_type(path.clone(), "object", Some(el))] };
    let mut out = vec![];
    let s = |pth: &Path, v: &Value| string(pth, v, None, None);
    let n = |pth: &Path, v: &Value| number(pth, v, None, None);
    opt_field(&mut out, o, path, "id", |pth, v| string(pth, v, Some(1), Some(200)));
    for k in ["type"] {
        opt_field(&mut out, o, path, k, s);
    }
    for k in ["x", "y", "width", "height", "angle"] {
        opt_field(&mut out, o, path, k, n);
    }
    for k in ["strokeColor", "backgroundColor", "fillStyle"] {
        opt_field(&mut out, o, path, k, s);
    }
    opt_field(&mut out, o, path, "strokeWidth", n);
    opt_field(&mut out, o, path, "strokeStyle", s);
    // roundness: any
    opt_field(&mut out, o, path, "boundElements", |pth, v| array_of(pth, v, |_, _| vec![]));
    opt_field(&mut out, o, path, "groupIds", |pth, v| array_of(pth, v, |pp, x| string(pp, x, None, None)));
    opt_field(&mut out, o, path, "frameId", s);
    for k in ["seed", "version", "versionNonce"] {
        opt_field(&mut out, o, path, k, n);
    }
    opt_field(&mut out, o, path, "isDeleted", boolean);
    opt_field(&mut out, o, path, "opacity", n);
    opt_field(&mut out, o, path, "link", s);
    opt_field(&mut out, o, path, "locked", boolean);
    opt_field(&mut out, o, path, "text", s);
    opt_field(&mut out, o, path, "fontSize", n);
    opt_field(&mut out, o, path, "fontFamily", |pth, v| {
        union(pth.clone(), vec![number(&vec![], v, None, None), string(&vec![], v, None, Some(200))])
    });
    opt_field(&mut out, o, path, "textAlign", s);
    opt_field(&mut out, o, path, "verticalAlign", s);
    opt_field(&mut out, o, path, "customData", |pth, v| record_of(pth, v, |_, _| vec![]));
    out
}

// --- security.ts appStateSchema ---------------------------------------------------------------

fn object_fields(path: &Path, v: &Value, fields: &[(&str, &dyn Fn(&Path, &Value) -> Vec<Issue>, bool)]) -> Vec<Issue> {
    let Value::Object(o) = v else { return vec![invalid_type(path.clone(), "object", Some(v))] };
    let mut out = vec![];
    for (key, check, optional) in fields {
        match o.get(*key) {
            None if *optional => {}
            None => out.push(invalid_type(p(path, *key), expected_name(*key), None)),
            Some(Value::Null) if *optional => {}
            Some(x) => out.extend(check(&p(path, *key), x)),
        }
    }
    out
}

fn expected_name(key: &str) -> &'static str {
    match key {
        "value" => "number",
        _ => "string",
    }
}

pub fn app_state_issues(path: &Path, v: &Value) -> Vec<Issue> {
    let Value::Object(o) = v else { return vec![invalid_type(path.clone(), "object", Some(v))] };
    let mut out = vec![];
    let num = |min: Option<f64>, max: Option<f64>| move |pth: &Path, x: &Value| number(pth, x, min, max);
    let s = |pth: &Path, x: &Value| string(pth, x, None, None);
    let keys: [&str; 24] = [
        "gridSize", "gridStep", "viewBackgroundColor", "currentItemStrokeColor", "currentItemBackgroundColor",
        "currentItemFillStyle", "currentItemStrokeWidth", "currentItemStrokeStyle", "currentItemRoundness",
        "currentItemFontSize", "currentItemFontFamily", "currentItemTextAlign", "currentItemVerticalAlign", "scrollX",
        "scrollY", "zoom", "selection", "selectedElementIds", "selectedGroupIds", "activeEmbeddable", "activeTool",
        "cursorX", "cursorY", "collaborators",
    ];
    for key in keys {
        let check: Box<dyn Fn(&Path, &Value) -> Vec<Issue>> = match key {
            "gridSize" => Box::new(num(Some(0.0), Some(1000.0))),
            "gridStep" => Box::new(num(Some(1.0), Some(1000.0))),
            "viewBackgroundColor" | "currentItemStrokeColor" | "currentItemBackgroundColor" => Box::new(s),
            "currentItemFillStyle" => Box::new(|pth: &Path, x: &Value| enumv(pth, x, &["solid", "hachure", "cross-hatch", "dots"])),
            "currentItemStrokeWidth" => Box::new(num(Some(0.0), Some(50.0))),
            "currentItemStrokeStyle" => Box::new(|pth: &Path, x: &Value| enumv(pth, x, &["solid", "dashed", "dotted"])),
            "currentItemRoundness" => Box::new(|pth: &Path, x: &Value| {
                let enum_branch = enumv(&vec![], x, &["sharp", "round"]);
                let obj_branch = object_fields(
                    &vec![],
                    x,
                    &[
                        ("type", &|pp: &Path, y: &Value| enumv(pp, y, &["round", "sharp"]), false),
                        ("value", &|pp: &Path, y: &Value| number(pp, y, Some(0.0), Some(1.0)), false),
                    ],
                );
                union(pth.clone(), vec![enum_branch, obj_branch])
            }),
            "currentItemFontSize" => Box::new(num(Some(1.0), Some(500.0))),
            "currentItemFontFamily" => Box::new(|pth: &Path, x: &Value| {
                union(pth.clone(), vec![number(&vec![], x, Some(0.0), None), string(&vec![], x, None, Some(200))])
            }),
            "currentItemTextAlign" => Box::new(|pth: &Path, x: &Value| enumv(pth, x, &["left", "center", "right"])),
            "currentItemVerticalAlign" => Box::new(|pth: &Path, x: &Value| enumv(pth, x, &["top", "middle", "bottom"])),
            "scrollX" | "scrollY" => Box::new(num(Some(-10000000.0), Some(10000000.0))),
            "zoom" => Box::new(|pth: &Path, x: &Value| {
                object_fields(pth, x, &[("value", &|pp: &Path, y: &Value| number(pp, y, Some(0.01), Some(100.0)), false)])
            }),
            "selection" => Box::new(|pth: &Path, x: &Value| array_of(pth, x, |pp, y| string(pp, y, None, None))),
            "selectedElementIds" | "selectedGroupIds" => Box::new(|pth: &Path, x: &Value| record_of(pth, x, boolean)),
            "activeEmbeddable" => Box::new(|pth: &Path, x: &Value| {
                object_fields(pth, x, &[("elementId", &|pp: &Path, y: &Value| string(pp, y, None, None), false), ("state", &|pp: &Path, y: &Value| string(pp, y, None, None), false)])
            }),
            "activeTool" => Box::new(|pth: &Path, x: &Value| {
                object_fields(pth, x, &[("type", &|pp: &Path, y: &Value| string(pp, y, None, None), false), ("customType", &|pp: &Path, y: &Value| string(pp, y, None, None), true)])
            }),
            "cursorX" | "cursorY" => Box::new(num(None, None)),
            "collaborators" => Box::new(|pth: &Path, x: &Value| record_of(pth, x, |_, _| vec![])),
            _ => unreachable!(),
        };
        opt_field(&mut out, o, path, key, |pth, x| check(pth, x));
    }
    // catchall(z.any().refine(val => typeof val === "string" ? sanitizeText(val, 1000) : true))
    for (k, x) in o {
        if keys.contains(&k.as_str()) {
            continue;
        }
        if let Value::String(sv) = x {
            if crate::security::sanitize_text(sv, 1000).is_empty() {
                out.push(custom(p(path, k.as_str()), "Invalid input"));
            }
        }
    }
    out
}
