//! drawingListRoutes.ts — GET /drawings, GET /drawings/shared, GET /drawings/:id/preview.
use axum::{
    extract::{Path, State},
    http::{header, HeaderValue, StatusCode},
    response::IntoResponse,
};
use rusqlite::{types::{ToSql, Value as SqlValue}, OptionalExtension};
use serde_json::{json, Map, Value};

use super::{err_only, js_num, js_string, parse_json_field, query, truthy, DrawingRow, DRAWING_COLS, MAX_PAGE_SIZE};
use crate::authz::{get_drawing_access, normalize_permission};
use crate::drawings_cache::{CacheKeyParts, DrawingsCache};
use crate::http::ctx::Ctx;
use crate::http::error::{json_bytes, ok, ApiError, ApiResult};
use crate::security::js_trim;
use crate::state::AppState;
use crate::trash::{to_public, user_trash_collection_id};

const DEFAULT_PAGE_SIZE: f64 = 50.0;

/// JS `Number.parseInt(s, 10)` (NaN → None).
pub fn js_parse_int(s: &str) -> Option<f64> {
    let t = js_trim(s);
    let (neg, rest) = match t.as_bytes().first() {
        Some(b'-') => (true, &t[1..]),
        Some(b'+') => (false, &t[1..]),
        _ => (false, t),
    };
    let digits: &str = &rest[..rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len())];
    if digits.is_empty() {
        return None;
    }
    let v: f64 = digits.parse().ok()?;
    Some(if neg { -v } else { v })
}

fn raw_param(v: Option<&Value>) -> Option<String> {
    // `raw ? parseInt(raw) : undefined` — arrays are truthy and stringify with commas.
    truthy(v).then(|| js_string(v.unwrap()))
}

fn clamp_limit(v: Option<&Value>) -> f64 {
    match raw_param(v).and_then(|s| js_parse_int(&s)) {
        Some(n) if n.is_finite() => n.max(1.0).min(MAX_PAGE_SIZE),
        _ => DEFAULT_PAGE_SIZE,
    }
}

fn clamp_offset(v: Option<&Value>) -> f64 {
    match raw_param(v).and_then(|s| js_parse_int(&s)) {
        Some(n) if n.is_finite() => n.max(0.0) + 0.0,
        _ => 0.0,
    }
}

struct ListParams {
    search: Option<String>,
    include_data: bool,
    sort_field: &'static str,
    sort_dir: &'static str,
    limit: f64,
    offset: f64,
}

fn list_params(q: &Map<String, Value>) -> ListParams {
    let search = match q.get("search") {
        Some(Value::String(s)) if !js_trim(s).is_empty() => Some(js_trim(s).to_string()),
        _ => None,
    };
    let include_data = match q.get("includeData") {
        Some(Value::String(s)) => s.to_lowercase() == "true" || s == "1",
        _ => false,
    };
    let sort_field = match q.get("sortField").and_then(|v| v.as_str()) {
        Some("name") => "name",
        Some("createdAt") => "createdAt",
        _ => "updatedAt",
    };
    let sort_dir = match q.get("sortDirection").and_then(|v| v.as_str()) {
        Some("asc") => "asc",
        Some("desc") => "desc",
        _ if sort_field == "name" => "asc",
        _ => "desc",
    };
    ListParams {
        search,
        include_data,
        sort_field,
        sort_dir,
        limit: clamp_limit(q.get("limit")),
        offset: clamp_offset(q.get("offset")),
    }
}

fn num_key(n: f64) -> String {
    crate::util::js_num_str(n)
}

/// GET /drawings
pub async fn list_drawings(State(st): State<AppState>, ctx: Ctx) -> ApiResult {
    let user = crate::auth::require_auth(&st.db, &ctx).await?;
    let q = query(&ctx);
    let p = list_params(&q);
    let trash_id = user_trash_collection_id(&user.id);

    let mut conds: Vec<String> = vec![];
    let mut params: Vec<SqlValue> = vec![];
    let mut add = |sql: &str, vals: Vec<SqlValue>, params: &mut Vec<SqlValue>| {
        let mut parts = sql.split('?');
        let mut s = parts.next().unwrap_or("").to_string();
        let mut vals = vals.into_iter();
        for part in parts {
            if let Some(v) = vals.next() {
                params.push(v);
            }
            s.push_str(&format!("?{}{part}", params.len()));
        }
        conds.push(s);
    };
    let mut owner_filter = true;
    let mut extra: Vec<(String, Vec<SqlValue>)> = vec![];
    if let Some(term) = &p.search {
        extra.push((r#"d."name" LIKE ?"#.into(), vec![SqlValue::from(format!("%{term}%"))]));
    }
    let collection_filter_key: String;
    let cid = q.get("collectionId");
    if cid.and_then(|v| v.as_str()) == Some("null") {
        extra.push((r#"d."collectionId" IS NULL"#.into(), vec![]));
        collection_filter_key = "null".into();
    } else if truthy(cid) {
        let cid = js_string(cid.unwrap());
        if cid == "trash" {
            extra.push((r#"d."collectionId" IN (?, ?)"#.into(), vec![SqlValue::from(trash_id.clone()), SqlValue::from("trash".to_string())]));
            collection_filter_key = "trash".into();
        } else {
            let (uid, c2) = (user.id.clone(), cid.clone());
            let allowed = st
                .db
                .call(move |c| {
                    let owner: Option<String> = c
                        .query_row(r#"SELECT "userId" FROM "Collection" WHERE "id" = ?1 LIMIT 1"#, [&c2], |r| r.get(0))
                        .optional()?;
                    Ok(match owner {
                        None => false,
                        Some(o) if o == uid => true,
                        Some(_) => crate::db::exists(
                            c,
                            r#"SELECT 1 FROM "CollectionShare" WHERE "collectionId" = ?1 AND "granteeUserId" = ?2 LIMIT 1"#,
                            [&c2, &uid],
                        )?,
                    })
                })
                .await?;
            if !allowed {
                return Err(err_only(404, "Collection not found"));
            }
            owner_filter = false;
            extra.push((r#"d."collectionId" = ?"#.into(), vec![SqlValue::from(cid.clone())]));
            collection_filter_key = format!("id:{cid}");
        }
    } else {
        extra.push((
            r#"((d."collectionId" NOT IN (?, ?) AND d."collectionId" IS NOT NULL) OR d."collectionId" IS NULL)"#.into(),
            vec![SqlValue::from(trash_id.clone()), SqlValue::from("trash".to_string())],
        ));
        collection_filter_key = "default".into();
    }
    if owner_filter {
        add(r#"d."userId" = ?"#, vec![SqlValue::from(user.id.clone())], &mut params);
    }
    for (sql, vals) in extra {
        add(&sql, vals, &mut params);
    }

    let cache_key = format!(
        "{}:{}:{}",
        DrawingsCache::build_key(&CacheKeyParts {
            user_id: &user.id,
            search_term: p.search.as_deref().unwrap_or(""),
            collection_filter: &collection_filter_key,
            include_data: p.include_data,
            sort_field: p.sort_field,
            sort_direction: p.sort_dir,
        }),
        num_key(p.limit),
        num_key(p.offset)
    );
    if let Some(body) = st.drawings_cache.get(&cache_key) {
        return Ok(cached_json(body.to_vec(), "HIT"));
    }

    let where_sql = if conds.is_empty() { "1=1".to_string() } else { conds.join(" AND ") };
    let order = format!(r#"d."{}" {}"#, p.sort_field, p.sort_dir.to_uppercase());
    let include_data = p.include_data;
    let (limit, offset) = (p.limit as i64, p.offset.min(i64::MAX as f64) as i64);
    let uid = user.id.clone();
    let (drawings, total) = st
        .db
        .call(move |c| {
            let refs: Vec<&dyn ToSql> = params.iter().map(|b| b as &dyn ToSql).collect();
            let n = refs.len();
            let sql = format!(
                r#"SELECT {cols}, u."name" FROM "Drawing" d JOIN "User" u ON u."id" = d."userId" WHERE {where_sql} ORDER BY {order} LIMIT ?{} OFFSET ?{}"#,
                n + 1,
                n + 2,
                cols = DRAWING_COLS.split(',').map(|c| format!("d.{c}")).collect::<Vec<_>>().join(",")
            );
            let mut all: Vec<&dyn ToSql> = refs.clone();
            all.push(&limit);
            all.push(&offset);
            let mut stmt = c.prepare(&sql)?;
            let rows: Vec<Value> = stmt
                .query_map(all.as_slice(), |r| {
                    let d = DrawingRow::from_row_at(r, 0)?;
                    let creator: Option<String> = r.get(11)?;
                    let public_cid = super::opt_str_json(to_public(d.collection_id.as_deref(), &uid));
                    let mut m = if include_data {
                        d.to_json_with(public_cid)
                    } else {
                        let mut m = Map::new();
                        m.insert("id".into(), json!(d.id));
                        m.insert("name".into(), json!(d.name));
                        m.insert("collectionId".into(), public_cid);
                        m.insert("version".into(), json!(d.version));
                        m.insert("createdAt".into(), json!(crate::util::iso_from_ms(d.created_at)));
                        m.insert("updatedAt".into(), json!(crate::util::iso_from_ms(d.updated_at)));
                        m.insert("userId".into(), json!(d.user_id));
                        m
                    };
                    m.insert("creatorName".into(), json!(creator));
                    Ok(Value::Object(m))
                })?
                .collect::<Result<_, _>>()?;
            let total: i64 = c.query_row(
                &format!(r#"SELECT COUNT(*) FROM "Drawing" d WHERE {where_sql}"#),
                refs.as_slice(),
                |r| r.get(0),
            )?;
            Ok((rows, total))
        })
        .await?;

    let payload = json!({
        "drawings": drawings,
        "totalCount": total,
        "limit": js_num(p.limit),
        "offset": js_num(p.offset),
    });
    let body = serde_json::to_vec(&payload).unwrap_or_default();
    st.drawings_cache.put(&cache_key, bytes::Bytes::from(body.clone()), &user.id);
    Ok(cached_json(body, "MISS"))
}

fn cached_json(body: Vec<u8>, cache: &'static str) -> axum::response::Response {
    let mut res = json_bytes(StatusCode::OK, body);
    res.headers_mut().insert("x-cache", HeaderValue::from_static(cache));
    res.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    res
}

/// GET /drawings/shared
pub async fn shared_drawings(st: AppState, ctx: Ctx) -> ApiResult {
    let user = crate::auth::require_auth(&st.db, &ctx).await?;
    let q = query(&ctx);
    let p = list_params(&q);
    let uid = user.id.clone();
    let order = format!(r#"d."{}" {}"#, p.sort_field, p.sort_dir.to_uppercase());
    let (limit, offset) = (p.limit as i64, p.offset.min(i64::MAX as f64) as i64);
    let include_data = p.include_data;
    let search = p.search.clone();
    let (drawings, total) = st
        .db
        .call(move |c| {
            let shared_cols: Vec<String> = {
                let mut s = c.prepare(r#"SELECT "collectionId" FROM "CollectionShare" WHERE "granteeUserId" = ?1"#)?;
                s.query_map([&uid], |r| r.get(0))?.collect::<Result<_, _>>()?
            };
            let mut params: Vec<Box<dyn ToSql>> = vec![Box::new(uid.clone())];
            let mut where_sql = r#"d."userId" <> ?1 AND EXISTS (SELECT 1 FROM "DrawingPermission" p WHERE p."drawingId" = d."id" AND p."granteeUserId" = ?1 AND p."hidden" = 0)"#.to_string();
            if !shared_cols.is_empty() {
                where_sql.push_str(&format!(r#" AND NOT (d."collectionId" IN ({}))"#, super::placeholders(2, shared_cols.len())));
                for s in &shared_cols {
                    params.push(Box::new(s.clone()));
                }
            }
            if let Some(term) = &search {
                params.push(Box::new(format!("%{term}%")));
                where_sql.push_str(&format!(r#" AND d."name" LIKE ?{}"#, params.len()));
            }
            let refs: Vec<&dyn ToSql> = params.iter().map(|b| b.as_ref()).collect();
            let n = refs.len();
            let sql = format!(
                r#"SELECT {cols}, u."name", (SELECT p2."permission" FROM "DrawingPermission" p2 WHERE p2."drawingId" = d."id" AND p2."granteeUserId" = ?1 LIMIT 1)
                   FROM "Drawing" d JOIN "User" u ON u."id" = d."userId" WHERE {where_sql} ORDER BY {order} LIMIT ?{} OFFSET ?{}"#,
                n + 1,
                n + 2,
                cols = DRAWING_COLS.split(',').map(|c| format!("d.{c}")).collect::<Vec<_>>().join(",")
            );
            let mut all = refs.clone();
            all.push(&limit);
            all.push(&offset);
            let mut stmt = c.prepare(&sql)?;
            let rows: Vec<Value> = stmt
                .query_map(all.as_slice(), |r| {
                    let d = DrawingRow::from_row_at(r, 0)?;
                    let creator: Option<String> = r.get(11)?;
                    let perm: Option<String> = r.get(12)?;
                    let mut m = if include_data {
                        let mut m = d.to_map();
                        m.insert("elements".into(), parse_json_field(Some(&d.elements), json!([])));
                        m.insert("appState".into(), parse_json_field(Some(&d.app_state), json!({})));
                        m.insert("files".into(), parse_json_field(Some(&d.files), json!({})));
                        m
                    } else {
                        let mut m = Map::new();
                        m.insert("id".into(), json!(d.id));
                        m.insert("name".into(), json!(d.name));
                        m.insert("collectionId".into(), Value::Null);
                        m.insert("version".into(), json!(d.version));
                        m.insert("createdAt".into(), json!(crate::util::iso_from_ms(d.created_at)));
                        m.insert("updatedAt".into(), json!(crate::util::iso_from_ms(d.updated_at)));
                        m.insert("userId".into(), json!(d.user_id));
                        m
                    };
                    m.insert("collectionId".into(), Value::Null);
                    // Upstream only selects permissions in summary mode; full mode falls back to "view".
                    let access = if include_data { None } else { normalize_permission(perm.as_deref()) };
                    m.insert("accessLevel".into(), json!(access.map(|a| a.as_str()).unwrap_or("view")));
                    m.insert("creatorName".into(), json!(creator));
                    Ok(Value::Object(m))
                })?
                .collect::<Result<_, _>>()?;
            let total: i64 =
                c.query_row(&format!(r#"SELECT COUNT(*) FROM "Drawing" d WHERE {where_sql}"#), refs.as_slice(), |r| r.get(0))?;
            Ok((rows, total))
        })
        .await?;
    ok(json!({
        "drawings": drawings,
        "totalCount": total,
        "limit": js_num(p.limit),
        "offset": js_num(p.offset),
    }))
}

fn drawing_not_found() -> ApiError {
    ApiError::err(404, "Drawing not found", "Drawing does not exist")
}

/// GET /drawings/:id/preview
pub async fn drawing_preview(State(st): State<AppState>, ctx: Ctx, Path(id): Path<String>) -> ApiResult {
    let opt = crate::auth::optional_auth(&st.db, &ctx).await;
    let principal = super::principal(&opt);
    let id2 = id.clone();
    let (access, row) = st
        .db
        .call(move |c| {
            let access = get_drawing_access(c, principal.as_deref(), &id2, None)?;
            let row = c
                .query_row(r#"SELECT "preview","updatedAt" FROM "Drawing" WHERE "id" = ?1"#, [&id2], |r| {
                    Ok((r.get::<_, Option<String>>(0)?, crate::db::dt(r, 1)?))
                })
                .optional()?;
            Ok((access, row))
        })
        .await?;
    if !access.can_view() {
        if let Some(e) = super::auth_error(&opt) {
            return Err(e);
        }
        return Err(drawing_not_found());
    }
    let Some((preview, updated_ms)) = row else { return Err(drawing_not_found()) };
    let etag = format!("W/\"preview-{id}-{updated_ms}\"");
    let fresh = ctx.header("if-none-match") == Some(etag.as_str());
    let mut res = if fresh {
        StatusCode::NOT_MODIFIED.into_response()
    } else {
        crate::http::error::json_response(StatusCode::OK, &json!({ "preview": preview, "updatedAt": updated_ms }))
    };
    let h = res.headers_mut();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("private, max-age=0, must-revalidate"));
    if let Ok(v) = HeaderValue::from_str(&etag) {
        h.insert(header::ETAG, v);
    }
    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_int_like_js() {
        assert_eq!(js_parse_int("12abc"), Some(12.0));
        assert_eq!(js_parse_int("  -3"), Some(-3.0));
        assert_eq!(js_parse_int("0x10"), Some(0.0));
        assert_eq!(js_parse_int("abc"), None);
        assert_eq!(js_parse_int(""), None);
    }

    #[test]
    fn clamps() {
        assert_eq!(clamp_limit(None), 50.0);
        assert_eq!(clamp_limit(Some(&json!("0"))), 1.0);
        assert_eq!(clamp_limit(Some(&json!("999"))), 200.0);
        assert_eq!(clamp_limit(Some(&json!(["3", "4"]))), 3.0);
        assert_eq!(clamp_limit(Some(&json!(""))), 50.0);
        assert_eq!(clamp_offset(Some(&json!("-5"))), 0.0);
        assert_eq!(clamp_offset(Some(&json!("x"))), 0.0);
        assert_eq!(clamp_offset(Some(&json!("7"))), 7.0);
    }
}
