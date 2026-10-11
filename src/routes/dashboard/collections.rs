//! collections.ts — collections CRUD and collection sharing.
use axum::extract::{Path, State};
use crate::sql::{Connection, OptionalExtension, Row};
use serde_json::{json, Map, Value};
use std::collections::HashSet;

use super::schema::collection_name;
use super::{audit, err_only, js_string, query, truthy};
use crate::http::body::Body;
use crate::http::ctx::Ctx;
use crate::http::error::{ok, ApiError, ApiResult};
use crate::security::{js_trim, sanitize_text};
use crate::state::AppState;
use crate::trash::{ensure_trash_collection, is_trash_collection_id, user_trash_collection_id};

const COLLECTION_COLS: &str = r#""id","name","userId","createdAt","updatedAt""#;

fn collection_map(r: &Row<'_>, o: usize) -> crate::sql::Result<Map<String, Value>> {
    let mut m = Map::new();
    m.insert("id".into(), json!(r.get::<_, String>(o)?));
    m.insert("name".into(), json!(r.get::<_, String>(o + 1)?));
    m.insert("userId".into(), json!(r.get::<_, String>(o + 2)?));
    m.insert("createdAt".into(), crate::db::iso(r, o + 3)?);
    m.insert("updatedAt".into(), crate::db::iso(r, o + 4)?);
    Ok(m)
}

fn find_owned(c: &Connection, id: &str, user_id: &str) -> crate::sql::Result<Option<Map<String, Value>>> {
    c.query_row(
        &format!(r#"SELECT {COLLECTION_COLS} FROM "Collection" WHERE "id" = ?1 AND "userId" = ?2 LIMIT 1"#),
        [id, user_id],
        |r| collection_map(r, 0),
    )
    .optional()
}

async fn require_owned(st: &AppState, id: &str, user_id: &str) -> Result<Map<String, Value>, ApiError> {
    let (id, uid) = (id.to_string(), user_id.to_string());
    st.db
        .call(move |c| Ok(find_owned(c, &id, &uid)?))
        .await?
        .ok_or_else(|| err_only(404, "Collection not found"))
}

fn name_error() -> ApiError {
    ApiError::err(400, "Validation error", "Collection name must be between 1 and 100 characters")
}

/// `req.body.name` (TypeError → 500 when the body is undefined).
fn body_field<'a>(body: &'a Body, key: &str) -> Result<Option<&'a Value>, ApiError> {
    match &body.0 {
        None => Err(ApiError::internal(format!("Cannot read properties of undefined (reading '{key}')"))),
        Some(Value::Object(m)) => Ok(m.get(key)),
        Some(_) => Ok(None),
    }
}

/// GET /collections
pub async fn list_collections(State(st): State<AppState>, ctx: Ctx) -> ApiResult {
    let user = crate::auth::require_auth(&st.db, &ctx).await?;
    let uid = user.id.clone();
    let out = st
        .db
        .call(move |c| {
            let trash_id = user_trash_collection_id(&uid);
            ensure_trash_collection(c, &uid)?;
            let mut s = c.prepare(&format!(
                r#"SELECT {COLLECTION_COLS} FROM "Collection" WHERE "userId" = ?1 ORDER BY "createdAt" DESC"#
            ))?;
            let raw: Vec<Map<String, Value>> = s.query_map([&uid], |r| collection_map(r, 0))?.collect::<Result<_, _>>()?;
            let ids: Vec<String> = raw.iter().map(|m| m["id"].as_str().unwrap_or("").to_string()).collect();
            let has_internal_trash = ids.contains(&trash_id);
            let shared: HashSet<String> = if ids.is_empty() {
                HashSet::new()
            } else {
                let sql = format!(
                    r#"SELECT DISTINCT "collectionId" FROM "CollectionShare" WHERE "collectionId" IN ({})"#,
                    super::placeholders(1, ids.len())
                );
                let mut s = c.prepare(&sql)?;
                s.query_map(crate::sql::params_from_iter(ids.iter()), |r| r.get(0))?.collect::<Result<_, _>>()?
            };
            let mut out: Vec<Value> = vec![];
            for mut m in raw {
                let id = m["id"].as_str().unwrap_or("").to_string();
                if has_internal_trash && id == "trash" {
                    continue;
                }
                if id == trash_id {
                    m.insert("id".into(), json!("trash"));
                    m.insert("name".into(), json!("Trash"));
                    m.insert("sharedRole".into(), Value::Null);
                    m.insert("isOwner".into(), json!(true));
                    m.insert("isShared".into(), json!(false));
                } else {
                    m.insert("sharedRole".into(), Value::Null);
                    m.insert("isOwner".into(), json!(true));
                    m.insert("isShared".into(), json!(shared.contains(&id)));
                }
                out.push(Value::Object(m));
            }
            let mut s = c.prepare(&format!(
                r#"SELECT s."role", {cols}, u."id", u."name", u."email"
                   FROM "CollectionShare" s JOIN "Collection" c ON c."id" = s."collectionId" JOIN "User" u ON u."id" = c."userId"
                   WHERE s."granteeUserId" = ?1"#,
                cols = COLLECTION_COLS.split(',').map(|x| format!("c.{x}")).collect::<Vec<_>>().join(",")
            ))?;
            let shared_rows: Vec<Value> = s
                .query_map([&uid], |r| {
                    let mut m = collection_map(r, 1)?;
                    m.insert(
                        "user".into(),
                        json!({"id": r.get::<_, String>(6)?, "name": r.get::<_, String>(7)?, "email": r.get::<_, String>(8)?}),
                    );
                    m.insert("sharedRole".into(), json!(r.get::<_, String>(0)?));
                    m.insert("isOwner".into(), json!(false));
                    Ok(Value::Object(m))
                })?
                .collect::<Result<_, _>>()?;
            out.extend(shared_rows);
            Ok(out)
        })
        .await?;
    ok(Value::Array(out))
}

/// POST /collections
pub async fn create_collection(State(st): State<AppState>, ctx: Ctx, body: Body) -> ApiResult {
    let user = crate::auth::require_auth(&st.db, &ctx).await?;
    let Some(name) = collection_name(body_field(&body, "name")?) else { return Err(name_error()) };
    let name = sanitize_text(&name, 100);
    let uid = user.id.clone();
    let mut m = st
        .db
        .call(move |c| {
            let id = crate::util::uuid_v4();
            let now = crate::util::now_ms();
            c.execute(
                r#"INSERT INTO "Collection" ("id","name","userId","createdAt","updatedAt") VALUES (?1,?2,?3,?4,?4)"#,
                crate::sql::params![id, name, uid, now],
            )?;
            Ok(find_owned(c, &id, &uid)?.unwrap_or_default())
        })
        .await?;
    m.insert("sharedRole".into(), Value::Null);
    m.insert("isOwner".into(), json!(true));
    ok(Value::Object(m))
}

/// PUT /collections/:id
pub async fn rename_collection(State(st): State<AppState>, ctx: Ctx, Path(id): Path<String>, body: Body) -> ApiResult {
    let user = crate::auth::require_auth(&st.db, &ctx).await?;
    if is_trash_collection_id(Some(&id), &user.id) {
        return Err(ApiError::err(400, "Validation error", "Trash collection cannot be renamed"));
    }
    require_owned(&st, &id, &user.id).await?;
    let Some(name) = collection_name(body_field(&body, "name")?) else { return Err(name_error()) };
    let name = sanitize_text(&name, 100);
    let uid = user.id.clone();
    let updated = st
        .db
        .call(move |c| {
            c.execute(
                r#"UPDATE "Collection" SET "name" = ?1, "updatedAt" = ?2 WHERE "id" = ?3 AND "userId" = ?4"#,
                crate::sql::params![name, crate::util::now_ms(), id, uid],
            )?;
            Ok(find_owned(c, &id, &uid)?)
        })
        .await?;
    match updated {
        Some(m) => ok(Value::Object(m)),
        None => Err(err_only(404, "Collection not found")),
    }
}

/// DELETE /collections/:id
pub async fn delete_collection(State(st): State<AppState>, ctx: Ctx, Path(id): Path<String>) -> ApiResult {
    let user = crate::auth::require_auth(&st.db, &ctx).await?;
    if is_trash_collection_id(Some(&id), &user.id) {
        return Err(ApiError::err(400, "Validation error", "Trash collection cannot be deleted"));
    }
    let collection = require_owned(&st, &id, &user.id).await?;
    let (id2, uid) = (id.clone(), user.id.clone());
    st.db
        .tx(move |tx| {
            tx.execute(
                r#"UPDATE "Drawing" SET "collectionId" = NULL, "updatedAt" = ?1 WHERE "collectionId" = ?2 AND "userId" = ?3"#,
                crate::sql::params![crate::util::now_ms(), id2, uid],
            )?;
            tx.execute(r#"DELETE FROM "CollectionShare" WHERE "collectionId" = ?1"#, [&id2])?;
            tx.execute(r#"DELETE FROM "Collection" WHERE "id" = ?1 AND "userId" = ?2"#, [&id2, &uid])?;
            Ok(())
        })
        .await?;
    st.drawings_cache.invalidate(None);
    audit(
        &st,
        &ctx,
        &user.id,
        "collection_deleted",
        format!("collection:{id}"),
        json!({"collectionId": id, "collectionName": collection.get("name")}),
    )
    .await;
    ok(json!({ "success": true }))
}

const SHARE_SELECT: &str = r#"SELECT s."id",s."collectionId",s."granteeUserId",s."role",s."createdByUserId",s."createdAt",s."updatedAt",u."id",u."name",u."email"
    FROM "CollectionShare" s JOIN "User" u ON u."id" = s."granteeUserId""#;

fn share_json(r: &Row<'_>) -> crate::sql::Result<Value> {
    Ok(json!({
        "id": r.get::<_, String>(0)?,
        "collectionId": r.get::<_, String>(1)?,
        "granteeUserId": r.get::<_, String>(2)?,
        "role": r.get::<_, String>(3)?,
        "createdByUserId": r.get::<_, String>(4)?,
        "createdAt": crate::db::iso(r, 5)?,
        "updatedAt": crate::db::iso(r, 6)?,
        "granteeUser": {"id": r.get::<_, String>(7)?, "name": r.get::<_, String>(8)?, "email": r.get::<_, String>(9)?},
    }))
}

/// GET /collections/:id/shares
pub async fn list_shares(State(st): State<AppState>, ctx: Ctx, Path(id): Path<String>) -> ApiResult {
    let user = crate::auth::require_auth(&st.db, &ctx).await?;
    require_owned(&st, &id, &user.id).await?;
    let shares = st
        .db
        .call(move |c| {
            let mut s = c.prepare(&format!(r#"{SHARE_SELECT} WHERE s."collectionId" = ?1 ORDER BY s."createdAt" ASC"#))?;
            let v: Vec<Value> = s.query_map([&id], share_json)?.collect::<Result<_, _>>()?;
            Ok(v)
        })
        .await?;
    ok(json!({ "shares": shares }))
}

fn is_role(v: Option<&Value>) -> Option<String> {
    match v {
        Some(Value::String(s)) if s == "view" || s == "edit" => Some(s.clone()),
        _ => None,
    }
}

/// POST /collections/:id/shares
pub async fn upsert_share(State(st): State<AppState>, ctx: Ctx, Path(id): Path<String>, body: Body) -> ApiResult {
    let user = crate::auth::require_auth(&st.db, &ctx).await?;
    let identifier = body_field(&body, "identifier")?.cloned();
    let role = is_role(body.get("role"));
    let (true, Some(role)) = (truthy(identifier.as_ref()), role) else {
        return Err(err_only(400, "identifier and role (view|edit) are required"));
    };
    require_owned(&st, &id, &user.id).await?;
    let Some(Value::String(identifier)) = identifier else {
        return Err(ApiError::internal("identifier.toLowerCase is not a function"));
    };
    let lower = identifier.to_lowercase();
    let grantee = st
        .db
        .call(move |c| {
            Ok(c.query_row(
                r#"SELECT "id" FROM "User" WHERE "isActive" = 1 AND ("email" = ?1 OR "username" = ?2 OR "name" = ?2) LIMIT 1"#,
                [&lower, &identifier],
                |r| r.get::<_, String>(0),
            )
            .optional()?)
        })
        .await?;
    let Some(grantee) = grantee else { return Err(err_only(404, "User not found")) };
    if grantee == user.id {
        return Err(err_only(400, "Cannot share with yourself"));
    }
    let (id2, me) = (id.clone(), user.id.clone());
    let share = st
        .db
        .call(move |c| {
            let now = crate::util::now_ms();
            c.execute(
                r#"INSERT INTO "CollectionShare" ("id","collectionId","granteeUserId","role","createdByUserId","createdAt","updatedAt")
                   VALUES (?1,?2,?3,?4,?5,?6,?6)
                   ON CONFLICT("collectionId","granteeUserId") DO UPDATE SET "role" = excluded."role", "updatedAt" = excluded."updatedAt""#,
                crate::sql::params![crate::util::uuid_v4(), id2, grantee, role, me, now],
            )?;
            Ok(c.query_row(
                &format!(r#"{SHARE_SELECT} WHERE s."collectionId" = ?1 AND s."granteeUserId" = ?2"#),
                [&id2, &grantee],
                share_json,
            )?)
        })
        .await?;
    st.drawings_cache.invalidate(None);
    ok(json!({ "share": share }))
}

/// PATCH /collections/:id/shares/:userId
pub async fn update_share(
    State(st): State<AppState>,
    ctx: Ctx,
    Path((id, grantee)): Path<(String, String)>,
    body: Body,
) -> ApiResult {
    let user = crate::auth::require_auth(&st.db, &ctx).await?;
    let Some(role) = is_role(body_field(&body, "role")?) else {
        return Err(err_only(400, "role must be view or edit"));
    };
    require_owned(&st, &id, &user.id).await?;
    let n = st
        .db
        .call(move |c| {
            Ok(c.execute(
                r#"UPDATE "CollectionShare" SET "role" = ?1, "updatedAt" = ?2 WHERE "collectionId" = ?3 AND "granteeUserId" = ?4"#,
                crate::sql::params![role, crate::util::now_ms(), id, grantee],
            )?)
        })
        .await?;
    if n == 0 {
        return Err(err_only(404, "Share not found"));
    }
    st.drawings_cache.invalidate(None);
    ok(json!({ "success": true }))
}

/// DELETE /collections/:id/shares/:userId
pub async fn delete_share(State(st): State<AppState>, ctx: Ctx, Path((id, grantee)): Path<(String, String)>) -> ApiResult {
    let user = crate::auth::require_auth(&st.db, &ctx).await?;
    require_owned(&st, &id, &user.id).await?;
    st.db
        .call(move |c| {
            c.execute(r#"DELETE FROM "CollectionShare" WHERE "collectionId" = ?1 AND "granteeUserId" = ?2"#, [&id, &grantee])?;
            Ok(())
        })
        .await?;
    st.drawings_cache.invalidate(None);
    ok(json!({ "success": true }))
}

/// GET /collections/:id/share-resolve
pub async fn share_resolve(State(st): State<AppState>, ctx: Ctx, Path(id): Path<String>) -> ApiResult {
    let user = crate::auth::require_auth(&st.db, &ctx).await?;
    let qv = query(&ctx);
    let raw = qv.get("q");
    let q = if truthy(raw) { js_trim(&js_string(raw.unwrap())).to_string() } else { String::new() };
    if crate::util::js_len(&q) < 2 {
        return ok(json!({ "users": [] }));
    }
    require_owned(&st, &id, &user.id).await?;
    let uid = user.id.clone();
    let users = st
        .db
        .call(move |c| {
            let mut exclude: Vec<String> = vec![uid];
            let mut s = c.prepare(r#"SELECT "granteeUserId" FROM "CollectionShare" WHERE "collectionId" = ?1"#)?;
            for r in s.query_map([&id], |r| r.get::<_, String>(0))? {
                exclude.push(r?);
            }
            let like = format!("%{q}%");
            let n = exclude.len();
            let sql = format!(
                r#"SELECT "id","name","email" FROM "User" WHERE "isActive" = 1 AND "id" NOT IN ({})
                   AND ("email" LIKE ?{p} OR "name" LIKE ?{p} OR "username" LIKE ?{p}) LIMIT 8"#,
                super::placeholders(1, n),
                p = n + 1
            );
            let mut params: Vec<String> = exclude;
            params.push(like);
            let mut s = c.prepare(&sql)?;
            let rows: Vec<Value> = s
                .query_map(crate::sql::params_from_iter(params.iter()), |r| {
                    Ok(json!({"id": r.get::<_, String>(0)?, "name": r.get::<_, String>(1)?, "email": r.get::<_, String>(2)?}))
                })?
                .collect::<Result<_, _>>()?;
            Ok(rows)
        })
        .await?;
    ok(json!({ "users": users }))
}
