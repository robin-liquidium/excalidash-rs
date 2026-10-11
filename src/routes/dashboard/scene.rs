//! routes/dashboard/sceneUpdate.ts (applySceneUpdateTx) and
//! routes/storage/retainedFiles.ts (collectRetainedDrawingFileIds).
use crate::sql::{types::ToSql, Connection, TransactionBehavior};
use serde_json::{Map, Value};
use std::collections::HashSet;

use super::{parse_json_field, DrawingRow};
use crate::db::DbError;
use crate::state::AppState;

/// Prisma update fields (without `version`, which is owned by the scene update).
#[derive(Debug, Clone, Default)]
pub struct UpdateData {
    pub name: Option<String>,
    pub elements: Option<String>,
    pub app_state: Option<String>,
    pub files: Option<String>,
    pub preview: Option<Option<String>>,
    pub collection_id: Option<Option<String>>,
}

impl UpdateData {
    pub fn is_empty(&self) -> bool {
        self.name.is_none()
            && self.elements.is_none()
            && self.app_state.is_none()
            && self.files.is_none()
            && self.preview.is_none()
            && self.collection_id.is_none()
    }

    /// `"col" = ?N` fragments (params appended to `params`).
    pub fn sets(&self, params: &mut Vec<Box<dyn ToSql>>) -> Vec<String> {
        let mut sets = vec![];
        let mut push = |col: &str, v: Box<dyn ToSql>, params: &mut Vec<Box<dyn ToSql>>| {
            params.push(v);
            sets.push(format!(r#""{col}" = ?{}"#, params.len()));
        };
        if let Some(v) = &self.name {
            push("name", Box::new(v.clone()), params);
        }
        if let Some(v) = &self.elements {
            push("elements", Box::new(v.clone()), params);
        }
        if let Some(v) = &self.app_state {
            push("appState", Box::new(v.clone()), params);
        }
        if let Some(v) = &self.files {
            push("files", Box::new(v.clone()), params);
        }
        if let Some(v) = &self.preview {
            push("preview", Box::new(v.clone()), params);
        }
        if let Some(v) = &self.collection_id {
            push("collectionId", Box::new(v.clone()), params);
        }
        sets
    }
}

#[derive(Debug, Clone, Copy)]
pub enum VersionGuard {
    Exact(i64),
    Optimistic,
}

#[derive(Debug, Clone, Default)]
pub struct SceneMutation {
    pub data: UpdateData,
    /// Already-processed files to union-merge; `None` leaves files untouched.
    pub incoming_files: Option<Map<String, Value>>,
    pub required_file_ids: Vec<String>,
}

#[derive(Debug)]
pub enum SceneError {
    /// VERSION_CONFLICT
    Conflict,
    Db(DbError),
}

impl From<DbError> for SceneError {
    fn from(e: DbError) -> Self {
        SceneError::Db(e)
    }
}

fn is_blank_file_entry(entry: Option<&Value>) -> bool {
    match entry {
        Some(Value::Object(o)) => !matches!(o.get("dataURL"), Some(Value::String(s)) if !s.is_empty()),
        _ => true,
    }
}

/// mergeFilesUnion(existing, incoming)
pub fn merge_files_union(existing: &Map<String, Value>, incoming: &Map<String, Value>) -> Map<String, Value> {
    let mut merged = existing.clone();
    for (id, entry) in incoming {
        if is_blank_file_entry(Some(entry)) && merged.contains_key(id) && !is_blank_file_entry(merged.get(id)) {
            continue;
        }
        merged.insert(id.clone(), entry.clone());
    }
    merged
}

fn attempt(c: &mut Connection, drawing_id: &str, guard: VersionGuard, m: &SceneMutation) -> Result<Option<DrawingRow>, DbError> {
    let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let Some(current) = DrawingRow::find(&tx, drawing_id)? else { return Ok(None) };
    if let VersionGuard::Exact(v) = guard {
        if current.version != v {
            return Ok(None);
        }
    }
    if !m.required_file_ids.is_empty() {
        let ids: Vec<String> = m.required_file_ids.iter().cloned().collect::<HashSet<_>>().into_iter().collect();
        let sql = format!(
            r#"SELECT COUNT(*) FROM "DrawingFile" WHERE "drawingId" = ?1 AND "fileId" IN ({})"#,
            super::placeholders(2, ids.len())
        );
        let mut params: Vec<&dyn ToSql> = vec![&drawing_id];
        for id in &ids {
            params.push(id);
        }
        let n: i64 = tx.query_row(&sql, params.as_slice(), |r| r.get(0))?;
        if n as usize != ids.len() {
            return Ok(None);
        }
    }
    let now = crate::util::now_ms();
    tx.execute(
        r#"INSERT INTO "DrawingSnapshot" ("id","drawingId","version","elements","appState","files","createdAt") VALUES (?1,?2,?3,?4,?5,?6,?7)"#,
        crate::sql::params![
            crate::util::uuid_v4(),
            drawing_id,
            current.version,
            crate::snapshots::encode_field(&current.elements, true),
            crate::snapshots::encode_field(&current.app_state, true),
            crate::snapshots::encode_field(&current.files, true),
            now,
        ],
    )?;
    let mut data = m.data.clone();
    if let Some(incoming) = &m.incoming_files {
        let existing = match parse_json_field(Some(&current.files), Value::Object(Map::new())) {
            Value::Object(o) => o,
            _ => Map::new(),
        };
        data.files = Some(Value::Object(merge_files_union(&existing, incoming)).to_string());
    }
    let mut params: Vec<Box<dyn ToSql>> = vec![];
    let mut sets = data.sets(&mut params);
    sets.push(r#""version" = "version" + 1"#.into());
    params.push(Box::new(now));
    sets.push(format!(r#""updatedAt" = ?{}"#, params.len()));
    params.push(Box::new(drawing_id.to_string()));
    let id_idx = params.len();
    let expected = match guard {
        VersionGuard::Exact(v) => v,
        VersionGuard::Optimistic => current.version,
    };
    params.push(Box::new(expected));
    let sql = format!(
        r#"UPDATE "Drawing" SET {} WHERE "id" = ?{} AND "version" = ?{}"#,
        sets.join(", "),
        id_idx,
        params.len()
    );
    let refs: Vec<&dyn ToSql> = params.iter().map(|b| b.as_ref()).collect();
    if tx.execute(&sql, refs.as_slice())? == 0 {
        return Ok(None);
    }
    let Some(updated) = DrawingRow::find(&tx, drawing_id)? else { return Ok(None) };
    tx.commit()?;
    Ok(Some(updated))
}

/// applySceneUpdateTx: snapshot the current scene and apply the mutation under a version guard.
pub async fn apply_scene_update(
    st: &AppState,
    drawing_id: &str,
    guard: VersionGuard,
    max_retries: u32,
    mutation: SceneMutation,
) -> Result<DrawingRow, SceneError> {
    let attempts = match guard {
        VersionGuard::Optimistic => max_retries + 1,
        VersionGuard::Exact(_) => 1,
    };
    for _ in 0..attempts {
        let id = drawing_id.to_string();
        let m = mutation.clone();
        if let Some(row) = st.db.call(move |c| attempt(c, &id, guard, &m)).await? {
            return Ok(row);
        }
    }
    Err(SceneError::Conflict)
}

/// collectRetainedDrawingFileIds: file ids referenced by the live scene or any snapshot.
/// `None` when any scene is unreadable.
pub fn collect_retained_drawing_file_ids(c: &Connection, drawing_id: &str) -> crate::sql::Result<Option<HashSet<String>>> {
    let mut scenes: Vec<(String, String)> = vec![];
    if let Some(cur) = c
        .query_row(r#"SELECT "elements","files" FROM "Drawing" WHERE "id" = ?1"#, [drawing_id], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })
        .ok()
    {
        scenes.push(cur);
    }
    let mut st = c.prepare(r#"SELECT "elements","files" FROM "DrawingSnapshot" WHERE "drawingId" = ?1"#)?;
    for row in st.query_map([drawing_id], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))? {
        scenes.push(row?);
    }
    let mut retained = HashSet::new();
    for (elements, files) in scenes {
        let (Ok(e), Ok(f)) = (crate::snapshots::decode_field(&elements), crate::snapshots::decode_field(&files)) else {
            return Ok(None);
        };
        let (Ok(Value::Array(e)), Ok(Value::Object(f))) = (serde_json::from_str::<Value>(&e), serde_json::from_str::<Value>(&f))
        else {
            return Ok(None);
        };
        retained.extend(f.keys().cloned());
        for el in e {
            if let Some(Value::String(fid)) = el.get("fileId") {
                retained.insert(fid.clone());
            }
        }
    }
    Ok(Some(retained))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn obj(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    fn retained_db(files: &str) -> Connection {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(
            r#"CREATE TABLE "Drawing" ("id" TEXT, "elements" TEXT, "files" TEXT);
               CREATE TABLE "DrawingSnapshot" ("drawingId" TEXT, "elements" TEXT, "files" TEXT);
               INSERT INTO "Drawing" VALUES ('d', '[{"fileId":"live-el"}]', '{"live":{}}');"#,
        )
        .unwrap();
        c.execute(r#"INSERT INTO "DrawingSnapshot" VALUES ('d', '[]', ?1)"#, [files]).unwrap();
        c
    }

    /// file-retention: "keeps all bytes when snapshot files cannot establish references"
    #[test]
    fn retained_ids_are_unknown_when_history_is_unreadable() {
        for files in ["br1:broken", "not-json", "[]"] {
            assert!(collect_retained_drawing_file_ids(&retained_db(files), "d").unwrap().is_none(), "{files}");
        }
        let hist = crate::snapshots::encode_field(&format!(r#"{{"hist":{{"description":"{}"}}}}"#, "x".repeat(1000)), true);
        let ids = collect_retained_drawing_file_ids(&retained_db(&hist), "d").unwrap().unwrap();
        let mut ids: Vec<String> = ids.into_iter().collect();
        ids.sort();
        assert_eq!(ids, ["hist", "live", "live-el"]);
    }

    #[test]
    fn union_merge_keeps_existing_and_ignores_blank_overwrites() {
        let existing = obj(json!({"a": {"dataURL": "data:a"}, "b": {"dataURL": "data:b"}}));
        let incoming = obj(json!({"b": {"dataURL": ""}, "c": {"dataURL": "data:c"}, "a": {"dataURL": "data:a2"}}));
        let merged = merge_files_union(&existing, &incoming);
        assert_eq!(
            Value::Object(merged),
            json!({"a": {"dataURL": "data:a2"}, "b": {"dataURL": "data:b"}, "c": {"dataURL": "data:c"}})
        );
        // Blank incoming entry for a blank/missing existing entry is stored.
        let merged = merge_files_union(&obj(json!({"x": {}})), &obj(json!({"x": {"dataURL": ""}, "y": null})));
        assert_eq!(Value::Object(merged), json!({"x": {"dataURL": ""}, "y": null}));
    }
}
