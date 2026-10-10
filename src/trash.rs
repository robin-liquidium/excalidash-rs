//! Per-user trash collection ids (routes/dashboard/trash.ts, index.ts ensureTrashCollection).
use rusqlite::Connection;

pub fn user_trash_collection_id(user_id: &str) -> String {
    format!("trash:{user_id}")
}

pub fn is_trash_collection_id(collection_id: Option<&str>, user_id: &str) -> bool {
    match collection_id {
        Some(c) if !c.is_empty() => c == "trash" || c == user_trash_collection_id(user_id),
        _ => false,
    }
}

/// toInternalTrashCollectionId: "trash" → "trash:<userId>".
pub fn to_internal(collection_id: Option<&str>, user_id: &str) -> Option<String> {
    match collection_id {
        Some("trash") => Some(user_trash_collection_id(user_id)),
        other => other.map(str::to_string),
    }
}

/// toPublicTrashCollectionId: own trash ids → "trash".
pub fn to_public(collection_id: Option<&str>, user_id: &str) -> Option<String> {
    if is_trash_collection_id(collection_id, user_id) {
        Some("trash".into())
    } else {
        collection_id.map(str::to_string)
    }
}

/// index.ts ensureTrashCollection: create the per-user trash collection and
/// migrate legacy `collectionId = 'trash'` drawings into it.
pub fn ensure_trash_collection(c: &Connection, user_id: &str) -> rusqlite::Result<()> {
    let trash_id = user_trash_collection_id(user_id);
    let exists = crate::db::exists(
        c,
        r#"SELECT 1 FROM "Collection" WHERE "id" = ?1 AND "userId" = ?2"#,
        [&trash_id, user_id],
    )?;
    let now = crate::util::now_ms();
    if !exists {
        c.execute(
            r#"INSERT INTO "Collection" ("id","name","userId","createdAt","updatedAt") VALUES (?1,'Trash',?2,?3,?3)"#,
            rusqlite::params![trash_id, user_id, now],
        )?;
    }
    c.execute(
        r#"UPDATE "Drawing" SET "collectionId" = ?1, "updatedAt" = ?2 WHERE "userId" = ?3 AND "collectionId" = 'trash'"#,
        rusqlite::params![trash_id, now, user_id],
    )?;
    Ok(())
}
