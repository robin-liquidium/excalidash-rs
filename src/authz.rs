//! authz/sharing.ts — drawing access resolution (owner / ACL / collection / link policy).
use crate::sql::{Connection, OptionalExtension};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    None,
    View,
    Edit,
    Owner,
}

impl Access {
    pub fn as_str(self) -> &'static str {
        match self {
            Access::None => "none",
            Access::View => "view",
            Access::Edit => "edit",
            Access::Owner => "owner",
        }
    }
    fn rank(self) -> u8 {
        match self {
            Access::Owner => 3,
            Access::Edit => 2,
            Access::View => 1,
            Access::None => 0,
        }
    }
    pub fn max(self, other: Access) -> Access {
        if self.rank() >= other.rank() { self } else { other }
    }
    pub fn can_view(self) -> bool {
        self != Access::None
    }
    pub fn can_edit(self) -> bool {
        matches!(self, Access::Edit | Access::Owner)
    }
    pub fn is_owner(self) -> bool {
        self == Access::Owner
    }
}

/// normalizeDrawingPermission
pub fn normalize_permission(input: Option<&str>) -> Option<Access> {
    match input {
        Some("view") => Some(Access::View),
        Some("edit") => Some(Access::Edit),
        _ => None,
    }
}

pub fn build_share_link_token() -> String {
    crate::util::b64url(&crate::util::random_bytes(24))
}

pub fn hash_share_link_token(token: &str) -> String {
    hash_token_for_storage(token)
}

/// auth/tokenSecurity.ts
pub fn hash_token_for_storage(token: &str) -> String {
    crate::util::sha256_hex(token.as_bytes())
}

pub fn token_lookup_candidates(token: &str) -> Vec<String> {
    let mut v = vec![token.to_string()];
    let h = hash_token_for_storage(token);
    if !v.contains(&h) {
        v.push(h);
    }
    v
}

/// getDrawingAccess. `principal` is the acting user id (None for anonymous).
pub fn get_drawing_access(
    c: &Connection,
    principal: Option<&str>,
    drawing_id: &str,
    now_ms: Option<i64>,
) -> crate::sql::Result<Access> {
    let now_ms = now_ms.unwrap_or_else(crate::util::now_ms);
    let mut base = Access::None;
    if let Some(user_id) = principal {
        let drawing: Option<(String, Option<String>)> = c
            .query_row(
                r#"SELECT "userId","collectionId" FROM "Drawing" WHERE "id" = ?1"#,
                [drawing_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let Some((owner, collection_id)) = drawing else { return Ok(Access::None) };
        if owner == user_id {
            return Ok(Access::Owner);
        }
        let perm: Option<String> = c
            .query_row(
                r#"SELECT "permission" FROM "DrawingPermission" WHERE "drawingId" = ?1 AND "granteeUserId" = ?2"#,
                [drawing_id, user_id],
                |r| r.get(0),
            )
            .optional()?;
        base = normalize_permission(perm.as_deref()).unwrap_or(base);
        if let Some(cid) = collection_id {
            let owned = crate::db::exists(
                c,
                r#"SELECT 1 FROM "Collection" WHERE "id" = ?1 AND "userId" = ?2"#,
                [&cid, user_id],
            )?;
            if owned {
                base = Access::Owner;
            } else {
                let role: Option<String> = c
                    .query_row(
                        r#"SELECT "role" FROM "CollectionShare" WHERE "collectionId" = ?1 AND "granteeUserId" = ?2 LIMIT 1"#,
                        [&cid, user_id],
                        |r| r.get(0),
                    )
                    .optional()?;
                base = base.max(normalize_permission(role.as_deref()).unwrap_or(Access::None));
            }
        }
    }
    let link = active_link_share_access(c, drawing_id, now_ms)?;
    Ok(base.max(link.unwrap_or(Access::None)))
}

fn active_link_share_access(c: &Connection, drawing_id: &str, now_ms: i64) -> crate::sql::Result<Option<Access>> {
    let perm: Option<String> = c
        .query_row(
            r#"SELECT "permission" FROM "DrawingLinkShare"
               WHERE "drawingId" = ?1 AND "revokedAt" IS NULL AND ("expiresAt" IS NULL OR "expiresAt" > ?2)
               ORDER BY "createdAt" DESC LIMIT 1"#,
            crate::sql::params![drawing_id, now_ms],
            |r| r.get(0),
        )
        .optional()?;
    Ok(normalize_permission(perm.as_deref()))
}
