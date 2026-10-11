//! utils/audit.ts — best-effort security audit log (ENABLE_AUDIT_LOGGING).
use serde_json::{json, Map, Value};

use crate::config::config;
use crate::db::Db;

#[derive(Default)]
pub struct AuditEvent {
    pub user_id: Option<String>,
    pub action: String,
    pub resource: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub details: Option<Map<String, Value>>,
}

pub async fn log_audit_event(db: &Db, ev: AuditEvent) {
    if !config().enable_audit_logging {
        return;
    }
    let r = db
        .call(move |c| {
            c.execute(
                r#"INSERT INTO "AuditLog" ("id","userId","action","resource","ipAddress","userAgent","details","createdAt") VALUES (?1,?2,?3,?4,?5,?6,?7,?8)"#,
                crate::sql::params![
                    crate::util::uuid_v4(),
                    ev.user_id.filter(|s| !s.is_empty()),
                    ev.action,
                    ev.resource.filter(|s| !s.is_empty()),
                    ev.ip_address.filter(|s| !s.is_empty()),
                    ev.user_agent.filter(|s| !s.is_empty()),
                    ev.details.map(|d| Value::Object(d).to_string()),
                    crate::util::now_ms(),
                ],
            )?;
            Ok(())
        })
        .await;
    if let Err(e) = r {
        if config().is_dev {
            eprintln!("Audit logging skipped (feature disabled or table missing): {e}");
        }
    }
}

/// getAuditLogs(userId?, limit)
pub async fn get_audit_logs(db: &Db, user_id: Option<String>, limit: i64) -> Vec<Value> {
    if !config().enable_audit_logging {
        return vec![];
    }
    let r = db
        .call(move |c| {
            let sql = format!(
                r#"SELECT a."id",a."userId",a."action",a."resource",a."ipAddress",a."userAgent",a."details",a."createdAt",u."id",u."email",u."name"
                   FROM "AuditLog" a LEFT JOIN "User" u ON u."id" = a."userId" {} ORDER BY a."createdAt" DESC LIMIT ?1"#,
                if user_id.is_some() { r#"WHERE a."userId" = ?2"# } else { "" }
            );
            let mut st = c.prepare(&sql)?;
            let map = |r: &crate::sql::Row<'_>| -> crate::sql::Result<Value> {
                let details: Option<String> = r.get(6)?;
                let user_id: Option<String> = r.get(8)?;
                Ok(json!({
                    "id": r.get::<_, String>(0)?,
                    "userId": r.get::<_, Option<String>>(1)?,
                    "action": r.get::<_, String>(2)?,
                    "resource": r.get::<_, Option<String>>(3)?,
                    "ipAddress": r.get::<_, Option<String>>(4)?,
                    "userAgent": r.get::<_, Option<String>>(5)?,
                    "details": details.and_then(|d| serde_json::from_str::<Value>(&d).ok()),
                    "createdAt": crate::db::iso(r, 7)?,
                    "user": match user_id {
                        Some(id) => json!({"id": id, "email": r.get::<_, String>(9)?, "name": r.get::<_, String>(10)?}),
                        None => Value::Null,
                    },
                }))
            };
            let rows: Vec<Value> = match &user_id {
                Some(uid) => st.query_map(crate::sql::params![limit, uid], map)?.collect::<Result<_, _>>()?,
                None => st.query_map(crate::sql::params![limit], map)?.collect::<Result<_, _>>()?,
            };
            Ok(rows)
        })
        .await;
    r.unwrap_or_default()
}
