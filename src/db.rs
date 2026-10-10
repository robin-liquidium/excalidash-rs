//! SQLite access with Prisma-compatible conventions.
//!
//! Prisma (5.x, SQLite) stores `DateTime` as INTEGER unix milliseconds when it
//! writes a value, while `DEFAULT CURRENT_TIMESTAMP` columns hold TEXT
//! (`YYYY-MM-DD HH:MM:SS`). Booleans are INTEGER 0/1. We read both date forms
//! and always write integer ms, exactly like Prisma.
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{types::ValueRef, Connection, OptionalExtension, Row};
use std::{path::Path, time::Duration};

include!(concat!(env!("OUT_DIR"), "/migrations.rs"));

pub type Conn = r2d2::PooledConnection<SqliteConnectionManager>;

#[derive(Clone)]
pub struct Db {
    pool: Pool<SqliteConnectionManager>,
}

#[derive(Debug)]
pub enum DbError {
    Sqlite(rusqlite::Error),
    Pool(String),
    Join(String),
}

impl std::fmt::Display for DbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DbError::Sqlite(e) => write!(f, "{e}"),
            DbError::Pool(e) => write!(f, "connection pool: {e}"),
            DbError::Join(e) => write!(f, "task: {e}"),
        }
    }
}
impl std::error::Error for DbError {}
impl From<rusqlite::Error> for DbError {
    fn from(e: rusqlite::Error) -> Self {
        DbError::Sqlite(e)
    }
}

impl DbError {
    /// True for UNIQUE constraint violations (Prisma P2002).
    pub fn is_unique_violation(&self) -> bool {
        matches!(self, DbError::Sqlite(rusqlite::Error::SqliteFailure(e, _))
            if e.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE
                || e.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_PRIMARYKEY)
    }
}

fn init_connection(c: &mut Connection) -> rusqlite::Result<()> {
    c.busy_timeout(Duration::from_millis(10_000))?;
    // Prisma's SQLite connector runs with foreign keys enforced (cascades are in the DDL).
    c.execute_batch("PRAGMA foreign_keys = ON; PRAGMA synchronous = NORMAL; PRAGMA cache_size = -1024;")?;
    Ok(())
}

impl Db {
    pub fn open(path: &Path) -> Result<Db, DbError> {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let manager = SqliteConnectionManager::file(path).with_init(init_connection);
        let pool = Pool::builder()
            .max_size(4)
            .min_idle(Some(1))
            .idle_timeout(Some(Duration::from_secs(60)))
            .connection_timeout(Duration::from_secs(15))
            .build(manager)
            .map_err(|e| DbError::Pool(e.to_string()))?;
        Ok(Db { pool })
    }

    pub fn get(&self) -> Result<Conn, DbError> {
        self.pool.get().map_err(|e| DbError::Pool(e.to_string()))
    }

    /// Run blocking DB work off the async runtime.
    pub async fn call<F, R>(&self, f: F) -> Result<R, DbError>
    where
        F: FnOnce(&mut Connection) -> Result<R, DbError> + Send + 'static,
        R: Send + 'static,
    {
        let pool = self.pool.clone();
        tokio::task::spawn_blocking(move || {
            let mut conn = pool.get().map_err(|e| DbError::Pool(e.to_string()))?;
            f(&mut conn)
        })
        .await
        .map_err(|e| DbError::Join(e.to_string()))?
    }

    /// Like [`Db::call`] but wraps the closure in an IMMEDIATE transaction.
    pub async fn tx<F, R>(&self, f: F) -> Result<R, DbError>
    where
        F: FnOnce(&rusqlite::Transaction<'_>) -> Result<R, DbError> + Send + 'static,
        R: Send + 'static,
    {
        self.call(move |c| {
            let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let out = f(&tx)?;
            tx.commit()?;
            Ok(out)
        })
        .await
    }
}

/// Mirror `configureSqlite()`: WAL journal + busy timeout.
pub fn configure_sqlite(c: &Connection) {
    let r = (|| -> rusqlite::Result<()> {
        c.busy_timeout(Duration::from_millis(10_000))?;
        let _: String = c.query_row("PRAGMA journal_mode = WAL;", [], |r| r.get(0))?;
        c.execute_batch("PRAGMA synchronous = NORMAL;")?;
        Ok(())
    })();
    if let Err(e) = r {
        eprintln!("[prisma] Failed to configure SQLite PRAGMAs: {e}");
    }
}

const PRISMA_MIGRATIONS_DDL: &str = r#"CREATE TABLE IF NOT EXISTS "_prisma_migrations" (
    "id"                    TEXT PRIMARY KEY NOT NULL,
    "checksum"              TEXT NOT NULL,
    "finished_at"           DATETIME,
    "migration_name"        TEXT NOT NULL,
    "logs"                  TEXT,
    "rolled_back_at"        DATETIME,
    "started_at"            DATETIME NOT NULL DEFAULT current_timestamp,
    "applied_steps_count"   INTEGER UNSIGNED NOT NULL DEFAULT 0
);"#;

/// `prisma migrate deploy` equivalent: applies pending embedded migrations and
/// records them in `_prisma_migrations` with Prisma's checksum (sha256 of the file).
pub fn migrate_deploy(c: &mut Connection) -> Result<usize, String> {
    c.execute_batch(PRISMA_MIGRATIONS_DDL).map_err(|e| e.to_string())?;
    // Fail like Prisma (P3009) when a previous migration attempt failed.
    let failed: Option<String> = c
        .query_row(
            r#"SELECT migration_name FROM "_prisma_migrations" WHERE finished_at IS NULL AND rolled_back_at IS NULL LIMIT 1"#,
            [],
            |r| r.get(0),
        )
        .optional()
        .map_err(|e| e.to_string())?;
    if let Some(name) = failed {
        return Err(format!(
            "migrate found failed migrations in the target database, new migrations will not be applied. The `{name}` migration started at an earlier time failed"
        ));
    }
    let mut applied: std::collections::HashSet<String> = std::collections::HashSet::new();
    {
        let mut st = c
            .prepare(r#"SELECT migration_name FROM "_prisma_migrations" WHERE rolled_back_at IS NULL AND finished_at IS NOT NULL"#)
            .map_err(|e| e.to_string())?;
        let rows = st.query_map([], |r| r.get::<_, String>(0)).map_err(|e| e.to_string())?;
        for r in rows {
            applied.insert(r.map_err(|e| e.to_string())?);
        }
    }
    let pending: Vec<&(&str, &str)> = MIGRATIONS.iter().filter(|(n, _)| !applied.contains(*n)).collect();
    if pending.is_empty() {
        println!("No pending migrations to apply.");
        return Ok(0);
    }
    println!("{} migrations found in prisma/migrations", MIGRATIONS.len());
    println!("Applying migration{}", if pending.len() == 1 { "" } else { "s" });
    for (name, sql) in &pending {
        let id = crate::util::uuid_v4();
        let checksum = crate::util::sha256_hex(sql.as_bytes());
        let started = crate::util::now_ms();
        c.execute(
            r#"INSERT INTO "_prisma_migrations" (id, checksum, started_at, finished_at, migration_name, logs, rolled_back_at, applied_steps_count) VALUES (?1, ?2, ?3, NULL, ?4, NULL, NULL, 0)"#,
            rusqlite::params![id, checksum, started, name],
        )
        .map_err(|e| e.to_string())?;
        if let Err(e) = c.execute_batch(sql) {
            let _ = c.execute(
                r#"UPDATE "_prisma_migrations" SET logs = ?1 WHERE id = ?2"#,
                rusqlite::params![e.to_string(), id],
            );
            return Err(format!("Migration `{name}` failed: {e}"));
        }
        c.execute(
            r#"UPDATE "_prisma_migrations" SET finished_at = ?1, applied_steps_count = 1 WHERE id = ?2"#,
            rusqlite::params![crate::util::now_ms(), id],
        )
        .map_err(|e| e.to_string())?;
        println!("  - {name}");
    }
    println!("All migrations have been successfully applied.");
    Ok(pending.len())
}

// ---------------------------------------------------------------------------
// Row helpers

/// Read a Prisma DateTime column (INTEGER ms or TEXT) as unix ms.
pub fn dt(row: &Row<'_>, idx: impl rusqlite::RowIndex) -> rusqlite::Result<i64> {
    Ok(opt_dt(row, idx)?.unwrap_or(0))
}

pub fn opt_dt(row: &Row<'_>, idx: impl rusqlite::RowIndex) -> rusqlite::Result<Option<i64>> {
    Ok(match row.get_ref(idx)? {
        ValueRef::Null => None,
        ValueRef::Integer(i) => Some(i),
        ValueRef::Real(f) => Some(f as i64),
        ValueRef::Text(t) => crate::util::parse_date_ms(std::str::from_utf8(t).unwrap_or("")),
        ValueRef::Blob(_) => None,
    })
}

pub fn boolean(row: &Row<'_>, idx: impl rusqlite::RowIndex) -> rusqlite::Result<bool> {
    Ok(opt_bool(row, idx)?.unwrap_or(false))
}

pub fn opt_bool(row: &Row<'_>, idx: impl rusqlite::RowIndex) -> rusqlite::Result<Option<bool>> {
    Ok(match row.get_ref(idx)? {
        ValueRef::Null => None,
        ValueRef::Integer(i) => Some(i != 0),
        ValueRef::Real(f) => Some(f != 0.0),
        ValueRef::Text(t) => Some(matches!(t, b"true" | b"1")),
        ValueRef::Blob(_) => None,
    })
}

/// ISO string for a DateTime column (`null` when NULL).
pub fn iso(row: &Row<'_>, idx: impl rusqlite::RowIndex) -> rusqlite::Result<serde_json::Value> {
    Ok(match opt_dt(row, idx)? {
        Some(ms) => serde_json::Value::String(crate::util::iso_from_ms(ms)),
        None => serde_json::Value::Null,
    })
}

/// SQL fragment that compares a Prisma DateTime column against an integer-ms
/// parameter the same way Prisma does (raw `col < ?`). Kept as a helper so call
/// sites document the intent.
pub const fn dt_col(col: &'static str) -> &'static str {
    col
}

pub fn exists(c: &Connection, sql: &str, params: impl rusqlite::Params) -> rusqlite::Result<bool> {
    Ok(c.query_row(sql, params, |_| Ok(())).optional()?.is_some())
}
