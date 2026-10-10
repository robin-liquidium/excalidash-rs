//! db/sqliteMaintenance.ts — incremental auto-vacuum + free-space reclaim.
use futures_util::future::{BoxFuture, FutureExt, Shared};
use rusqlite::Connection;
use std::path::Path;
use std::sync::Mutex;
use std::time::Instant;

use crate::state::AppState;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SqliteSpaceMetrics {
    pub page_count: i64,
    pub free_page_count: i64,
    pub page_size: i64,
    pub file_bytes: i64,
    pub free_bytes: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReclaimMode {
    Incremental,
    Full,
}

impl ReclaimMode {
    fn as_str(self) -> &'static str {
        match self {
            ReclaimMode::Incremental => "incremental",
            ReclaimMode::Full => "full",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SqliteReclaimResult {
    pub mode: ReclaimMode,
    pub before: SqliteSpaceMetrics,
    pub after: SqliteSpaceMetrics,
    pub reclaimed_bytes: i64,
    pub duration_ms: i64,
}

const AUTO_VACUUM_NONE: i64 = 0;
const AUTO_VACUUM_INCREMENTAL: i64 = 2;
const AUTO_VACUUM_CONVERT_BELOW_BYTES: i64 = 8 * 1024 * 1024;
const FULL_VACUUM_MIN_FREE_BYTES: i64 = 64 * 1024 * 1024;
const FULL_VACUUM_MIN_FREE_RATIO: f64 = 0.3;
const FULL_VACUUM_ALWAYS_ABOVE_BYTES: i64 = 1024 * 1024 * 1024;
const INCREMENTAL_MIN_FREE_BYTES: i64 = 8 * 1024 * 1024;
const INCREMENTAL_PAGE_BUDGET: i64 = 20_000;

fn pragma_number(c: &Connection, name: &str) -> rusqlite::Result<i64> {
    c.query_row(&format!("PRAGMA {name}"), [], |r| r.get::<_, Option<i64>>(0)).map(|v| v.unwrap_or(0))
}

pub fn read_metrics(c: &Connection) -> rusqlite::Result<SqliteSpaceMetrics> {
    let page_count = pragma_number(c, "page_count")?;
    let free_page_count = pragma_number(c, "freelist_count")?;
    let page_size = pragma_number(c, "page_size")?;
    Ok(SqliteSpaceMetrics {
        page_count,
        free_page_count,
        page_size,
        file_bytes: page_count * page_size,
        free_bytes: free_page_count * page_size,
    })
}

/// Free bytes available to unprivileged users on the filesystem holding `dir`.
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
fn available_bytes(dir: &Path) -> Result<u64, String> {
    use std::os::unix::ffi::OsStrExt;
    unsafe extern "C" {
        fn statvfs(path: *const std::ffi::c_char, buf: *mut u64) -> i32;
    }
    let c = std::ffi::CString::new(dir.as_os_str().as_bytes()).map_err(|e| e.to_string())?;
    // struct statvfs on 64-bit Linux (glibc and musl): f_bsize, f_frsize, f_blocks,
    // f_bfree, f_bavail, ... — all 64-bit; the buffer is oversized for safety.
    let mut buf = [0u64; 32];
    let rc = unsafe { statvfs(c.as_ptr(), buf.as_mut_ptr()) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(buf[4].saturating_mul(buf[0]))
}

#[cfg(not(all(target_os = "linux", target_pointer_width = "64")))]
fn available_bytes(_dir: &Path) -> Result<u64, String> {
    Err("statfs is not supported on this platform".into())
}

fn has_rewrite_headroom(database_path: &Path, file_bytes: i64) -> bool {
    let dir = database_path.parent().unwrap_or(Path::new("."));
    match available_bytes(dir) {
        Ok(avail) => {
            let needed = file_bytes as f64 * 2.0;
            if avail as f64 >= needed {
                return true;
            }
            eprintln!(
                "[Cleanup] Skipping SQLite VACUUM: needs about {} MB free, but {} MB is available",
                (needed / 1024.0 / 1024.0).ceil(),
                (avail as f64 / 1024.0 / 1024.0).floor()
            );
            false
        }
        Err(e) => {
            eprintln!("[Cleanup] Skipping SQLite VACUUM because disk headroom could not be read {e}");
            false
        }
    }
}

/// enableIncrementalAutoVacuum: convert small databases while the one-time
/// rewrite is cheap. Larger legacy databases convert on the first eligible reclaim.
pub fn enable_incremental_auto_vacuum_on(c: &Connection) -> rusqlite::Result<bool> {
    if pragma_number(c, "auto_vacuum")? != AUTO_VACUUM_NONE {
        return Ok(false);
    }
    let m = read_metrics(c)?;
    if m.page_size == 0 || m.file_bytes > AUTO_VACUUM_CONVERT_BELOW_BYTES {
        return Ok(false);
    }
    c.execute_batch("PRAGMA auto_vacuum = INCREMENTAL; VACUUM;")?;
    println!("[prisma] SQLite switched to incremental auto-vacuum");
    Ok(true)
}

/// The reclaim heuristics (`reclaim` in sqliteMaintenance.ts).
pub fn reclaim_on(c: &Connection, database_path: Option<&Path>) -> rusqlite::Result<Option<SqliteReclaimResult>> {
    let before = read_metrics(c)?;
    if before.page_count == 0 || before.page_size == 0 {
        return Ok(None);
    }
    let auto_vacuum = pragma_number(c, "auto_vacuum")?;
    let started = Instant::now();
    let mode = if auto_vacuum == AUTO_VACUUM_INCREMENTAL {
        if before.free_bytes < INCREMENTAL_MIN_FREE_BYTES {
            return Ok(None);
        }
        let pages = before.free_page_count.min(INCREMENTAL_PAGE_BUDGET);
        c.execute_batch(&format!("PRAGMA incremental_vacuum({pages})"))?;
        ReclaimMode::Incremental
    } else {
        let ratio = before.free_page_count as f64 / before.page_count as f64;
        let worth = before.free_bytes >= FULL_VACUUM_ALWAYS_ABOVE_BYTES
            || (before.free_bytes >= FULL_VACUUM_MIN_FREE_BYTES && ratio >= FULL_VACUUM_MIN_FREE_RATIO);
        if !worth {
            return Ok(None);
        }
        let Some(path) = database_path else { return Ok(None) };
        if !has_rewrite_headroom(path, before.file_bytes) {
            return Ok(None);
        }
        c.execute_batch("PRAGMA auto_vacuum = INCREMENTAL; VACUUM;")?;
        ReclaimMode::Full
    };
    let after = read_metrics(c)?;
    let reclaimed_bytes = (before.file_bytes - after.file_bytes).max(0);
    let duration_ms = started.elapsed().as_millis() as i64;
    println!(
        "[Cleanup] SQLite {} vacuum returned {:.1} MB (pages {} -> {}, free {} -> {}) in {} ms",
        mode.as_str(),
        reclaimed_bytes as f64 / 1024.0 / 1024.0,
        before.page_count,
        after.page_count,
        before.free_page_count,
        after.free_page_count,
        duration_ms
    );
    Ok(Some(SqliteReclaimResult { mode, before, after, reclaimed_bytes, duration_ms }))
}

type Active = Shared<BoxFuture<'static, Option<SqliteReclaimResult>>>;

static ACTIVE: Mutex<Option<Active>> = Mutex::new(None);

/// Single-flight wrapper: while a run is in flight every caller gets it.
fn single_flight<F>(work: F) -> Active
where
    F: std::future::Future<Output = Option<SqliteReclaimResult>> + Send + 'static,
{
    let mut guard = ACTIVE.lock().unwrap();
    if let Some(active) = guard.as_ref() {
        return active.clone();
    }
    // The task clears ACTIVE when done; it needs the lock we hold, so it
    // cannot finish before the shared handle is stored.
    let handle = tokio::spawn(async move {
        let r = work.await;
        *ACTIVE.lock().unwrap() = None;
        r
    });
    let shared = async move { handle.await.ok().flatten() }.boxed().shared();
    *guard = Some(shared.clone());
    shared
}

/// enableIncrementalAutoVacuum(prisma, databaseUrl) as called from configureSqlite.
pub async fn enable_incremental_auto_vacuum(st: &AppState) {
    let r = st.db.call(|c| Ok(enable_incremental_auto_vacuum_on(c)?)).await;
    if let Err(e) = r {
        eprintln!("[prisma] Failed to configure SQLite PRAGMAs: {e}");
    }
}

/// reclaimSqliteFreeSpace: return deleted pages to the filesystem, at most one run in flight.
pub async fn reclaim_sqlite_free_space(st: &AppState) -> Option<SqliteReclaimResult> {
    let db = st.db.clone();
    let path = st.cfg.database_path.clone();
    single_flight(async move {
        match db.call(move |c| Ok(reclaim_on(c, Some(&path))?)).await {
            Ok(r) => r,
            Err(e) => {
                eprintln!("[Cleanup] SQLite vacuum failed: {e}");
                None
            }
        }
    })
    .await
}

/// Let graceful shutdown avoid closing the database during active maintenance.
pub async fn wait_for_sqlite_maintenance() {
    let active = ACTIVE.lock().unwrap().clone();
    if let Some(a) = active {
        a.await;
    }
}

/// Port of sqlite-maintenance.integration.ts.
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    const MB: i64 = 1024 * 1024;

    fn create_database(incremental: bool) -> (tempfile::TempDir, std::path::PathBuf, Connection) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.db");
        let db = Connection::open(&path).unwrap();
        db.execute_batch("PRAGMA page_size = 4096").unwrap();
        if incremental {
            db.execute_batch("PRAGMA auto_vacuum = INCREMENTAL; VACUUM;").unwrap();
        }
        db.execute_batch("CREATE TABLE payload (id INTEGER PRIMARY KEY, value BLOB NOT NULL)").unwrap();
        (dir, path, db)
    }

    fn fill_then_delete(db: &mut Connection, megabytes: i64) {
        let tx = db.transaction().unwrap();
        for _ in 0..megabytes {
            tx.execute("INSERT INTO payload (value) VALUES (zeroblob(?1))", [MB]).unwrap();
        }
        tx.commit().unwrap();
        db.execute_batch("DELETE FROM payload").unwrap();
    }

    fn consistent(m: &SqliteSpaceMetrics, expected_file_bytes: i64) {
        assert_eq!(m.file_bytes, m.page_count * m.page_size);
        assert_eq!(m.free_bytes, m.free_page_count * m.page_size);
        assert_eq!(m.file_bytes, expected_file_bytes);
    }

    #[test]
    fn reclaims_legacy_file_with_measured_metrics() {
        let (_dir, path, mut db) = create_database(false);
        fill_then_delete(&mut db, 72);
        let size_before = std::fs::metadata(&path).unwrap().len() as i64;
        let result = reclaim_on(&db, Some(&path)).unwrap().unwrap();
        let size_after = std::fs::metadata(&path).unwrap().len() as i64;
        assert_eq!(result.mode, ReclaimMode::Full);
        assert!(result.before.free_bytes > 64 * MB);
        assert!(result.after.free_page_count < result.before.free_page_count);
        assert_eq!(result.reclaimed_bytes, size_before - size_after);
        consistent(&result.before, size_before);
        consistent(&result.after, size_after);
        assert_eq!(pragma_number(&db, "auto_vacuum").unwrap(), 2);
    }

    #[test]
    fn skips_small_free_space_and_converts_small_databases() {
        let (_dir, path, db) = create_database(false);
        assert!(reclaim_on(&db, Some(&path)).unwrap().is_none());
        assert!(enable_incremental_auto_vacuum_on(&db).unwrap());
        assert_eq!(pragma_number(&db, "auto_vacuum").unwrap(), 2);
        assert!(!enable_incremental_auto_vacuum_on(&db).unwrap());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn coalesces_overlapping_calls_into_one_incremental_vacuum() {
        let (_dir, path, mut db) = create_database(true);
        fill_then_delete(&mut db, 12);
        drop(db);
        let (release, gate) = tokio::sync::oneshot::channel::<()>();
        let calls = Arc::new(AtomicUsize::new(0));
        let c2 = calls.clone();
        let p = path.clone();
        let first = single_flight(async move {
            c2.fetch_add(1, Ordering::SeqCst);
            let _ = gate.await;
            tokio::task::spawn_blocking(move || {
                let db = Connection::open(&p).unwrap();
                reclaim_on(&db, Some(&p)).unwrap()
            })
            .await
            .unwrap()
        });
        tokio::task::yield_now().await;
        let c3 = calls.clone();
        let second = single_flight(async move {
            c3.fetch_add(1, Ordering::SeqCst);
            None
        });
        release.send(()).unwrap();
        let (a, b) = futures_util::future::join(first, second).await;
        assert_eq!(a, b);
        let r = a.unwrap();
        assert_eq!(r.mode, ReclaimMode::Incremental);
        assert!(r.after.page_count <= r.before.page_count);
        assert_eq!(r.reclaimed_bytes, r.before.file_bytes - r.after.file_bytes);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        // Once settled, a new call starts a fresh run.
        wait_for_sqlite_maintenance().await;
        assert!(ACTIVE.lock().unwrap().is_none());
    }
}
