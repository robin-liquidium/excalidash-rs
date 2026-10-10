//! backups/scheduler.ts — scheduled SQLite backups.
use chrono::{Datelike, Local, Timelike};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::state::AppState;

#[derive(Debug, Clone, PartialEq)]
pub struct ParsedCron {
    pub seconds: BTreeSet<u32>,
    pub minutes: BTreeSet<u32>,
    pub hours: BTreeSet<u32>,
    pub days_of_month: BTreeSet<u32>,
    pub months: BTreeSet<u32>,
    pub days_of_week: BTreeSet<u32>,
    pub days_of_month_restricted: bool,
    pub days_of_week_restricted: bool,
}

/// JS `Number(s)` restricted to what `Number.isInteger` accepts.
fn js_int(s: &str) -> Option<i64> {
    let n = crate::config::js_number(s);
    if n.is_finite() && n.fract() == 0.0 { Some(n as i64) } else { None }
}

fn parse_cron_part(raw: &str, min: u32, max: u32) -> Result<BTreeSet<u32>, String> {
    let mut values = BTreeSet::new();
    for token in raw.split(',') {
        let trimmed = crate::security::js_trim(token);
        if trimmed.is_empty() {
            continue;
        }
        let mut parts = trimmed.split('/');
        let range = parts.next().unwrap_or("");
        let step = match parts.next() {
            // `stepToken ? Number(stepToken) : 1`
            Some(s) if !s.is_empty() => js_int(s),
            _ => Some(1),
        };
        let step = match step {
            Some(s) if s > 0 => s as u32,
            _ => return Err(format!("Invalid cron step: {trimmed}")),
        };
        let add = |values: &mut BTreeSet<u32>, start: u32, end: u32| {
            let mut v = start;
            while v <= end {
                values.insert(v);
                v += step;
            }
        };
        if range == "*" {
            add(&mut values, min, max);
            continue;
        }
        if range.contains('-') {
            let mut it = range.split('-');
            let (start, end) = (it.next().and_then(js_int), it.next().and_then(js_int));
            match (start, end) {
                (Some(s), Some(e)) if s >= min as i64 && e <= max as i64 && s <= e => add(&mut values, s as u32, e as u32),
                _ => return Err(format!("Invalid cron range: {trimmed}")),
            }
            continue;
        }
        match js_int(range) {
            Some(v) if v >= min as i64 && v <= max as i64 => {
                values.insert(v as u32);
            }
            _ => return Err(format!("Invalid cron value: {trimmed}")),
        }
    }
    if values.is_empty() {
        return Err(format!("Invalid empty cron field: {raw}"));
    }
    Ok(values)
}

/// parseCronSchedule: 5 fields (seconds = 0) or 6 fields.
pub fn parse_cron_schedule(raw: &str) -> Result<ParsedCron, String> {
    let parts: Vec<&str> = crate::security::js_trim(raw).split(|c: char| c.is_whitespace()).filter(|s| !s.is_empty()).collect();
    let n: Vec<&str> = if parts.len() == 5 { std::iter::once("0").chain(parts).collect() } else { parts };
    if n.len() != 6 {
        return Err("BACKUP_SCHEDULE must be a 5- or 6-field cron expression".into());
    }
    Ok(ParsedCron {
        seconds: parse_cron_part(n[0], 0, 59)?,
        minutes: parse_cron_part(n[1], 0, 59)?,
        hours: parse_cron_part(n[2], 0, 23)?,
        days_of_month: parse_cron_part(n[3], 1, 31)?,
        months: parse_cron_part(n[4], 1, 12)?,
        days_of_week: parse_cron_part(n[5], 0, 7)?,
        days_of_month_restricted: n[3] != "*",
        days_of_week_restricted: n[5] != "*",
    })
}

/// cronMatches (local time, like JS Date getters).
pub fn cron_matches<T: Datelike + Timelike>(cron: &ParsedCron, date: &T) -> bool {
    let day = date.weekday().num_days_from_sunday();
    let dom = cron.days_of_month.contains(&date.day());
    let dow = cron.days_of_week.contains(&day) || (day == 0 && cron.days_of_week.contains(&7));
    let day_match = if cron.days_of_month_restricted && cron.days_of_week_restricted { dom || dow } else { dom && dow };
    cron.seconds.contains(&date.second())
        && cron.minutes.contains(&date.minute())
        && cron.hours.contains(&date.hour())
        && cron.months.contains(&date.month())
        && day_match
}

fn timestamp_for_filename(iso: &str) -> String {
    iso.replace([':', '.'], "-")
}

fn is_backup_name(name: &str) -> bool {
    name.starts_with("excalidash-sqlite-") && name.ends_with(".db") && name.len() >= "excalidash-sqlite-.db".len()
}

fn prune_old_backups(dir: &Path, retention_days: f64) {
    if !retention_days.is_finite() || retention_days <= 0.0 {
        return;
    }
    let cutoff = crate::util::now_ms() as f64 - retention_days * 24.0 * 60.0 * 60.0 * 1000.0;
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if !e.file_type().map(|t| t.is_file()).unwrap_or(false) || !is_backup_name(&name) {
            continue;
        }
        let mtime = e
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs_f64() * 1000.0);
        if let Some(m) = mtime {
            if m < cutoff {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
}

/// createSqliteBackup: checkpoint, online-backup the database into
/// `<dir>/excalidash-sqlite-<ISO>.db` (0600, dir 0700), prune old backups.
pub fn create_sqlite_backup(
    checkpoint: &rusqlite::Connection,
    database_path: &Path,
    backup_dir: &Path,
    retention_days: f64,
) -> Result<PathBuf, String> {
    create_private_dir(backup_dir).map_err(|e| e.to_string())?;
    checkpoint.query_row("PRAGMA wal_checkpoint(PASSIVE)", [], |_| Ok(())).map_err(|e| e.to_string())?;
    let target = backup_dir.join(format!("excalidash-sqlite-{}.db", timestamp_for_filename(&crate::util::iso_now())));
    {
        let source = rusqlite::Connection::open_with_flags(
            database_path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|e| e.to_string())?;
        source.busy_timeout(Duration::from_secs(10)).map_err(|e| e.to_string())?;
        source.backup(rusqlite::MAIN_DB, &target, None).map_err(|e| e.to_string())?;
    }
    set_mode(&target, 0o600).map_err(|e| e.to_string())?;
    prune_old_backups(backup_dir, retention_days);
    println!("[backup] Wrote SQLite backup: {}", target.display());
    Ok(target)
}

fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(dir)
    }
}

fn set_mode(path: &Path, mode: u32) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
        Ok(())
    }
}

/// startScheduledBackups: tick every second, run when the cron matches.
pub fn start_scheduled_backups(st: &AppState) {
    let Some(schedule) = st.cfg.backups.schedule.clone() else { return };
    let cron = match parse_cron_schedule(&schedule) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[backup] Invalid BACKUP_SCHEDULE; scheduled backups disabled: Error: {e}");
            return;
        }
    };
    let dir = st.cfg.backups.dir.clone();
    let retention = st.cfg.backups.retention_days;
    let db_path = st.cfg.database_path.clone();
    let db = st.db.clone();
    let log_dir = dir.display().to_string();
    tokio::spawn(async move {
        let mut last_run: Option<String> = None;
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        interval.tick().await;
        loop {
            interval.tick().await;
            let now = Local::now();
            if !cron_matches(&cron, &now) {
                continue;
            }
            let key = now.format("%Y-%m-%d-%H-%M-%S").to_string();
            if last_run.as_deref() == Some(key.as_str()) {
                continue;
            }
            last_run = Some(key);
            // Runs are awaited, so they never overlap (`running` upstream).
            let (dir, db_path) = (dir.clone(), db_path.clone());
            let r = db.call(move |c| Ok(create_sqlite_backup(c, &db_path, &dir, retention))).await;
            match r {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => eprintln!("[backup] Scheduled backup failed: Error: {e}"),
                Err(e) => eprintln!("[backup] Scheduled backup failed: Error: {e}"),
            }
        }
    });
    println!("[backup] Scheduled SQLite backups enabled ({schedule}) -> {log_dir}");
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn parses_five_and_six_field_schedules() {
        let c = parse_cron_schedule("0 3 * * *").unwrap();
        assert_eq!(c.seconds, BTreeSet::from([0]));
        assert_eq!(c.hours, BTreeSet::from([3]));
        assert!(!c.days_of_month_restricted && !c.days_of_week_restricted);
        let c = parse_cron_schedule("*/15 * * * * *").unwrap();
        assert_eq!(c.seconds, BTreeSet::from([0, 15, 30, 45]));
        let c = parse_cron_schedule("0 0 1-5/2,10 * 1,3 0").unwrap();
        assert_eq!(c.hours, BTreeSet::from([1, 3, 5, 10]));
        assert_eq!(c.months, BTreeSet::from([1, 3]));
        assert_eq!(
            parse_cron_schedule("* * *").unwrap_err(),
            "BACKUP_SCHEDULE must be a 5- or 6-field cron expression"
        );
        assert_eq!(parse_cron_schedule("61 * * * * *").unwrap_err(), "Invalid cron value: 61");
        assert_eq!(parse_cron_schedule("*/0 * * * *").unwrap_err(), "Invalid cron step: */0");
        assert_eq!(parse_cron_schedule("0 5-2 * * *").unwrap_err(), "Invalid cron range: 5-2");
        assert_eq!(parse_cron_schedule("0 , * * *").unwrap_err(), "Invalid empty cron field: ,");
    }

    #[test]
    fn day_fields_or_when_both_restricted() {
        // 2026-10-11 is a Sunday.
        let sunday = Local.with_ymd_and_hms(2026, 10, 11, 3, 0, 0).unwrap();
        assert!(cron_matches(&parse_cron_schedule("0 3 * * 7").unwrap(), &sunday));
        assert!(cron_matches(&parse_cron_schedule("0 3 * * 0").unwrap(), &sunday));
        assert!(!cron_matches(&parse_cron_schedule("0 3 1 * *").unwrap(), &sunday));
        assert!(cron_matches(&parse_cron_schedule("0 3 1 * 0").unwrap(), &sunday));
        assert!(!cron_matches(&parse_cron_schedule("0 4 * * *").unwrap(), &sunday));
        assert!(!cron_matches(&parse_cron_schedule("30 0 3 * * *").unwrap(), &sunday));
    }

    #[test]
    fn filenames_and_retention_patterns() {
        assert_eq!(timestamp_for_filename("2026-10-10T12:34:56.789Z"), "2026-10-10T12-34-56-789Z");
        assert!(is_backup_name("excalidash-sqlite-2026-10-10T12-34-56-789Z.db"));
        assert!(!is_backup_name("other.db"));
        assert!(!is_backup_name("excalidash-sqlite-x.db-wal"));
    }

    /// scheduled-backups: "checkpoints a real database and creates a private, independent SQLite backup"
    #[test]
    fn creates_private_independent_backup() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("dev.db");
        let c = rusqlite::Connection::open(&db_path).unwrap();
        let _: String = c.query_row("PRAGMA journal_mode = WAL", [], |r| r.get(0)).unwrap();
        c.execute_batch("CREATE TABLE Drawing (id TEXT PRIMARY KEY, name TEXT); INSERT INTO Drawing VALUES ('d','Backup drawing');")
            .unwrap();
        let backups = dir.path().join("backups");
        // An old backup gets pruned, a fresh one survives.
        create_private_dir(&backups).unwrap();
        let old = backups.join("excalidash-sqlite-old.db");
        std::fs::write(&old, b"x").unwrap();
        let f = std::fs::File::options().write(true).open(&old).unwrap();
        f.set_modified(std::time::SystemTime::now() - Duration::from_secs(20 * 86400)).unwrap();
        let target = create_sqlite_backup(&c, &db_path, &backups, 14.0).unwrap();
        assert!(!old.exists());
        assert_eq!(std::fs::metadata(&target).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::metadata(&backups).unwrap().permissions().mode() & 0o777, 0o700);
        c.execute("UPDATE Drawing SET name = 'Changed after backup'", []).unwrap();
        let b = rusqlite::Connection::open_with_flags(&target, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        let ok: String = b.query_row("PRAGMA integrity_check", [], |r| r.get(0)).unwrap();
        assert_eq!(ok, "ok");
        let name: String = b.query_row("SELECT name FROM Drawing WHERE id='d'", [], |r| r.get(0)).unwrap();
        assert_eq!(name, "Backup drawing");
    }
}
