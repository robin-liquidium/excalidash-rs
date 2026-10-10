//! Ports of scheduled-backups.integration.ts and the startup side of
//! sqlite-maintenance / storageDoctor (black-box against the real binary).
mod common;

use common::*;
use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, Instant};

fn wait_until(timeout: Duration, mut f: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if f() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    f()
}

#[test]
fn writes_scheduled_private_independent_backups() {
    let backups = tempfile::tempdir().unwrap();
    let dir = backups.path().join("scheduled");
    let server = TestServer::start(&[("BACKUP_SCHEDULE", "* * * * * *"), ("BACKUP_DIR", dir.to_str().unwrap())]);
    let (_c, user) = user_session(&server, "backup@example.test", "USER");
    let now = chrono::Utc::now().timestamp_millis();
    server
        .db()
        .execute(
            r#"INSERT INTO "Drawing" ("id","name","elements","appState","files","version","userId","createdAt","updatedAt")
               VALUES ('backup-drawing','Backup drawing','[]','{}','{}',1,?1,?2,?2)"#,
            rusqlite::params![user, now],
        )
        .unwrap();
    let out = server.output();
    assert!(
        out.contains(&format!("[backup] Scheduled SQLite backups enabled (* * * * * *) -> {}", dir.display())),
        "{out}"
    );
    // Wait for a backup taken after the drawing was inserted.
    let mut found = None;
    assert!(
        wait_until(Duration::from_secs(10), || {
            let Ok(entries) = std::fs::read_dir(&dir) else { return false };
            for e in entries.flatten() {
                let name = e.file_name().to_string_lossy().into_owned();
                let mode = e.metadata().unwrap().permissions().mode() & 0o777;
                if !(name.starts_with("excalidash-sqlite-") && name.ends_with(".db") && mode == 0o600) {
                    continue;
                }
                let b = rusqlite::Connection::open_with_flags(e.path(), rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
                let has: Option<String> =
                    b.query_row(r#"SELECT "name" FROM "Drawing" WHERE "id" = 'backup-drawing'"#, [], |r| r.get(0)).ok();
                if has.is_some() {
                    found = Some(e.path());
                    return true;
                }
            }
            false
        }),
        "no scheduled backup: {}",
        server.output()
    );
    let target = found.unwrap();
    assert_eq!(std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o700);
    let name = target.file_name().unwrap().to_string_lossy().into_owned();
    // excalidash-sqlite-YYYY-MM-DDTHH-MM-SS-mmmZ.db
    assert_eq!(name.len(), "excalidash-sqlite-2026-10-10T12-00-00-000Z.db".len(), "{name}");
    assert!(server.output().contains(&format!("[backup] Wrote SQLite backup: {}", target.display())));
    server.db().execute(r#"UPDATE "Drawing" SET "name" = 'Changed after backup'"#, []).unwrap();
    let b = rusqlite::Connection::open_with_flags(&target, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    let ok: String = b.query_row("PRAGMA integrity_check", [], |r| r.get(0)).unwrap();
    assert_eq!(ok, "ok");
    let n: String = b.query_row(r#"SELECT "name" FROM "Drawing" WHERE "id" = 'backup-drawing'"#, [], |r| r.get(0)).unwrap();
    assert_eq!(n, "Backup drawing");
}

#[test]
fn invalid_backup_schedule_disables_backups_without_failing_startup() {
    let backups = tempfile::tempdir().unwrap();
    let server = TestServer::start(&[("BACKUP_SCHEDULE", "61 * * * *"), ("BACKUP_DIR", backups.path().to_str().unwrap())]);
    let out = server.output();
    assert!(out.contains("[backup] Invalid BACKUP_SCHEDULE; scheduled backups disabled: Error: Invalid cron value: 61"), "{out}");
    assert!(!out.contains("Scheduled SQLite backups enabled"));
}

#[test]
fn fresh_database_uses_incremental_auto_vacuum_like_upstream() {
    let server = TestServer::start(&[]);
    let mode: i64 = server.db().query_row("PRAGMA auto_vacuum", [], |r| r.get(0)).unwrap();
    assert_eq!(mode, 2);
    let journal: String = server.db().query_row("PRAGMA journal_mode", [], |r| r.get(0)).unwrap();
    assert_eq!(journal, "wal");
    assert!(server.output().contains("[prisma] SQLite switched to incremental auto-vacuum"));
}

#[test]
fn prints_storage_summary_box_at_startup() {
    let server = TestServer::start(&[("FILE_UPLOAD_MAX_MB", "10"), ("BODY_LIMIT_MB", "50")]);
    let target = server.db_path.display().to_string();
    let lines = [
        format!("Database:      sqlite ({target})"),
        "File storage:  database (default)".to_string(),
        "  Image blobs are stored in the database (DrawingFile.data).".to_string(),
        "Limits:        FILE_UPLOAD_MAX_MB=10 (per image), BODY_LIMIT_MB=50 (scene JSON)".to_string(),
        "Backups:       off".to_string(),
    ];
    let width = lines.iter().map(|l| l.len()).max().unwrap() + 2;
    let pad = |t: &str| format!("| {t:<w$}|", w = width - 1);
    let top = format!("+{}+", "-".repeat(width));
    let mut expected = vec![top.clone(), pad("STORAGE"), pad("-------")];
    expected.extend(lines.iter().map(|l| pad(l)));
    expected.push(top);
    let expected = format!("\n{}\n", expected.join("\n"));
    assert!(wait_until(Duration::from_secs(5), || server.output().contains(&expected)), "{}", server.output());
}
