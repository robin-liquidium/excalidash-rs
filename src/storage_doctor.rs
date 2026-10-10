//! server/storageDoctor.ts — boxed STORAGE summary printed at startup.
use crate::config::S3Config;
use crate::state::AppState;
use crate::util::{js_len, js_num_str};

pub struct StorageDoctorConfig<'a> {
    pub database_url: Option<&'a str>,
    pub file_upload_max_mb: f64,
    pub body_limit_mb: f64,
    pub backup_schedule: Option<&'a str>,
    pub s3: &'a S3Config,
}

/// parseDatabaseTarget: provider + credential-free target.
pub fn parse_database_target(database_url: Option<&str>) -> (String, String) {
    let Some(url) = database_url.filter(|u| !crate::security::js_trim(u).is_empty()) else {
        return ("unknown".into(), "<unset>".into());
    };
    if let Some(rest) = url.strip_prefix("file:") {
        return ("sqlite".into(), rest.to_string());
    }
    match url::Url::parse(url) {
        Ok(u) => {
            let scheme = u.scheme().to_lowercase();
            let provider = match scheme.as_str() {
                "postgres" | "postgresql" => "postgresql".to_string(),
                "mysql" => "mysql".to_string(),
                _ => scheme,
            };
            let host = u.host_str().filter(|h| !h.is_empty()).unwrap_or("localhost");
            let port = u.port().map(|p| format!(":{p}")).unwrap_or_default();
            let db = u.path().trim_start_matches('/');
            let db = if db.is_empty() { "<default>" } else { db };
            (provider, format!("{host}{port}/{db}"))
        }
        Err(_) => ("unknown".into(), "<unparseable>".into()),
    }
}

/// buildStorageSummary: content lines (no borders). `probe` is None when skipped.
pub fn build_storage_summary(cfg: &StorageDoctorConfig<'_>, s3_enabled: bool, probe: Option<&Result<(), String>>) -> Vec<String> {
    let mut lines = Vec::new();
    let (provider, target) = parse_database_target(cfg.database_url);
    lines.push(format!("Database:      {provider} ({target})"));
    match (&cfg.s3.bucket, s3_enabled) {
        (Some(bucket), true) if !bucket.is_empty() => {
            lines.push("File storage:  s3".into());
            lines.push(format!("  Bucket:      {bucket}"));
            lines.push(format!("  Region:      {}", cfg.s3.region));
            lines.push(format!("  Endpoint:    {}", cfg.s3.endpoint.as_deref().unwrap_or("AWS default")));
            lines.push(format!("  Public URL:  {}", cfg.s3.public_url.as_deref().unwrap_or("(virtual-hosted-style)")));
            lines.push(format!("  Path style:  {}", if cfg.s3.force_path_style { "on" } else { "off" }));
            match probe {
                Some(Ok(())) => lines.push("  Reachable:   yes (HeadBucket ok)".into()),
                Some(Err(e)) => {
                    lines.push("  Reachable:   NO".into());
                    lines.push(format!("  WARNING: could not reach bucket '{bucket}': {e}"));
                    lines.push("  Likely a bad credential, endpoint, or missing bucket. S3 uploads will fail until fixed.".into());
                }
                None => {}
            }
            if cfg.s3.endpoint.as_deref().is_some_and(|e| !e.is_empty()) && cfg.s3.public_url.as_deref().is_none_or(str::is_empty) {
                lines.push("  WARNING: custom S3_ENDPOINT set without S3_PUBLIC_URL; public image URLs may not resolve.".into());
                lines.push("  Set S3_PUBLIC_URL to the public base URL of your bucket or CDN.".into());
            }
        }
        _ => {
            lines.push("File storage:  database (default)".into());
            lines.push("  Image blobs are stored in the database (DrawingFile.data).".into());
        }
    }
    lines.push(format!(
        "Limits:        FILE_UPLOAD_MAX_MB={} (per image), BODY_LIMIT_MB={} (scene JSON)",
        js_num_str(cfg.file_upload_max_mb),
        js_num_str(cfg.body_limit_mb)
    ));
    lines.push(match cfg.backup_schedule.filter(|s| !crate::security::js_trim(s).is_empty()) {
        Some(s) => format!("Backups:       on ({s})"),
        None => "Backups:       off".into(),
    });
    lines
}

/// renderStorageBox
pub fn render_storage_box(title: &str, lines: &[String]) -> String {
    let width = lines.iter().map(|l| js_len(l)).chain(std::iter::once(js_len(title))).max().unwrap_or(0) + 2;
    let top = format!("+{}+", "-".repeat(width));
    let pad = |t: &str| format!("| {}{}|", t, " ".repeat((width - 1).saturating_sub(js_len(t))));
    let mut out = vec![top.clone(), pad(title), pad(&"-".repeat(js_len(title)))];
    out.extend(lines.iter().map(|l| pad(l)));
    out.push(top);
    out.join("\n")
}

/// runStorageDoctor: probe S3 when enabled, print the box once. Never fails.
pub async fn run_storage_doctor(st: &AppState) {
    let cfg = st.cfg;
    let s3_enabled = crate::s3::is_s3_enabled();
    let probe = if s3_enabled { Some(crate::s3::check_bucket_reachable(st.http(), 3000).await) } else { None };
    let doctor = StorageDoctorConfig {
        database_url: Some(&cfg.database_url),
        file_upload_max_mb: cfg.file_upload_max_mb,
        body_limit_mb: cfg.body_limit_mb,
        backup_schedule: cfg.backups.schedule.as_deref(),
        s3: &cfg.s3,
    };
    let lines = build_storage_summary(&doctor, s3_enabled, probe.as_ref());
    println!("\n{}\n", render_storage_box("STORAGE", &lines));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s3(bucket: Option<&str>, endpoint: Option<&str>, public_url: Option<&str>) -> S3Config {
        S3Config {
            bucket: bucket.map(str::to_string),
            region: "us-east-1".into(),
            endpoint: endpoint.map(str::to_string),
            public_url: public_url.map(str::to_string),
            force_path_style: true,
            key_prefix: "excalidash".into(),
            access_key_id: None,
            secret_access_key: None,
        }
    }

    #[test]
    fn database_targets_drop_credentials() {
        assert_eq!(parse_database_target(Some("file:/app/prisma/dev.db")), ("sqlite".into(), "/app/prisma/dev.db".into()));
        assert_eq!(
            parse_database_target(Some("postgres://user:pw@db:5432/excalidash")),
            ("postgresql".into(), "db:5432/excalidash".into())
        );
        assert_eq!(parse_database_target(Some("mysql://h/")), ("mysql".into(), "h/<default>".into()));
        assert_eq!(parse_database_target(None), ("unknown".into(), "<unset>".into()));
        assert_eq!(parse_database_target(Some("nope")), ("unknown".into(), "<unparseable>".into()));
    }

    #[test]
    fn renders_default_box_exactly() {
        let s3 = s3(None, None, None);
        let cfg = StorageDoctorConfig {
            database_url: Some("file:/app/prisma/dev.db"),
            file_upload_max_mb: 10.0,
            body_limit_mb: 50.0,
            backup_schedule: None,
            s3: &s3,
        };
        let out = render_storage_box("STORAGE", &build_storage_summary(&cfg, false, None));
        let expected = [
            "+---------------------------------------------------------------------------------+",
            "| STORAGE                                                                         |",
            "| -------                                                                         |",
            "| Database:      sqlite (/app/prisma/dev.db)                                      |",
            "| File storage:  database (default)                                               |",
            "|   Image blobs are stored in the database (DrawingFile.data).                    |",
            "| Limits:        FILE_UPLOAD_MAX_MB=10 (per image), BODY_LIMIT_MB=50 (scene JSON) |",
            "| Backups:       off                                                              |",
            "+---------------------------------------------------------------------------------+",
        ]
        .join("\n");
        assert_eq!(out, expected);
    }

    #[test]
    fn s3_lines_and_warnings() {
        let s3 = s3(Some("bucket"), Some("http://minio:9000"), None);
        let cfg = StorageDoctorConfig {
            database_url: Some("file:/d.db"),
            file_upload_max_mb: 2.5,
            body_limit_mb: 50.0,
            backup_schedule: Some("0 3 * * *"),
            s3: &s3,
        };
        let lines = build_storage_summary(&cfg, true, Some(&Err("timed out after 3000ms".into())));
        assert!(lines.contains(&"File storage:  s3".to_string()));
        assert!(lines.contains(&"  Reachable:   NO".to_string()));
        assert!(lines.contains(&"  WARNING: could not reach bucket 'bucket': timed out after 3000ms".to_string()));
        assert!(lines.iter().any(|l| l.contains("custom S3_ENDPOINT set without S3_PUBLIC_URL")));
        assert!(lines.contains(&"Limits:        FILE_UPLOAD_MAX_MB=2.5 (per image), BODY_LIMIT_MB=50 (scene JSON)".to_string()));
        assert_eq!(lines.last().unwrap(), "Backups:       on (0 3 * * *)");
        let ok = build_storage_summary(&cfg, true, Some(&Ok(())));
        assert!(ok.contains(&"  Reachable:   yes (HeadBucket ok)".to_string()));
    }
}
