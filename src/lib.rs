//! ExcaliDash backend, Rust edition. Feature parity target: upstream v0.6.5.
pub mod audit;
pub mod auth;
pub mod authz;
pub mod backups;
pub mod bootstrap;
pub mod config;
pub mod db;
pub mod drawings_cache;
pub mod files;
pub mod http;
pub mod mail;
pub mod models;
pub mod net;
pub mod routes;
pub mod s3;
pub mod security;
pub mod snapshots;
pub mod socket;
pub mod sqlite_maintenance;
pub mod state;
pub mod storage_doctor;
pub mod util;

/// Backend version: `VERSION` file next to the binary root, else the embedded one.
pub fn backend_version() -> String {
    static V: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    V.get_or_init(|| {
        let cfg = config::config();
        let candidates = [cfg.backend_root.join("VERSION"), cfg.backend_root.join("../VERSION")];
        let version = candidates
            .iter()
            .find_map(|p| std::fs::read_to_string(p).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()))
            .unwrap_or_else(|| include_str!("../VERSION").trim().to_string());
        if let Some(label) = &cfg.build_label {
            let re = regex::Regex::new(r"^\d+\.\d+\.\d+-dev\.[0-9a-f]{7,40}$").unwrap();
            if label == &version || (label.starts_with(&format!("{version}-dev.")) && re.is_match(label)) {
                return label.clone();
            }
        }
        version
    })
    .clone()
}
