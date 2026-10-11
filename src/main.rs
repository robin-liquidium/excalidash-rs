use std::{net::SocketAddr, path::PathBuf, time::Duration};

use axum::{extract::Request, Router};
use excalidash_rs::{
    config::{self, Config, ProcessEnv},
    db::{self, Db},
    http::{self, Frontdoor},
    state::AppState,
    util,
};

/// docker-entrypoint.sh duties that the Rust image performs natively:
/// persisted JWT/CSRF secrets next to the database and migrations under a lock.
fn entrypoint(data_dir: &std::path::Path) {
    if std::env::var("EXCALIDASH_ENTRYPOINT").ok().as_deref() != Some("1") {
        return;
    }
    let _ = std::fs::create_dir_all(data_dir);
    let persist = |var: &str, file: &str, generate: fn() -> String| {
        let path = data_dir.join(file);
        let provided = std::env::var(var).ok().filter(|v| !v.is_empty());
        let value = match provided {
            Some(v) => v,
            None => {
                println!("{var} not provided, resolving persisted secret...");
                let existing = std::fs::read_to_string(&path).ok().map(|s| s.replace(['\r', '\n'], "")).filter(|s| !s.is_empty());
                match existing {
                    Some(v) => v,
                    None => {
                        println!("No persisted {} secret found. Generating a new secret...", var.trim_end_matches("_SECRET"));
                        generate()
                    }
                }
            }
        };
        write_private(&path, &value);
        // Single-threaded at this point: safe to export for config loading.
        unsafe { std::env::set_var(var, &value) };
    };
    persist("JWT_SECRET", ".jwt_secret", || hex::encode(util::random_bytes(32)));
    persist("CSRF_SECRET", ".csrf_secret", || util::b64_std(&util::random_bytes(32)));
    match std::env::var("DATABASE_PROVIDER").ok().filter(|v| !v.is_empty()) {
        None => println!("DATABASE_PROVIDER not set, defaulting to sqlite"),
        Some(p) if p == "sqlite" => {}
        Some(p) if p == "postgresql" => {
            eprintln!("ERROR: DATABASE_PROVIDER=postgresql is not supported by the Rust build (SQLite only).");
            std::process::exit(1);
        }
        Some(p) => {
            eprintln!("ERROR: DATABASE_PROVIDER must be 'sqlite' or 'postgresql', got '{p}'");
            std::process::exit(1);
        }
    }
}

fn write_private(path: &std::path::Path, value: &str) {
    use std::io::Write;
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).write(true).truncate(true).mode(0o600).open(path) {
            let _ = f.write_all(value.as_bytes());
        }
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    {
        let _ = std::fs::write(path, value);
    }
}

fn run_migrations(cfg: &Config) {
    let flag = std::env::var("RUN_MIGRATIONS").unwrap_or_else(|_| "true".into());
    if flag != "true" && flag != "1" {
        println!("Skipping database migrations (RUN_MIGRATIONS={flag})");
        return;
    }
    println!("Running database migrations...");
    let data_dir = cfg.database_path.parent().map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."));
    let _ = std::fs::create_dir_all(&data_dir);
    let lock = data_dir.join(".migration-lock");
    let timeout: u64 = std::env::var("MIGRATION_LOCK_TIMEOUT_SECONDS").ok().and_then(|v| v.parse().ok()).unwrap_or(120);
    let mut waited = 0;
    while std::fs::create_dir(&lock).is_err() {
        if waited >= timeout {
            eprintln!("Timed out waiting for migration lock after {timeout}s");
            std::process::exit(1);
        }
        waited += 1;
        std::thread::sleep(Duration::from_secs(1));
    }
    let result = (|| -> Result<usize, String> {
        let mut c = rusqlite::Connection::open(&cfg.database_path).map_err(|e| e.to_string())?;
        c.busy_timeout(Duration::from_secs(10)).map_err(|e| e.to_string())?;
        c.execute_batch("PRAGMA foreign_keys = OFF;").map_err(|e| e.to_string())?;
        println!("Datasource \"db\": SQLite database \"{}\"", cfg.database_path.file_name().map(|f| f.to_string_lossy().to_string()).unwrap_or_default());
        db::migrate_deploy(&mut c)
    })();
    let _ = std::fs::remove_dir(&lock);
    if let Err(e) = result {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

fn inspect_list(items: &[String]) -> String {
    let quoted: Vec<String> = items.iter().map(|s| format!("'{}'", s.replace('\'', "\\'"))).collect();
    format!("[ {} ]", quoted.join(", "))
}

/// `excalidash-rs healthcheck`: exit 0 when GET /health returns 200 (for scratch images).
fn healthcheck() -> ! {
    use std::io::{Read, Write};
    let port = std::env::var("PORT").ok().and_then(|p| p.parse::<u16>().ok()).unwrap_or(8000);
    // With the frontend bundled, /health is the SPA; the API lives under /api.
    let dist = std::env::var("FRONTEND_DIST_DIR").unwrap_or_default();
    let combined = dist != "none" && (!dist.is_empty() || std::path::Path::new("public/index.html").is_file());
    let path = if combined { "/api/health" } else { "/health" };
    let ok = (|| -> std::io::Result<bool> {
        let mut s = std::net::TcpStream::connect(("127.0.0.1", port))?;
        s.set_read_timeout(Some(Duration::from_secs(5)))?;
        s.write_all(format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n").as_bytes())?;
        let mut buf = [0u8; 16];
        let n = s.read(&mut buf)?;
        Ok(buf[..n].starts_with(b"HTTP/1.1 200"))
    })()
    .unwrap_or(false);
    std::process::exit(if ok { 0 } else { 1 });
}

fn main() {
    if std::env::args().nth(1).as_deref() == Some("healthcheck") {
        healthcheck();
    }
    let blocking: usize = std::env::var("EXCALIDASH_BLOCKING_THREADS").ok().and_then(|v| v.parse().ok()).unwrap_or(8);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(blocking)
        .thread_keep_alive(Duration::from_secs(10))
        .build()
        .expect("tokio runtime");
    rt.block_on(async_main());
}

async fn async_main() {
    excalidash_rs::net::install_crypto_provider();
    let backend_root = std::env::var("EXCALIDASH_BACKEND_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));

    // Resolve the DB path first so the entrypoint can persist secrets beside it.
    match config::resolve_database_url(&backend_root, std::env::var("DATABASE_URL").ok()) {
        Ok((_, path)) => entrypoint(path.parent().unwrap_or(&backend_root)),
        Err(_) => entrypoint(&backend_root.join("prisma")),
    }
    let cfg = match Config::from_env(&ProcessEnv, backend_root) {
        Ok(c) => config::init(c),
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    };
    println!("Configuration validated successfully");
    run_migrations(cfg);

    println!("Resolved DATABASE_URL: {}", config::redact_database_url(&cfg.database_url));
    if let Some(bucket) = &cfg.s3.bucket {
        println!("S3 image storage enabled {{ bucket: '{bucket}', region: '{}' }}", cfg.s3.region);
    }
    println!("Allowed origins: {}", inspect_list(&cfg.allowed_origins));
    match cfg.trust_proxy {
        config::TrustProxy::All => println!("[config] trust proxy: enabled (handles multiple proxy layers)"),
        other => println!("[config] trust proxy: {}", other.log_value()),
    }

    let database = match Db::open(&cfg.database_path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Failed to open database: {e}");
            std::process::exit(1);
        }
    };
    let st = AppState::new(database);

    // Socket.IO (attached at the HTTP server level, like socket.io on Node).
    let (io_layer, io) = socketioxide::SocketIo::builder()
        .max_payload(cfg.body_limit_bytes as u64)
        .build_layer();
    excalidash_rs::socket::register(&io, st.clone());
    st.set_io(io);

    let backend = excalidash_rs::routes::router(st.clone());
    let fd = Frontdoor { st: st.clone(), backend };
    let bundled = cfg.frontend_dist_dir.is_some();
    let app = Router::new()
        .fallback(move |req: Request| http::dispatch(fd.clone(), req))
        .layer(io_layer)
        .layer(axum::middleware::from_fn(move |req: Request, next: axum::middleware::Next| {
            http::outer_layer(bundled, req, next)
        }));

    // configureSqlite + security settings, then background jobs.
    excalidash_rs::security::configure_max_data_url_size(cfg.file_upload_max_bytes as u64);
    {
        let c = st.db.get().expect("db connection");
        db::configure_sqlite(&c);
    }
    excalidash_rs::sqlite_maintenance::enable_incremental_auto_vacuum(&st).await;
    excalidash_rs::backups::start_scheduled_backups(&st);
    spawn_snapshot_cleanup(st.clone());
    {
        let st = st.clone();
        tokio::spawn(async move {
            let mut t = tokio::time::interval(Duration::from_secs(60));
            t.tick().await;
            loop {
                t.tick().await;
                st.drawings_cache.sweep();
            }
        });
    }

    let addr = format!("{}:{}", cfg.listen_host, cfg.port);
    let listener = match tokio::net::TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Failed to listen on {addr}: {e}");
            std::process::exit(1);
        }
    };
    let _ = std::fs::create_dir_all(&cfg.uploads_dir);
    if cfg.auth_mode == config::AuthMode::Disabled {
        let line = "!".repeat(72);
        eprintln!("\n{line}\n! AUTH_MODE=disabled: authentication is OFF. Every request runs as a\n! single shared local user and NO login is required. Do NOT expose this\n! instance to the public internet or any untrusted network.\n{line}\n");
    }
    excalidash_rs::storage_doctor::run_storage_doctor(&st).await;
    excalidash_rs::bootstrap::issue_bootstrap_setup_code_if_required(&st, "startup").await;
    println!("Server running on port {}", cfg.port);
    println!("Environment: {}", cfg.node_env);
    println!("Frontend URL: {}", cfg.frontend_url.clone().unwrap_or_else(|| "undefined".into()));

    let server = axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(shutdown_signal());
    if let Err(e) = server.await {
        eprintln!("Server error: {e}");
    }
    excalidash_rs::sqlite_maintenance::wait_for_sqlite_maintenance().await;
}

fn spawn_snapshot_cleanup(st: AppState) {
    tokio::spawn(async move {
        let mut t = tokio::time::interval(Duration::from_secs(60 * 60));
        t.tick().await;
        loop {
            t.tick().await;
            let cutoff = util::now_ms() - st.cfg.snapshot_retention_ms as i64;
            let r = st
                .db
                .call(move |c| Ok(c.execute(r#"DELETE FROM "DrawingSnapshot" WHERE "createdAt" < ?1"#, [cutoff])?))
                .await;
            match r {
                Ok(n) if n > 0 => println!("[Cleanup] Deleted {n} old drawing snapshots"),
                Ok(_) => {}
                Err(e) => eprintln!("[Cleanup] Snapshot cleanup failed: {e}"),
            }
            excalidash_rs::sqlite_maintenance::reclaim_sqlite_free_space(&st).await;
        }
    });
}

async fn shutdown_signal() {
    let term = async {
        #[cfg(unix)]
        {
            let mut s = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("signal");
            s.recv().await;
            "SIGTERM"
        }
        #[cfg(not(unix))]
        std::future::pending::<&str>().await
    };
    let int = async {
        let _ = tokio::signal::ctrl_c().await;
        "SIGINT"
    };
    let sig = tokio::select! { s = term => s, s = int => s };
    println!("[shutdown] Received {sig}, shutting down gracefully");
    tokio::spawn(async {
        tokio::time::sleep(Duration::from_secs(10)).await;
        eprintln!("[shutdown] Forced exit after timeout");
        std::process::exit(1);
    });
}
