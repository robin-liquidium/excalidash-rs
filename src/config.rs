//! Typed environment configuration. Mirrors backend/src/config.ts and
//! backend/src/config/* (registry, env readers, derived values, validation).
use std::{
    path::{Path, PathBuf},
    sync::OnceLock,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMode {
    Local,
    Hybrid,
    OidcEnforced,
    Disabled,
}

impl AuthMode {
    pub fn as_str(self) -> &'static str {
        match self {
            AuthMode::Local => "local",
            AuthMode::Hybrid => "hybrid",
            AuthMode::OidcEnforced => "oidc_enforced",
            AuthMode::Disabled => "disabled",
        }
    }
    /// True only for env-enforced (OIDC-backed) modes.
    pub fn enables_auth(self) -> bool {
        matches!(self, AuthMode::Hybrid | AuthMode::OidcEnforced)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustProxy {
    Off,
    All,
    Hops(u32),
}

impl TrustProxy {
    pub fn trusts_headers(self) -> bool {
        !matches!(self, TrustProxy::Off)
    }
    pub fn log_value(self) -> String {
        match self {
            TrustProxy::Off => "false".into(),
            TrustProxy::All => "true".into(),
            TrustProxy::Hops(n) => n.to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct OidcConfig {
    pub enabled: bool,
    pub enforced: bool,
    pub provider_name: String,
    pub issuer_url: Option<String>,
    pub discovery_url: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub redirect_uri: Option<String>,
    pub id_token_signed_response_alg: Option<String>,
    pub token_endpoint_auth_method: Option<String>,
    pub scopes: String,
    pub email_claim: String,
    pub email_verified_claim: String,
    pub groups_claim: String,
    pub admin_groups: Vec<String>,
    pub require_email_verified: bool,
    pub jit_provisioning: bool,
    pub first_user_admin: bool,
}

#[derive(Debug, Clone)]
pub struct PasswordPolicy {
    pub min_length: f64,
    pub max_length: f64,
    pub require_uppercase: bool,
    pub require_lowercase: bool,
    pub require_number: bool,
    pub require_symbol: bool,
}

#[derive(Debug, Clone)]
pub struct BackupConfig {
    pub schedule: Option<String>,
    pub dir: PathBuf,
    pub retention_days: f64,
}

#[derive(Debug, Clone)]
pub struct S3Config {
    pub bucket: Option<String>,
    pub region: String,
    pub endpoint: Option<String>,
    pub public_url: Option<String>,
    pub force_path_style: bool,
    pub key_prefix: String,
    pub access_key_id: Option<String>,
    pub secret_access_key: Option<String>,
}

#[derive(Debug, Clone)]
pub struct LinkShareConfig {
    pub edit_default_ttl_ms: f64,
    pub view_default_ttl_ms: f64,
    pub max_ttl_ms: f64,
}

#[derive(Debug, Clone)]
pub struct UpdateCheckConfig {
    pub outbound: bool,
    pub github_token: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MailTransport {
    Resend,
    Smtp,
    None,
}

#[derive(Debug, Clone)]
pub struct SmtpConfig {
    pub host: Option<String>,
    pub port: f64,
    pub secure: bool,
    pub user: Option<String>,
    pub password: Option<String>,
}

#[derive(Debug, Clone)]
pub struct MailConfig {
    pub transport: MailTransport,
    pub resend_api_key: Option<String>,
    pub from: Option<String>,
    pub reply_to: Option<String>,
    pub smtp: SmtpConfig,
}

#[derive(Debug, Clone)]
pub struct Config {
    /// Root that upstream calls `backendRoot` (/app in the image).
    pub backend_root: PathBuf,
    pub port: u16,
    pub listen_host: String,
    pub node_env: String,
    pub build_label: Option<String>,
    pub is_dev: bool,
    pub is_production: bool,
    /// Normalized `file:/abs/path` URL (SQLite only in this build).
    pub database_url: String,
    /// SQLite file (None for PostgreSQL).
    pub database_path: Option<PathBuf>,
    pub frontend_url: Option<String>,
    pub allowed_origins: Vec<String>,
    pub trust_proxy: TrustProxy,
    pub drawings_cache_ttl_ms: u64,
    pub auth_mode: AuthMode,
    pub jwt_secret: String,
    pub jwt_access_expires_in: String,
    pub jwt_refresh_expires_in: String,
    pub rate_limit_max_requests: f64,
    pub rate_limit_window_ms: f64,
    pub csrf_max_requests: f64,
    pub csrf_rate_limit_window_ms: f64,
    pub snapshot_retention_ms: f64,
    pub upload_max_bytes: f64,
    pub body_limit_mb: f64,
    pub body_limit_bytes: usize,
    pub file_upload_max_mb: f64,
    pub file_upload_max_bytes: f64,
    pub csrf_secret: Option<String>,
    pub debug_csrf: bool,
    pub api_key_hash_pepper: String,
    pub oidc: OidcConfig,
    pub enable_password_reset: bool,
    pub enable_refresh_token_rotation: bool,
    pub enable_audit_logging: bool,
    pub enforce_https_redirect: bool,
    pub disable_onboarding_gate: bool,
    pub bootstrap_setup_code_ttl_ms: f64,
    pub bootstrap_setup_code_max_attempts: f64,
    pub password_policy: PasswordPolicy,
    pub backups: BackupConfig,
    pub s3: S3Config,
    pub link_share: LinkShareConfig,
    pub update_check: UpdateCheckConfig,
    pub mail: MailConfig,
    /// Rust-only: directory holding the built frontend (served when present).
    pub frontend_dist_dir: Option<PathBuf>,
    pub uploads_dir: PathBuf,
}

static CONFIG: OnceLock<Config> = OnceLock::new();

pub fn config() -> &'static Config {
    CONFIG.get().expect("config not initialised")
}

pub fn init(cfg: Config) -> &'static Config {
    let _ = CONFIG.set(cfg);
    config()
}

/// Environment source; tests inject maps instead of the process env.
pub trait EnvSource {
    fn get(&self, name: &str) -> Option<String>;
}

pub struct ProcessEnv;
impl EnvSource for ProcessEnv {
    fn get(&self, name: &str) -> Option<String> {
        std::env::var(name).ok()
    }
}

impl EnvSource for std::collections::HashMap<String, String> {
    fn get(&self, name: &str) -> Option<String> {
        std::collections::HashMap::get(self, name).cloned()
    }
}

/// JavaScript `Number(str)` semantics for env values.
pub fn js_number(raw: &str) -> f64 {
    let s = raw.trim();
    if s.is_empty() {
        return 0.0;
    }
    let lower = s.to_ascii_lowercase();
    let radix = |p: &str, r| i64::from_str_radix(&lower[p.len()..], r).map(|v| v as f64).unwrap_or(f64::NAN);
    if lower.starts_with("0x") {
        return radix("0x", 16);
    }
    if lower.starts_with("0o") {
        return radix("0o", 8);
    }
    if lower.starts_with("0b") {
        return radix("0b", 2);
    }
    match s {
        "Infinity" | "+Infinity" => return f64::INFINITY,
        "-Infinity" => return f64::NEG_INFINITY,
        _ => {}
    }
    // Rust accepts "inf"/"nan" which JS rejects.
    if lower.contains("inf") || lower.contains("nan") {
        return f64::NAN;
    }
    s.parse::<f64>().unwrap_or(f64::NAN)
}

struct Env<'a> {
    src: &'a dyn EnvSource,
}

impl Env<'_> {
    fn raw(&self, name: &str) -> Option<String> {
        if let Some(v) = self.src.get(name) {
            return Some(v);
        }
        // Registry aliases.
        if name == "UPDATE_CHECK_GITHUB_TOKEN" {
            if let Some(v) = self.src.get("GITHUB_TOKEN") {
                eprintln!("GITHUB_TOKEN is deprecated, use UPDATE_CHECK_GITHUB_TOKEN");
                return Some(v);
            }
        }
        None
    }
    fn string(&self, name: &str, default: &str) -> String {
        match self.raw(name) {
            Some(v) if !v.is_empty() => v,
            _ => default.to_string(),
        }
    }
    fn opt_string(&self, name: &str) -> Option<String> {
        let raw = self.raw(name)?;
        let t = raw.trim();
        if t.is_empty() {
            None
        } else {
            Some(t.to_string())
        }
    }
    fn number(&self, name: &str, default: f64) -> Result<f64, String> {
        match self.raw(name) {
            Some(v) if !v.is_empty() => {
                let parsed = js_number(&v);
                if !parsed.is_finite() || parsed <= 0.0 {
                    Err(format!(
                        "Invalid value for environment variable {name}: must be a positive number"
                    ))
                } else {
                    Ok(parsed)
                }
            }
            _ => Ok(default),
        }
    }
    fn boolean(&self, name: &str, default: bool) -> bool {
        match self.raw(name) {
            Some(v) if !v.is_empty() => v.to_lowercase() == "true" || v == "1",
            _ => default,
        }
    }
    fn csv(&self, name: &str) -> Vec<String> {
        match self.raw(name) {
            Some(v) if !v.is_empty() => v
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
            _ => vec![],
        }
    }
}

const ALLOWED_OIDC_ID_TOKEN_ALGS: &[&str] = &[
    "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA", "HS256",
    "HS384", "HS512",
];

pub fn normalize_origins(raw: Option<&str>) -> Vec<String> {
    let fallback = vec!["http://localhost:6767".to_string()];
    let Some(raw) = raw.filter(|r| !r.trim().is_empty()) else {
        return fallback;
    };
    let proto = regex::Regex::new(r"(?i)^https?://").unwrap();
    let parsed: Vec<String> = raw
        .split(',')
        .map(|o| o.trim())
        .filter(|o| !o.is_empty())
        .map(|o| if proto.is_match(o) { o.to_string() } else { format!("http://{o}") })
        .map(|o| o.strip_suffix('/').map(str::to_string).unwrap_or(o))
        .collect();
    if parsed.is_empty() {
        fallback
    } else {
        parsed
    }
}

pub fn resolve_database_url(backend_root: &Path, raw: Option<String>) -> Result<(String, Option<PathBuf>), String> {
    let default_path = backend_root.join("prisma/dev.db");
    let raw = match raw {
        Some(r) if !r.trim().is_empty() => r,
        _ => return Ok((format!("file:{}", default_path.display()), Some(default_path))),
    };
    let Some(file_path) = raw.strip_prefix("file:") else {
        #[cfg(feature = "postgres")]
        if crate::sql::pg::is_postgres_url(&raw) {
            return Ok((raw, None));
        }
        return Err(format!(
            "DATABASE_URL '{}' is not supported by this build: only {} databases are supported",
            redact_database_url(&raw),
            if cfg!(feature = "postgres") { "SQLite (file:) and PostgreSQL (postgresql://)" } else { "SQLite (file:)" }
        ));
    };
    let prisma_dir = backend_root.join("prisma");
    let normalized_relative = file_path.strip_prefix("./").or_else(|| file_path.strip_prefix('.')).unwrap_or(file_path);
    let has_leading_prisma = normalized_relative == "prisma" || normalized_relative.starts_with("prisma/");
    let abs = if Path::new(file_path).is_absolute() {
        PathBuf::from(file_path)
    } else if has_leading_prisma {
        normalize_path(&backend_root.join(normalized_relative))
    } else {
        normalize_path(&prisma_dir.join(normalized_relative))
    };
    Ok((format!("file:{}", abs.display()), Some(abs)))
}

fn normalize_path(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            std::path::Component::ParentDir => {
                out.pop();
            }
            std::path::Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

pub fn redact_database_url(value: &str) -> String {
    if value.is_empty() {
        return "<unset>".into();
    }
    if value.starts_with("file:") {
        return value.to_string();
    }
    match url::Url::parse(value) {
        Ok(mut u) => {
            if !u.username().is_empty() {
                let _ = u.set_username("***");
            }
            if u.password().is_some() {
                let _ = u.set_password(Some("***"));
            }
            u.to_string()
        }
        Err(_) => "<redacted>".into(),
    }
}

impl Config {
    pub fn from_env(src: &dyn EnvSource, backend_root: PathBuf) -> Result<Config, String> {
        let env = Env { src };
        let node_env = env.string("NODE_ENV", "development");

        let auth_mode = match env.raw("AUTH_MODE").unwrap_or_else(|| "local".into()).trim().to_lowercase().as_str() {
            "" | "local" => AuthMode::Local,
            "hybrid" => AuthMode::Hybrid,
            "oidc_enforced" => AuthMode::OidcEnforced,
            "disabled" => AuthMode::Disabled,
            _ => return Err("Invalid AUTH_MODE. Expected one of: local, hybrid, oidc_enforced, disabled".into()),
        };

        // validateS3Configuration
        if env.opt_string("S3_BUCKET").is_none() {
            let mut set: Vec<&str> = vec![];
            for name in ["S3_ENDPOINT", "S3_PUBLIC_URL", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"] {
                if env.opt_string(name).is_some() {
                    set.push(name);
                }
            }
            if let Some(prefix) = env.raw("S3_KEY_PREFIX").map(|p| p.trim().to_string()) {
                if !prefix.is_empty() && prefix != "excalidash" {
                    set.push("S3_KEY_PREFIX");
                }
            }
            if !set.is_empty() {
                return Err(format!(
                    "S3 is half-configured: {} set without S3_BUCKET. Set S3_BUCKET to enable S3 storage, or remove the other S3_*/AWS_* variables to use database storage.",
                    set.join(", ")
                ));
            }
        }
        let file_upload_max_mb = match env.raw("FILE_UPLOAD_MAX_MB") {
            Some(raw) if !raw.trim().is_empty() => {
                let parsed = js_number(&raw);
                if !parsed.is_finite() || parsed <= 0.0 {
                    return Err(format!(
                        "Invalid FILE_UPLOAD_MAX_MB: expected a positive number of megabytes, got '{raw}'."
                    ));
                }
                parsed
            }
            _ => 100.0,
        };

        let jwt_secret = match env.raw("JWT_SECRET") {
            Some(s) if !s.trim().is_empty() => s,
            _ => {
                if node_env == "production" {
                    return Err("Missing required environment variable: JWT_SECRET".into());
                }
                eprintln!("[security] JWT_SECRET is not set (non-production). Using an ephemeral secret; tokens will be invalidated on restart.");
                hex::encode(crate::util::random_bytes(32))
            }
        };

        let frontend_url = env.raw("FRONTEND_URL").and_then(|raw| {
            let joined = raw.split(',').map(|o| o.trim()).filter(|o| !o.is_empty()).collect::<Vec<_>>().join(",");
            if joined.is_empty() { None } else { Some(joined) }
        });

        let trust_proxy = {
            let raw = env.raw("TRUST_PROXY").unwrap_or_else(|| "false".into());
            let raw = raw.trim();
            if raw == "true" {
                TrustProxy::All
            } else if raw == "false" {
                TrustProxy::Off
            } else {
                // Number.parseInt semantics: leading integer digits.
                let digits: String = raw.chars().take_while(|c| c.is_ascii_digit()).collect();
                match digits.parse::<u32>() {
                    Ok(n) if n > 0 => TrustProxy::Hops(n),
                    _ => TrustProxy::Off,
                }
            }
        };

        let drawings_cache_ttl_ms = {
            let parsed = env.raw("DRAWINGS_CACHE_TTL_MS").map(|v| js_number(&v)).unwrap_or(f64::NAN);
            if !parsed.is_finite() || parsed <= 0.0 { 5000 } else { parsed as u64 }
        };

        let (database_url, database_path) = resolve_database_url(&backend_root, env.raw("DATABASE_URL"))?;

        // OIDC
        let oidc = {
            let issuer_url = env.opt_string("OIDC_ISSUER_URL");
            let discovery_url = env.opt_string("OIDC_DISCOVERY_URL");
            let client_id = env.opt_string("OIDC_CLIENT_ID");
            let client_secret = {
                let direct = env.opt_string("OIDC_CLIENT_SECRET");
                match env.opt_string("OIDC_CLIENT_SECRET_FILE") {
                    None => direct,
                    Some(file) => {
                        if direct.is_some() {
                            return Err("Use only one of OIDC_CLIENT_SECRET and OIDC_CLIENT_SECRET_FILE".into());
                        }
                        let secret = std::fs::read_to_string(&file)
                            .map_err(|_| "OIDC_CLIENT_SECRET_FILE is not readable".to_string())?
                            .replace(['\r', '\n'], "")
                            .trim()
                            .to_string();
                        if secret.is_empty() {
                            return Err("OIDC_CLIENT_SECRET_FILE is empty".into());
                        }
                        Some(secret)
                    }
                }
            };
            let redirect_uri = env.opt_string("OIDC_REDIRECT_URI");
            let groups_claim = env.string("OIDC_GROUPS_CLAIM", "groups").trim().to_string();
            let admin_groups = env.csv("OIDC_ADMIN_GROUPS");
            if groups_claim.is_empty() {
                return Err("Invalid OIDC_GROUPS_CLAIM: must be a non-empty claim key/path".into());
            }
            let enabled = auth_mode.enables_auth();
            let required = [
                ("OIDC_ISSUER_URL", &issuer_url),
                ("OIDC_CLIENT_ID", &client_id),
                ("OIDC_REDIRECT_URI", &redirect_uri),
            ];
            let missing: Vec<&str> = required.iter().filter(|(_, v)| v.is_none()).map(|(k, _)| *k).collect();
            if enabled && !missing.is_empty() {
                return Err(format!(
                    "AUTH_MODE={} requires OIDC configuration. Missing: {}",
                    auth_mode.as_str(),
                    missing.join(", ")
                ));
            }
            if !enabled {
                let has = required.iter().any(|(_, v)| v.is_some()) || !admin_groups.is_empty();
                if has {
                    eprintln!("[config] AUTH_MODE={}; ignoring OIDC_* provider settings.", auth_mode.as_str());
                }
            }
            let id_token_alg = if enabled {
                match env.raw("OIDC_ID_TOKEN_SIGNED_RESPONSE_ALG") {
                    Some(raw) if !raw.is_empty() => {
                        let n = raw.trim().to_string();
                        if n.is_empty() || n.eq_ignore_ascii_case("none") {
                            return Err("OIDC_ID_TOKEN_SIGNED_RESPONSE_ALG must not be empty or 'none'".into());
                        }
                        if !ALLOWED_OIDC_ID_TOKEN_ALGS.contains(&n.as_str()) {
                            return Err(format!(
                                "OIDC_ID_TOKEN_SIGNED_RESPONSE_ALG must be one of: {}",
                                ALLOWED_OIDC_ID_TOKEN_ALGS.join(", ")
                            ));
                        }
                        Some(n)
                    }
                    _ => None,
                }
            } else {
                None
            };
            let token_auth = if enabled {
                match env.raw("OIDC_TOKEN_ENDPOINT_AUTH_METHOD") {
                    Some(raw) if !raw.is_empty() => {
                        let n = raw.trim().to_lowercase();
                        if n.is_empty() {
                            None
                        } else if ["none", "client_secret_basic", "client_secret_post"].contains(&n.as_str()) {
                            Some(n)
                        } else {
                            return Err("OIDC_TOKEN_ENDPOINT_AUTH_METHOD must be one of: none, client_secret_basic, client_secret_post".into());
                        }
                    }
                    _ => None,
                }
            } else {
                None
            };
            if enabled
                && id_token_alg.as_deref().map(|a| a.to_ascii_uppercase().starts_with("HS")).unwrap_or(false)
                && client_secret.is_none()
            {
                return Err("OIDC_ID_TOKEN_SIGNED_RESPONSE_ALG using HS* requires OIDC_CLIENT_SECRET for a confidential client".into());
            }
            OidcConfig {
                enabled,
                enforced: auth_mode == AuthMode::OidcEnforced,
                provider_name: env.string("OIDC_PROVIDER_NAME", "OIDC"),
                issuer_url,
                discovery_url,
                client_id,
                client_secret,
                redirect_uri,
                id_token_signed_response_alg: id_token_alg,
                token_endpoint_auth_method: token_auth,
                scopes: env.string("OIDC_SCOPES", "openid profile email"),
                email_claim: env.string("OIDC_EMAIL_CLAIM", "email"),
                email_verified_claim: env.string("OIDC_EMAIL_VERIFIED_CLAIM", "email_verified"),
                groups_claim,
                admin_groups,
                require_email_verified: env.boolean("OIDC_REQUIRE_EMAIL_VERIFIED", true),
                jit_provisioning: env.boolean("OIDC_JIT_PROVISIONING", true),
                first_user_admin: env.boolean("OIDC_FIRST_USER_ADMIN", true),
            }
        };

        let password_policy = {
            let min_length = env.number("PASSWORD_MIN_LENGTH", 12.0)?;
            let max_length = env.number("PASSWORD_MAX_LENGTH", 100.0)?;
            if max_length < min_length {
                return Err("PASSWORD_MAX_LENGTH must be greater than or equal to PASSWORD_MIN_LENGTH".into());
            }
            PasswordPolicy {
                min_length,
                max_length,
                require_uppercase: env.boolean("PASSWORD_REQUIRE_UPPERCASE", true),
                require_lowercase: env.boolean("PASSWORD_REQUIRE_LOWERCASE", true),
                require_number: env.boolean("PASSWORD_REQUIRE_NUMBER", true),
                require_symbol: env.boolean("PASSWORD_REQUIRE_SYMBOL", true),
            }
        };

        let backups = BackupConfig {
            schedule: env.opt_string("BACKUP_SCHEDULE"),
            dir: env.opt_string("BACKUP_DIR").map(PathBuf::from).unwrap_or_else(|| backend_root.join("backups")),
            retention_days: env.number("BACKUP_RETENTION_DAYS", 14.0)?,
        };

        let s3 = S3Config {
            bucket: env.opt_string("S3_BUCKET"),
            region: env.string("S3_REGION", "us-east-1"),
            endpoint: env.opt_string("S3_ENDPOINT"),
            public_url: env.opt_string("S3_PUBLIC_URL"),
            force_path_style: env.string("S3_FORCE_PATH_STYLE", "false").to_lowercase() == "true",
            key_prefix: {
                let p = env.raw("S3_KEY_PREFIX").map(|p| p.trim_end_matches('/').to_string()).unwrap_or_default();
                if p.is_empty() { "excalidash".into() } else { p }
            },
            access_key_id: env.opt_string("AWS_ACCESS_KEY_ID"),
            secret_access_key: env.opt_string("AWS_SECRET_ACCESS_KEY"),
        };

        let ttl = |name: &str, default: f64| {
            let parsed = env.raw(name).filter(|r| !r.is_empty()).map(|r| js_number(&r)).unwrap_or(f64::NAN);
            if parsed.is_finite() && parsed > 0.0 { parsed } else { default }
        };
        let link_share = LinkShareConfig {
            edit_default_ttl_ms: ttl("LINK_SHARE_EDIT_DEFAULT_TTL_MS", 7.0 * 24.0 * 60.0 * 60.0 * 1000.0),
            view_default_ttl_ms: ttl("LINK_SHARE_VIEW_DEFAULT_TTL_MS", 30.0 * 24.0 * 60.0 * 60.0 * 1000.0),
            max_ttl_ms: ttl("LINK_SHARE_MAX_TTL_MS", 90.0 * 24.0 * 60.0 * 60.0 * 1000.0),
        };

        let update_check = {
            let outbound_raw = env.raw("UPDATE_CHECK_OUTBOUND").unwrap_or_else(|| "true".into()).trim().to_lowercase();
            let token = env.raw("UPDATE_CHECK_GITHUB_TOKEN").unwrap_or_default().trim().to_string();
            UpdateCheckConfig {
                outbound: matches!(outbound_raw.as_str(), "true" | "1" | "yes"),
                github_token: if token.is_empty() { None } else { Some(token) },
            }
        };

        let mail = {
            let resend_api_key = env.opt_string("RESEND_API_KEY");
            let smtp_host = env.opt_string("SMTP_HOST");
            let explicit = env.raw("MAIL_TRANSPORT").map(|v| v.trim().to_lowercase()).unwrap_or_default();
            let transport = match explicit.as_str() {
                "resend" => MailTransport::Resend,
                "smtp" => MailTransport::Smtp,
                "none" => MailTransport::None,
                "" => {
                    if resend_api_key.is_some() {
                        MailTransport::Resend
                    } else if smtp_host.is_some() {
                        MailTransport::Smtp
                    } else {
                        MailTransport::None
                    }
                }
                _ => return Err("MAIL_TRANSPORT must be one of: resend, smtp, none".into()),
            };
            MailConfig {
                transport,
                resend_api_key,
                from: env.opt_string("MAIL_FROM"),
                reply_to: env.opt_string("MAIL_REPLY_TO"),
                smtp: SmtpConfig {
                    host: smtp_host,
                    port: env.number("SMTP_PORT", 587.0)?,
                    secure: env.boolean("SMTP_SECURE", false),
                    user: env.opt_string("SMTP_USER"),
                    password: env.opt_string("SMTP_PASSWORD"),
                },
            }
        };

        let port = env.number("PORT", 8000.0)?;
        let body_limit_mb = env.number("BODY_LIMIT_MB", 50.0)?;
        let frontend_dist_dir = match env.opt_string("FRONTEND_DIST_DIR") {
            // "none" disables the bundled frontend (backend-only, like the upstream backend image).
            Some(p) if p == "none" => None,
            Some(p) => Some(PathBuf::from(p)),
            None => {
                let default = backend_root.join("public");
                default.join("index.html").is_file().then_some(default)
            }
        };

        let cfg = Config {
            uploads_dir: backend_root.join("uploads"),
            backend_root,
            port: port as u16,
            listen_host: env.string("BACKEND_HOST", "0.0.0.0"),
            is_dev: node_env == "development",
            is_production: node_env == "production",
            node_env,
            build_label: env.opt_string("APP_BUILD_LABEL"),
            database_url,
            database_path,
            allowed_origins: normalize_origins(frontend_url.as_deref()),
            frontend_url,
            trust_proxy,
            drawings_cache_ttl_ms,
            auth_mode,
            jwt_secret,
            jwt_access_expires_in: env.string("JWT_ACCESS_EXPIRES_IN", "15m"),
            jwt_refresh_expires_in: env.string("JWT_REFRESH_EXPIRES_IN", "7d"),
            rate_limit_max_requests: env.number("RATE_LIMIT_MAX_REQUESTS", 1000.0)?,
            rate_limit_window_ms: env.number("RATE_LIMIT_WINDOW_MS", 900000.0)?,
            csrf_max_requests: env.number("CSRF_MAX_REQUESTS", 60.0)?,
            csrf_rate_limit_window_ms: env.number("CSRF_RATE_LIMIT_WINDOW_MS", 60000.0)?,
            snapshot_retention_ms: env.number("SNAPSHOT_RETENTION_DAYS", 2.0)? * 24.0 * 60.0 * 60.0 * 1000.0,
            upload_max_bytes: env.number("UPLOAD_MAX_MB", 100.0)? * 1024.0 * 1024.0,
            body_limit_mb,
            body_limit_bytes: (body_limit_mb * 1024.0 * 1024.0) as usize,
            file_upload_max_mb,
            file_upload_max_bytes: file_upload_max_mb * 1024.0 * 1024.0,
            csrf_secret: env.raw("CSRF_SECRET").filter(|s| !s.is_empty()),
            debug_csrf: env.raw("DEBUG_CSRF").as_deref() == Some("true"),
            api_key_hash_pepper: env.raw("API_KEY_HASH_PEPPER").filter(|s| !s.is_empty()).unwrap_or_else(|| "api-key-hash-pepper".into()),
            oidc,
            enable_password_reset: env.boolean("ENABLE_PASSWORD_RESET", false),
            enable_refresh_token_rotation: env.boolean("ENABLE_REFRESH_TOKEN_ROTATION", true),
            enable_audit_logging: env.boolean("ENABLE_AUDIT_LOGGING", false),
            enforce_https_redirect: env.boolean("ENFORCE_HTTPS_REDIRECT", true),
            disable_onboarding_gate: env.raw("DISABLE_ONBOARDING_GATE").as_deref() == Some("true"),
            bootstrap_setup_code_ttl_ms: env.number("BOOTSTRAP_SETUP_CODE_TTL_MS", 900000.0)?,
            bootstrap_setup_code_max_attempts: env.number("BOOTSTRAP_SETUP_CODE_MAX_ATTEMPTS", 10.0)?,
            password_policy,
            backups,
            s3,
            link_share,
            update_check,
            mail,
            frontend_dist_dir,
        };
        if cfg.node_env == "production" {
            validate_production(&cfg)?;
        }
        Ok(cfg)
    }

    pub fn is_allowed_origin(&self, origin: Option<&str>) -> bool {
        let Some(origin) = origin else { return true };
        if self.allowed_origins.iter().any(|o| o == origin) {
            return true;
        }
        // index.ts uses !isProduction, auth.ts uses nodeEnv !== "production": same thing.
        if !self.is_production && is_local_dev_origin(origin) {
            return true;
        }
        false
    }
}

pub fn is_local_dev_origin(origin: &str) -> bool {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"(?i)^http://(localhost|127\.0\.0\.1):\d+$").unwrap())
        .is_match(origin)
}

fn validate_production(cfg: &Config) -> Result<(), String> {
    if cfg.api_key_hash_pepper == "api-key-hash-pepper" {
        eprintln!("[security] API_KEY_HASH_PEPPER is using the built-in default value in production. Set a unique API_KEY_HASH_PEPPER BEFORE creating any API keys; changing it later invalidates all existing API keys.");
    }
    let normalized = cfg.jwt_secret.trim();
    // JS string length counts UTF-16 code units.
    if cfg.jwt_secret.encode_utf16().count() < 32 {
        return Err("JWT_SECRET must be at least 32 characters long in production".into());
    }
    if ["your-secret-key-change-in-production", "change-this-secret-in-production-min-32-chars"].contains(&normalized) {
        return Err("JWT_SECRET must be changed from placeholder/default value in production".into());
    }
    if cfg.oidc.enabled {
        if let Some(uri) = &cfg.oidc.redirect_uri {
            if !uri.to_ascii_lowercase().starts_with("https://") {
                return Err("OIDC_REDIRECT_URI must be HTTPS in production".into());
            }
        }
    }
    Ok(())
}

pub fn build_password_policy_message(p: &PasswordPolicy) -> String {
    let mut req = vec![format!("at least {} characters", crate::util::js_num_str(p.min_length))];
    if p.require_uppercase {
        req.push("one uppercase letter".into());
    }
    if p.require_lowercase {
        req.push("one lowercase letter".into());
    }
    if p.require_number {
        req.push("one number".into());
    }
    if p.require_symbol {
        req.push("one symbol".into());
    }
    format!("Password must be {}", req.join(", "))
}

/// Returns an error message when the password violates the policy.
pub fn validate_password_against_policy(password: &str, p: &PasswordPolicy) -> Option<String> {
    let len = password.encode_utf16().count() as f64;
    if len < p.min_length {
        return Some(build_password_policy_message(p));
    }
    if len > p.max_length {
        return Some(format!("Password must be at most {} characters long", crate::util::js_num_str(p.max_length)));
    }
    if p.require_uppercase && !password.chars().any(|c| c.is_ascii_uppercase()) {
        return Some(build_password_policy_message(p));
    }
    if p.require_lowercase && !password.chars().any(|c| c.is_ascii_lowercase()) {
        return Some(build_password_policy_message(p));
    }
    if p.require_number && !password.chars().any(|c| c.is_ascii_digit()) {
        return Some(build_password_policy_message(p));
    }
    if p.require_symbol && !password.chars().any(|c| !c.is_ascii_alphanumeric()) {
        return Some(build_password_policy_message(p));
    }
    None
}
