//! auth/coreRoutes.ts + auth/coreRouteHelpers.ts (and the schemas they use):
//! register, login, refresh, logout, stop-impersonation, me, status,
//! onboarding-choice, auth-enabled.
use axum::{
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use rusqlite::{Connection, OptionalExtension};
use serde_json::{json, Map, Value};

use super::helpers::{
    can_use_local_password_flows, effective_oidc_jit_provisioning, effective_registration_enabled, ensure_auth_enabled,
    find_user_by_identifier, login_attempt_rate_limit, refresh_token_expires_at_ms, require_csrf,
};
use crate::audit::{log_audit_event, AuditEvent};
use crate::auth::cookies::{clear_auth_cookies, read_refresh_token, set_access_token_cookie, set_auth_cookies};
use crate::auth::jwt::{decode_any, generate_tokens, parse_payload, sign_claims, TokenOptions};
use crate::auth::middleware::{clear_auth_enabled_cache, ensure_system_config, optional_auth, require_auth};
use crate::bootstrap::VerifyFailure;
use crate::config::{config, AuthMode};
use crate::db::DbError;
use crate::http::body::Body;
use crate::http::ctx::Ctx;
use crate::http::error::{json_response, ApiError};
use crate::models::{bootstrap_acting_user, SystemConfig, User, BOOTSTRAP_USER_ID, DEFAULT_SYSTEM_CONFIG_ID};
use crate::security::js_trim;
use crate::state::AppState;
use crate::util::{js_len, now_ms, sha256_hex, uuid_v4};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/register", post(register))
        .route("/login", post(login))
        .route("/refresh", post(refresh))
        .route("/logout", post(logout))
        .route("/stop-impersonation", post(stop_impersonation))
        .route("/me", get(me))
        .route("/status", get(status))
        .route("/onboarding-choice", post(onboarding_choice))
        .route("/auth-enabled", post(auth_enabled))
}

// ---------------------------------------------------------------------------
// Response plumbing

type Inner = Result<Response, ApiError>;

fn reply(status: u16, body: Value) -> Inner {
    Ok(json_response(StatusCode::from_u16(status).unwrap_or(StatusCode::OK), &body))
}

fn err(status: u16, error: &str, message: &str) -> Inner {
    reply(status, json!({ "error": error, "message": message }))
}

/// Explicit responses pass through; anything thrown lands in the route's
/// `catch` (console.error + 500). Headers set earlier (`res.cookie`, rate-limit
/// headers) stay on whatever response is finally sent.
fn finish(result: Inner, extra: HeaderMap, log_label: &str, fail_message: &str) -> Response {
    let mut res = match result {
        Ok(r) => r,
        Err(ApiError::Json(status, body)) => json_response(status, &body),
        Err(ApiError::Thrown { message, .. }) => {
            eprintln!("{log_label} {message}");
            json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &json!({ "error": "Internal server error", "message": fail_message }),
            )
        }
    };
    let mut last = None;
    for (k, v) in extra {
        let k = match k {
            Some(k) => {
                last = Some(k.clone());
                k
            }
            None => last.clone().unwrap(),
        };
        if k == header::SET_COOKIE {
            res.headers_mut().append(k, v);
        } else if !res.headers().contains_key(&k) {
            res.headers_mut().insert(k, v);
        }
    }
    res
}

fn thrown(e: impl std::fmt::Display) -> ApiError {
    ApiError::internal(e.to_string())
}

/// JS number → JSON (integers without a trailing `.0`).
fn js_number(n: f64) -> Value {
    if n.is_finite() && n.fract() == 0.0 && n.abs() < 9_007_199_254_740_992.0 {
        Value::from(n as i64)
    } else {
        Value::from(n)
    }
}

fn is_missing_refresh_token_table(e: &DbError) -> bool {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"(?i)no such table:\s*RefreshToken").unwrap()).is_match(&e.to_string())
}

fn refresh_storage_unavailable() -> Inner {
    err(503, "Service unavailable", "Refresh token storage is unavailable. Please run database migrations.")
}

fn audit(ctx: &Ctx, user_id: Option<String>, action: &str, details: Option<Map<String, Value>>) -> AuditEvent {
    AuditEvent {
        user_id,
        action: action.to_string(),
        resource: None,
        ip_address: Some(ctx.ip.clone()).filter(|s| !s.is_empty()),
        user_agent: ctx.user_agent().map(str::to_string).filter(|s| !s.is_empty()),
        details,
    }
}

// ---------------------------------------------------------------------------
// bcrypt (node `bcrypt` compatible: $2b$, cost 10, C-string password)

const SALT_ROUNDS: u32 = 10;

fn c_string_bytes(password: &str) -> Vec<u8> {
    let b = password.as_bytes();
    b[..b.iter().position(|&x| x == 0).unwrap_or(b.len())].to_vec()
}

async fn bcrypt_hash(password: String) -> Result<String, ApiError> {
    tokio::task::spawn_blocking(move || bcrypt::hash(c_string_bytes(&password), SALT_ROUNDS))
        .await
        .map_err(thrown)?
        .map_err(thrown)
}

async fn bcrypt_compare(password: String, hash: String) -> Result<bool, ApiError> {
    tokio::task::spawn_blocking(move || bcrypt::verify(c_string_bytes(&password), &hash))
        .await
        .map_err(thrown)?
        .map_err(thrown)
}

// ---------------------------------------------------------------------------
// zod (v4) subset used by auth/schemas.ts

fn js_type(v: Option<&Value>) -> &'static str {
    match v {
        None => "undefined",
        Some(Value::Null) => "null",
        Some(Value::Bool(_)) => "boolean",
        Some(Value::Number(_)) => "number",
        Some(Value::String(_)) => "string",
        Some(Value::Array(_)) => "array",
        Some(Value::Object(_)) => "object",
    }
}

fn expected(kind: &str, v: Option<&Value>) -> String {
    format!("Invalid input: expected {kind}, received {}", js_type(v))
}

/// zod's default (practical) email regex, minus JS lookaheads which are checked by hand.
pub fn zod_email_ok(s: &str) -> bool {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let re = RE.get_or_init(|| {
        regex::Regex::new(r"^([A-Za-z0-9_'+\-\.]*)[A-Za-z0-9_+-]@([A-Za-z0-9][A-Za-z0-9\-]*\.)+[A-Za-z]{2,}$").unwrap()
    });
    !s.starts_with('.') && !s.contains("..") && re.is_match(s)
}

/// `z.string().trim().min(min).max(max)` (optional when `required` is false).
fn zod_trimmed(v: Option<&Value>, min: usize, max: usize, required: bool) -> Result<Option<String>, String> {
    match v {
        None if !required => Ok(None),
        Some(Value::String(s)) => {
            let t = js_trim(s).to_string();
            let len = js_len(&t);
            if len < min {
                return Err(format!("Too small: expected string to have >={min} characters"));
            }
            if len > max {
                return Err(format!("Too big: expected string to have <={max} characters"));
            }
            Ok(Some(t))
        }
        other => Err(expected("string", other)),
    }
}

/// `z.string().email().toLowerCase().trim()` (checks run before the overwrites).
fn zod_email(v: Option<&Value>, required: bool) -> Result<Option<String>, String> {
    match v {
        None if !required => Ok(None),
        Some(Value::String(s)) => {
            if !zod_email_ok(s) {
                return Err("Invalid email address".into());
            }
            Ok(Some(js_trim(&s.to_lowercase()).to_string()))
        }
        other => Err(expected("string", other)),
    }
}

struct RegisterInput {
    email: String,
    password: String,
    name: String,
    username: Option<String>,
    setup_code: Option<String>,
}

/// registerSchema.safeParse → data, or the 400 body coreRoutes sends.
fn parse_register(body: &Body) -> Result<RegisterInput, Value> {
    let fail = |form: Vec<String>, fields: Map<String, Value>| {
        let mut messages: Vec<String> = form.clone();
        for v in fields.values() {
            if let Some(a) = v.as_array() {
                messages.extend(a.iter().filter_map(|m| m.as_str().map(str::to_string)));
            }
        }
        let first = messages.into_iter().find(|m| !js_trim(m).is_empty());
        json!({
            "error": "Validation error",
            "message": first.unwrap_or_else(|| "Invalid registration data".into()),
            "details": { "formErrors": form, "fieldErrors": fields },
        })
    };
    let obj = match &body.0 {
        Some(Value::Object(m)) => m,
        other => return Err(fail(vec![expected("object", other.as_ref())], Map::new())),
    };
    let mut fields = Map::new();
    let mut note = |k: &str, r: Result<(), String>| {
        if let Err(m) = r {
            fields.insert(k.into(), json!([m]));
        }
    };
    let username = zod_trimmed(obj.get("username"), 3, 50, false);
    let email = zod_email(obj.get("email"), true);
    let password = match obj.get("password") {
        Some(Value::String(p)) => match crate::config::validate_password_against_policy(p, &config().password_policy) {
            Some(m) => Err(m),
            None => Ok(p.clone()),
        },
        other => Err(expected("string", other)),
    };
    let name = zod_trimmed(obj.get("name"), 1, 100, true);
    let setup_code = zod_trimmed(obj.get("setupCode"), 1, 64, false);
    note("username", username.as_ref().map(|_| ()).map_err(Clone::clone));
    note("email", email.as_ref().map(|_| ()).map_err(Clone::clone));
    note("password", password.as_ref().map(|_| ()).map_err(Clone::clone));
    note("name", name.as_ref().map(|_| ()).map_err(Clone::clone));
    note("setupCode", setup_code.as_ref().map(|_| ()).map_err(Clone::clone));
    if !fields.is_empty() {
        return Err(fail(vec![], fields));
    }
    Ok(RegisterInput {
        email: email.unwrap().unwrap_or_default(),
        password: password.unwrap(),
        name: name.unwrap().unwrap_or_default(),
        username: username.unwrap(),
        setup_code: setup_code.unwrap(),
    })
}

/// loginSchema.safeParse → (identifier, password).
fn parse_login(body: &Body) -> Option<(String, String)> {
    let Some(Value::Object(obj)) = &body.0 else { return None };
    let identifier = zod_trimmed(obj.get("identifier"), 1, 255, false).ok()?;
    let email = zod_email(obj.get("email"), false).ok()?;
    let username = zod_trimmed(obj.get("username"), 1, 255, false).ok()?;
    let password = obj.get("password")?.as_str()?.to_string();
    let pick = |v: &Option<String>| v.clone().filter(|s| !s.is_empty());
    let id = pick(&email).or_else(|| pick(&username)).or_else(|| pick(&identifier))?;
    Some((id, password))
}

/// `z.object({ <key>: z.boolean() })`
fn parse_bool_field(body: &Body, key: &str) -> Option<bool> {
    match &body.0 {
        Some(Value::Object(m)) => m.get(key)?.as_bool(),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// coreRouteHelpers.ts

struct OnboardingStatus {
    active_users: i64,
    needs_choice: bool,
    mode: &'static str,
}

fn count(c: &Connection, sql: &str) -> rusqlite::Result<i64> {
    c.query_row(sql, [], |r| r.get(0))
}

fn count_active_users(c: &Connection) -> rusqlite::Result<i64> {
    count(c, r#"SELECT COUNT(*) FROM "User" WHERE "isActive" = 1"#)
}

/// `prisma.user.findUnique({ where: { id: BOOTSTRAP_USER_ID }, select: { isActive } })`
fn bootstrap_user_active(c: &Connection) -> rusqlite::Result<Option<bool>> {
    c.query_row(r#"SELECT "isActive" FROM "User" WHERE "id" = ?1"#, [BOOTSTRAP_USER_ID], |r| crate::db::boolean(r, 0))
        .optional()
}

fn auth_onboarding_status(c: &Connection, sc: &SystemConfig) -> rusqlite::Result<OnboardingStatus> {
    let active_users = count_active_users(c)?;
    let drawings = count(c, r#"SELECT COUNT(*) FROM "Drawing""#)?;
    let collections = count(c, r#"SELECT COUNT(*) FROM "Collection""#)?;
    let has_legacy_data = drawings > 0 || collections > 0;
    Ok(OnboardingStatus {
        active_users,
        needs_choice: !sc.auth_enabled && active_users == 0 && !sc.auth_onboarding_completed,
        mode: if has_legacy_data { "migration" } else { "fresh" },
    })
}

fn bootstrap_required(auth_enabled: bool, bootstrap_active: Option<bool>, active_users: i64) -> bool {
    auth_enabled && !config().oidc.enforced && bootstrap_active == Some(false) && active_users == 0
}

/// upsertAuthModeState (authOnboardingCompleted = true).
fn upsert_auth_mode_state(c: &Connection, registration_enabled: bool, auth_enabled: bool) -> rusqlite::Result<SystemConfig> {
    let now = now_ms();
    c.execute(
        r#"INSERT INTO "SystemConfig" ("id","authEnabled","authOnboardingCompleted","registrationEnabled","authLoginRateLimitEnabled","authLoginRateLimitWindowMs","authLoginRateLimitMax","bootstrapSetupCodeFailedAttempts","createdAt","updatedAt")
           VALUES (?1, ?2, 1, ?3, 1, 900000, 20, 0, ?4, ?4)
           ON CONFLICT("id") DO UPDATE SET "authEnabled" = excluded."authEnabled", "authOnboardingCompleted" = 1, "updatedAt" = excluded."updatedAt""#,
        rusqlite::params![DEFAULT_SYSTEM_CONFIG_ID, auth_enabled, registration_enabled, now],
    )?;
    Ok(SystemConfig::find(c)?.expect("system config row"))
}

/// `prisma.collection.upsert({ where: { id: trash:<id> }, update: {}, create })`
fn upsert_trash_collection(c: &Connection, user_id: &str) -> rusqlite::Result<()> {
    let now = now_ms();
    c.execute(
        r#"INSERT INTO "Collection" ("id","name","userId","createdAt","updatedAt") VALUES (?1,'Trash',?2,?3,?3) ON CONFLICT("id") DO NOTHING"#,
        rusqlite::params![crate::trash::user_trash_collection_id(user_id), user_id, now],
    )?;
    Ok(())
}

fn create_refresh_token(c: &Connection, user_id: &str, refresh_token: &str, expires_at: i64) -> rusqlite::Result<()> {
    c.execute(
        r#"INSERT INTO "RefreshToken" ("id","userId","token","expiresAt","revoked","createdAt") VALUES (?1,?2,?3,?4,0,?5)"#,
        rusqlite::params![uuid_v4(), user_id, sha256_hex(refresh_token), expires_at, now_ms()],
    )?;
    Ok(())
}

async fn store_refresh_token(st: &AppState, user_id: &str, refresh_token: &str) -> Result<(), DbError> {
    let (uid, token, expires_at) = (user_id.to_string(), refresh_token.to_string(), refresh_token_expires_at_ms());
    st.db.call(move |c| Ok(create_refresh_token(c, &uid, &token, expires_at)?)).await
}

fn user_summary(u: &User) -> Value {
    json!({
        "id": u.id,
        "email": u.email,
        "name": u.name,
        "role": u.role,
        "mustResetPassword": u.must_reset_password,
    })
}

// ---------------------------------------------------------------------------
// POST /register

async fn register(State(st): State<AppState>, ctx: Ctx, body: Body) -> Response {
    let decision = match login_attempt_rate_limit(&st.db, &ctx, &body).await {
        Ok(d) => d,
        Err(r) => return r,
    };
    let mut extra = HeaderMap::new();
    decision.apply(&mut extra);
    let result = register_inner(&st, &ctx, &body, &mut extra).await;
    finish(result, extra, "Registration error:", "Failed to register user")
}

async fn register_inner(st: &AppState, ctx: &Ctx, body: &Body, extra: &mut HeaderMap) -> Inner {
    let cfg = config();
    ensure_auth_enabled(&st.db).await?;
    if cfg.auth_mode == AuthMode::OidcEnforced {
        return err(403, "Forbidden", "Local registration is disabled in OIDC enforced mode");
    }
    require_csrf(ctx)?;
    let input = match parse_register(body) {
        Ok(i) => i,
        Err(b) => return reply(400, b),
    };
    let system_config = ensure_system_config(&st.db).await?;
    let (active_users, bootstrap_active) =
        st.db.call(|c| Ok((count_active_users(c)?, bootstrap_user_active(c)?))).await?;
    let is_bootstrap_flow = bootstrap_active == Some(false) && active_users == 0;

    if is_bootstrap_flow {
        let max_attempts = (cfg.bootstrap_setup_code_max_attempts.floor() as i64).max(1);
        if let Err(reason) = crate::bootstrap::verify(&st.db, input.setup_code.clone(), max_attempts).await? {
            if matches!(reason, VerifyFailure::Unavailable | VerifyFailure::Expired | VerifyFailure::Locked) {
                crate::bootstrap::issue_if_required(&st.db, "bootstrap_register_reissue").await?;
            }
            return match reason {
                VerifyFailure::Missing => {
                    err(400, "Bad request", "Bootstrap setup code is required for first admin registration")
                }
                VerifyFailure::Invalid => err(401, "Unauthorized", "Invalid bootstrap setup code"),
                VerifyFailure::Locked => err(
                    429,
                    "Too many requests",
                    "Too many invalid setup code attempts. A new setup code has been issued in backend logs.",
                ),
                _ => err(
                    409,
                    "Conflict",
                    "Bootstrap setup code is unavailable or expired. A new setup code has been issued in backend logs.",
                ),
            };
        }
        let password_hash = bcrypt_hash(input.password.clone()).await?;
        let name = crate::security::sanitize_text(&input.name, 100);
        let (email, username) = (input.email.clone(), input.username.clone());
        let conflict = st
            .db
            .call(move |c| {
                let by_email: Option<String> = c
                    .query_row(r#"SELECT "id" FROM "User" WHERE "email" = ?1"#, [&email], |r| r.get(0))
                    .optional()?;
                if by_email.is_some_and(|id| id != BOOTSTRAP_USER_ID) {
                    return Ok(Some("User with this email already exists"));
                }
                if let Some(u) = &username {
                    let by_username: Option<String> = c
                        .query_row(r#"SELECT "id" FROM "User" WHERE "username" = ?1 LIMIT 1"#, [u], |r| r.get(0))
                        .optional()?;
                    if by_username.is_some_and(|id| id != BOOTSTRAP_USER_ID) {
                        return Ok(Some("User with this username already exists"));
                    }
                }
                Ok(None)
            })
            .await?;
        if let Some(message) = conflict {
            return err(409, "Conflict", message);
        }
        let (email, username) = (input.email.clone(), input.username.clone());
        let updated = st
            .db
            .call(move |c| {
                c.execute(
                    r#"UPDATE "User" SET "email" = ?1, "username" = ?2, "passwordHash" = ?3, "name" = ?4, "role" = 'ADMIN',
                       "mustResetPassword" = 0, "isActive" = 1, "updatedAt" = ?5 WHERE "id" = ?6"#,
                    rusqlite::params![email, username, password_hash, name, now_ms(), BOOTSTRAP_USER_ID],
                )?;
                Ok(User::find_by_id(c, BOOTSTRAP_USER_ID)?)
            })
            .await;
        let user = match updated {
            Ok(Some(u)) => u,
            Ok(None) => return Err(ApiError::internal("Record to update not found.")),
            Err(e) if e.is_unique_violation() => {
                return err(409, "Conflict", "User with this email or username already exists");
            }
            Err(e) => return Err(thrown(e)),
        };
        let uid = user.id.clone();
        st.db.call(move |c| Ok(upsert_trash_collection(c, &uid)?)).await?;
        let (access, refresh) = generate_tokens(&user.id, &user.email, TokenOptions::default());
        set_auth_cookies(ctx, extra, &access, &refresh);
        if cfg.enable_refresh_token_rotation {
            store_refresh_token(st, &user.id, &refresh).await?;
        }
        log_audit_event(&st.db, audit(ctx, Some(user.id.clone()), "bootstrap_admin", None)).await;
        return reply(
            201,
            json!({
                "user": user_summary(&user),
                "registrationEnabled": system_config.registration_enabled,
                "bootstrapped": true,
            }),
        );
    }

    if !system_config.registration_enabled {
        return err(403, "Forbidden", "User registration is disabled.");
    }
    let (email, username) = (input.email.clone(), input.username.clone());
    let conflict = st
        .db
        .call(move |c| {
            if User::find_by_email(c, &email)?.is_some() {
                return Ok(Some("User with this email already exists"));
            }
            if let Some(u) = &username {
                if crate::db::exists(c, r#"SELECT 1 FROM "User" WHERE "username" = ?1 LIMIT 1"#, [u])? {
                    return Ok(Some("User with this username already exists"));
                }
            }
            Ok(None)
        })
        .await?;
    if let Some(message) = conflict {
        return err(409, "Conflict", message);
    }
    let password_hash = bcrypt_hash(input.password.clone()).await?;
    let name = crate::security::sanitize_text(&input.name, 100);
    let (email, username) = (input.email.clone(), input.username.clone());
    let user = st
        .db
        .call(move |c| {
            let id = uuid_v4();
            let now = now_ms();
            c.execute(
                r#"INSERT INTO "User" ("id","username","email","passwordHash","name","role","mustResetPassword","isActive","createdAt","updatedAt")
                   VALUES (?1,?2,?3,?4,?5,'USER',0,1,?6,?6)"#,
                rusqlite::params![id, username, email, password_hash, name, now],
            )?;
            upsert_trash_collection(c, &id)?;
            Ok(User::find_by_id(c, &id)?.expect("created user"))
        })
        .await?;
    let (access, refresh) = generate_tokens(&user.id, &user.email, TokenOptions::default());
    set_auth_cookies(ctx, extra, &access, &refresh);
    if cfg.enable_refresh_token_rotation {
        if let Err(e) = store_refresh_token(st, &user.id, &refresh).await {
            if is_missing_refresh_token_table(&e) {
                eprintln!("Refresh token rotation is enabled but refresh token storage is unavailable");
                return refresh_storage_unavailable();
            }
            return Err(thrown(e));
        }
    }
    log_audit_event(&st.db, audit(ctx, Some(user.id.clone()), "user_registered", None)).await;
    reply(
        201,
        json!({
            "user": user_summary(&user),
            "registrationEnabled": system_config.registration_enabled,
        }),
    )
}

// ---------------------------------------------------------------------------
// POST /login

async fn login(State(st): State<AppState>, ctx: Ctx, body: Body) -> Response {
    let decision = match login_attempt_rate_limit(&st.db, &ctx, &body).await {
        Ok(d) => d,
        Err(r) => return r,
    };
    let mut extra = HeaderMap::new();
    decision.apply(&mut extra);
    let result = login_inner(&st, &ctx, &body, &mut extra).await;
    finish(result, extra, "Login error:", "Failed to login")
}

async fn login_inner(st: &AppState, ctx: &Ctx, body: &Body, extra: &mut HeaderMap) -> Inner {
    let cfg = config();
    ensure_auth_enabled(&st.db).await?;
    if cfg.auth_mode == AuthMode::OidcEnforced {
        return err(403, "Forbidden", "Local login is disabled in OIDC enforced mode");
    }
    require_csrf(ctx)?;
    let Some((identifier, password)) = parse_login(body) else {
        return err(400, "Validation error", "Invalid login credentials");
    };
    let ident = identifier.clone();
    let (needs_bootstrap, user) = st
        .db
        .call(move |c| {
            if bootstrap_user_active(c)? == Some(false) && count_active_users(c)? == 0 {
                return Ok((true, None));
            }
            Ok((false, find_user_by_identifier(c, &ident)?))
        })
        .await?;
    if needs_bootstrap {
        return err(
            409,
            "Bootstrap required",
            "Initial admin account has not been configured yet. Register to bootstrap.",
        );
    }
    let invalid = || err(401, "Unauthorized", "Invalid email or password");
    let Some(user) = user else { return invalid() };
    if !user.is_active || !can_use_local_password_flows(Some(&user.password_hash)) {
        return invalid();
    }
    if !bcrypt_compare(password, user.password_hash.clone()).await? {
        let mut details = Map::new();
        details.insert("identifier".into(), Value::String(identifier));
        log_audit_event(&st.db, audit(ctx, None, "login_failed", Some(details))).await;
        return invalid();
    }
    let (access, refresh) = generate_tokens(&user.id, &user.email, TokenOptions::default());
    set_auth_cookies(ctx, extra, &access, &refresh);
    if cfg.enable_refresh_token_rotation {
        if let Err(e) = store_refresh_token(st, &user.id, &refresh).await {
            if is_missing_refresh_token_table(&e) {
                eprintln!("Refresh token rotation is enabled but refresh token storage is unavailable");
                return refresh_storage_unavailable();
            }
            return Err(thrown(e));
        }
    }
    log_audit_event(&st.db, audit(ctx, Some(user.id.clone()), "login", None)).await;
    reply(200, json!({ "user": user_summary(&user) }))
}

// ---------------------------------------------------------------------------
// POST /refresh

/// jsonwebtoken `expiresIn` (string → `ms`, purely numeric string = ms).
fn expires_in_seconds(expires_in: &str) -> Option<i64> {
    let t = expires_in.trim();
    if !t.is_empty() && t.chars().all(|c| c.is_ascii_digit()) {
        return t.parse::<f64>().ok().map(|n| (n / 1000.0).floor() as i64);
    }
    crate::util::parse_ms(expires_in).map(|ms| (ms / 1000.0).floor() as i64)
}

async fn refresh(State(st): State<AppState>, ctx: Ctx) -> Response {
    let mut extra = HeaderMap::new();
    let result = refresh_inner(&st, &ctx, &mut extra).await;
    finish(result, extra, "Refresh token error:", "Failed to refresh token")
}

enum RotateError {
    Http(&'static str),
    Db(DbError),
}

async fn refresh_inner(st: &AppState, ctx: &Ctx, extra: &mut HeaderMap) -> Inner {
    ensure_auth_enabled(&st.db).await?;
    require_csrf(ctx)?;
    let Some(old_refresh) = read_refresh_token(ctx) else {
        return err(401, "Unauthorized", "Refresh token required");
    };
    match refresh_verified(st, ctx, extra, &old_refresh).await {
        Ok(r) => Ok(r),
        Err(_) => err(401, "Unauthorized", "Invalid or expired refresh token"),
    }
}

/// The inner `try` of the refresh route: anything thrown here becomes a 401.
async fn refresh_verified(st: &AppState, ctx: &Ctx, extra: &mut HeaderMap, old_refresh: &str) -> Inner {
    let cfg = config();
    let Some(claims) = decode_any(old_refresh, &cfg.jwt_secret) else {
        return Err(ApiError::internal("jwt verify failed"));
    };
    let Some(decoded) = parse_payload(claims, false) else {
        return err(401, "Unauthorized", "Invalid token payload");
    };
    if decoded.token_type != "refresh" {
        return err(401, "Unauthorized", "Invalid token type");
    }
    let uid = decoded.user_id.clone();
    let user = st.db.call(move |c| Ok(User::find_by_id(c, &uid)?)).await?;
    let Some(user) = user.filter(|u| u.is_active) else {
        return err(401, "Unauthorized", "User account not found or inactive");
    };

    if cfg.enable_refresh_token_rotation {
        let (access, new_refresh) = generate_tokens(
            &user.id,
            &user.email,
            TokenOptions {
                impersonator_id: decoded.impersonator_id.clone(),
                auth_provider: decoded.auth_provider.clone(),
                oidc_groups: decoded.oidc_groups.clone(),
            },
        );
        let expires_at = refresh_token_expires_at_ms();
        let (old, new, user_id) = (old_refresh.to_string(), new_refresh.clone(), user.id.clone());
        let rotated = st
            .db
            .tx(move |tx| {
                let candidates = [old.clone(), sha256_hex(&old)];
                let stored = tx
                    .query_row(
                        r#"SELECT "id","userId","revoked","expiresAt" FROM "RefreshToken" WHERE "token" = ?1 OR "token" = ?2 LIMIT 1"#,
                        rusqlite::params![candidates[0], candidates[1]],
                        |r| {
                            Ok((
                                r.get::<_, String>(0)?,
                                r.get::<_, String>(1)?,
                                crate::db::boolean(r, 2)?,
                                crate::db::dt(r, 3)?,
                            ))
                        },
                    )
                    .optional()?;
                let Some((id, owner, revoked, token_expires)) = stored else {
                    return Ok(Err("Invalid or revoked refresh token"));
                };
                if owner != user_id || revoked {
                    return Ok(Err("Invalid or revoked refresh token"));
                }
                if now_ms() > token_expires {
                    return Ok(Err("Refresh token has expired"));
                }
                let n = tx.execute(r#"UPDATE "RefreshToken" SET "revoked" = 1 WHERE "id" = ?1 AND "revoked" = 0"#, [&id])?;
                if n != 1 {
                    return Ok(Err("Invalid or revoked refresh token"));
                }
                create_refresh_token(tx, &user_id, &new, expires_at)?;
                Ok(Ok(()))
            })
            .await
            .map_err(RotateError::Db)
            .and_then(|r| r.map_err(RotateError::Http));
        return match rotated {
            Ok(()) => {
                set_auth_cookies(ctx, extra, &access, &new_refresh);
                reply(200, json!({ "ok": true }))
            }
            Err(RotateError::Http(message)) => err(401, "Unauthorized", message),
            Err(RotateError::Db(e)) if is_missing_refresh_token_table(&e) => {
                eprintln!("Refresh token rotation is enabled but refresh token storage is unavailable");
                refresh_storage_unavailable()
            }
            Err(RotateError::Db(e)) => {
                eprintln!("Refresh token rotation error: {e}");
                err(500, "Internal server error", "Failed to rotate refresh token")
            }
        };
    }

    // jwt.sign({ userId, email, type, impersonatorId, authProvider, oidcGroups }, secret, { expiresIn })
    let Some(exp_secs) = expires_in_seconds(&cfg.jwt_access_expires_in) else {
        return Err(ApiError::internal("invalid expiresIn"));
    };
    let iat = chrono::Utc::now().timestamp();
    let mut claims = Map::new();
    claims.insert("userId".into(), Value::String(user.id.clone()));
    claims.insert("email".into(), Value::String(user.email.clone()));
    claims.insert("type".into(), Value::String("access".into()));
    if let Some(i) = &decoded.impersonator_id {
        claims.insert("impersonatorId".into(), Value::String(i.clone()));
    }
    if let Some(p) = &decoded.auth_provider {
        claims.insert("authProvider".into(), Value::String(p.clone()));
    }
    if let Some(g) = &decoded.oidc_groups {
        claims.insert("oidcGroups".into(), json!(g));
    }
    claims.insert("iat".into(), Value::from(iat));
    claims.insert("exp".into(), Value::from(iat + exp_secs));
    let access = sign_claims(&claims);
    set_access_token_cookie(ctx, extra, &access);
    reply(200, json!({ "ok": true }))
}

// ---------------------------------------------------------------------------
// POST /logout

async fn logout(State(st): State<AppState>, ctx: Ctx) -> Response {
    let opt = optional_auth(&st.db, &ctx).await;
    let mut extra = HeaderMap::new();
    let result = async {
        ensure_auth_enabled(&st.db).await?;
        require_csrf(&ctx)?;
        clear_auth_cookies(&ctx, &mut extra);
        if config().enable_refresh_token_rotation {
            if let Some(uid) = opt.user.as_ref().map(|u| u.id.clone()).filter(|id| !id.is_empty()) {
                st.db
                    .call(move |c| {
                        c.execute(r#"UPDATE "RefreshToken" SET "revoked" = 1 WHERE "userId" = ?1 AND "revoked" = 0"#, [&uid])?;
                        Ok(())
                    })
                    .await?;
            }
        }
        reply(200, json!({ "ok": true }))
    }
    .await;
    finish(result, extra, "Logout error:", "Failed to logout")
}

// ---------------------------------------------------------------------------
// POST /stop-impersonation

async fn stop_impersonation(State(st): State<AppState>, ctx: Ctx) -> Response {
    let user = match require_auth(&st.db, &ctx).await {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };
    let mut extra = HeaderMap::new();
    let result = async {
        ensure_auth_enabled(&st.db).await?;
        require_csrf(&ctx)?;
        let Some(impersonator_id) = user.impersonator_id.clone() else {
            return err(409, "Conflict", "Not currently impersonating another user");
        };
        let impersonator = st.db.call(move |c| Ok(User::find_by_id(c, &impersonator_id)?)).await?;
        let Some(imp) = impersonator.filter(|u| u.is_active && u.role == "ADMIN") else {
            return err(403, "Forbidden", "Impersonator account is unavailable or no longer authorized");
        };
        let (access, refresh) = generate_tokens(&imp.id, &imp.email, TokenOptions::default());
        set_auth_cookies(&ctx, &mut extra, &access, &refresh);
        if config().enable_refresh_token_rotation {
            if let Err(e) = store_refresh_token(&st, &imp.id, &refresh).await {
                if is_missing_refresh_token_table(&e) {
                    return refresh_storage_unavailable();
                }
                return Err(thrown(e));
            }
        }
        reply(
            200,
            json!({
                "user": {
                    "id": imp.id,
                    "username": imp.username,
                    "email": imp.email,
                    "name": imp.name,
                    "role": imp.role,
                    "mustResetPassword": imp.must_reset_password,
                }
            }),
        )
    }
    .await;
    finish(result, extra, "Stop impersonation error:", "Failed to stop impersonation")
}

// ---------------------------------------------------------------------------
// GET /me

async fn me(State(st): State<AppState>, ctx: Ctx) -> Response {
    let user = match require_auth(&st.db, &ctx).await {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };
    let result = async {
        ensure_auth_enabled(&st.db).await?;
        let id = user.id.clone();
        let Some(u) = st.db.call(move |c| Ok(User::find_by_id(c, &id)?)).await? else {
            return err(404, "Not found", "User not found");
        };
        reply(
            200,
            json!({
                "user": {
                    "id": u.id,
                    "username": u.username,
                    "email": u.email,
                    "name": u.name,
                    "role": u.role,
                    "mustResetPassword": u.must_reset_password,
                    "createdAt": u.created_iso(),
                    "updatedAt": u.updated_iso(),
                }
            }),
        )
    }
    .await;
    finish(result, HeaderMap::new(), "Get user error:", "Failed to get user information")
}

// ---------------------------------------------------------------------------
// GET /status

async fn status(State(st): State<AppState>, ctx: Ctx) -> Response {
    let opt = optional_auth(&st.db, &ctx).await;
    let result = async {
        let cfg = config();
        let sc = ensure_system_config(&st.db).await?;
        let sc2 = sc.clone();
        let (onboarding, bootstrap_active) =
            st.db.call(move |c| Ok((auth_onboarding_status(c, &sc2)?, bootstrap_user_active(c)?))).await?;
        let effective_auth_enabled =
            if cfg.auth_mode != AuthMode::Local { cfg.auth_mode.enables_auth() } else { sc.auth_enabled };
        let local = cfg.auth_mode == AuthMode::Local;
        let onboarding_required = local && onboarding.needs_choice;
        let exposed = if effective_auth_enabled { opt.user.as_ref() } else { None };
        let user = match exposed {
            Some(u) => {
                let mut m = Map::new();
                m.insert("id".into(), json!(u.id));
                m.insert("username".into(), json!(u.username));
                m.insert("email".into(), json!(u.email));
                m.insert("name".into(), json!(u.name));
                m.insert("role".into(), json!(u.role));
                m.insert("mustResetPassword".into(), json!(u.must_reset_password));
                if let Some(i) = &u.impersonator_id {
                    m.insert("impersonatorId".into(), json!(i));
                }
                Value::Object(m)
            }
            None => Value::Null,
        };
        let p = &cfg.password_policy;
        reply(
            200,
            json!({
                "enabled": effective_auth_enabled,
                "authenticated": exposed.is_some(),
                "authEnabled": effective_auth_enabled,
                "authMode": cfg.auth_mode.as_str(),
                "oidcEnabled": cfg.oidc.enabled,
                "oidcEnforced": cfg.oidc.enforced,
                "oidcProvider": cfg.oidc.provider_name,
                "oidcJitProvisioningEnabled": effective_oidc_jit_provisioning(&sc),
                "registrationEnabled": effective_auth_enabled && effective_registration_enabled(sc.registration_enabled),
                "bootstrapRequired": effective_auth_enabled
                    && bootstrap_required(effective_auth_enabled, bootstrap_active, onboarding.active_users),
                "authOnboardingRequired": onboarding_required,
                "authOnboardingMode": if local { json!(onboarding.mode) } else { Value::Null },
                "authOnboardingRecommended": if onboarding_required { json!("enable") } else { Value::Null },
                "passwordPolicy": {
                    "minLength": js_number(p.min_length),
                    "maxLength": js_number(p.max_length),
                    "requireUppercase": p.require_uppercase,
                    "requireLowercase": p.require_lowercase,
                    "requireNumber": p.require_number,
                    "requireSymbol": p.require_symbol,
                },
                "user": user,
            }),
        )
    }
    .await;
    finish(result, HeaderMap::new(), "Auth status error:", "Failed to fetch auth status")
}

// ---------------------------------------------------------------------------
// POST /onboarding-choice

async fn onboarding_choice(State(st): State<AppState>, ctx: Ctx, body: Body) -> Response {
    let _ = optional_auth(&st.db, &ctx).await;
    let result = async {
        if config().auth_mode != AuthMode::Local {
            return err(409, "Conflict", "Onboarding choice is managed by AUTH_MODE configuration");
        }
        require_csrf(&ctx)?;
        let Some(enable_auth) = parse_bool_field(&body, "enableAuth") else {
            return err(400, "Bad request", "Invalid onboarding choice payload");
        };
        let sc = ensure_system_config(&st.db).await?;
        let sc2 = sc.clone();
        let onboarding = st.db.call(move |c| Ok(auth_onboarding_status(c, &sc2)?)).await?;
        if !onboarding.needs_choice {
            return err(409, "Conflict", "Authentication onboarding is already completed");
        }
        let registration_enabled = sc.registration_enabled;
        let updated = st
            .db
            .call(move |c| {
                if enable_auth {
                    bootstrap_acting_user(c)?;
                }
                Ok(upsert_auth_mode_state(c, registration_enabled, enable_auth)?)
            })
            .await?;
        clear_auth_enabled_cache();
        if enable_auth {
            crate::bootstrap::issue_if_required(&st.db, "onboarding_enabled").await?;
        }
        reply(
            200,
            json!({
                "authEnabled": updated.auth_enabled,
                "authOnboardingCompleted": updated.auth_onboarding_completed,
                "bootstrapRequired": enable_auth,
            }),
        )
    }
    .await;
    finish(result, HeaderMap::new(), "Auth onboarding choice error:", "Failed to apply authentication onboarding choice")
}

// ---------------------------------------------------------------------------
// POST /auth-enabled

async fn auth_enabled(State(st): State<AppState>, ctx: Ctx, body: Body) -> Response {
    let user = match require_auth(&st.db, &ctx).await {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };
    let result = async {
        let cfg = config();
        if cfg.auth_mode != AuthMode::Local {
            return err(409, "Conflict", &format!("Authentication mode is managed by AUTH_MODE={}", cfg.auth_mode.as_str()));
        }
        require_csrf(&ctx)?;
        if user.role != "ADMIN" {
            return err(403, "Forbidden", "Admin access required");
        }
        let Some(next) = parse_bool_field(&body, "enabled") else {
            return err(400, "Bad request", "Invalid toggle payload");
        };
        let sc = ensure_system_config(&st.db).await?;
        let current = sc.auth_enabled;
        let registration_enabled = sc.registration_enabled;
        let updated = st
            .db
            .call(move |c| {
                if !current && next {
                    bootstrap_acting_user(c)?;
                }
                Ok(upsert_auth_mode_state(c, registration_enabled, next)?)
            })
            .await?;
        clear_auth_enabled_cache();
        if !current && next {
            crate::bootstrap::issue_if_required(&st.db, "auth_enabled_toggle").await?;
        }
        let (bootstrap_active, active_users) =
            st.db.call(|c| Ok((bootstrap_user_active(c)?, count_active_users(c)?))).await?;
        reply(
            200,
            json!({
                "authEnabled": updated.auth_enabled,
                "bootstrapRequired": bootstrap_required(updated.auth_enabled, bootstrap_active, active_users),
            }),
        )
    }
    .await;
    finish(result, HeaderMap::new(), "Auth enabled toggle error:", "Failed to update authentication mode")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zod_email_matches_upstream_cases() {
        for ok in ["a@b.co", "first.last+tag@sub.example.test", "o'neil@x.io", "a_b-c@d-e.fg"] {
            assert!(zod_email_ok(ok), "{ok}");
        }
        for bad in [" a@b.co", "A@B.CO ", "bad", ".a@b.co", "a..b@b.co", "a.@b.co", "a@b.c", "a@-b.co", "a@b..co", "é@b.co", ""] {
            assert!(!zod_email_ok(bad), "{bad}");
        }
    }

    #[test]
    fn expires_in_parsing() {
        assert_eq!(expires_in_seconds("15m"), Some(900));
        assert_eq!(expires_in_seconds("7d"), Some(604800));
        assert_eq!(expires_in_seconds("900"), Some(0));
    }

    #[test]
    fn c_string_truncation() {
        assert_eq!(c_string_bytes("ab\0cd"), b"ab".to_vec());
        assert_eq!(c_string_bytes("abc"), b"abc".to_vec());
    }
}
