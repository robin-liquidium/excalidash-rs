//! Ports of upstream backend tests for the auth core:
//! auth-enabled.integration.ts, auth-onboarding.integration.ts,
//! admin-login-rate-limit.integration.ts (backend limiter behaviour),
//! production-health.integration.ts.
mod common;
use common::*;
use serde_json::{json, Value};

fn sql(s: &TestServer, sql: &str) {
    s.db().execute_batch(sql).unwrap();
}

fn bearer(c: &TestClient, token: &str) -> TestClient {
    TestClient {
        http: c.http.clone(),
        base: c.base.clone(),
        origin: c.origin.clone(),
        csrf: c.csrf.clone(),
        bearer: Some(token.to_string()),
        extra: c.extra.clone(),
    }
}

fn anonymous(c: &TestClient) -> TestClient {
    TestClient { bearer: None, ..bearer(c, "") }
}

fn no_csrf(c: &TestClient) -> TestClient {
    TestClient { csrf: None, ..anonymous(c) }
}

// ---------------------------------------------------------------------------
// auth-enabled.integration.ts — "Auth Enabled Toggle Authorization"

struct AuthEnabledCtx {
    s: TestServer,
    agent: TestClient,
    regular: String,
    admin: String,
}

fn auth_enabled_setup() -> AuthEnabledCtx {
    let s = TestServer::start(&[]);
    sql(&s, r#"INSERT INTO "SystemConfig" ("id","authEnabled","registrationEnabled","createdAt","updatedAt") VALUES ('default',1,0,0,0)
               ON CONFLICT("id") DO UPDATE SET "authEnabled"=1, "registrationEnabled"=0"#);
    let user = seed_user(&s, "regular-user@test.local", "Regular User", "USER");
    let admin = seed_user(&s, "admin-user@test.local", "Admin User", "ADMIN");
    // Upstream signs `{ userId, email, type }` only (no authProvider/jti).
    let sign = |id: &str, email: &str| {
        let now = chrono::Utc::now().timestamp();
        jsonwebtoken::encode(
            &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
            &json!({"userId": id, "email": email, "type": "access", "iat": now, "exp": now + 900}),
            &jsonwebtoken::EncodingKey::from_secret(TEST_JWT_SECRET.as_bytes()),
        )
        .unwrap()
    };
    let regular = sign(&user, "regular-user@test.local");
    let admin = sign(&admin, "admin-user@test.local");
    let mut agent = s.client().with_header("User-Agent", "vitest-auth-enabled");
    agent.fetch_csrf();
    AuthEnabledCtx { s, agent, regular, admin }
}

#[test]
fn auth_enabled_rejects_unauthenticated_toggle_when_auth_is_enabled() {
    let t = auth_enabled_setup();
    let r = t.agent.post("/auth/auth-enabled", json!({"enabled": false}));
    assert_eq!(r.status, 401);
}

#[test]
fn auth_enabled_rejects_non_admin_toggle() {
    let t = auth_enabled_setup();
    let r = bearer(&t.agent, &t.regular).post("/auth/auth-enabled", json!({"enabled": false}));
    assert_eq!(r.status, 403);
    assert!(r.json()["message"].as_str().unwrap().contains("Admin access required"));
}

// "protects the bootstrap admin role through both admin endpoints" (/auth/admins,
// /auth/users/:id) and "persists the compact sidebar preference" (/auth/preferences)
// exercise admin/account routes and are ported with those areas.

#[test]
fn auth_enabled_applies_auth_mode_change_immediately_for_subsequent_requests() {
    let t = auth_enabled_setup();
    let warm = anonymous(&t.agent).get("/auth/status");
    assert_eq!(warm.status, 200);
    assert_eq!(warm.json()["authEnabled"], true);
    // Warm the requireAuth cache with an authenticated request.
    assert_eq!(bearer(&t.agent, &t.admin).get("/auth/me").status, 200);

    let toggle = bearer(&t.agent, &t.admin).post("/auth/auth-enabled", json!({"enabled": false}));
    assert_eq!(toggle.status, 200);
    assert_eq!(toggle.json()["authEnabled"], false);

    // Without credentials, requests now run as the bootstrap acting user: requireAuth
    // passes and the auth-only route reports that authentication is disabled.
    let r = anonymous(&t.agent).post("/auth/stop-impersonation", json!({}));
    assert_eq!((r.status, r.json()["message"].clone()), (404, json!("Authentication is disabled")));
    // Upstream checks GET /drawings → 200; here: not blocked by auth or the onboarding gate.
    let drawings = anonymous(&t.agent).get("/drawings");
    assert!(drawings.status != 401 && drawings.status != 409, "{}", drawings.status);
    let _ = &t.s;
}

// ---------------------------------------------------------------------------
// auth-onboarding.integration.ts — "Auth onboarding decision" (sequential scenario)

#[test]
fn auth_onboarding_decision_flow() {
    let s = TestServer::start(&[]);
    let mut agent = s.client().with_header("User-Agent", "vitest-auth-onboarding");
    agent.fetch_csrf();

    // reports migration onboarding mode when no active users and legacy data exists
    sql(&s, r#"INSERT INTO "User" ("id","username","email","passwordHash","name","role","mustResetPassword","isActive","createdAt","updatedAt")
               VALUES ('bootstrap-admin',NULL,'bootstrap@excalidash.local','','Bootstrap Admin','ADMIN',1,0,0,0) ON CONFLICT("id") DO NOTHING;
               INSERT INTO "SystemConfig" ("id","authEnabled","authOnboardingCompleted","registrationEnabled","createdAt","updatedAt") VALUES ('default',0,0,0,0,0)
               ON CONFLICT("id") DO UPDATE SET "authEnabled"=0, "authOnboardingCompleted"=0;
               INSERT INTO "Collection" ("id","name","userId","createdAt","updatedAt") VALUES ('legacy-collection','Legacy','bootstrap-admin',0,0) ON CONFLICT("id") DO NOTHING;
               INSERT INTO "Drawing" ("id","name","elements","appState","files","userId","collectionId","createdAt","updatedAt")
               VALUES ('legacy-drawing','Legacy Drawing','[]','{}','{}','bootstrap-admin','legacy-collection',0,0) ON CONFLICT("id") DO NOTHING;"#);
    let r = anonymous(&agent).get("/auth/status");
    assert_eq!(r.status, 200);
    let body = r.json();
    assert_eq!(body["authEnabled"], false);
    assert_eq!(body["authOnboardingRequired"], true);
    assert_eq!(body["authOnboardingMode"], "migration");

    // persists a single-user onboarding choice
    sql(&s, r#"UPDATE "SystemConfig" SET "authEnabled"=0, "authOnboardingCompleted"=0 WHERE "id"='default'"#);
    let r = agent.post("/auth/onboarding-choice", json!({"enableAuth": false}));
    assert_eq!(r.status, 200);
    assert_eq!(r.json()["authEnabled"], false);
    assert_eq!(r.json()["authOnboardingCompleted"], true);
    let r = anonymous(&agent).get("/auth/status");
    assert_eq!(r.status, 200);
    assert_eq!(r.json()["authOnboardingRequired"], false);

    // enables auth and bootstrap flow from onboarding choice
    sql(&s, r#"DELETE FROM "Drawing"; DELETE FROM "Collection" WHERE "id" <> 'trash:bootstrap-admin';
               UPDATE "SystemConfig" SET "authEnabled"=0, "authOnboardingCompleted"=0 WHERE "id"='default'"#);
    let r = agent.post("/auth/onboarding-choice", json!({"enableAuth": true}));
    assert_eq!(r.status, 200);
    assert_eq!(r.json()["authEnabled"], true);
    assert_eq!(r.json()["bootstrapRequired"], true);
    assert_eq!(r.json()["authOnboardingCompleted"], true);
    let r = anonymous(&agent).get("/auth/status");
    assert_eq!(r.status, 200);
    assert_eq!(r.json()["authEnabled"], true);
    assert_eq!(r.json()["bootstrapRequired"], true);
    assert_eq!(r.json()["authOnboardingRequired"], false);

    // requires CSRF token for bootstrap registration
    let creds = json!({"email": "bootstrap-admin@test.local", "password": "StrongPass1!", "name": "Bootstrap Admin"});
    let r = no_csrf(&agent).post("/auth/register", creds.clone());
    assert_eq!(r.status, 403);
    assert_eq!(r.json()["error"], "CSRF token missing");
    // Upstream calls issueBootstrapSetupCodeIfRequired directly; the code issued by
    // the onboarding choice above is the equivalent one-time code from the log.
    let code = wait_for_setup_code(&s);
    assert!(!code.is_empty());
    let mut with_code = creds.clone();
    with_code["setupCode"] = json!(code);
    let r = agent.post("/auth/register", with_code);
    assert_eq!(r.status, 201, "{}", r.text());
    assert_eq!(r.json()["bootstrapped"], true);
    assert_eq!(r.json()["user"]["email"], "bootstrap-admin@test.local");
    assert!(r.json().get("accessToken").is_none());
    assert!(r.json().get("refreshToken").is_none());

    // requires CSRF token for login and does not expose tokens in response body
    let login = json!({"email": "bootstrap-admin@test.local", "password": "StrongPass1!"});
    let r = no_csrf(&agent).post("/auth/login", login.clone());
    assert_eq!(r.status, 403);
    assert_eq!(r.json()["error"], "CSRF token missing");
    let r = agent.post("/auth/login", login);
    assert_eq!(r.status, 200);
    assert_eq!(r.json()["user"]["email"], "bootstrap-admin@test.local");
    assert!(r.json().get("accessToken").is_none());
    assert!(r.json().get("refreshToken").is_none());
}

// ---------------------------------------------------------------------------
// admin-login-rate-limit.integration.ts — the upstream file drives the admin UI
// against a mocked API (enabled/windowMs/max, reset by identifier). These tests
// cover the backend limiter those settings configure, seeding SystemConfig directly.

fn limited_server(enabled: bool, window_ms: i64, max: i64) -> TestServer {
    let s = TestServer::start(&[]);
    enable_auth(&s);
    sql(&s, &format!(
        r#"UPDATE "SystemConfig" SET "authLoginRateLimitEnabled"={}, "authLoginRateLimitWindowMs"={window_ms}, "authLoginRateLimitMax"={max}"#,
        enabled as i32
    ));
    seed_user(&s, "localuser@example.test", "Local User", "USER");
    s
}

fn bad_login(c: &TestClient, email: &str) -> Resp {
    c.post("/auth/login", json!({"email": email, "password": "wrong-password"}))
}

#[test]
fn login_rate_limit_uses_system_config_and_limits_per_identifier() {
    let s = limited_server(true, 120_000, 4);
    let mut c = s.client();
    c.fetch_csrf();
    for i in 0..4 {
        let r = bad_login(&c, "localuser@example.test");
        assert_eq!(r.status, 401);
        assert_eq!(r.header("ratelimit-policy").as_deref(), Some("4;w=120"));
        assert_eq!(r.header("ratelimit-limit").as_deref(), Some("4"));
        assert_eq!(r.header("ratelimit-remaining"), Some((3 - i).to_string()));
    }
    let r = bad_login(&c, "localuser@example.test");
    assert_eq!(r.status, 429);
    assert_eq!(r.json(), json!({"error": "Too many requests", "message": "Too many login attempts, please try again later"}));
    // Even the right password is blocked for this identifier+IP…
    let r = c.post("/auth/login", json!({"email": "LocalUser@example.test ", "password": STRONG_PASSWORD}));
    assert_eq!(r.status, 429);
    // …but other identifiers from the same IP are not.
    assert_eq!(bad_login(&c, "someone-else@example.test").status, 401);
    // Registration shares the limiter.
    let r = c.post("/auth/register", json!({"email": "localuser@example.test", "password": STRONG_PASSWORD, "name": "X"}));
    assert_eq!(r.status, 429);
    // Requests without an identifier are keyed by IP alone.
    let r = c.post("/auth/login", json!({"password": "x"}));
    assert_eq!(r.status, 400);
    assert_eq!(r.header("ratelimit-remaining").as_deref(), Some("3"));
}

#[test]
fn login_rate_limit_disabled_never_blocks() {
    let s = limited_server(false, 60_000, 1);
    let mut c = s.client();
    c.fetch_csrf();
    for _ in 0..5 {
        let r = bad_login(&c, "localuser@example.test");
        assert_eq!(r.status, 401);
        // Only the general limiter headers remain.
        assert_eq!(r.header("ratelimit-policy").as_deref(), Some("100000;w=900"));
    }
    let r = c.post("/auth/login", json!({"email": "localuser@example.test", "password": STRONG_PASSWORD}));
    assert_eq!(r.status, 200);
}

#[test]
fn login_rate_limit_defaults() {
    let s = TestServer::start(&[]);
    enable_auth(&s);
    let mut c = s.client();
    c.fetch_csrf();
    let r = bad_login(&c, "x@example.test");
    assert_eq!(r.header("ratelimit-policy").as_deref(), Some("20;w=900"));
    assert_eq!(r.header("ratelimit-remaining").as_deref(), Some("19"));
    let _: Value = r.json();
}

// ---------------------------------------------------------------------------
// production-health.integration.ts

#[test]
fn production_health_serves_loopback_checks_without_https_redirects_or_onboarding() {
    let s = TestServer::start(&[("ENFORCE_HTTPS_REDIRECT", "true"), ("TRUST_PROXY", "1")]);
    let c = TestClient { origin: None, ..s.client() };
    let health = c.get("/health");
    assert_eq!(health.status, 200);
    assert_eq!(health.json(), json!({"status": "ok", "database": "ok"}));
    let gated = c.get("/drawings");
    assert_eq!(gated.status, 302);
    let secure = TestClient { origin: None, ..s.client() }.with_header("X-Forwarded-Proto", "https").get("/drawings");
    assert_eq!(secure.status, 409);
}
