//! /auth core routes (auth/coreRoutes.ts): register, login, refresh, logout,
//! stop-impersonation, me, status, onboarding-choice, auth-enabled.
mod common;
use common::*;
use serde_json::{json, Value};

/// `bcrypt.hashSync(STRONG_PASSWORD, 10)` produced by node `bcrypt@6` (upstream image).
const NODE_BCRYPT_HASH: &str = "$2b$10$X5x.9PlTGSiFdaKLnjbNQ.ZOh6LBzWBiOdqkIzuYLf9zQ3a3s5NBy";
/// `bcrypt.hashSync("x".repeat(80), 10)` from node (bcrypt truncates at 72 bytes).
const NODE_BCRYPT_LONG_HASH: &str = "$2b$10$m/bfzyZwDR3CwtGhhGREPOa0Hkg9y1RceYCbvLAzUMjgpQM7lp/k6";

fn sign(claims: Value) -> String {
    jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
        &claims,
        &jsonwebtoken::EncodingKey::from_secret(TEST_JWT_SECRET.as_bytes()),
    )
    .unwrap()
}

fn decode(token: &str) -> Value {
    let payload = token.split('.').nth(1).unwrap();
    use base64::Engine;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn now_s() -> i64 {
    chrono::Utc::now().timestamp()
}

fn sha256_hex(s: &str) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(s.as_bytes()))
}

/// Value of cookie `name` from the response's Set-Cookie headers.
fn cookie_value(r: &Resp, name: &str) -> Option<String> {
    r.header_all("set-cookie")
        .iter()
        .find(|c| c.starts_with(&format!("{name}=")))
        .map(|c| c.split(';').next().unwrap()[name.len() + 1..].to_string())
}

fn set_cookie(r: &Resp, name: &str) -> String {
    r.header_all("set-cookie").into_iter().find(|c| c.starts_with(&format!("{name}="))).unwrap_or_default()
}

fn assert_auth_cookie_format(r: &Resp, secure: bool) {
    let re = regex::Regex::new(&format!(
        r"^excalidash-access-token=[A-Za-z0-9_.-]+; Max-Age=900; Path=/; Expires=[A-Z][a-z]{{2}}, \d\d [A-Z][a-z]{{2}} \d{{4}} \d\d:\d\d:\d\d GMT; HttpOnly{}; SameSite=Lax$",
        if secure { "; Secure" } else { "" }
    ))
    .unwrap();
    let access = set_cookie(r, "excalidash-access-token");
    assert!(re.is_match(&access), "access cookie: {access}");
    let re = regex::Regex::new(&format!(
        r"^excalidash-refresh-token=[A-Za-z0-9_.-]+; Max-Age=604800; Path=/; Expires=[A-Z][a-z]{{2}}, \d\d [A-Z][a-z]{{2}} \d{{4}} \d\d:\d\d:\d\d GMT; HttpOnly{}; SameSite=Lax$",
        if secure { "; Secure" } else { "" }
    ))
    .unwrap();
    let refresh = set_cookie(r, "excalidash-refresh-token");
    assert!(re.is_match(&refresh), "refresh cookie: {refresh}");
}

fn count(s: &TestServer, sql: &str) -> i64 {
    s.db().query_row(sql, [], |r| r.get(0)).unwrap()
}

fn sql(s: &TestServer, sql: &str) {
    s.db().execute_batch(sql).unwrap();
}

fn setup_code_lines(s: &TestServer) -> usize {
    s.output().lines().filter(|l| l.contains("[BOOTSTRAP SETUP]")).count()
}

/// Server output is captured asynchronously: wait until `n` setup-code lines were logged.
fn wait_setup_code_lines(s: &TestServer, n: usize) -> usize {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while setup_code_lines(s) < n && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    setup_code_lines(s)
}

fn without_csrf(c: &TestClient) -> TestClient {
    TestClient { csrf: None, http: c.http.clone(), base: c.base.clone(), origin: c.origin.clone(), bearer: None, extra: c.extra.clone() }
}

// ---------------------------------------------------------------------------
// status / onboarding

#[test]
fn status_fresh_install_matches_upstream() {
    let s = TestServer::start(&[]);
    let r = s.client().get("/auth/status");
    assert_eq!(r.status, 200);
    assert_eq!(
        r.text(),
        r#"{"enabled":false,"authenticated":false,"authEnabled":false,"authMode":"local","oidcEnabled":false,"oidcEnforced":false,"oidcProvider":"OIDC","oidcJitProvisioningEnabled":false,"registrationEnabled":false,"bootstrapRequired":false,"authOnboardingRequired":true,"authOnboardingMode":"fresh","authOnboardingRecommended":"enable","passwordPolicy":{"minLength":12,"maxLength":100,"requireUppercase":true,"requireLowercase":true,"requireNumber":true,"requireSymbol":true},"user":null}"#
    );
    // optionalAuth (auth disabled) upserts the inactive bootstrap acting user.
    assert_eq!(count(&s, r#"SELECT COUNT(*) FROM "User" WHERE "id"='bootstrap-admin' AND "isActive"=0"#), 1);
}

#[test]
fn bootstrap_admin_flow_end_to_end() {
    let s = TestServer::start(&[]);
    let mut c = s.client();
    c.fetch_csrf();
    let r = c.post("/auth/onboarding-choice", json!({"enableAuth": true}));
    assert_eq!(r.status, 200);
    assert_eq!(r.text(), r#"{"authEnabled":true,"authOnboardingCompleted":true,"bootstrapRequired":true}"#);
    wait_for_setup_code(&s);
    let out = s.output();
    let line = out.lines().find(|l| l.contains("[BOOTSTRAP SETUP]")).unwrap();
    let re = regex::Regex::new(
        r"^\[BOOTSTRAP SETUP\] One-time admin setup code \(onboarding_enabled\): [A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4} \(expires \d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z\)$",
    )
    .unwrap();
    assert!(re.is_match(line), "{line}");
    let status = c.get("/auth/status").json();
    assert_eq!(status["authEnabled"], true);
    assert_eq!(status["bootstrapRequired"], true);
    assert_eq!(status["authOnboardingRequired"], false);

    // Login before bootstrap → 409.
    let r = c.post("/auth/login", json!({"email": "x@y.co", "password": "whatever"}));
    assert_eq!(r.status, 409);
    assert_eq!(r.json()["error"], "Bootstrap required");

    let code = wait_for_setup_code(&s);
    // Lowercase/space-separated codes are normalised.
    let sloppy = code.to_lowercase().replace('-', " ");
    let r = c.post(
        "/auth/register",
        json!({"email": "Admin@Example.test", "password": STRONG_PASSWORD, "name": "  Admin <b>User</b> ", "username": " admin ", "setupCode": sloppy}),
    );
    assert_eq!(r.status, 201, "{}", r.text());
    assert_eq!(
        r.json(),
        json!({"user": {"id": "bootstrap-admin", "email": "admin@example.test", "name": "Admin <b>User</b>", "role": "ADMIN", "mustResetPassword": false}, "registrationEnabled": false, "bootstrapped": true})
    );
    assert_eq!(r.header("ratelimit-policy").as_deref(), Some("20;w=900"));
    assert_auth_cookie_format(&r, false);
    let refresh = cookie_value(&r, "excalidash-refresh-token").unwrap();
    let claims = decode(&refresh);
    assert_eq!(claims["type"], "refresh");
    assert_eq!(claims["authProvider"], "local");
    assert_eq!(claims["userId"], "bootstrap-admin");

    let db = s.db();
    let (hash, active, role, username): (String, i64, String, Option<String>) = db
        .query_row(r#"SELECT "passwordHash","isActive","role","username" FROM "User" WHERE "id"='bootstrap-admin'"#, [], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
        })
        .unwrap();
    assert!(hash.starts_with("$2b$10$"), "{hash}");
    assert_eq!((active, role.as_str(), username.as_deref()), (1, "ADMIN", Some("admin")));
    let stored: String = db
        .query_row(r#"SELECT "token" FROM "RefreshToken" WHERE "userId"='bootstrap-admin'"#, [], |r| r.get(0))
        .unwrap();
    assert_eq!(stored, sha256_hex(&refresh));
    assert_eq!(count(&s, r#"SELECT COUNT(*) FROM "Collection" WHERE "id"='trash:bootstrap-admin' AND "name"='Trash'"#), 1);
    assert_eq!(
        count(&s, r#"SELECT COUNT(*) FROM "SystemConfig" WHERE "bootstrapSetupCodeHash" IS NULL AND "bootstrapSetupCodeExpiresAt" IS NULL"#),
        1
    );

    // Session works.
    c.fetch_csrf();
    let me = c.get("/auth/me");
    assert_eq!(me.status, 200);
    let u = &me.json()["user"];
    assert_eq!(u["username"], "admin");
    let keys: Vec<&String> = u.as_object().unwrap().keys().collect();
    assert_eq!(keys, ["id", "username", "email", "name", "role", "mustResetPassword", "createdAt", "updatedAt"]);
    let status = c.get("/auth/status").json();
    assert_eq!(status["authenticated"], true);
    assert_eq!(status["bootstrapRequired"], false);
    assert_eq!(status["authOnboardingMode"], "migration");
    assert_eq!(status["user"], json!({"id": "bootstrap-admin", "username": "admin", "email": "admin@example.test", "name": "Admin <b>User</b>", "role": "ADMIN", "mustResetPassword": false}));

    // Second bootstrap attempt is a normal registration (disabled).
    let r = c.post("/auth/register", json!({"email": "x@y.co", "password": STRONG_PASSWORD, "name": "X"}));
    assert_eq!(r.status, 403);
    assert_eq!(r.json(), json!({"error": "Forbidden", "message": "User registration is disabled."}));
    // Onboarding can't be repeated.
    let r = c.post("/auth/onboarding-choice", json!({"enableAuth": false}));
    assert_eq!(r.status, 409);
    assert_eq!(r.json()["message"], "Authentication onboarding is already completed");
}

#[test]
fn harness_bootstrap_admin_helper_works() {
    let s = TestServer::start(&[]);
    let (c, user) = bootstrap_admin(&s, "helper@example.test");
    assert_eq!(user["role"], "ADMIN");
    assert_eq!(c.get("/auth/me").json()["user"]["email"], "helper@example.test");
    let c2 = login(&s, "helper@example.test", STRONG_PASSWORD);
    assert_eq!(c2.get("/auth/me").status, 200);
}

#[test]
fn setup_code_failures_missing_invalid_locked_expired() {
    let s = TestServer::start(&[("BOOTSTRAP_SETUP_CODE_MAX_ATTEMPTS", "2")]);
    let mut c = s.client();
    c.fetch_csrf();
    c.post("/auth/onboarding-choice", json!({"enableAuth": true}));
    wait_for_setup_code(&s);
    assert_eq!(wait_setup_code_lines(&s, 1), 1);
    let body = |code: Option<&str>| {
        let mut b = json!({"email": "admin@example.test", "password": STRONG_PASSWORD, "name": "Admin"});
        if let Some(code) = code {
            b["setupCode"] = json!(code);
        }
        b
    };
    let r = c.post("/auth/register", body(None));
    assert_eq!(r.status, 400);
    assert_eq!(r.json(), json!({"error": "Bad request", "message": "Bootstrap setup code is required for first admin registration"}));
    let r = c.post("/auth/register", body(Some("AAAA-AAAA")));
    assert_eq!(r.status, 401);
    assert_eq!(r.json(), json!({"error": "Unauthorized", "message": "Invalid bootstrap setup code"}));
    assert_eq!(count(&s, r#"SELECT "bootstrapSetupCodeFailedAttempts" FROM "SystemConfig""#), 1);
    c.post("/auth/register", body(Some("AAAA-AAAA")));
    let before = setup_code_lines(&s);
    let r = c.post("/auth/register", body(Some("AAAA-AAAA")));
    assert_eq!(r.status, 429);
    assert_eq!(
        r.json()["message"],
        "Too many invalid setup code attempts. A new setup code has been issued in backend logs."
    );
    assert_eq!(wait_setup_code_lines(&s, before + 1), before + 1);
    assert!(s.output().contains("(bootstrap_register_reissue)"));
    assert_eq!(count(&s, r#"SELECT "bootstrapSetupCodeFailedAttempts" FROM "SystemConfig""#), 0);

    // Expired code → 409 + reissue.
    sql(&s, r#"UPDATE "SystemConfig" SET "bootstrapSetupCodeExpiresAt" = 1000"#);
    let code = wait_for_setup_code(&s); // still-valid hash, but expired
    let r = c.post("/auth/register", body(Some(&code)));
    assert_eq!(r.status, 409);
    assert_eq!(
        r.json()["message"],
        "Bootstrap setup code is unavailable or expired. A new setup code has been issued in backend logs."
    );
    assert_eq!(wait_setup_code_lines(&s, before + 2), before + 2);
    let code = wait_for_setup_code(&s);
    let r = c.post("/auth/register", body(Some(&code)));
    assert_eq!(r.status, 201, "{}", r.text());
}

#[test]
fn startup_issues_setup_code_when_bootstrap_pending() {
    let s = TestServer::start(&[]);
    enable_auth(&s);
    sql(&s, r#"INSERT OR IGNORE INTO "User" ("id","email","passwordHash","name","role","mustResetPassword","isActive","createdAt","updatedAt") VALUES ('bootstrap-admin','bootstrap@excalidash.local','','Bootstrap Admin','ADMIN',1,0,0,0)"#);
    assert!(!s.output().contains("[BOOTSTRAP SETUP]"));
    let dir = {
        let mut s = s;
        s.stop();
        // Keep the directory alive by moving it out.
        std::mem::replace(&mut s.dir, tempfile::tempdir().unwrap())
    };
    let s2 = TestServer::start_in(dir, &[]);
    let code = wait_for_setup_code(&s2);
    assert!(s2.output().contains("One-time admin setup code (startup): "));
    let mut c = s2.client();
    c.fetch_csrf();
    let r = c.post("/auth/register", json!({"email": "a@b.co", "password": STRONG_PASSWORD, "name": "A", "setupCode": code}));
    assert_eq!(r.status, 201);
}

#[test]
fn onboarding_choice_errors() {
    let s = TestServer::start(&[]);
    let mut c = s.client();
    let r = c.post("/auth/onboarding-choice", json!({"enableAuth": true}));
    assert_eq!(r.status, 403);
    assert_eq!(r.json()["error"], "CSRF token missing");
    c.fetch_csrf();
    for bad in [json!({}), json!({"enableAuth": "true"}), json!([])] {
        let r = c.post("/auth/onboarding-choice", bad);
        assert_eq!(r.status, 400);
        assert_eq!(r.json(), json!({"error": "Bad request", "message": "Invalid onboarding choice payload"}));
    }
    let r = c.post("/auth/onboarding-choice", json!({"enableAuth": false}));
    assert_eq!(r.text(), r#"{"authEnabled":false,"authOnboardingCompleted":true,"bootstrapRequired":false}"#);
    // Onboarding gate is lifted immediately (cache cleared).
    let r = c.get("/definitely-not-gated");
    assert_eq!(r.status, 404);
}

// ---------------------------------------------------------------------------
// register (validation + normal registration)

#[test]
fn register_validation_and_normal_registration() {
    let s = TestServer::start(&[]);
    let (_admin, _) = bootstrap_admin(&s, "admin@example.test");
    let mut c = s.client();
    c.fetch_csrf();
    let r = c.post("/auth/register", json!({"email": "bad", "password": "short", "name": ""}));
    assert_eq!(r.status, 400);
    assert_eq!(
        r.text(),
        r#"{"error":"Validation error","message":"Invalid email address","details":{"formErrors":[],"fieldErrors":{"email":["Invalid email address"],"password":["Password must be at least 12 characters, one uppercase letter, one lowercase letter, one number, one symbol"],"name":["Too small: expected string to have >=1 characters"]}}}"#
    );
    let r = c.post("/auth/register", json!({"email": "a@b.co", "password": 5, "name": 5, "username": null}));
    assert_eq!(
        r.json()["details"]["fieldErrors"],
        json!({"username": ["Invalid input: expected string, received null"], "password": ["Invalid input: expected string, received number"], "name": ["Invalid input: expected string, received number"]})
    );
    assert_eq!(r.json()["message"], "Invalid input: expected string, received null");
    let r = c.send_raw("POST", "/auth/register", Some(("text/plain".into(), b"hi".to_vec())));
    assert_eq!(
        r.text(),
        r#"{"error":"Validation error","message":"Invalid input: expected object, received undefined","details":{"formErrors":["Invalid input: expected object, received undefined"],"fieldErrors":{}}}"#
    );
    let r = c.post("/auth/register", json!({"email": "a@b.co", "password": "x".repeat(101), "name": "X", "username": "ab"}));
    assert_eq!(r.json()["message"], "Too small: expected string to have >=3 characters");
    assert_eq!(r.json()["details"]["fieldErrors"]["password"], json!(["Password must be at most 100 characters long"]));

    sql(&s, r#"UPDATE "SystemConfig" SET "registrationEnabled" = 1"#);
    let r = c.post("/auth/register", json!({"email": "New@Example.test", "password": STRONG_PASSWORD, "name": "New User", "username": "newbie"}));
    assert_eq!(r.status, 201, "{}", r.text());
    let body = r.json();
    assert_eq!(body["user"]["email"], "new@example.test");
    assert_eq!(body["user"]["role"], "USER");
    assert_eq!(body["registrationEnabled"], true);
    assert!(body.get("bootstrapped").is_none());
    let keys: Vec<&String> = body["user"].as_object().unwrap().keys().collect();
    assert_eq!(keys, ["id", "email", "name", "role", "mustResetPassword"]);
    assert_auth_cookie_format(&r, false);
    let id = body["user"]["id"].as_str().unwrap();
    assert_eq!(count(&s, &format!(r#"SELECT COUNT(*) FROM "Collection" WHERE "id"='trash:{id}' AND "userId"='{id}'"#)), 1);
    assert_eq!(count(&s, &format!(r#"SELECT COUNT(*) FROM "RefreshToken" WHERE "userId"='{id}'"#)), 1);

    let mut c2 = s.client();
    c2.fetch_csrf();
    let r = c2.post("/auth/register", json!({"email": "new@example.test", "password": STRONG_PASSWORD, "name": "Dup"}));
    assert_eq!(r.status, 409);
    assert_eq!(r.json()["message"], "User with this email already exists");
    let r = c2.post("/auth/register", json!({"email": "other@example.test", "password": STRONG_PASSWORD, "name": "Dup", "username": "newbie"}));
    assert_eq!(r.status, 409);
    assert_eq!(r.json()["message"], "User with this username already exists");
}

// ---------------------------------------------------------------------------
// login

#[test]
fn login_paths_and_node_bcrypt_compat() {
    let s = TestServer::start(&[]);
    enable_auth(&s);
    let id = seed_user(&s, "user@example.test", "User", "USER");
    sql(&s, &format!(r#"UPDATE "User" SET "passwordHash"='{NODE_BCRYPT_HASH}', "username"='bob' WHERE "id"='{id}'"#));
    let mut c = s.client();
    c.fetch_csrf();
    let r = c.post("/auth/login", json!({"email": "USER@example.test", "password": STRONG_PASSWORD}));
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(r.text(), format!(r#"{{"user":{{"id":"{id}","email":"user@example.test","name":"User","role":"USER","mustResetPassword":false}}}}"#));
    assert_auth_cookie_format(&r, false);
    assert_eq!(r.header("ratelimit-limit").as_deref(), Some("20"));
    let access = cookie_value(&r, "excalidash-access-token").unwrap();
    let claims = decode(&access);
    let keys: Vec<&String> = claims.as_object().unwrap().keys().collect();
    assert_eq!(keys, ["userId", "email", "authProvider", "type", "iat", "exp", "jti"]);
    assert_eq!(claims["exp"].as_i64().unwrap() - claims["iat"].as_i64().unwrap(), 900);

    // username / identifier logins
    for body in [json!({"username": " bob ", "password": STRONG_PASSWORD}), json!({"identifier": "user@example.test", "password": STRONG_PASSWORD})] {
        let r = c.post("/auth/login", body);
        assert_eq!(r.status, 200, "{}", r.text());
    }
    let invalid = json!({"error": "Unauthorized", "message": "Invalid email or password"});
    let r = c.post("/auth/login", json!({"email": "user@example.test", "password": "wrong"}));
    assert_eq!((r.status, r.json()), (401, invalid.clone()));
    let r = c.post("/auth/login", json!({"email": "nobody@example.test", "password": "wrong"}));
    assert_eq!((r.status, r.json()), (401, invalid.clone()));
    for bad in [json!({}), json!({"password": "x"}), json!({"email": "bad", "password": "x"}), json!({"identifier": "x"})] {
        let r = c.post("/auth/login", bad);
        assert_eq!(r.status, 400);
        assert_eq!(r.json(), json!({"error": "Validation error", "message": "Invalid login credentials"}));
    }
    // Long passwords: node bcrypt truncates at 72 bytes.
    sql(&s, &format!(r#"UPDATE "User" SET "passwordHash"='{NODE_BCRYPT_LONG_HASH}' WHERE "id"='{id}'"#));
    let r = c.post("/auth/login", json!({"email": "user@example.test", "password": format!("{}yyyy", "x".repeat(72))}));
    assert_eq!(r.status, 200);
    // OIDC-only (no local hash) and inactive users are rejected.
    sql(&s, &format!(r#"UPDATE "User" SET "passwordHash"='' WHERE "id"='{id}'"#));
    let r = c.post("/auth/login", json!({"email": "user@example.test", "password": ""}));
    assert_eq!((r.status, r.json()), (401, invalid.clone()));
    seed_user(&s, "other@example.test", "Other", "USER"); // keep an active user (else: bootstrap required)
    sql(&s, &format!(r#"UPDATE "User" SET "passwordHash"='{NODE_BCRYPT_HASH}', "isActive"=0 WHERE "id"='{id}'"#));
    let r = c.post("/auth/login", json!({"email": "user@example.test", "password": STRONG_PASSWORD}));
    assert_eq!((r.status, r.json()), (401, invalid));
}

#[test]
fn rust_hashes_verify_like_node() {
    // Hash produced by our registration must be a cost-10 $2b$ hash that bcrypt verifies.
    let s = TestServer::start(&[]);
    bootstrap_admin(&s, "admin@example.test");
    let hash: String = s.db().query_row(r#"SELECT "passwordHash" FROM "User" WHERE "id"='bootstrap-admin'"#, [], |r| r.get(0)).unwrap();
    assert!(hash.starts_with("$2b$10$") && hash.len() == 60);
    assert!(bcrypt::verify(STRONG_PASSWORD, &hash).unwrap());
}

// ---------------------------------------------------------------------------
// refresh / logout

#[test]
fn refresh_rotation_and_revocation() {
    let s = TestServer::start(&[]);
    enable_auth(&s);
    let id = seed_user(&s, "user@example.test", "User", "USER");
    let c = login(&s, "user@example.test", STRONG_PASSWORD);
    let first: String = s.db().query_row(r#"SELECT "token" FROM "RefreshToken""#, [], |r| r.get(0)).unwrap();

    let r = c.post("/auth/refresh", json!({}));
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(r.text(), r#"{"ok":true}"#);
    assert_auth_cookie_format(&r, false);
    let new_refresh = cookie_value(&r, "excalidash-refresh-token").unwrap();
    assert_eq!(count(&s, &format!(r#"SELECT "revoked" FROM "RefreshToken" WHERE "token"='{first}'"#)), 1);
    assert_eq!(count(&s, &format!(r#"SELECT COUNT(*) FROM "RefreshToken" WHERE "token"='{}' AND "revoked"=0"#, sha256_hex(&new_refresh))), 1);

    // A revoked (already rotated) token is rejected.
    let replay_token = {
        let tok = sign(json!({"userId": id, "email": "user@example.test", "authProvider": "local", "type": "refresh", "iat": now_s(), "exp": now_s() + 600, "jti": "replay"}));
        sql(&s, &format!(r#"INSERT INTO "RefreshToken" ("id","userId","token","expiresAt","revoked","createdAt") VALUES ('r1','{id}','{}',{},1,0)"#, sha256_hex(&tok), (now_s() + 600) * 1000));
        tok
    };
    let with_refresh = |tok: &str| {
        let mut cl = s.client().with_header("Cookie", &format!("excalidash-refresh-token={tok}"));
        cl.fetch_csrf_with_cookie_header();
        cl.post("/auth/refresh", json!({}))
    };
    let r = with_refresh(&replay_token);
    assert_eq!((r.status, r.json()), (401, json!({"error": "Unauthorized", "message": "Invalid or revoked refresh token"})));

    // Legacy rows storing the raw token are still accepted (lookup candidates).
    let raw = sign(json!({"userId": id, "email": "user@example.test", "type": "refresh", "iat": now_s(), "exp": now_s() + 600}));
    sql(&s, &format!(r#"INSERT INTO "RefreshToken" ("id","userId","token","expiresAt","revoked","createdAt") VALUES ('r2','{id}','{raw}',{},0,0)"#, (now_s() + 600) * 1000));
    let r = with_refresh(&raw);
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(decode(&cookie_value(&r, "excalidash-access-token").unwrap())["authProvider"], "local");

    // Expired row.
    let expired = sign(json!({"userId": id, "email": "user@example.test", "type": "refresh", "iat": now_s(), "exp": now_s() + 600, "jti": "e"}));
    sql(&s, &format!(r#"INSERT INTO "RefreshToken" ("id","userId","token","expiresAt","revoked","createdAt") VALUES ('r3','{id}','{}',1000,0,0)"#, sha256_hex(&expired)));
    let r = with_refresh(&expired);
    assert_eq!(r.json()["message"], "Refresh token has expired");
    // Unknown token.
    let unknown = sign(json!({"userId": id, "email": "user@example.test", "type": "refresh", "iat": now_s(), "exp": now_s() + 600, "jti": "u"}));
    assert_eq!(with_refresh(&unknown).json()["message"], "Invalid or revoked refresh token");
    // Wrong type / bad payload / garbage.
    let access = sign(json!({"userId": id, "email": "user@example.test", "type": "access", "iat": now_s(), "exp": now_s() + 600}));
    assert_eq!(with_refresh(&access).json()["message"], "Invalid token type");
    let bad = sign(json!({"userId": id, "type": "refresh", "iat": now_s(), "exp": now_s() + 600}));
    assert_eq!(with_refresh(&bad).json()["message"], "Invalid token payload");
    assert_eq!(with_refresh("garbage").json()["message"], "Invalid or expired refresh token");
    let old = sign(json!({"userId": id, "email": "user@example.test", "type": "refresh", "iat": now_s() - 100, "exp": now_s() - 10}));
    assert_eq!(with_refresh(&old).json()["message"], "Invalid or expired refresh token");
    // Inactive user.
    sql(&s, &format!(r#"UPDATE "User" SET "isActive"=0 WHERE "id"='{id}'"#));
    assert_eq!(with_refresh(&unknown).json()["message"], "User account not found or inactive");

    // Missing cookie.
    let mut none = s.client();
    none.fetch_csrf();
    let r = none.post("/auth/refresh", json!({}));
    assert_eq!((r.status, r.json()), (401, json!({"error": "Unauthorized", "message": "Refresh token required"})));
    // CSRF required.
    let r = without_csrf(&none).post("/auth/refresh", json!({}));
    assert_eq!(r.json()["error"], "CSRF token missing");
}

#[test]
fn refresh_without_rotation_issues_access_only() {
    let s = TestServer::start(&[("ENABLE_REFRESH_TOKEN_ROTATION", "false")]);
    enable_auth(&s);
    let admin = seed_user(&s, "admin@example.test", "Admin", "ADMIN");
    let c = login(&s, "admin@example.test", STRONG_PASSWORD);
    assert_eq!(count(&s, r#"SELECT COUNT(*) FROM "RefreshToken""#), 0);
    let r = c.post("/auth/refresh", json!({}));
    assert_eq!(r.status, 200, "{}", r.text());
    assert!(cookie_value(&r, "excalidash-refresh-token").is_none());
    let access = cookie_value(&r, "excalidash-access-token").unwrap();
    let claims = decode(&access);
    let keys: Vec<&String> = claims.as_object().unwrap().keys().collect();
    assert_eq!(keys, ["userId", "email", "type", "authProvider", "iat", "exp"]);

    // Impersonation claims are carried over; absent authProvider stays absent.
    let tok = sign(json!({"userId": admin, "email": "admin@example.test", "impersonatorId": "someone", "type": "refresh", "iat": now_s(), "exp": now_s() + 600}));
    let mut cl = s.client().with_header("Cookie", &format!("excalidash-refresh-token={tok}"));
    cl.fetch_csrf_with_cookie_header();
    let r = cl.post("/auth/refresh", json!({}));
    let claims = decode(&cookie_value(&r, "excalidash-access-token").unwrap());
    let keys: Vec<&String> = claims.as_object().unwrap().keys().collect();
    assert_eq!(keys, ["userId", "email", "type", "impersonatorId", "iat", "exp"]);
}

#[test]
fn logout_clears_cookies_and_revokes_tokens() {
    let s = TestServer::start(&[]);
    enable_auth(&s);
    seed_user(&s, "user@example.test", "User", "USER");
    let c = login(&s, "user@example.test", STRONG_PASSWORD);
    c.post("/auth/refresh", json!({}));
    assert_eq!(count(&s, r#"SELECT COUNT(*) FROM "RefreshToken" WHERE "revoked"=0"#), 1);
    let r = c.post("/auth/logout", json!({}));
    assert_eq!(r.status, 200);
    assert_eq!(r.text(), r#"{"ok":true}"#);
    assert_eq!(
        r.header_all("set-cookie"),
        vec![
            "excalidash-access-token=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Lax".to_string(),
            "excalidash-refresh-token=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Lax".to_string(),
        ]
    );
    assert_eq!(count(&s, r#"SELECT COUNT(*) FROM "RefreshToken" WHERE "revoked"=0"#), 0);
    assert_eq!(c.get("/auth/me").status, 401);
    // Anonymous logout still succeeds.
    let mut anon = s.client();
    anon.fetch_csrf();
    assert_eq!(anon.post("/auth/logout", json!({})).status, 200);
}

#[test]
fn secure_cookies_behind_https_proxy() {
    let s = TestServer::start(&[("TRUST_PROXY", "1")]);
    enable_auth(&s);
    seed_user(&s, "user@example.test", "User", "USER");
    let mut c = s.client().with_header("X-Forwarded-Proto", "https");
    // The csrf client cookie is Secure here, so pass it by hand over plain http.
    c.fetch_csrf_with_cookie_header();
    let r = c.post("/auth/login", json!({"email": "user@example.test", "password": STRONG_PASSWORD}));
    assert_eq!(r.status, 200);
    assert_auth_cookie_format(&r, true);
}

// ---------------------------------------------------------------------------
// me / must-reset / stop-impersonation

#[test]
fn me_and_must_reset_password() {
    let s = TestServer::start(&[]);
    let (c, id) = user_session(&s, "user@example.test", "USER");
    let r = c.get("/auth/me");
    assert_eq!(r.status, 200);
    let u = &r.json()["user"];
    assert_eq!(u["id"], id.as_str());
    assert_eq!(u["username"], Value::Null);
    assert!(u["createdAt"].as_str().unwrap().ends_with('Z'));
    let r = s.client().get("/auth/me");
    assert_eq!((r.status, r.json()), (401, json!({"error": "Unauthorized", "message": "Authentication token required"})));
    let r = s.client().with_header("Authorization", "Bearer nope").get("/auth/me");
    assert_eq!(r.json()["message"], "Invalid or expired token");

    sql(&s, &format!(r#"UPDATE "User" SET "mustResetPassword"=1 WHERE "id"='{id}'"#));
    let r = c.get("/auth/me");
    assert_eq!(r.status, 200);
    assert_eq!(r.json()["user"]["mustResetPassword"], true);
    let r = c.post("/auth/stop-impersonation", json!({}));
    assert_eq!(r.status, 403);
    assert_eq!(r.json()["code"], "MUST_RESET_PASSWORD");
    // Login still works and reports the flag.
    let mut lc = s.client();
    lc.fetch_csrf();
    let r = lc.post("/auth/login", json!({"email": "user@example.test", "password": STRONG_PASSWORD}));
    assert_eq!(r.json()["user"]["mustResetPassword"], true);
}

#[test]
fn stop_impersonation() {
    let s = TestServer::start(&[]);
    enable_auth(&s);
    let admin = seed_user(&s, "admin@example.test", "Admin", "ADMIN");
    sql(&s, &format!(r#"UPDATE "User" SET "username"='root' WHERE "id"='{admin}'"#));
    let user = seed_user(&s, "user@example.test", "User", "USER");
    let impersonating = |imp: &str| {
        let tok = sign(json!({"userId": user, "email": "user@example.test", "impersonatorId": imp, "authProvider": "local", "type": "access", "iat": now_s(), "exp": now_s() + 600}));
        let mut c = s.client().with_header("Cookie", &format!("excalidash-access-token={tok}"));
        c.fetch_csrf_with_cookie_header();
        c
    };
    let c = impersonating(&admin);
    let st = c.get("/auth/status").json();
    assert_eq!(st["user"]["impersonatorId"], admin.as_str());
    let r = c.post("/auth/stop-impersonation", json!({}));
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(
        r.json(),
        json!({"user": {"id": admin, "username": "root", "email": "admin@example.test", "name": "Admin", "role": "ADMIN", "mustResetPassword": false}})
    );
    assert_auth_cookie_format(&r, false);
    assert_eq!(decode(&cookie_value(&r, "excalidash-access-token").unwrap())["userId"], admin.as_str());
    assert_eq!(count(&s, &format!(r#"SELECT COUNT(*) FROM "RefreshToken" WHERE "userId"='{admin}'"#)), 1);

    let r = impersonating(&user).post("/auth/stop-impersonation", json!({}));
    assert_eq!((r.status, r.json()["message"].clone()), (403, json!("Impersonator account is unavailable or no longer authorized")));
    let plain = session_client(&s, &user, "user@example.test");
    let r = plain.post("/auth/stop-impersonation", json!({}));
    assert_eq!((r.status, r.json()), (409, json!({"error": "Conflict", "message": "Not currently impersonating another user"})));
    assert!(plain.get("/auth/status").json()["user"].get("impersonatorId").is_none());
    let r = s.client().post("/auth/stop-impersonation", json!({}));
    assert_eq!(r.status, 401);
}

// ---------------------------------------------------------------------------
// auth-enabled toggle

#[test]
fn auth_enabled_toggle_round_trip() {
    let s = TestServer::start(&[]);
    let (admin, _) = bootstrap_admin(&s, "admin@example.test");
    let r = admin.post("/auth/auth-enabled", json!({"enabled": "no"}));
    assert_eq!((r.status, r.json()), (400, json!({"error": "Bad request", "message": "Invalid toggle payload"})));
    let r = admin.post("/auth/auth-enabled", json!({"enabled": false}));
    assert_eq!(r.text(), r#"{"authEnabled":false,"bootstrapRequired":false}"#);
    let st = s.client().get("/auth/status").json();
    assert_eq!((st["authEnabled"].clone(), st["user"].clone(), st["registrationEnabled"].clone()), (json!(false), Value::Null, json!(false)));
    // Auth-disabled: auth routes report 404, anonymous requests act as the bootstrap admin.
    let mut anon = s.client();
    anon.fetch_csrf();
    let r = anon.post("/auth/login", json!({"email": "admin@example.test", "password": STRONG_PASSWORD}));
    assert_eq!((r.status, r.json()), (404, json!({"error": "Not found", "message": "Authentication is disabled"})));
    assert_eq!(anon.get("/auth/me").status, 404);
    let r = anon.post("/auth/auth-enabled", json!({"enabled": true}));
    assert_eq!(r.text(), r#"{"authEnabled":true,"bootstrapRequired":false}"#);
    assert_eq!(anon.post("/auth/auth-enabled", json!({"enabled": false})).status, 401);
}

// ---------------------------------------------------------------------------
// AUTH_MODE variants

#[test]
fn auth_mode_disabled_status_and_routes() {
    let s = TestServer::start(&[("AUTH_MODE", "disabled")]);
    let mut c = s.client();
    let st = c.get("/auth/status").json();
    assert_eq!(
        st,
        json!({"enabled": false, "authenticated": false, "authEnabled": false, "authMode": "disabled", "oidcEnabled": false, "oidcEnforced": false, "oidcProvider": "OIDC", "oidcJitProvisioningEnabled": false, "registrationEnabled": false, "bootstrapRequired": false, "authOnboardingRequired": false, "authOnboardingMode": null, "authOnboardingRecommended": null, "passwordPolicy": {"minLength": 12, "maxLength": 100, "requireUppercase": true, "requireLowercase": true, "requireNumber": true, "requireSymbol": true}, "user": null})
    );
    assert!(!s.output().contains("[BOOTSTRAP SETUP]"));
    c.fetch_csrf();
    let r = c.post("/auth/onboarding-choice", json!({"enableAuth": true}));
    assert_eq!((r.status, r.json()), (409, json!({"error": "Conflict", "message": "Onboarding choice is managed by AUTH_MODE configuration"})));
    let r = c.post("/auth/auth-enabled", json!({"enabled": true}));
    assert_eq!((r.status, r.json()), (409, json!({"error": "Conflict", "message": "Authentication mode is managed by AUTH_MODE=disabled"})));
    let r = c.post("/auth/register", json!({"email": "a@b.co", "password": STRONG_PASSWORD, "name": "A"}));
    assert_eq!(r.status, 404);
    assert_eq!(c.post("/auth/refresh", json!({})).status, 404);
    assert_eq!(c.post("/auth/logout", json!({})).status, 404);
}

#[test]
fn auth_mode_hybrid_status() {
    let s = TestServer::start(&[
        ("AUTH_MODE", "hybrid"),
        ("OIDC_ISSUER_URL", "https://idp.example.test"),
        ("OIDC_CLIENT_ID", "client"),
        ("OIDC_CLIENT_SECRET", "secret"),
        ("OIDC_REDIRECT_URI", "https://first.example.test/api/auth/oidc/callback"),
        ("OIDC_PROVIDER_NAME", "TestIdP"),
    ]);
    let st = s.client().get("/auth/status").json();
    assert_eq!(st["enabled"], true);
    assert_eq!(st["authMode"], "hybrid");
    assert_eq!(st["oidcEnabled"], true);
    assert_eq!(st["oidcEnforced"], false);
    assert_eq!(st["oidcProvider"], "TestIdP");
    assert_eq!(st["authOnboardingRequired"], false);
    assert_eq!(st["authOnboardingMode"], Value::Null);
    assert_eq!(st["registrationEnabled"], false);
    sql(&s, r#"UPDATE "SystemConfig" SET "registrationEnabled"=1"#);
    assert_eq!(s.client().get("/auth/status").json()["registrationEnabled"], true);
    let mut c = s.client();
    c.fetch_csrf();
    let r = c.post("/auth/onboarding-choice", json!({"enableAuth": true}));
    assert_eq!(r.status, 409);
    // requireAuth runs before the AUTH_MODE check.
    assert_eq!(c.post("/auth/auth-enabled", json!({"enabled": true})).status, 401);
    let id = seed_user(&s, "admin@example.test", "Admin", "ADMIN");
    let a = session_client(&s, &id, "admin@example.test");
    let r = a.post("/auth/auth-enabled", json!({"enabled": true}));
    assert_eq!(r.json()["message"], "Authentication mode is managed by AUTH_MODE=hybrid");
    let r = a.get("/auth/status").json();
    assert_eq!(r["authenticated"], true);
}
