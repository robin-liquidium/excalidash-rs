//! Admin routes: settings, users, admin password reset, impersonation, plus
//! the server side of admin-login-rate-limit.integration.ts.
mod common;

use base64::Engine;
use common::*;
use serde_json::{json, Value};

fn keys(v: &Value) -> Vec<String> {
    v.as_object().unwrap().keys().cloned().collect()
}

fn set_cookie_value(r: &Resp, name: &str) -> Option<String> {
    r.header_all("set-cookie")
        .iter()
        .find_map(|c| c.strip_prefix(&format!("{name}=")).map(|v| v.split(';').next().unwrap().to_string()))
}

fn client_with_access_token(server: &TestServer, token: &str) -> TestClient {
    let mut c = server.client().with_header("Cookie", &format!("excalidash-access-token={token}"));
    c.fetch_csrf_with_cookie_header();
    c
}

fn jwt_claims(token: &str) -> Value {
    let payload = token.split('.').nth(1).unwrap();
    serde_json::from_slice(&base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap()
}

fn db_user(server: &TestServer, id: &str) -> (String, bool, bool, i64) {
    server
        .db()
        .query_row(r#"SELECT "role","isActive","mustResetPassword","updatedAt" FROM "User" WHERE "id" = ?1"#, [id], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
        })
        .unwrap()
}

#[test]
fn admin_routes_require_an_admin() {
    let server = TestServer::start(&[]);
    let (user, _) = user_session(&server, "plain@test.local", "USER");
    let forbidden = json!({"error": "Forbidden", "message": "Admin access required"});
    let cases: Vec<(&str, &str, Option<Value>)> = vec![
        ("GET", "/auth/users", None),
        ("POST", "/auth/users", Some(json!({}))),
        ("PATCH", "/auth/users/someone", Some(json!({}))),
        ("POST", "/auth/users/someone/reset-password", Some(json!({}))),
        ("POST", "/auth/admins", Some(json!({}))),
        ("POST", "/auth/registration/toggle", Some(json!({"enabled": true}))),
        ("POST", "/auth/oidc/jit-provisioning", Some(json!({"enabled": true}))),
        ("GET", "/auth/rate-limit/login", None),
        ("PUT", "/auth/rate-limit/login", Some(json!({}))),
        ("POST", "/auth/rate-limit/login/reset", Some(json!({}))),
        ("GET", "/auth/impersonation-targets", None),
        ("POST", "/auth/impersonate", Some(json!({"userId": "x"}))),
    ];
    let anon = server.client();
    for (m, p, b) in &cases {
        let r = user.send(m, p, b.as_ref());
        assert_eq!(r.status, 403, "{m} {p}: {}", r.text());
        assert_eq!(r.json(), forbidden, "{m} {p}");
        let r = anon.send(m, p, b.as_ref());
        assert_eq!(r.status, 401, "{m} {p}");
        assert_eq!(r.json(), json!({"error": "Unauthorized", "message": "Authentication token required"}));
    }
}

#[test]
fn admin_routes_404_when_auth_disabled() {
    let server = TestServer::start(&[]);
    let r = server.client().get("/auth/users");
    assert_eq!(r.status, 404);
    assert_eq!(r.json(), json!({"error": "Not found", "message": "Authentication is disabled"}));
}

#[test]
fn admin_user_management() {
    let server = TestServer::start(&[]);
    let (admin, admin_id) = user_session(&server, "admin@test.local", "ADMIN");

    let r = admin.get("/auth/users");
    assert_eq!(r.status, 200);
    let users = r.json()["users"].clone();
    // The SQLite add_user_auth migration seeds the inactive bootstrap admin (the
    // PostgreSQL baseline migration does not).
    assert_eq!(users.as_array().unwrap().len(), if is_pg() { 1 } else { 2 });
    assert_eq!(
        keys(&users[0]),
        ["id", "username", "email", "name", "role", "mustResetPassword", "isActive", "createdAt", "updatedAt"]
    );

    // Validation
    let invalid = json!({"error": "Validation error", "message": "Invalid user payload"});
    for bad in [
        json!({"email": "u1@test.local", "name": "No Password"}),
        json!({"email": "u1@test.local", "name": "Weak", "password": "weak"}),
        json!({"email": " u1@test.local", "name": "Space", "password": STRONG_PASSWORD}),
        json!({"email": "u1@test.local", "name": " ", "password": STRONG_PASSWORD}),
        json!({"email": "u1@test.local", "name": "x", "password": STRONG_PASSWORD, "username": "ab"}),
        json!({"email": "u1@test.local", "name": "x", "password": STRONG_PASSWORD, "role": "OWNER"}),
    ] {
        let r = admin.post("/auth/users", bad.clone());
        assert_eq!(r.status, 400, "{bad}");
        assert_eq!(r.json(), invalid);
    }

    let r = admin.post(
        "/auth/users",
        json!({"email": "U1@Test.local", "password": STRONG_PASSWORD, "name": "  User <b>One</b><script>x</script> ", "username": " userone "}),
    );
    assert_eq!(r.status, 201, "{}", r.text());
    assert_eq!(r.header("ratelimit-limit").as_deref(), Some("60"));
    let u1 = r.json()["user"].clone();
    assert_eq!(keys(&u1), ["id", "username", "email", "name", "role", "mustResetPassword", "isActive", "createdAt", "updatedAt"]);
    assert_eq!(u1["email"], "u1@test.local");
    assert_eq!(u1["username"], "userone");
    assert_eq!(u1["name"], "User <b>One</b>");
    assert_eq!(u1["role"], "USER");
    assert_eq!(u1["mustResetPassword"], false);
    assert_eq!(u1["isActive"], true);
    let u1_id = u1["id"].as_str().unwrap().to_string();
    let hash: String =
        server.db().query_row(r#"SELECT "passwordHash" FROM "User" WHERE "id" = ?1"#, [&u1_id], |r| r.get(0)).unwrap();
    assert!(hash.starts_with("$2b$10$") && bcrypt::verify(STRONG_PASSWORD, &hash).unwrap());

    let r = admin.post("/auth/users", json!({"email": "u1@test.local", "password": STRONG_PASSWORD, "name": "Dup"}));
    assert_eq!(r.status, 409);
    assert_eq!(r.json(), json!({"error": "Conflict", "message": "User with this email already exists"}));
    let r = admin.post("/auth/users", json!({"email": "u9@test.local", "password": STRONG_PASSWORD, "name": "Dup", "username": "userone"}));
    assert_eq!(r.status, 409);
    assert_eq!(r.json()["message"], "User with this username already exists");
    let r = admin.post("/auth/users", json!({"email": "oidc@test.local", "name": "Oidc", "oidcOnly": true}));
    assert_eq!(r.status, 409);
    assert_eq!(r.json()["message"], "OIDC-only invited users require OIDC to be enabled.");

    let r = admin.post(
        "/auth/users",
        json!({"email": "u2@test.local", "password": STRONG_PASSWORD, "name": "Two", "role": "ADMIN", "mustResetPassword": true, "isActive": false}),
    );
    assert_eq!(r.status, 201);
    let u2 = r.json()["user"].clone();
    assert_eq!((u2["role"].clone(), u2["mustResetPassword"].clone(), u2["isActive"].clone()), (json!("ADMIN"), json!(true), json!(false)));
    let u2_id = u2["id"].as_str().unwrap().to_string();

    let listed = admin.get("/auth/users").json()["users"].clone();
    let emails: Vec<&str> = listed.as_array().unwrap().iter().map(|u| u["email"].as_str().unwrap()).collect();
    // createdAt asc in SQL: the migration's TEXT timestamp sorts after Prisma's integer ones
    // (no seeded bootstrap row on PostgreSQL).
    let mut expected = vec!["admin@test.local", "u1@test.local", "u2@test.local"];
    if !is_pg() {
        expected.push("bootstrap@excalidash.local");
    }
    assert_eq!(emails, expected);

    // PATCH
    let before = db_user(&server, &u1_id).3;
    std::thread::sleep(std::time::Duration::from_millis(5));
    let r = admin.patch(&format!("/auth/users/{u1_id}"), json!({}));
    assert_eq!(r.status, 200);
    assert_eq!(db_user(&server, &u1_id).3, before, "empty update does not touch updatedAt");

    let r = admin.patch(&format!("/auth/users/{u1_id}"), json!({"role": "nope"}));
    assert_eq!(r.status, 400);
    assert_eq!(r.json(), json!({"error": "Bad request", "message": "Invalid update payload"}));
    let r = admin.patch("/auth/users/missing", json!({"name": "x"}));
    assert_eq!(r.status, 404);
    assert_eq!(r.json(), json!({"error": "Not found", "message": "User not found"}));
    let r = admin.patch("/auth/users/%20", json!({}));
    assert_eq!(r.status, 400);
    assert_eq!(r.json(), json!({"error": "Bad request", "message": "Invalid user id"}));

    let r = admin.patch(
        &format!("/auth/users/{u1_id}"),
        json!({"name": " Renamed ", "username": null, "role": "ADMIN", "mustResetPassword": true, "isActive": true}),
    );
    assert_eq!(r.status, 200, "{}", r.text());
    let u = r.json()["user"].clone();
    assert_eq!(u["name"], "Renamed");
    assert_eq!(u["username"], Value::Null);
    assert_eq!(u["role"], "ADMIN");
    assert_eq!(u["mustResetPassword"], true);
    assert!(u["updatedAt"].as_str().unwrap() > u["createdAt"].as_str().unwrap());

    let r = admin.patch(&format!("/auth/users/{u2_id}"), json!({"username": "taken"}));
    assert_eq!(r.status, 200);
    let r = admin.patch(&format!("/auth/users/{u1_id}"), json!({"username": "taken"}));
    assert_eq!(r.status, 409);
    assert_eq!(r.json(), json!({"error": "Conflict", "message": "User with this username already exists"}));

    // Self-protection (keeps at least the acting admin active).
    let r = admin.patch(&format!("/auth/users/{admin_id}"), json!({"isActive": false}));
    assert_eq!(r.status, 409);
    assert_eq!(r.json()["message"], "You cannot deactivate your own account");
    let r = admin.patch(&format!("/auth/users/{admin_id}"), json!({"role": "USER"}));
    assert_eq!(r.status, 409);
    assert_eq!(r.json()["message"], "You cannot change your own role from ADMIN");

    // Demoting/deactivating another admin is fine while another active admin remains.
    let r = admin.patch(&format!("/auth/users/{u1_id}"), json!({"role": "USER", "isActive": false}));
    assert_eq!(r.status, 200);
    assert_eq!(db_user(&server, &u1_id).0, "USER");
}

#[test]
fn admin_role_endpoint_and_bootstrap_protection() {
    let server = TestServer::start(&[]);
    let (admin, admin_id) = user_session(&server, "admin@test.local", "ADMIN");
    let uid = seed_user(&server, "member@test.local", "Member", "USER");
    server.db().execute(r#"UPDATE "User" SET "username" = 'member' WHERE "id" = ?1"#, [&uid]).unwrap();

    for bad in [json!({}), json!({"identifier": " ", "role": "ADMIN"}), json!({"identifier": "member", "role": "ROOT"})] {
        let r = admin.post("/auth/admins", bad);
        assert_eq!(r.status, 400);
        assert_eq!(r.json(), json!({"error": "Bad request", "message": "Invalid admin update payload"}));
    }
    let r = admin.post("/auth/admins", json!({"identifier": "ghost@test.local", "role": "ADMIN"}));
    assert_eq!(r.status, 404);

    let r = admin.post("/auth/admins", json!({"identifier": " member ", "role": "ADMIN"}));
    assert_eq!(r.status, 200, "{}", r.text());
    let u = r.json()["user"].clone();
    assert_eq!(keys(&u), ["id", "username", "email", "name", "role", "mustResetPassword", "isActive"]);
    assert_eq!(u["role"], "ADMIN");
    let r = admin.post("/auth/admins", json!({"identifier": "MEMBER@test.local", "role": "USER"}));
    assert_eq!(r.status, 200);
    assert_eq!(r.json()["user"]["role"], "USER");

    let r = admin.post("/auth/admins", json!({"identifier": "admin@test.local", "role": "USER"}));
    assert_eq!(r.status, 409);
    assert_eq!(r.json()["message"], "You cannot change your own role from ADMIN");

    // auth-enabled.integration.ts: protects the bootstrap admin role through both endpoints
    // (the migration-seeded row: role ADMIN, inactive).
    if is_pg() {
        server.db().execute(r#"INSERT INTO "User" ("id","email","passwordHash","name","role","mustResetPassword","isActive","createdAt","updatedAt") VALUES ('bootstrap-admin','bootstrap@excalidash.local','','Bootstrap Admin','ADMIN',1,0,0,0)"#, []).unwrap();
    }
    server.db().execute(r#"UPDATE "User" SET "role" = 'ADMIN', "isActive" = 0 WHERE "id" = 'bootstrap-admin'"#, []).unwrap();
    let r = admin.post("/auth/admins", json!({"identifier": "bootstrap@excalidash.local", "role": "USER"}));
    assert_eq!(r.status, 409);
    assert!(r.json()["message"].as_str().unwrap().contains("bootstrap account"));
    let r = admin.patch("/auth/users/bootstrap-admin", json!({"role": "USER"}));
    assert_eq!(r.status, 409);
    assert!(r.json()["message"].as_str().unwrap().contains("bootstrap account"));
    let role: String =
        server.db().query_row(r#"SELECT "role" FROM "User" WHERE "id" = 'bootstrap-admin'"#, [], |r| r.get(0)).unwrap();
    assert_eq!(role, "ADMIN");
    let _ = admin_id;
}

#[test]
fn admin_settings_routes() {
    let server = TestServer::start(&[]);
    let (admin, _) = user_session(&server, "admin@test.local", "ADMIN");

    let r = admin.post("/auth/registration/toggle", json!({"enabled": "yes"}));
    assert_eq!(r.status, 400);
    assert_eq!(r.json(), json!({"error": "Bad request", "message": "Invalid toggle payload"}));
    let r = admin.post("/auth/registration/toggle", json!({"enabled": true}));
    assert_eq!(r.status, 200);
    assert_eq!(r.json(), json!({"registrationEnabled": true}));
    let enabled: bool = server
        .db()
        .query_row(r#"SELECT "registrationEnabled" FROM "SystemConfig" WHERE "id" = 'default'"#, [], |r| r.get(0))
        .unwrap();
    assert!(enabled);
    assert_eq!(admin.post("/auth/registration/toggle", json!({"enabled": false})).json(), json!({"registrationEnabled": false}));

    let r = admin.post("/auth/oidc/jit-provisioning", json!({"enabled": true}));
    assert_eq!(r.status, 409);
    assert_eq!(r.json(), json!({"error": "Conflict", "message": "OIDC is not enabled."}));

    // CSRF required on mutations
    let mut no_csrf = admin;
    let token = no_csrf.csrf.take();
    let r = no_csrf.post("/auth/registration/toggle", json!({"enabled": true}));
    assert_eq!(r.status, 403);
    assert_eq!(r.json()["error"], "CSRF token missing");
    no_csrf.csrf = token;
}

/// admin-login-rate-limit.integration.ts drives these endpoints from the admin UI:
/// GET → { config }, PUT { enabled, windowMs, max } → { config }, reset → { ok: true }.
#[test]
fn admin_login_rate_limit_settings() {
    let server = TestServer::start(&[]);
    let (admin, _) = user_session(&server, "admin@test.local", "ADMIN");

    let r = admin.get("/auth/rate-limit/login");
    assert_eq!(r.status, 200);
    assert_eq!(r.text(), r#"{"config":{"enabled":true,"windowMs":900000,"max":20}}"#);

    let invalid = json!({"error": "Validation error", "message": "Invalid rate limit config"});
    for bad in [
        json!({"enabled": true, "windowMs": 9_999, "max": 5}),
        json!({"enabled": true, "windowMs": 86_400_001, "max": 5}),
        json!({"enabled": true, "windowMs": 60_000, "max": 0}),
        json!({"enabled": true, "windowMs": 60_000, "max": 10_001}),
        json!({"enabled": true, "windowMs": 60_000, "max": 1.5}),
        json!({"windowMs": 60_000, "max": 5}),
        json!({"enabled": true, "windowMs": "60000", "max": 5}),
    ] {
        let r = admin.put("/auth/rate-limit/login", bad.clone());
        assert_eq!(r.status, 400, "{bad}");
        assert_eq!(r.json(), invalid);
    }

    // The UI autosaves normalized values (2.4 min → 120000 ms, 3.6 → 4).
    let r = admin.put("/auth/rate-limit/login", json!({"enabled": false, "windowMs": 120_000, "max": 4}));
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(r.text(), r#"{"config":{"enabled":false,"windowMs":120000,"max":4}}"#);
    let row: (bool, i64, i64) = server
        .db()
        .query_row(
            r#"SELECT "authLoginRateLimitEnabled","authLoginRateLimitWindowMs","authLoginRateLimitMax" FROM "SystemConfig" WHERE "id" = 'default'"#,
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(row, (false, 120_000, 4));
    assert_eq!(admin.get("/auth/rate-limit/login").json(), json!({"config": {"enabled": false, "windowMs": 120000, "max": 4}}));

    for bad in [json!({}), json!({"identifier": "   "}), json!({"identifier": "x".repeat(256)})] {
        let r = admin.post("/auth/rate-limit/login/reset", bad);
        assert_eq!(r.status, 400);
        assert_eq!(r.json(), json!({"error": "Validation error", "message": "Invalid reset payload"}));
    }
    let r = admin.post("/auth/rate-limit/login/reset", json!({"identifier": "localuser"}));
    assert_eq!(r.status, 200);
    assert_eq!(r.json(), json!({"ok": true}));
}

/// The login limiter is shared by the password-reset endpoints, so its config and
/// reset can be observed without the /auth/login route.
#[test]
fn login_rate_limit_config_applies_and_reset_unlocks() {
    let server = TestServer::start(&[]);
    let (admin, _) = user_session(&server, "admin@test.local", "ADMIN");
    let r = admin.put("/auth/rate-limit/login", json!({"enabled": true, "windowMs": 60_000, "max": 2}));
    assert_eq!(r.status, 200);

    let c = server.client();
    let attempt = || c.post("/auth/password-reset-request", json!({"email": "Locked@Test.local"}));
    assert_eq!(attempt().status, 404, "feature off → 404 after the limiter");
    let r = attempt();
    assert_eq!(r.header("ratelimit-limit").as_deref(), Some("2"));
    assert_eq!(r.header("ratelimit-remaining").as_deref(), Some("0"));
    let r = attempt();
    assert_eq!(r.status, 429);
    assert_eq!(r.json(), json!({"error": "Too many requests", "message": "Too many login attempts, please try again later"}));

    let r = admin.post("/auth/rate-limit/login/reset", json!({"identifier": "  LOCKED@test.local  "}));
    assert_eq!(r.json(), json!({"ok": true}));
    assert_eq!(attempt().status, 404, "reset clears the lockout for that identifier");

    // Disabling the limiter removes the limit entirely.
    admin.put("/auth/rate-limit/login", json!({"enabled": false, "windowMs": 60_000, "max": 1}));
    for _ in 0..3 {
        let r = attempt();
        assert_eq!(r.status, 404);
        assert_eq!(r.header("ratelimit-limit").as_deref(), Some("100000"), "only the general limiter applies");
    }
}

#[test]
fn admin_reset_user_password() {
    let server = TestServer::start(&[]);
    let (admin, admin_id) = user_session(&server, "admin@test.local", "ADMIN");
    let uid = seed_user(&server, "target@test.local", "Target", "USER");
    let now = chrono::Utc::now().timestamp_millis();
    let db = server.db();
    db.execute(r#"UPDATE "User" SET "isActive" = 0, "username" = 'target' WHERE "id" = ?1"#, [&uid]).unwrap();
    db.execute(
        r#"INSERT INTO "RefreshToken" ("id","userId","token","expiresAt","revoked","createdAt") VALUES ('rt1',?1,'h1',?2,0,?3)"#,
        excalidash_rs::sql::params![uid, now + 100_000, now],
    )
    .unwrap();

    let r = admin.post(&format!("/auth/users/{admin_id}/reset-password"), json!({}));
    assert_eq!(r.status, 409);
    assert_eq!(r.json(), json!({"error": "Conflict", "message": "Use Profile -> Change Password for your own account"}));
    let r = admin.post("/auth/users/missing/reset-password", json!({}));
    assert_eq!(r.status, 404);

    let r = admin.send("POST", &format!("/auth/users/{uid}/reset-password"), None);
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(r.header("ratelimit-limit").as_deref(), Some("60"));
    let body = r.json();
    assert_eq!(keys(&body), ["user", "tempPassword"]);
    assert_eq!(body["user"], json!({"id": uid, "email": "target@test.local", "username": "target", "role": "USER"}));
    let temp = body["tempPassword"].as_str().unwrap();
    // Upstream strips +/= from 24 base64 chars, so the length varies (<= 24).
    assert!(temp.len() <= 24 && temp.len() >= 12, "{temp}");
    assert!(temp.chars().all(|c| c.is_ascii_alphanumeric()));
    let (hash, must_reset, active): (String, bool, bool) = db
        .query_row(r#"SELECT "passwordHash","mustResetPassword","isActive" FROM "User" WHERE "id" = ?1"#, [&uid], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })
        .unwrap();
    assert!(bcrypt::verify(temp, &hash).unwrap());
    assert!(must_reset && active);
    let revoked: bool = db.query_row(r#"SELECT "revoked" FROM "RefreshToken" WHERE "id" = 'rt1'"#, [], |r| r.get(0)).unwrap();
    assert!(revoked);
}

#[test]
fn impersonation_flow() {
    let server = TestServer::start(&[]);
    let (admin, admin_id) = user_session(&server, "admin@test.local", "ADMIN");
    let bob = seed_user(&server, "bob@test.local", "Bob", "USER");
    let alice = seed_user(&server, "alice@test.local", "Alice", "USER");
    let admin2 = seed_user(&server, "admin2@test.local", "Zed Admin", "ADMIN");
    let inactive = seed_user(&server, "gone@test.local", "Gone", "USER");
    server.db().execute(r#"UPDATE "User" SET "isActive" = 0 WHERE "id" = ?1"#, [&inactive]).unwrap();

    let r = admin.get("/auth/impersonation-targets");
    assert_eq!(r.status, 200);
    let body = r.json();
    let names: Vec<&str> = body["users"].as_array().unwrap().iter().map(|u| u["name"].as_str().unwrap()).collect();
    assert_eq!(names, ["Alice", "Bob", "Zed Admin"]);
    assert_eq!(keys(&body["users"][0]), ["id", "username", "email", "name", "role", "isActive"]);
    assert_eq!(body["impersonator"], json!({"id": admin_id, "email": "admin@test.local", "name": "Test User"}));

    for bad in [json!({}), json!({"userId": " "}), json!({"identifier": ""})] {
        let r = admin.post("/auth/impersonate", bad);
        assert_eq!(r.status, 400);
        assert_eq!(r.json(), json!({"error": "Bad request", "message": "Invalid impersonation payload"}));
    }
    assert_eq!(admin.post("/auth/impersonate", json!({"userId": "missing"})).status, 404);
    let r = admin.post("/auth/impersonate", json!({"userId": admin_id}));
    assert_eq!(r.status, 409);
    assert_eq!(r.json()["message"], "Already using the admin account. Use stop impersonation to return.");
    let r = admin.post("/auth/impersonate", json!({"userId": inactive}));
    assert_eq!(r.status, 403);
    assert_eq!(r.json(), json!({"error": "Forbidden", "message": "Target user is inactive"}));

    let r = admin.post("/auth/impersonate", json!({"identifier": "BOB@test.local"}));
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(r.header("ratelimit-limit").as_deref(), Some("60"));
    assert_eq!(
        r.json(),
        json!({"user": {"id": bob, "username": null, "email": "bob@test.local", "name": "Bob", "role": "USER", "mustResetPassword": false}})
    );
    let access = set_cookie_value(&r, "excalidash-access-token").unwrap();
    let refresh = set_cookie_value(&r, "excalidash-refresh-token").unwrap();
    let claims = jwt_claims(&access);
    assert_eq!(claims["userId"], json!(bob));
    assert_eq!(claims["email"], "bob@test.local");
    assert_eq!(claims["impersonatorId"], json!(admin_id));
    assert_eq!(claims["authProvider"], "local");
    assert_eq!(claims["type"], "access");
    assert_eq!(jwt_claims(&refresh)["type"], "refresh");
    let stored: i64 = server
        .db()
        .query_row(r#"SELECT COUNT(*) FROM "RefreshToken" WHERE "userId" = ?1 AND "revoked" = 0"#, [&bob], |r| r.get(0))
        .unwrap();
    assert_eq!(stored, 1);

    // Acting as Bob (impersonated): the impersonator still counts as the acting admin.
    let as_bob = client_with_access_token(&server, &access);
    let r = as_bob.get("/auth/impersonation-targets");
    assert_eq!(r.status, 200);
    let body = r.json();
    assert_eq!(body["impersonator"]["id"], json!(admin_id));
    let ids: Vec<&str> = body["users"].as_array().unwrap().iter().map(|u| u["id"].as_str().unwrap()).collect();
    assert!(ids.contains(&bob.as_str()) && !ids.contains(&admin_id.as_str()));
    // Account mutations are blocked while impersonating.
    for (m, p, b, msg) in [
        ("PUT", "/auth/preferences", json!({"theme": "dark"}), "Preference updates are not allowed while impersonating"),
        ("PUT", "/auth/profile", json!({"name": "x"}), "Profile updates are not allowed while impersonating"),
        ("PUT", "/auth/email", json!({"email": "x@test.local", "currentPassword": "x"}), "Email changes are not allowed while impersonating"),
        ("POST", "/auth/api-keys", json!({"name": "x"}), "API key creation is not allowed while impersonating"),
        ("DELETE", "/auth/api-keys/x", json!({}), "API key revocation is not allowed while impersonating"),
        ("POST", "/auth/change-password", json!({}), "Password changes are not allowed while impersonating"),
        ("POST", "/auth/must-reset-password", json!({}), "Password changes are not allowed while impersonating"),
    ] {
        let r = as_bob.send(m, p, Some(&b));
        assert_eq!(r.status, 403, "{m} {p}");
        assert_eq!(r.json(), json!({"error": "Forbidden", "message": msg}), "{m} {p}");
    }
    // Switch directly to another user from an impersonated session.
    let r = as_bob.post("/auth/impersonate", json!({"userId": alice}));
    assert_eq!(r.status, 200);
    let claims = jwt_claims(&set_cookie_value(&r, "excalidash-access-token").unwrap());
    assert_eq!((claims["userId"].clone(), claims["impersonatorId"].clone()), (json!(alice), json!(admin_id)));
    let r = as_bob.post("/auth/impersonate", json!({"userId": admin_id}));
    assert_eq!(r.status, 409, "returning to the admin goes through stop-impersonation");

    // Admin impersonating another admin cannot generate password resets.
    let r = admin.post("/auth/impersonate", json!({"userId": admin2}));
    let as_admin2 = client_with_access_token(&server, &set_cookie_value(&r, "excalidash-access-token").unwrap());
    let r = as_admin2.post(&format!("/auth/users/{bob}/reset-password"), json!({}));
    assert_eq!(r.status, 403);
    assert_eq!(r.json()["message"], "Password resets are not allowed while impersonating");

    // Once the impersonator loses admin rights the impersonated session loses access.
    server.db().execute(r#"UPDATE "User" SET "role" = 'USER' WHERE "id" = ?1"#, [&admin_id]).unwrap();
    let r = as_bob.get("/auth/impersonation-targets");
    assert_eq!(r.status, 403);
    assert_eq!(r.json(), json!({"error": "Forbidden", "message": "Admin access required"}));
}
