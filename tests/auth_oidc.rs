//! End-to-end OIDC login against an in-test mock OpenID Provider.
mod common;
#[path = "auth_oidc_support/mod.rs"]
mod support;

use common::*;
use serde_json::{json, Value};
use support::*;

fn start_server(idp: &MockIdp, mode: &str, extra: &[(&str, &str)]) -> TestServer {
    let mut env = oidc_env(idp, mode);
    for (k, v) in extra {
        env.retain(|(ek, _)| ek != k);
        env.push((k.to_string(), v.to_string()));
    }
    let pairs: Vec<(&str, &str)> = env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    TestServer::start(&pairs)
}

fn verified(email: &str, sub: &str) -> Value {
    json!({"sub": sub, "email": email, "email_verified": true, "name": "Ada Lovelace"})
}

fn user_row(s: &TestServer, email: &str) -> Option<(String, String, String, bool, String)> {
    s.db()
        .query_row(
            r#"SELECT "id","role","name","isActive","passwordHash" FROM "User" WHERE "email" = ?1"#,
            [email],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get::<_, i64>(3)? == 1, r.get(4)?)),
        )
        .ok()
}

fn count(s: &TestServer, sql: &str) -> i64 {
    s.db().query_row(sql, [], |r| r.get(0)).unwrap()
}

#[test]
fn start_redirects_to_provider_with_pkce_and_signed_flow_cookie() {
    let idp = MockIdp::start();
    let s = start_server(&idp, "hybrid", &[("OIDC_SCOPES", "openid email profile groups")]);
    let c = s.client();
    let r = c.get("/auth/oidc/start?returnTo=%2Fdrawings%2Fabc");
    assert_eq!(r.status, 302);
    let loc = r.header("location").unwrap();
    assert!(loc.starts_with(&format!("{}/authorize?client_id={CLIENT_ID}&scope=openid%20email%20profile%20groups&response_type=code&redirect_uri=", idp.issuer)), "{loc}");
    assert_eq!(query_param(&loc, "redirect_uri").as_deref(), Some(REDIRECT_URI));
    assert_eq!(query_param(&loc, "code_challenge_method").as_deref(), Some("S256"));
    let state = query_param(&loc, "state").unwrap();
    let nonce = query_param(&loc, "nonce").unwrap();
    assert_eq!(state.len(), 43);
    assert_eq!(nonce.len(), 43);
    assert_ne!(state, nonce);
    assert_eq!(r.header("content-type").as_deref(), Some("text/plain; charset=utf-8"));
    assert_eq!(r.text(), format!("Found. Redirecting to {loc}"));

    let set = r.header_all("set-cookie");
    assert_eq!(set.len(), 1, "{set:?}");
    let cookie = &set[0];
    assert!(cookie.starts_with("excalidash-oidc-flow="));
    assert!(cookie.contains("; Max-Age=600; Path=/; Expires="), "{cookie}");
    assert!(cookie.ends_with("; HttpOnly; SameSite=Lax"), "{cookie}");
    // Flow payload: base64url(JSON) + "." + HMAC-SHA256(jwtSecret).
    let value = set_cookie_value(&r, "excalidash-oidc-flow").unwrap();
    let (payload, _sig) = value.split_once('.').unwrap();
    use base64::Engine;
    let flow: Value =
        serde_json::from_slice(&base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap();
    let keys: Vec<&String> = flow.as_object().unwrap().keys().collect();
    assert_eq!(keys, ["state", "nonce", "codeVerifier", "returnTo", "expiresAt"]);
    assert_eq!(flow["state"], state);
    assert_eq!(flow["returnTo"], "/drawings/abc");
    assert_eq!(pkce_challenge(flow["codeVerifier"].as_str().unwrap()), query_param(&loc, "code_challenge").unwrap());

    // Secure flag follows X-Forwarded-Proto even without trust proxy.
    let c2 = s.client().with_header("X-Forwarded-Proto", "https");
    let r = c2.get("/auth/oidc/start?returnTo=//evil.test");
    let cookie = r.header("set-cookie").unwrap();
    assert!(cookie.contains("; HttpOnly; Secure; SameSite=Lax"), "{cookie}");
    let value = set_cookie_value(&r, "excalidash-oidc-flow").unwrap();
    let flow: Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(value.split('.').next().unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(flow["returnTo"], "/");
    assert_eq!(idp.state.lock().unwrap().discovery_hits, 1, "discovery is cached");

    // Browser Accept → HTML body.
    let r = s.client().with_header("Accept", "text/html,*/*;q=0.8").get("/auth/oidc/start");
    assert_eq!(r.header("content-type").as_deref(), Some("text/html; charset=utf-8"));
    assert!(r.text().starts_with("<p>Found. Redirecting to "));
}

#[test]
fn hybrid_jit_first_user_admin_and_session() {
    let idp = MockIdp::start();
    let s = start_server(&idp, "hybrid", &[]);
    let c = s.client();
    let r = oidc_login(&c, &idp, verified("Ada@Example.test", "sub-ada"));
    assert_eq!(r.status, 302, "{}", r.text());
    assert_eq!(r.header("location").as_deref(), Some("/dashboard"));
    let cookies = r.header_all("set-cookie");
    assert!(cookies[0].starts_with("excalidash-oidc-flow=; Path=/; Expires=Thu, 01 Jan 1970"), "{cookies:?}");
    let access = set_cookie_value(&r, "excalidash-access-token").expect("access cookie");
    let refresh = set_cookie_value(&r, "excalidash-refresh-token").expect("refresh cookie");
    let claims = decode_jwt_claims(&access);
    assert_eq!(claims["authProvider"], "oidc");
    assert_eq!(claims["oidcGroups"], json!([]));
    assert_eq!(claims["email"], "ada@example.test");
    assert_eq!(claims["type"], "access");

    let (uid, role, name, active, hash) = user_row(&s, "ada@example.test").expect("user created");
    assert_eq!(role, "ADMIN", "first user becomes admin");
    assert_eq!(name, "Ada Lovelace");
    assert!(active);
    assert_eq!(hash, "");
    let db = s.db();
    let (provider, issuer, subject, email_at_link, last_login): (String, String, String, String, Option<i64>) = db
        .query_row(
            r#"SELECT "provider","issuer","subject","emailAtLink","lastLoginAt" FROM "AuthIdentity" WHERE "userId" = ?1"#,
            [&uid],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .unwrap();
    assert_eq!((provider.as_str(), issuer.as_str(), subject.as_str()), ("oidc", idp.issuer.as_str(), "sub-ada"));
    assert_eq!(email_at_link, "ada@example.test");
    assert!(last_login.unwrap() > 1_600_000_000_000, "lastLoginAt stored as ms");
    let trash: i64 = db
        .query_row(r#"SELECT COUNT(*) FROM "Collection" WHERE "id" = ?1 AND "userId" = ?2"#, [format!("trash:{uid}"), uid.clone()], |r| r.get(0))
        .unwrap();
    assert_eq!(trash, 1);
    let stored: String = db.query_row(r#"SELECT "token" FROM "RefreshToken" WHERE "userId" = ?1"#, [&uid], |r| r.get(0)).unwrap();
    use sha2::Digest;
    assert_eq!(stored, hex::encode(sha2::Sha256::digest(refresh.as_bytes())));

    // Token endpoint saw client_secret_basic + PKCE verifier + redirect_uri.
    {
        let g = idp.state.lock().unwrap();
        let (headers, body) = g.token_requests.last().unwrap();
        use base64::Engine;
        let basic = base64::engine::general_purpose::STANDARD.encode(format!("{CLIENT_ID}:{CLIENT_SECRET}"));
        assert_eq!(headers.get("authorization"), Some(&format!("Basic {basic}")));
        assert!(body.starts_with("grant_type=authorization_code&code="), "{body}");
        assert!(body.contains("&redirect_uri=https%3A%2F%2Fapp.example.test%2Fauth%2Foidc%2Fcallback&code_verifier="), "{body}");
        assert!(!body.contains("client_secret"));
        assert_eq!(g.jwks_hits, 1);
    }

    // Second user → USER; same subject again → linked identity reused.
    let c2 = s.client();
    let r = oidc_login(&c2, &idp, verified("bob@example.test", "sub-bob"));
    assert_eq!(r.header("location").as_deref(), Some("/dashboard"));
    assert_eq!(user_row(&s, "bob@example.test").unwrap().1, "USER");
    let r = oidc_login(&s.client(), &idp, json!({"sub": "sub-ada", "email": "ada.renamed@example.test", "email_verified": true}));
    assert_eq!(r.status, 302);
    assert_eq!(r.header("location").as_deref(), Some("/dashboard"));
    assert_eq!(count(&s, r#"SELECT COUNT(*) FROM "User" WHERE "email" LIKE 'ada%'"#), 1);
    let email_at_link: String = s
        .db()
        .query_row(r#"SELECT "emailAtLink" FROM "AuthIdentity" WHERE "subject" = 'sub-ada'"#, [], |r| r.get(0))
        .unwrap();
    assert_eq!(email_at_link, "ada.renamed@example.test");
    assert_eq!(idp.state.lock().unwrap().jwks_hits, 1, "JWKS is cached");

    // The session cookie authenticates (when /auth/me is mounted).
    let me = c.get("/auth/me");
    if me.status != 404 {
        assert_eq!(me.status, 200, "{}", me.text());
        assert_eq!(me.json()["user"]["email"], "ada@example.test");
    }
}

#[test]
fn jit_disabled_rejects_unknown_users_and_system_config_overrides() {
    let idp = MockIdp::start();
    let s = start_server(&idp, "hybrid", &[("OIDC_JIT_PROVISIONING", "false")]);
    let r = oidc_login(&s.client(), &idp, verified("new@example.test", "sub-new"));
    let loc = assert_login_error(&r, "provisioning_disabled");
    assert_eq!(
        loc,
        "/login?oidcError=provisioning_disabled&oidcErrorMessage=No+account+found.+Ask+an+admin+to+create+your+account+or+enable+OIDC+auto-provisioning.&returnTo=%2Fdashboard"
    );
    let cookies = r.header_all("set-cookie");
    assert_eq!(cookies.len(), 2, "flow cookie cleared twice like upstream: {cookies:?}");
    assert!(cookies.iter().all(|c| c.starts_with("excalidash-oidc-flow=;")));
    assert!(user_row(&s, "new@example.test").is_none());

    // SystemConfig.oidcJitProvisioningEnabled wins over the env default.
    s.db()
        .execute(r#"UPDATE "SystemConfig" SET "oidcJitProvisioningEnabled" = 1 WHERE "id" = 'default'"#, [])
        .unwrap();
    let r = oidc_login(&s.client(), &idp, verified("new@example.test", "sub-new"));
    assert_eq!(r.header("location").as_deref(), Some("/dashboard"));
    assert!(user_row(&s, "new@example.test").is_some());
}

#[test]
fn oidc_enforced_links_existing_local_user_by_email() {
    let idp = MockIdp::start();
    let s = start_server(&idp, "oidc_enforced", &[("OIDC_JIT_PROVISIONING", "false")]);
    let local_id = seed_user(&s, "carol@example.test", "Carol Local", "USER");
    let r = oidc_login(&s.client(), &idp, json!({"sub": "sub-carol", "email": " CAROL@example.test ", "email_verified": "true"}));
    assert_eq!(r.header("location").as_deref(), Some("/dashboard"), "{:?}", r.header("location"));
    let linked: String = s
        .db()
        .query_row(r#"SELECT "userId" FROM "AuthIdentity" WHERE "subject" = 'sub-carol'"#, [], |r| r.get(0))
        .unwrap();
    assert_eq!(linked, local_id);
    assert_eq!(count(&s, r#"SELECT COUNT(*) FROM "User" WHERE "id" != 'bootstrap-admin'"#), 1);
    let (_, role, name, _, _) = user_row(&s, "carol@example.test").unwrap();
    assert_eq!((role.as_str(), name.as_str()), ("USER", "Carol Local"));

    // A different subject for the same user replaces the provider identity.
    let r = oidc_login(&s.client(), &idp, json!({"sub": "sub-carol-2", "email": "carol@example.test", "email_verified": true}));
    assert_eq!(r.header("location").as_deref(), Some("/dashboard"));
    let subjects: Vec<String> = {
        let db = s.db();
        let mut st = db.prepare(r#"SELECT "subject" FROM "AuthIdentity""#).unwrap();
        st.query_map([], |r| r.get(0)).unwrap().map(Result::unwrap).collect()
    };
    assert_eq!(subjects, vec!["sub-carol-2".to_string()]);

    // Inactive account: no link, account_inactive.
    let dave = seed_user(&s, "dave@example.test", "Dave", "USER");
    s.db().execute(r#"UPDATE "User" SET "isActive" = 0 WHERE "id" = ?1"#, [&dave]).unwrap();
    let r = oidc_login(&s.client(), &idp, verified("dave@example.test", "sub-dave"));
    assert_login_error(&r, "account_inactive");
    assert!(set_cookie_value(&r, "excalidash-access-token").is_none());
    assert_eq!(count(&s, r#"SELECT COUNT(*) FROM "AuthIdentity" WHERE "subject" = 'sub-dave'"#), 0);
}

#[test]
fn admin_groups_map_roles_and_middleware_reconciles() {
    let idp = MockIdp::start();
    let s = start_server(
        &idp,
        "hybrid",
        &[("OIDC_ADMIN_GROUPS", "excalidash-admins"), ("OIDC_GROUPS_CLAIM", "realm_access.roles")],
    );
    // First user but not in the admin group → USER (group mapping overrides first-user-admin).
    let r = oidc_login(&s.client(), &idp, json!({"sub": "s1", "email": "u1@example.test", "email_verified": true, "realm_access": {"roles": ["staff"]}}));
    assert_eq!(r.status, 302);
    assert_eq!(user_row(&s, "u1@example.test").unwrap().1, "USER");

    let c = s.client();
    let r = oidc_login(
        &c,
        &idp,
        json!({"sub": "s2", "email": "u2@example.test", "email_verified": true, "realm_access": {"roles": [" excalidash-admins ", "staff", "staff"]}}),
    );
    assert_eq!(r.header("location").as_deref(), Some("/dashboard"));
    assert_eq!(user_row(&s, "u2@example.test").unwrap().1, "ADMIN");
    let access = set_cookie_value(&r, "excalidash-access-token").unwrap();
    assert_eq!(decode_jwt_claims(&access)["oidcGroups"], json!(["excalidash-admins", "staff"]));

    // Linked identity path keeps the stored role; the token carries the new groups,
    // and requireAuth reconciles the role on the next request.
    let c3 = s.client();
    let r = oidc_login(&c3, &idp, json!({"sub": "s2", "email": "u2@example.test", "email_verified": true, "realm_access": {"roles": ["staff"]}}));
    assert_eq!(r.header("location").as_deref(), Some("/dashboard"));
    assert_eq!(user_row(&s, "u2@example.test").unwrap().1, "ADMIN");
    let me = c3.get("/auth/me");
    if me.status != 404 {
        assert_eq!(me.status, 200, "{}", me.text());
        assert_eq!(user_row(&s, "u2@example.test").unwrap().1, "USER", "middleware demotes");
        let me = c.get("/auth/me");
        assert_eq!(me.status, 200);
        assert_eq!(user_row(&s, "u2@example.test").unwrap().1, "ADMIN", "middleware promotes");
    }
}

#[test]
fn email_verification_and_missing_claims() {
    let idp = MockIdp::start();
    let s = start_server(&idp, "hybrid", &[]);
    let r = oidc_login(&s.client(), &idp, json!({"sub": "x", "email": "x@example.test", "email_verified": false}));
    assert_login_error(&r, "unverified_email");
    let r = oidc_login(&s.client(), &idp, json!({"sub": "x", "email": "x@example.test"}));
    assert_login_error(&r, "unverified_email");
    assert!(user_row(&s, "x@example.test").is_none());

    // Missing email in the ID token → userinfo; email_verified from userinfo is not trusted.
    idp.state.lock().unwrap().userinfo = Some(json!({"sub": "x", "email": "x@example.test", "email_verified": true}));
    let r = oidc_login(&s.client(), &idp, json!({"sub": "x", "email_verified": false}));
    assert_login_error(&r, "unverified_email");
    assert_eq!(
        idp.state.lock().unwrap().userinfo_requests.last().unwrap().get("authorization").map(|s| s.starts_with("Bearer at-")),
        Some(true)
    );
    let r = oidc_login(&s.client(), &idp, json!({"sub": "x", "email_verified": true}));
    assert_eq!(r.header("location").as_deref(), Some("/dashboard"), "{:?}", r.header("location"));

    // Userinfo failure → missing_email.
    idp.state.lock().unwrap().userinfo = None;
    let r = oidc_login(&s.client(), &idp, json!({"sub": "y", "email_verified": true}));
    assert_login_error(&r, "missing_email");

    let s2 = start_server(&idp, "hybrid", &[("OIDC_REQUIRE_EMAIL_VERIFIED", "false")]);
    let r = oidc_login(&s2.client(), &idp, json!({"sub": "z", "email": "z@example.test", "email_verified": false}));
    assert_eq!(r.header("location").as_deref(), Some("/dashboard"));
}

#[test]
fn state_nonce_and_flow_failures() {
    let idp = MockIdp::start();
    let s = start_server(&idp, "hybrid", &[]);

    // No flow cookie.
    let r = s.client().get("/auth/oidc/callback?code=x&state=y");
    let loc = assert_login_error(&r, "missing_flow");
    assert!(!loc.contains("returnTo"));

    // Tampered flow cookie.
    let r = s.client().with_header("Cookie", "excalidash-oidc-flow=eyJ9.abc").get("/auth/oidc/callback?code=x&state=y");
    assert_login_error(&r, "missing_flow");

    // State mismatch.
    let c = s.client();
    let st = oidc_start(&c, "/x");
    idp.register_code("code-1", &st.challenge, &st.nonce, verified("s@example.test", "s"));
    let r = c.get("/auth/oidc/callback?code=code-1&state=wrong");
    let loc = assert_login_error(&r, "callback_failed");
    assert!(loc.ends_with("&returnTo=%2Fx"), "{loc}");
    // The flow cookie was cleared, so a retry with the right state has no flow.
    let r = c.get(&format!("/auth/oidc/callback?code=code-1&state={}", st.state));
    assert_login_error(&r, "missing_flow");

    // Nonce mismatch.
    let c = s.client();
    let st = oidc_start(&c, "/");
    idp.register_code("code-2", &st.challenge, "other-nonce", verified("s@example.test", "s"));
    let r = c.get(&format!("/auth/oidc/callback?code=code-2&state={}", st.state));
    assert_login_error(&r, "callback_failed");
    assert!(user_row(&s, "s@example.test").is_none());

    // Provider error.
    let c = s.client();
    let st = oidc_start(&c, "/y");
    let r = c.get(&format!("/auth/oidc/callback?error=access_denied&state={}", st.state));
    let loc = assert_login_error(&r, "provider_error");
    assert!(loc.ends_with("&returnTo=%2Fy"));

    // Wrong audience / expired token.
    for bad in [json!({"aud": "someone-else"}), json!({"exp": 1000}), json!({"iss": "https://evil.test"})] {
        let c = s.client();
        let st = oidc_start(&c, "/");
        let mut claims = verified("t@example.test", "t");
        for (k, v) in bad.as_object().unwrap() {
            claims[k] = v.clone();
        }
        idp.register_code("code-3", &st.challenge, &st.nonce, claims);
        let r = c.get(&format!("/auth/oidc/callback?code=code-3&state={}", st.state));
        assert_login_error(&r, "callback_failed");
    }
    assert!(user_row(&s, "t@example.test").is_none());
    assert!(s.output().contains("OIDC callback error:"));
}

#[test]
fn token_endpoint_auth_methods_and_hs256() {
    // client_secret_post when that is all the provider advertises (and configured explicitly).
    let idp = MockIdp::start();
    idp.state.lock().unwrap().discovery_overrides.insert("token_endpoint_auth_methods_supported".into(), json!(["client_secret_post"]));
    let s = start_server(&idp, "hybrid", &[("OIDC_TOKEN_ENDPOINT_AUTH_METHOD", "client_secret_post")]);
    let r = oidc_login(&s.client(), &idp, verified("p@example.test", "p"));
    assert_eq!(r.header("location").as_deref(), Some("/dashboard"));
    {
        let g = idp.state.lock().unwrap();
        let (headers, body) = g.token_requests.last().unwrap();
        assert!(headers.get("authorization").is_none());
        assert!(body.ends_with(&format!("&client_id={CLIENT_ID}&client_secret={CLIENT_SECRET}")), "{body}");
    }

    // Configured method the provider does not advertise → start fails closed.
    let idp2 = MockIdp::start();
    idp2.state.lock().unwrap().discovery_overrides.insert("token_endpoint_auth_methods_supported".into(), json!(["client_secret_basic"]));
    let s2 = start_server(&idp2, "hybrid", &[("OIDC_TOKEN_ENDPOINT_AUTH_METHOD", "none")]);
    let r = s2.client().get("/auth/oidc/start");
    assert_eq!(
        r.header("location").as_deref(),
        Some("/login?oidcError=callback_failed&oidcErrorMessage=OIDC+callback+validation+failed.")
    );
    assert!(s2.output().contains("OIDC start error:"));

    // HS256-signed ID token: alg mismatch → one retry with the observed alg.
    let idp3 = MockIdp::start();
    idp3.state.lock().unwrap().hs_secret = Some(CLIENT_SECRET.into());
    let s3 = start_server(&idp3, "hybrid", &[]);
    let c = s3.client();
    let st = oidc_start(&c, "/");
    idp3.register_code("hs-code", &st.challenge, &st.nonce, verified("h@example.test", "h"));
    let r = c.get(&format!("/auth/oidc/callback?code=hs-code&state={}", st.state));
    // The retry re-sends the (now consumed) code like upstream, so the provider rejects it.
    assert_login_error(&r, "callback_failed");
    assert!(s3.output().contains("OIDC callback id_token alg mismatch (expected RS256, got HS256); retrying once with HS256."));
    assert_eq!(idp3.state.lock().unwrap().token_requests.len(), 2);

    // With OIDC_ID_TOKEN_SIGNED_RESPONSE_ALG=HS256 the token validates with the client secret.
    let s4 = start_server(&idp3, "hybrid", &[("OIDC_ID_TOKEN_SIGNED_RESPONSE_ALG", "HS256")]);
    let r = oidc_login(&s4.client(), &idp3, verified("h@example.test", "h"));
    assert_eq!(r.header("location").as_deref(), Some("/dashboard"));
}

#[test]
fn routes_absent_when_oidc_disabled() {
    let s = TestServer::start(&[]);
    let r = s.client().get("/auth/oidc/start");
    assert_eq!(r.status, 404);
    assert!(r.text().contains("Cannot GET /auth/oidc/start"));
}
