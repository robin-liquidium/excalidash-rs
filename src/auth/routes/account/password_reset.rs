//! auth/accountPasswordResetRoutes.ts
use axum::{
    extract::State,
    response::Response,
    routing::{get, post},
    Router,
};
use crate::sql::OptionalExtension;
use serde_json::json;

use super::common::*;
use crate::auth::routes::helpers::{ensure_auth_enabled, login_attempt_rate_limit};
use crate::config::config;
use crate::http::body::Body;
use crate::http::ctx::Ctx;
use crate::http::error::{ok, ApiError, ApiResult};
use crate::mail::{build_password_reset_email, mailer, MailMessage, MailResult};
use crate::state::AppState;
use crate::util::{self, now_ms};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/password-reset-capability", get(capability))
        .route("/password-reset-request", post(request_reset))
        .route("/password-reset-confirm", post(confirm_reset))
}

fn delivery_available() -> bool {
    config().node_env != "production" || mailer().enabled()
}

async fn capability() -> ApiResult {
    ok(json!({ "enabled": config().enable_password_reset && delivery_available() }))
}

fn invalid_token() -> ApiError {
    ApiError::err(400, "Invalid token", "Password reset token is invalid or has already been used")
}

fn not_enabled() -> ApiError {
    ApiError::not_found("Password reset feature is not enabled")
}

/// buildResetUrl
fn build_reset_url(token: &str) -> String {
    let configured = config()
        .frontend_url
        .as_deref()
        .and_then(|f| f.split(',').next())
        .map(|s| crate::security::js_trim(s).to_string())
        .filter(|s| !s.is_empty());
    let origin = match configured {
        Some(o) => {
            let lower = o.to_ascii_lowercase();
            if lower.starts_with("http://") || lower.starts_with("https://") { o } else { format!("http://{o}") }
        }
        None => "http://localhost:6767".to_string(),
    };
    let origin = origin.strip_suffix('/').unwrap_or(&origin);
    format!("{origin}/reset-password-confirm#token={}", encode_uri_component(token))
}

fn encode_uri_component(v: &str) -> String {
    const SET: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
        .remove(b'-')
        .remove(b'_')
        .remove(b'.')
        .remove(b'!')
        .remove(b'~')
        .remove(b'*')
        .remove(b'\'')
        .remove(b'(')
        .remove(b')');
    percent_encoding::utf8_percent_encode(v, SET).to_string()
}

async fn request_reset(State(st): State<AppState>, ctx: Ctx, body: Body) -> Response {
    let decision = match login_attempt_rate_limit(&st.db, &ctx, &body).await {
        Ok(d) => d,
        Err(r) => return r,
    };
    let r: ApiResult = async {
        ensure_auth_enabled(&st.db).await?;
        if !config().enable_password_reset {
            return Err(not_enabled());
        }
        if config().node_env == "production" && !mailer().enabled() {
            eprintln!("[mail] Password reset is enabled, but mail delivery is not configured");
            return Err(ApiError::err(503, "Service unavailable", "Password reset is temporarily unavailable"));
        }
        let Ok(email) = object(&body.0).and_then(|o| email(&o, "email")) else {
            return Err(ApiError::err(400, "Validation error", "Invalid email address"));
        };
        let ip = ip_of(&ctx);
        let ua = ua_of(&ctx);
        // Lookup, token creation and delivery happen after the neutral response is produced
        // so timing does not reveal whether the address belongs to an active local account.
        let st2 = st.clone();
        tokio::spawn(async move {
            if let Err(reason) = process_reset_request(st2, email, ip, ua).await {
                eprintln!("[mail] Password reset processing failed: {reason}");
            }
        });
        ok(json!({ "message": "If an account with that email exists, a password reset link has been sent." }))
    }
    .await;
    finish(Some(decision), r)
}

async fn process_reset_request(st: AppState, email: String, ip: Option<String>, ua: Option<String>) -> Result<(), String> {
    let e = email.clone();
    let user = st
        .db
        .call(move |c| Ok(crate::models::User::find_by_email(c, &e)?))
        .await
        .map_err(|e| e.to_string())?;
    let Some(user) = user.filter(|u| u.is_active && can_use_local_password(&u.password_hash)) else {
        return Ok(());
    };
    let reset_token = hex::encode(util::random_bytes(32));
    let hashed = util::sha256_hex(reset_token.as_bytes());
    let expires_at = now_ms() + 60 * 60 * 1000;
    let uid = user.id.clone();
    st.db
        .call(move |c| {
            c.execute(r#"UPDATE "PasswordResetToken" SET "used" = 1 WHERE "userId" = ?1 AND "used" = 0"#, [&uid])?;
            c.execute(
                r#"INSERT INTO "PasswordResetToken" ("id","userId","token","expiresAt","used","createdAt") VALUES (?1,?2,?3,?4,0,?5)"#,
                crate::sql::params![util::uuid_v4(), uid, hashed, expires_at, now_ms()],
            )?;
            Ok(())
        })
        .await
        .map_err(|e| e.to_string())?;
    if config().enable_audit_logging {
        crate::audit::log_audit_event(
            &st.db,
            crate::audit::AuditEvent {
                user_id: Some(user.id.clone()),
                action: "password_reset_requested".into(),
                ip_address: ip,
                user_agent: ua,
                ..Default::default()
            },
        )
        .await;
    }
    let reset_url = build_reset_url(&reset_token);
    if config().node_env == "development" {
        println!("[DEV] Password reset token for {email}: {reset_token}");
        println!("[DEV] Reset URL: {reset_url}");
    }
    let mailer = mailer();
    if !mailer.enabled() {
        return Ok(());
    }
    let msg = build_password_reset_email(&reset_url, 60);
    let result = mailer
        .send(
            st.http(),
            MailMessage {
                to: email,
                subject: msg.subject,
                html: msg.html,
                text: msg.text,
                idempotency_key: Some(format!("password-reset/{}", util::uuid_v4())),
            },
        )
        .await;
    if let MailResult::NotDelivered { reason } = result {
        eprintln!("[mail] Password reset email was not delivered: {reason}");
    }
    Ok(())
}

async fn confirm_reset(State(st): State<AppState>, ctx: Ctx, body: Body) -> Response {
    let decision = match login_attempt_rate_limit(&st.db, &ctx, &body).await {
        Ok(d) => d,
        Err(r) => return r,
    };
    let r: ApiResult = async {
        ensure_auth_enabled(&st.db).await?;
        if !config().enable_password_reset {
            return Err(not_enabled());
        }
        let inner: ApiResult = async {
            let parsed =
                object(&body.0).and_then(|o| Ok((raw_string(&o, "token", 1, usize::MAX)?, password_value(o.get("password"))?)));
            let Ok((token, password)) = parsed else {
                return Err(ApiError::err(400, "Validation error", "Invalid reset data"));
            };
            let hashed = util::sha256_hex(token.as_bytes());
            let found = st
                .db
                .call(move |c| {
                    let row = c
                        .query_row(
                            r#"SELECT "id","userId","expiresAt","used" FROM "PasswordResetToken" WHERE "token" = ?1 LIMIT 1"#,
                            [&hashed],
                            |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, crate::db::dt(r, 2)?, crate::db::boolean(r, 3)?)),
                        )
                        .optional()?;
                    let Some(row) = row else { return Ok(None) };
                    let user = crate::models::User::find_by_id(c, &row.1)?;
                    Ok(user.map(|u| (row, u)))
                })
                .await?;
            let Some(((token_id, user_id, expires_at, used), user)) = found else {
                return Err(invalid_token());
            };
            if used {
                return Err(invalid_token());
            }
            if now_ms() > expires_at {
                return Err(ApiError::err(400, "Expired token", "Password reset token has expired"));
            }
            if !user.is_active {
                return Err(ApiError::forbidden("Account is inactive"));
            }
            let mark_used = |id: String| async {
                st.db
                    .call(move |c| {
                        c.execute(r#"UPDATE "PasswordResetToken" SET "used" = 1 WHERE "id" = ?1"#, [&id])?;
                        Ok(())
                    })
                    .await
            };
            if !can_use_local_password(&user.password_hash) {
                mark_used(token_id).await?;
                return Err(ApiError::err(400, "Bad request", "Password reset is not available for this account"));
            }
            let hash = bcrypt_hash(password).await?;
            let uid = user_id.clone();
            st.db
                .call(move |c| {
                    c.execute(
                        r#"UPDATE "User" SET "passwordHash" = ?1, "mustResetPassword" = 0, "updatedAt" = ?2 WHERE "id" = ?3"#,
                        crate::sql::params![hash, now_ms(), uid],
                    )?;
                    Ok(())
                })
                .await?;
            mark_used(token_id).await?;
            if config().enable_refresh_token_rotation {
                revoke_refresh_tokens(&st, &user_id).await;
            }
            audit(&st, &ctx, &user_id, "password_changed", None, None).await;
            ok(json!({ "message": "Password has been reset successfully" }))
        }
        .await;
        catch(inner, "Password reset confirm error:", "Failed to reset password")
    }
    .await;
    finish(Some(decision), r)
}

#[cfg(test)]
mod tests {
    use super::encode_uri_component;

    #[test]
    fn encodes_like_encode_uri_component() {
        assert_eq!(encode_uri_component("ab-_.!~*'()"), "ab-_.!~*'()");
        assert_eq!(encode_uri_component("a b/c?d#e&f=g"), "a%20b%2Fc%3Fd%23e%26f%3Dg");
    }
}
