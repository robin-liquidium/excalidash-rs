//! auth/bootstrapSetupCode.ts — one-time admin setup code for the first registration.
use sha2::{Digest, Sha256};

use crate::config::{config, AuthMode};
use crate::db::{Db, DbError};
use crate::models::{SystemConfig, BOOTSTRAP_USER_ID, DEFAULT_SYSTEM_CONFIG_ID};
use crate::state::AppState;
use crate::util::{iso_from_ms, now_ms};

const BOOTSTRAP_CODE_ALPHABET: &[u8; 32] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

fn generate_bootstrap_setup_code() -> String {
    // 256 is a multiple of the 32-char alphabet, so `byte % 32` is uniform (like crypto.randomInt).
    let raw: String = crate::util::random_bytes(8)
        .into_iter()
        .map(|b| BOOTSTRAP_CODE_ALPHABET[(b % 32) as usize] as char)
        .collect();
    format!("{}-{}", &raw[..4], &raw[4..])
}

fn normalize_bootstrap_setup_code(value: &str) -> String {
    value.to_uppercase().chars().filter(|c| c.is_ascii_uppercase() || c.is_ascii_digit()).collect()
}

fn hash_bootstrap_setup_code(normalized: &str) -> String {
    hex::encode(Sha256::digest(normalized.as_bytes()))
}

/// Node `Buffer.from(hex, "hex")`: decodes valid pairs up to the first invalid one.
fn hex_buffer(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = vec![];
    let mut i = 0;
    while i + 1 < b.len() {
        match hex::decode(&s[i..i + 2]) {
            Ok(v) => out.extend(v),
            Err(_) => break,
        }
        i += 2;
    }
    out
}

fn timing_safe_hex_compare(expected_hex: &str, actual_hex: &str) -> bool {
    let expected = hex_buffer(expected_hex);
    let actual = hex_buffer(actual_hex);
    expected.len() == actual.len() && crate::util::constant_time_eq(&expected, &actual)
}

fn should_require_bootstrap_setup_code(c: &crate::sql::Connection) -> crate::sql::Result<bool> {
    let mode = config().auth_mode;
    if mode == AuthMode::OidcEnforced || mode == AuthMode::Disabled {
        return Ok(false);
    }
    let sc = SystemConfig::ensure(c)?;
    let bootstrap_active = {
        use crate::sql::OptionalExtension;
        c.query_row(r#"SELECT "isActive" FROM "User" WHERE "id" = ?1"#, [BOOTSTRAP_USER_ID], |r| crate::db::boolean(r, 0))
            .optional()?
    };
    let active_users: i64 = c.query_row(r#"SELECT COUNT(*) FROM "User" WHERE "isActive" = 1"#, [], |r| r.get(0))?;
    Ok(sc.auth_enabled && bootstrap_active == Some(false) && active_users == 0)
}

/// issueBootstrapSetupCodeIfRequired → `Some((code, expiresAtMs))` when a code was issued.
pub async fn issue_if_required(db: &Db, reason: &str) -> Result<Option<(String, i64)>, DbError> {
    let mode = config().auth_mode;
    if mode == AuthMode::OidcEnforced || mode == AuthMode::Disabled {
        return Ok(None);
    }
    let ttl_ms = config().bootstrap_setup_code_ttl_ms as i64;
    let issued = db
        .call(move |c| {
            if !should_require_bootstrap_setup_code(c)? {
                return Ok(None);
            }
            let code = generate_bootstrap_setup_code();
            let code_hash = hash_bootstrap_setup_code(&normalize_bootstrap_setup_code(&code));
            let now = now_ms();
            let expires_at = now + ttl_ms;
            c.execute(
                r#"UPDATE "SystemConfig" SET "bootstrapSetupCodeHash" = ?1, "bootstrapSetupCodeIssuedAt" = ?2,
                   "bootstrapSetupCodeExpiresAt" = ?3, "bootstrapSetupCodeFailedAttempts" = 0, "updatedAt" = ?2 WHERE "id" = ?4"#,
                crate::sql::params![code_hash, now, expires_at, DEFAULT_SYSTEM_CONFIG_ID],
            )?;
            Ok(Some((code, expires_at)))
        })
        .await?;
    if let Some((code, expires_at)) = &issued {
        println!(
            "[BOOTSTRAP SETUP] One-time admin setup code ({reason}): {code} (expires {})",
            iso_from_ms(*expires_at)
        );
    }
    Ok(issued)
}

/// Startup hook (index.ts): failures are logged, never fatal.
pub async fn issue_bootstrap_setup_code_if_required(st: &AppState, reason: &str) {
    if let Err(e) = issue_if_required(&st.db, reason).await {
        eprintln!("Failed to issue bootstrap setup code: {e}");
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyFailure {
    Missing,
    Unavailable,
    Expired,
    Invalid,
    Locked,
}

/// verifyBootstrapSetupCode
pub async fn verify(db: &Db, provided: Option<String>, max_attempts: i64) -> Result<Result<(), VerifyFailure>, DbError> {
    db.call(move |c| {
        let now = now_ms();
        let Some(sc) = SystemConfig::find(c)? else { return Ok(Err(VerifyFailure::Unavailable)) };
        let (Some(hash), Some(expires_at)) = (sc.bootstrap_setup_code_hash.as_deref(), sc.bootstrap_setup_code_expires_at)
        else {
            return Ok(Err(VerifyFailure::Unavailable));
        };
        if hash.is_empty() {
            return Ok(Err(VerifyFailure::Unavailable));
        }
        if now > expires_at {
            return Ok(Err(VerifyFailure::Expired));
        }
        if sc.bootstrap_setup_code_failed_attempts >= max_attempts {
            return Ok(Err(VerifyFailure::Locked));
        }
        let Some(provided) = provided.filter(|p| !crate::security::js_trim(p).is_empty()) else {
            return Ok(Err(VerifyFailure::Missing));
        };
        let provided_hash = hash_bootstrap_setup_code(&normalize_bootstrap_setup_code(&provided));
        if !timing_safe_hex_compare(hash, &provided_hash) {
            c.execute(
                r#"UPDATE "SystemConfig" SET "bootstrapSetupCodeFailedAttempts" = "bootstrapSetupCodeFailedAttempts" + 1, "updatedAt" = ?1 WHERE "id" = ?2"#,
                crate::sql::params![now_ms(), DEFAULT_SYSTEM_CONFIG_ID],
            )?;
            return Ok(Err(VerifyFailure::Invalid));
        }
        c.execute(
            r#"UPDATE "SystemConfig" SET "bootstrapSetupCodeHash" = NULL, "bootstrapSetupCodeIssuedAt" = NULL,
               "bootstrapSetupCodeExpiresAt" = NULL, "bootstrapSetupCodeFailedAttempts" = 0, "updatedAt" = ?1 WHERE "id" = ?2"#,
            crate::sql::params![now_ms(), DEFAULT_SYSTEM_CONFIG_ID],
        )?;
        Ok(Ok(()))
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_format_and_normalization() {
        let code = generate_bootstrap_setup_code();
        assert_eq!(code.len(), 9);
        assert_eq!(&code[4..5], "-");
        assert!(code.chars().filter(|c| *c != '-').all(|c| BOOTSTRAP_CODE_ALPHABET.contains(&(c as u8))));
        assert_eq!(normalize_bootstrap_setup_code(" abcd-ef12 "), "ABCDEF12");
        assert_eq!(
            hash_bootstrap_setup_code("ABCDEF12"),
            hex::encode(Sha256::digest(b"ABCDEF12"))
        );
        let h = hash_bootstrap_setup_code("X");
        assert!(timing_safe_hex_compare(&h, &h));
        assert!(!timing_safe_hex_compare(&h, &hash_bootstrap_setup_code("Y")));
        assert!(!timing_safe_hex_compare(&h, "abcd"));
    }
}
