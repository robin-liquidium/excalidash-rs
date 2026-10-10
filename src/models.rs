//! Shared row types for the most widely used tables.
use rusqlite::{Connection, OptionalExtension, Row};
use serde_json::{json, Value};

use crate::db::{boolean, dt, opt_bool, opt_dt};
use crate::util::{iso_from_ms, now_ms};

pub const BOOTSTRAP_USER_ID: &str = "bootstrap-admin";
pub const DEFAULT_SYSTEM_CONFIG_ID: &str = "default";

#[derive(Debug, Clone)]
pub struct User {
    pub id: String,
    pub username: Option<String>,
    pub email: String,
    pub password_hash: String,
    pub name: String,
    pub role: String,
    pub must_reset_password: bool,
    pub is_active: bool,
    pub preferences: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

pub const USER_COLS: &str =
    r#""id","username","email","passwordHash","name","role","mustResetPassword","isActive","preferences","createdAt","updatedAt""#;

impl User {
    pub fn from_row(r: &Row<'_>) -> rusqlite::Result<User> {
        Ok(User {
            id: r.get(0)?,
            username: r.get(1)?,
            email: r.get(2)?,
            password_hash: r.get(3)?,
            name: r.get(4)?,
            role: r.get(5)?,
            must_reset_password: boolean(r, 6)?,
            is_active: boolean(r, 7)?,
            preferences: r.get(8)?,
            created_at: dt(r, 9)?,
            updated_at: dt(r, 10)?,
        })
    }

    pub fn find_by_id(c: &Connection, id: &str) -> rusqlite::Result<Option<User>> {
        c.query_row(&format!(r#"SELECT {USER_COLS} FROM "User" WHERE "id" = ?1"#), [id], User::from_row)
            .optional()
    }

    pub fn find_by_email(c: &Connection, email: &str) -> rusqlite::Result<Option<User>> {
        c.query_row(&format!(r#"SELECT {USER_COLS} FROM "User" WHERE "email" = ?1"#), [email], User::from_row)
            .optional()
    }

    pub fn is_admin(&self) -> bool {
        self.role == "ADMIN"
    }

    /// Prisma `select { id, username, email, name, role, mustResetPassword }`-style JSON.
    pub fn public_json(&self) -> Value {
        json!({
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "name": self.name,
            "role": self.role,
            "mustResetPassword": self.must_reset_password,
        })
    }

    pub fn created_iso(&self) -> String {
        iso_from_ms(self.created_at)
    }
    pub fn updated_iso(&self) -> String {
        iso_from_ms(self.updated_at)
    }
}

#[derive(Debug, Clone)]
pub struct SystemConfig {
    pub id: String,
    pub auth_enabled: bool,
    pub auth_onboarding_completed: bool,
    pub registration_enabled: bool,
    pub oidc_jit_provisioning_enabled: Option<bool>,
    pub auth_login_rate_limit_enabled: bool,
    pub auth_login_rate_limit_window_ms: i64,
    pub auth_login_rate_limit_max: i64,
    pub bootstrap_setup_code_hash: Option<String>,
    pub bootstrap_setup_code_issued_at: Option<i64>,
    pub bootstrap_setup_code_expires_at: Option<i64>,
    pub bootstrap_setup_code_failed_attempts: i64,
    pub ai_chatgpt_enabled: Option<bool>,
    pub created_at: i64,
    pub updated_at: i64,
}

pub const SYSTEM_CONFIG_COLS: &str = r#""id","authEnabled","authOnboardingCompleted","registrationEnabled","oidcJitProvisioningEnabled","authLoginRateLimitEnabled","authLoginRateLimitWindowMs","authLoginRateLimitMax","bootstrapSetupCodeHash","bootstrapSetupCodeIssuedAt","bootstrapSetupCodeExpiresAt","bootstrapSetupCodeFailedAttempts","aiChatgptEnabled","createdAt","updatedAt""#;

impl SystemConfig {
    pub fn from_row(r: &Row<'_>) -> rusqlite::Result<SystemConfig> {
        Ok(SystemConfig {
            id: r.get(0)?,
            auth_enabled: boolean(r, 1)?,
            auth_onboarding_completed: boolean(r, 2)?,
            registration_enabled: boolean(r, 3)?,
            oidc_jit_provisioning_enabled: opt_bool(r, 4)?,
            auth_login_rate_limit_enabled: boolean(r, 5)?,
            auth_login_rate_limit_window_ms: r.get(6)?,
            auth_login_rate_limit_max: r.get(7)?,
            bootstrap_setup_code_hash: r.get(8)?,
            bootstrap_setup_code_issued_at: opt_dt(r, 9)?,
            bootstrap_setup_code_expires_at: opt_dt(r, 10)?,
            bootstrap_setup_code_failed_attempts: r.get(11)?,
            ai_chatgpt_enabled: opt_bool(r, 12)?,
            created_at: dt(r, 13)?,
            updated_at: dt(r, 14)?,
        })
    }

    pub fn find(c: &Connection) -> rusqlite::Result<Option<SystemConfig>> {
        c.query_row(
            &format!(r#"SELECT {SYSTEM_CONFIG_COLS} FROM "SystemConfig" WHERE "id" = ?1"#),
            [DEFAULT_SYSTEM_CONFIG_ID],
            SystemConfig::from_row,
        )
        .optional()
    }

    /// authMode.ts ensureSystemConfig: read first, upsert only when missing.
    pub fn ensure(c: &Connection) -> rusqlite::Result<SystemConfig> {
        if let Some(existing) = Self::find(c)? {
            return Ok(existing);
        }
        let now = now_ms();
        let auth_enabled = crate::config::config().auth_mode.enables_auth();
        c.execute(
            r#"INSERT INTO "SystemConfig" ("id","authEnabled","authOnboardingCompleted","registrationEnabled","oidcJitProvisioningEnabled","authLoginRateLimitEnabled","authLoginRateLimitWindowMs","authLoginRateLimitMax","createdAt","updatedAt")
               VALUES (?1, ?2, 0, 0, NULL, 1, 900000, 20, ?3, ?3) ON CONFLICT("id") DO NOTHING"#,
            rusqlite::params![DEFAULT_SYSTEM_CONFIG_ID, auth_enabled, now],
        )?;
        Ok(Self::find(c)?.expect("system config row"))
    }
}

/// authMode.ts getBootstrapActingUser (upsert, never modifies an existing row).
pub fn bootstrap_acting_user(c: &Connection) -> rusqlite::Result<User> {
    if let Some(u) = User::find_by_id(c, BOOTSTRAP_USER_ID)? {
        return Ok(u);
    }
    let now = now_ms();
    c.execute(
        r#"INSERT INTO "User" ("id","username","email","passwordHash","name","role","mustResetPassword","isActive","createdAt","updatedAt")
           VALUES (?1, NULL, 'bootstrap@excalidash.local', '', 'Bootstrap Admin', 'ADMIN', 1, 0, ?2, ?2) ON CONFLICT("id") DO NOTHING"#,
        rusqlite::params![BOOTSTRAP_USER_ID, now],
    )?;
    Ok(User::find_by_id(c, BOOTSTRAP_USER_ID)?.expect("bootstrap user"))
}
