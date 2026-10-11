# Parity matrix — ExcaliDash 0.6.5 (Node) → excalidash-rs

Status legend: ✅ ported + tested · ⚠️ ported with a documented deviation · ⏳ pending.
"Tests" lists the Rust tests that prove the behaviour (`tests/*.rs` unless noted).

## HTTP routes (backend paths; served under `/api` with the bundled frontend)

| Method | Path | Upstream | Rust | Status | Tests |
|---|---|---|---|---|---|
| GET | /health | index.ts | routes/mod.rs | ✅ | core_http::health_and_core_headers |
| GET | /csrf-token | server/csrf.ts | http/csrf.rs | ✅ | core_http::csrf_required_for_mutations |
| POST | /auth/register | auth/coreRoutes.ts | auth/routes/core.rs | ✅ | auth_core, auth_core_upstream |
| POST | /auth/login | auth/coreRoutes.ts | auth/routes/core.rs | ✅ | auth_core, auth_core_upstream (login limiter) |
| POST | /auth/refresh | auth/coreRoutes.ts | auth/routes/core.rs | ✅ | auth_core |
| POST | /auth/logout | auth/coreRoutes.ts | auth/routes/core.rs | ✅ | auth_core |
| POST | /auth/stop-impersonation | auth/coreRoutes.ts | auth/routes/core.rs | ✅ | auth_core |
| GET | /auth/me | auth/coreRoutes.ts | auth/routes/core.rs | ✅ | auth_core |
| GET | /auth/status | auth/coreRoutes.ts | auth/routes/core.rs | ✅ | auth_core |
| POST | /auth/onboarding-choice | auth/coreRoutes.ts | auth/routes/core.rs | ✅ | auth_core, auth_core_upstream::auth_onboarding_decision_flow |
| POST | /auth/auth-enabled | auth/coreRoutes.ts | auth/routes/core.rs | ✅ | auth_core_upstream |
| GET | /auth/oidc/start | auth/oidcRoutes.ts | auth/routes/oidc.rs | ✅ | auth_oidc |
| GET | /auth/oidc/callback | auth/oidcCallbackRoute.ts | auth/routes/oidc.rs | ✅ | auth_oidc, auth_oidc_secret_file |
| GET/POST | /auth/api-keys | auth/accountApiKeyRoutes.ts | auth/routes/account.rs | ✅ | auth_account::api_key_* |
| DELETE | /auth/api-keys/:id | auth/accountApiKeyRoutes.ts | auth/routes/account.rs | ✅ | auth_account::api_key_management_lifecycle |
| POST | /auth/change-password | auth/accountPasswordChangeRoutes.ts | auth/routes/account.rs | ✅ | auth_account::change_password_flow |
| POST | /auth/must-reset-password | auth/accountPasswordChangeRoutes.ts | auth/routes/account.rs | ✅ | auth_account::must_reset_password_flow |
| GET | /auth/password-reset-capability | auth/accountPasswordResetRoutes.ts | auth/routes/account.rs | ✅ | auth_account |
| POST | /auth/password-reset-request | auth/accountPasswordResetRoutes.ts | auth/routes/account.rs | ✅ | auth_account_mail (SMTP + Resend fakes) |
| POST | /auth/password-reset-confirm | auth/accountPasswordResetRoutes.ts | auth/routes/account.rs | ✅ | auth_account_mail, auth_account::password_reset_dev_flow |
| GET/PUT | /auth/preferences | auth/accountPreferencesRoutes.ts | auth/routes/account.rs | ✅ | auth_account::preferences_roundtrip_and_validation |
| PUT | /auth/profile | auth/accountProfileRoutes.ts | auth/routes/account.rs | ✅ | auth_account::profile_and_email_updates |
| PUT | /auth/email | auth/accountProfileRoutes.ts | auth/routes/account.rs | ✅ | auth_account::profile_and_email_updates |
| POST | /auth/admins | auth/adminUserRoutes.ts | auth/routes/admin.rs | ✅ | auth_admin::admin_role_endpoint_and_bootstrap_protection |
| GET/POST | /auth/users | auth/adminUserRoutes.ts | auth/routes/admin.rs | ✅ | auth_admin::admin_user_management |
| PATCH | /auth/users/:id | auth/adminUserRoutes.ts | auth/routes/admin.rs | ✅ | auth_admin::admin_user_management |
| POST | /auth/users/:id/reset-password | auth/adminUserPasswordRoutes.ts | auth/routes/admin.rs | ✅ | auth_admin::admin_reset_user_password |
| POST | /auth/registration/toggle | auth/adminSettingsRoutes.ts | auth/routes/admin.rs | ✅ | auth_admin::admin_settings_routes |
| POST | /auth/oidc/jit-provisioning | auth/adminSettingsRoutes.ts | auth/routes/admin.rs | ✅ | auth_admin::admin_settings_routes |
| GET/PUT | /auth/rate-limit/login | auth/adminSettingsRoutes.ts | auth/routes/admin.rs | ✅ | auth_admin::admin_login_rate_limit_settings |
| POST | /auth/rate-limit/login/reset | auth/adminSettingsRoutes.ts | auth/routes/admin.rs | ✅ | auth_admin::login_rate_limit_config_applies_and_reset_unlocks |
| GET | /auth/impersonation-targets | auth/adminImpersonationRoutes.ts | auth/routes/admin.rs | ✅ | auth_admin::impersonation_flow |
| POST | /auth/impersonate | auth/adminImpersonationRoutes.ts | auth/routes/admin.rs | ✅ | auth_admin::impersonation_flow |
| GET | /drawings | routes/dashboard/drawingListRoutes.ts | routes/dashboard | ✅ | dashboard_drawings, dashboard_scene |
| GET | /drawings/shared | routes/dashboard/drawingListRoutes.ts | routes/dashboard | ✅ | dashboard_shared |
| GET | /drawings/:id/preview | routes/dashboard/drawingListRoutes.ts | routes/dashboard | ✅ | dashboard_drawings::preview_* |
| GET | /drawings/:id | routes/dashboard/drawingReadRoutes.ts | routes/dashboard | ✅ | dashboard_drawings, dashboard_scene, files_s3 (S3 delete) |
| POST | /drawings | routes/dashboard/drawingCreateUpdateRoutes.ts | routes/dashboard | ✅ | dashboard_drawings, dashboard_scene |
| PUT | /drawings/:id | routes/dashboard/drawingCreateUpdateRoutes.ts + sceneUpdate.ts | routes/dashboard | ✅ | dashboard_drawings, dashboard_scene, files_s3 (S3 delete) |
| DELETE | /drawings/:id | routes/dashboard/drawingDeleteDuplicateRoutes.ts | routes/dashboard | ✅ | dashboard_drawings, dashboard_scene, files_s3 (S3 delete) |
| POST | /drawings/:id/duplicate | routes/dashboard/drawingDeleteDuplicateRoutes.ts | routes/dashboard | ✅ | dashboard_drawings::delete_and_duplicate_*, files_s3::duplicate_copies_and_delete_removes_s3_objects |
| GET | /drawings/:id/history | routes/dashboard/drawingHistoryRoutes.ts | routes/dashboard | ✅ | dashboard_history |
| GET | /drawings/:id/history/:snapshotId | routes/dashboard/drawingHistoryRoutes.ts | routes/dashboard | ✅ | dashboard_history |
| POST | /drawings/:id/history/:snapshotId/restore | routes/dashboard/drawingHistoryRoutes.ts | routes/dashboard | ✅ | dashboard_history |
| PATCH | /drawings/:id/shared-visibility | routes/dashboard/drawingSharedVisibilityRoutes.ts | routes/dashboard | ✅ | dashboard_shared |
| GET | /drawings/:id/share-resolve | routes/dashboard/drawingSharingRoutes.ts | routes/dashboard | ✅ | dashboard_link_sharing |
| GET | /drawings/:id/sharing | routes/dashboard/drawingSharingRoutes.ts | routes/dashboard | ✅ | dashboard_drawings::owner_sharing_routes |
| POST | /drawings/:id/permissions | routes/dashboard/drawingSharingRoutes.ts | routes/dashboard | ✅ | dashboard_drawings::owner_sharing_routes |
| DELETE | /drawings/:id/permissions/:permId | routes/dashboard/drawingSharingRoutes.ts | routes/dashboard | ✅ | dashboard_drawings::owner_sharing_routes |
| POST | /drawings/:id/link-shares | routes/dashboard/drawingSharingRoutes.ts | routes/dashboard | ✅ | dashboard_link_sharing |
| DELETE | /drawings/:id/link-shares/:shareId | routes/dashboard/drawingSharingRoutes.ts | routes/dashboard | ✅ | dashboard_link_sharing |
| GET/POST | /collections | routes/dashboard/collections.ts | routes/dashboard | ✅ | dashboard_collections |
| PUT/DELETE | /collections/:id | routes/dashboard/collections.ts | routes/dashboard | ✅ | dashboard_collections |
| GET/POST | /collections/:id/shares | routes/dashboard/collections.ts | routes/dashboard | ✅ | dashboard_collections |
| PATCH/DELETE | /collections/:id/shares/:userId | routes/dashboard/collections.ts | routes/dashboard | ✅ | dashboard_collections |
| GET | /collections/:id/share-resolve | routes/dashboard/collections.ts | routes/dashboard | ✅ | dashboard_collections |
| GET/PUT | /library | routes/dashboard/library.ts | routes/dashboard | ✅ | dashboard_drawings::library_routes |
| GET | /files/config | routes/files.ts | routes/files.rs | ✅ | files_store::files_config_requires_auth |
| PUT | /drawings/:drawingId/files/:fileId | routes/files.ts | routes/files.rs | ✅ | files_store, files_s3 |
| GET | /files/:drawingId/:fileId | routes/files.ts | routes/files.rs | ✅ | files_store, files_s3 |
| POST | /drawings/:id/trim | routes/storage.ts | routes/storage.rs | ✅ | storage_routes, files_s3 |
| GET | /drawings/:id/files/diff | routes/storage.ts | routes/storage.rs | ✅ | storage_routes |
| DELETE | /drawings/:id/files/orphans | routes/storage.ts | routes/storage.rs | ✅ | storage_routes, files_s3 |
| GET | /export/excalidash | routes/importExport/exportRoutes.ts | routes/import_export | ✅ | import_export_compat (+ Node↔Rust archive round trip) |
| POST | /import/excalidash/verify | routes/importExport/excalidashImportRoutes.ts | routes/import_export | ✅ | import_export_compat |
| POST | /import/excalidash | routes/importExport/excalidashImportRoutes.ts | routes/import_export | ✅ | import_export_compat |
| POST | /import/sqlite/legacy/verify | routes/importExport/legacySqliteImportRoutes.ts | routes/import_export | ✅ | import_export_compat |
| POST | /import/sqlite/legacy | routes/importExport/legacySqliteImportRoutes.ts | routes/import_export | ✅ | import_export_compat |
| GET | /system/update | routes/system/update.ts | routes/system.rs | ✅ | ops_release |

## Cross-cutting behaviour

| Feature | Upstream | Rust | Status | Tests |
|---|---|---|---|---|
| Request id, helmet headers, CORS (incl. preflight), body parsers + limits, request log, general rate limit, ETag/304, finalhandler 404 | index.ts, helmet, cors, express | src/http/mod.rs, src/http/body.rs, src/http/rate_limit.rs | ✅ | core_http::*, tests/diff |
| Express routing semantics: case-insensitive literal segments, trailing slash, automatic `OPTIONS` reply (`Allow`, sorted) | express / router 2 | src/http/mod.rs, src/http/express_routes.rs (generated from upstream) | ✅ | core_http::express_options_reply_and_case_insensitive_paths, http::express_routing_tests, tests/diff |
| CSRF tokens (HMAC, cookie client id + legacy id), CSRF middleware | security.ts, server/csrf.ts, security/csrfClient.ts | src/http/csrf.rs | ✅ | core_http::csrf_required_for_mutations |
| HTTPS redirect policy | server/httpsRedirectPolicy.ts | src/http/mod.rs | ✅ | auth_core_upstream::production_health_* |
| Onboarding gate | index.ts | src/http/mod.rs | ✅ | core_http::onboarding_gate_blocks_app_routes_until_setup |
| requireAuth / optionalAuth (JWT cookie/bearer, API keys + scopes, must-reset, OIDC role reconcile, bootstrap acting user) | middleware/auth.ts, auth/authMode.ts | src/auth/middleware.rs | ✅ | harness_selftest, auth suites |
| JWT format (HS256, claims, ms-style expiries), auth cookies | auth.ts, auth/cookies.ts | src/auth/jwt.rs, src/auth/cookies.rs | ✅ | auth_core (Set-Cookie formats), tests/realdata (live-secret tokens) |
| API key hashing (scrypt N=2^14 r=8 p=1, pepper) | auth/apiKeys.ts | src/auth/api_keys.rs | ✅ | auth_account::api_key_authentication (Node-created key) |
| XSS sanitisation (DOMPurify → ammonia), zod element/appState schemas, file dataURL rules | security.ts | src/security.rs | ✅ | security::tests, dashboard_drawings::sanitizer_*, sanitize_corpus (byte-identical to DOMPurify) |
| Snapshot codec (brotli `br1:`) | snapshots/snapshotCodec.ts | src/snapshots.rs | ✅ | snapshots::tests (unit) |
| Drawing access (owner/ACL/collection/link policy) | authz/sharing.ts | src/authz.rs | ✅ | dashboard_collections, dashboard_link_sharing |
| Socket.IO collab (join-room, cursor-move, element-update, user-activity, presence, revalidation; per-socket in-order event handling like Node's event loop; engine.io CORS/preflight) | server/socket.ts, server/socketAccess.ts, index.ts (io cors) | src/socket.rs, src/http/mod.rs (outer_layer) | ✅ | dashboard_scene (broadcast), e2e collaboration.spec / image-collab.spec (25/25 with --repeat-each=5, no retries), tests/diff socket.io steps |
| Drawings list cache (LRU, TTL, per-user invalidation) | server/drawingsCache.ts | src/drawings_cache.rs | ✅ | dashboard_drawings::drawings_cache_keys_are_user_scoped |
| Audit log | utils/audit.ts | src/audit.rs | ✅ | tests/diff (ENABLE_AUDIT_LOGGING=true) |
| Prisma migrations (`migrate deploy` bookkeeping, checksums) | prisma + docker-entrypoint.sh | src/db.rs, src/main.rs | ✅ | schema identical to Prisma's (see Verification) |
| PostgreSQL (`DATABASE_PROVIDER=postgresql`, `postgres` cargo feature): upstream's PostgreSQL migrations with Prisma's `_prisma_migrations` table and advisory lock, Prisma URL arguments (`schema`, `connection_limit`, `connect_timeout`, `sslmode`, `sslaccept`, `sslcert`, `host`, `application_name`, `options`), same queries via a dialect shim | prisma/migrations/postgresql, docker-entrypoint.sh | src/sql/ (mod.rs shim, pg.rs), src/db.rs | ✅ | whole cargo suite against PostgreSQL 17 (`EXCALIDASH_TEST_PG`), tests/diff and e2e (anonymous) against upstream Node on PostgreSQL, sql::pg::tests |
| Persisted JWT/CSRF secrets, migration lock, RUN_MIGRATIONS | docker-entrypoint.sh | src/main.rs (`EXCALIDASH_ENTRYPOINT=1`) | ✅ | |
| Static frontend serving (SPA fallback, per-location headers, caching, gzip + Vary, ETag/Last-Modified/304, asset 404, directory 301/403, 405, `Server`) | frontend/nginx.conf.template | src/http/static_files.rs | ✅ | tests/diff (11 static steps: SPA index/deep link/index.html, favicon, asset gzip/identity/304, missing asset, directory redirect/forbidden, POST) |
| Bootstrap setup code | auth/bootstrapSetupCode.ts | src/bootstrap.rs | ✅ | auth_core, auth_core_upstream::auth_onboarding_decision_flow |
| Login rate limiter (SystemConfig-driven), account-action limiter | auth.ts | src/auth/routes/helpers.rs | ✅ | auth_core_upstream::login_rate_limit_*, auth_admin |
| OIDC (openid-client v5 semantics: discovery, PKCE, ID token checks, JWKS, JIT, groups→role) | auth/oidc*.ts | src/auth/routes/oidc.rs, src/auth/oidc_client.rs | ✅ | auth_oidc, auth_oidc_secret_file |
| Password-reset mail (SMTP via lettre, Resend via HTTPS) | mail/*, config/mail.ts | src/mail.rs | ✅ | auth_account_mail; image-level: SMTP mail received, link confirmed, login with new password |
| Image interning, DrawingFile store (db + S3), S3 client | fileProcessing.ts, drawingFileStore.ts, s3.ts | src/files.rs, src/s3.rs, src/aws_credentials.rs | ✅ | files_store, files_s3 (incl. AWS credential chain), files::tests |
| Scene update (versioned tx, snapshots, file merge, element-update broadcast) | routes/dashboard/sceneUpdate.ts | src/routes/dashboard/scene.rs | ✅ | dashboard_scene |
| zod validation issues (dev-mode `details`), refine/abort semantics | index.ts schemas, security.ts | src/zodlike.rs, src/routes/dashboard/schema.rs | ✅ | zod_issues (37 upstream-captured cases) |
| JS `new Date(string)` parsing for link-share expiry | drawingSharingRoutes.ts | src/jsdate.rs | ✅ | jsdate::tests (41 Node-captured cases) |
| Scheduled SQLite backups (cron 5/6 fields, retention) | backups/scheduler.ts | src/backups.rs | ✅ | ops_backups_maintenance, backups::tests; image-level: backups written on schedule, 0600/uid 1001, integrity_check ok |
| SQLite incremental auto-vacuum + reclaim | db/sqliteMaintenance.ts | src/sqlite_maintenance.rs | ✅ | ops_backups_maintenance, sqlite_maintenance::tests |
| Storage doctor startup box | server/storageDoctor.ts | src/storage_doctor.rs | ✅ | storage_doctor::tests |
| Legacy SQLite import integrity worker | workers/db-verify.js | src/routes/import_export/legacy_sqlite_import.rs | ✅ | import_export_compat |
| Snapshot retention sweep | index.ts | src/main.rs | ✅ | |
| Every env var in config/registry | config/** | src/config.rs | ✅ | |

## Upstream test files

28 of 29 `backend/src/__tests__/*.integration.ts` files are ported (see the Tests column above
and the agent-written test names in each `tests/*.rs`). `image-export.integration.ts` imports
`frontend/src/utils/rehydrateFiles` and tests frontend code only; the frontend is unchanged.
Not portable through HTTP and covered by unit tests instead: S3 upload races that upstream
mocks inside the AWS SDK (`files::tests`), `account-backup-images` (S3 download stub in
`export_files.rs` tests), import cleanup races (`import_export` unit tests).

## Remaining differences

Everything else — status codes, headers (incl. `Server`, framing, CORS, cache headers), JSON
bodies and key order, cookies, routing quirks, static-file semantics, sanitiser output,
validation issues in dev mode, date parsing — is verified identical against upstream
(see Verification in README.md). What remains:

Header names are sent with upstream's exact spellings (e.g. `X-Request-ID`, `ETag`,
`RateLimit-Policy`, lowercase `cache-control` on engine.io) and 204 preflights carry
`Content-Length: 0` like Express — both through the vendored hyper patches in `vendor/`.

**PostgreSQL (matches upstream on PostgreSQL, differs from SQLite by design)**
- Search (`contains`) is a case-sensitive `LIKE` on PostgreSQL, case-insensitive on SQLite,
  without wildcard escaping on either — same as Prisma.
- The PostgreSQL baseline migration seeds no `bootstrap-admin` row (the SQLite history does).
- Scheduled backups log `[backup] Scheduled backups currently support SQLite file: DATABASE_URL
  values only.` on each run; SQLite auto-vacuum/reclaim and PRAGMAs are skipped.
- Prisma engine knobs without an equivalent are ignored: `pool_timeout`, `socket_timeout`,
  `pgbouncer`, `statement_cache_size`, and client certificates (`sslidentity`/`sslpassword`).
- Not in the default image: build with `--build-arg FEATURES=postgres` (+0.6 MB binary).

**Not observable by clients (protocol level)**
- The WebSocket `101` handshake also carries a `Date` header (Node's `ws` writes only
  `Upgrade`, `Connection`, `Sec-WebSocket-Accept`).

**Implementation choices with identical responses**
- JS/CSS ship pre-gzipped in the image and are inflated on the fly for clients without gzip;
  nginx compresses on the fly. Same bytes, `Content-Encoding`, `Vary`, weak ETag, chunking
  (verified in tests/diff).
- Server-to-S3 calls use short-lived SigV4-presigned URLs; S3 error texts come from the
  service's XML `<Message>`/`<Code>` (what the AWS SDK surfaces as `error.message`).
- Sanitiser: ammonia (html5ever) configured to DOMPurify's semantics — output verified
  byte-identical on tests/fixtures/sanitize_corpus (127 texts × 2 lengths, 14 SVGs) and on the
  real previews of the live data.
- A legacy-import BLOB scene column is read as `{}`.

**Rust-only environment variables**
- `FRONTEND_DIST_DIR` (default `/app/public` when present; `none` = backend-only mode),
  `EXCALIDASH_ENTRYPOINT=1` (docker-entrypoint duties: persisted secrets, migration lock),
  `EXCALIDASH_BACKEND_ROOT` (upstream's `backendRoot`), `EXCALIDASH_BLOCKING_THREADS`
  (default 8), `EXCALIDASH_GITHUB_API_URL` (tests only). Upstream's entrypoint variables
  `RUN_MIGRATIONS`, `MIGRATION_LOCK_TIMEOUT_SECONDS`, `DATABASE_PROVIDER` are honoured.
- AWS default credential chain variables (`AWS_PROFILE`, `AWS_SHARED_CREDENTIALS_FILE`,
  `AWS_CONFIG_FILE`, `AWS_SESSION_TOKEN`, `AWS_WEB_IDENTITY_TOKEN_FILE`/`AWS_ROLE_ARN`,
  `AWS_CONTAINER_CREDENTIALS_*`, `AWS_EC2_METADATA_*`) are read like the AWS SDK does.

## Heavy crates (justification)

| Crate | Why |
|---|---|
| axum + hyper + tokio (current-thread runtime) | HTTP server; one worker thread, blocking pool for SQLite/bcrypt/scrypt |
| socketioxide | Socket.IO v5 protocol compatible with the unmodified `socket.io-client` |
| rusqlite (bundled SQLite) + r2d2 | Prisma-compatible SQLite access; 4-connection pool, 1 MiB page cache each |
| postgres + tokio-postgres-rustls (`postgres` feature only) | PostgreSQL client with rustls TLS; not compiled into the default image |
| reqwest + rustls (ring) + webpki-roots | outbound HTTPS (OIDC, Resend, GitHub, S3) without OpenSSL or system certs (scratch image) |
| lettre (rustls) | SMTP password-reset delivery (nodemailer equivalent) |
| rusty-s3 | S3 request signing without the AWS SDK |
| ammonia | HTML/SVG sanitisation (DOMPurify equivalent) |
| jsonwebtoken (rust_crypto) | HS256 sessions + OIDC ID-token verification (RS/PS/ES256/ES384/EdDSA) |
| p521, k256 (ecdsa only) | OIDC ES512 / ES256K ID tokens (not covered by jsonwebtoken) |
| bcrypt, scrypt | Node-compatible password hashes and API-key hashes |
| zip (flate2) | `.excalidash` archives compatible with JSZip/archiver |
| brotli | snapshot field codec (`br1:`), Node zlib-compatible |
