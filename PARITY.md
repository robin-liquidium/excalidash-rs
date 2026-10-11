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
| Request id, helmet headers, CORS (incl. preflight), body parsers + limits, request log, general rate limit, ETag/304, finalhandler 404 | index.ts, helmet, cors, express | src/http/mod.rs, src/http/body.rs, src/http/rate_limit.rs | ✅ | core_http::* |
| CSRF tokens (HMAC, cookie client id + legacy id), CSRF middleware | security.ts, server/csrf.ts, security/csrfClient.ts | src/http/csrf.rs | ✅ | core_http::csrf_required_for_mutations |
| HTTPS redirect policy | server/httpsRedirectPolicy.ts | src/http/mod.rs | ⚠️ | auth_core_upstream::production_health_* |
| Onboarding gate | index.ts | src/http/mod.rs | ✅ | core_http::onboarding_gate_blocks_app_routes_until_setup |
| requireAuth / optionalAuth (JWT cookie/bearer, API keys + scopes, must-reset, OIDC role reconcile, bootstrap acting user) | middleware/auth.ts, auth/authMode.ts | src/auth/middleware.rs | ✅ | harness_selftest, auth suites |
| JWT format (HS256, claims, ms-style expiries), auth cookies | auth.ts, auth/cookies.ts | src/auth/jwt.rs, src/auth/cookies.rs | ✅ | auth_core (Set-Cookie formats), tests/realdata (live-secret tokens) |
| API key hashing (scrypt N=2^14 r=8 p=1, pepper) | auth/apiKeys.ts | src/auth/api_keys.rs | ✅ | auth_account::api_key_authentication (Node-created key) |
| XSS sanitisation (DOMPurify → ammonia), zod element/appState schemas, file dataURL rules | security.ts | src/security.rs | ⚠️ | security::tests, dashboard_drawings::sanitizer_* |
| Snapshot codec (brotli `br1:`) | snapshots/snapshotCodec.ts | src/snapshots.rs | ✅ | snapshots::tests (unit) |
| Drawing access (owner/ACL/collection/link policy) | authz/sharing.ts | src/authz.rs | ✅ | dashboard_collections, dashboard_link_sharing |
| Socket.IO collab (join-room, cursor-move, element-update, user-activity, presence, revalidation; per-socket in-order event handling like Node's event loop; engine.io CORS/preflight) | server/socket.ts, server/socketAccess.ts, index.ts (io cors) | src/socket.rs, src/http/mod.rs (outer_layer) | ✅ | dashboard_scene (broadcast), e2e collaboration.spec / image-collab.spec (25/25 with --repeat-each=5, no retries), tests/diff socket.io steps |
| Drawings list cache (LRU, TTL, per-user invalidation) | server/drawingsCache.ts | src/drawings_cache.rs | ✅ | dashboard_drawings::drawings_cache_keys_are_user_scoped |
| Audit log | utils/audit.ts | src/audit.rs | ✅ | tests/diff (ENABLE_AUDIT_LOGGING=true) |
| Prisma migrations (`migrate deploy` bookkeeping, checksums) | prisma + docker-entrypoint.sh | src/db.rs, src/main.rs | ✅ | schema identical to Prisma's (see Verification) |
| Persisted JWT/CSRF secrets, migration lock, RUN_MIGRATIONS | docker-entrypoint.sh | src/main.rs (`EXCALIDASH_ENTRYPOINT=1`) | ✅ | |
| Static frontend serving (SPA fallback, nginx headers/caching/gzip) | frontend/nginx.conf.template | src/http/static_files.rs | ⚠️ | tests/diff (spa index, deep link, /api headers) |
| Bootstrap setup code | auth/bootstrapSetupCode.ts | src/bootstrap.rs | ✅ | auth_core, auth_core_upstream::auth_onboarding_decision_flow |
| Login rate limiter (SystemConfig-driven), account-action limiter | auth.ts | src/auth/routes/helpers.rs | ✅ | auth_core_upstream::login_rate_limit_*, auth_admin |
| OIDC (openid-client v5 semantics: discovery, PKCE, ID token checks, JWKS, JIT, groups→role) | auth/oidc*.ts | src/auth/routes/oidc.rs, src/auth/oidc_client.rs | ⚠️ | auth_oidc, auth_oidc_secret_file |
| Password-reset mail (SMTP via lettre, Resend via HTTPS) | mail/*, config/mail.ts | src/mail.rs | ✅ | auth_account_mail |
| Image interning, DrawingFile store (db + S3), S3 client | fileProcessing.ts, drawingFileStore.ts, s3.ts | src/files.rs, src/s3.rs | ⚠️ | files_store, files_s3, files::tests |
| Scene update (versioned tx, snapshots, file merge, element-update broadcast) | routes/dashboard/sceneUpdate.ts | src/routes/dashboard/scene.rs | ✅ | dashboard_scene |
| Scheduled SQLite backups (cron 5/6 fields, retention) | backups/scheduler.ts | src/backups.rs | ✅ | ops_backups_maintenance, backups::tests |
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

## Deliberate deviations

Everything below was checked against upstream; none is visible to the shipped frontend
(the differential test and the full upstream e2e suite pass).

**Scope**
- **PostgreSQL is not implemented.** The build is SQLite-only (the setup this targets);
  `DATABASE_PROVIDER=postgresql` or a non-`file:` `DATABASE_URL` stops startup with a clear error.
  Upstream's Postgres migrations are not vendored. Adding it later means a second query
  backend behind a cargo feature; nothing in the SQLite path would change.

**HTTP surface**
- Header names are sent lowercase. Header names are case-insensitive (RFC 9110), and the live
  path goes through Cloudflare, which speaks HTTP/2/3 to browsers where names are always
  lowercase, so clients cannot observe a difference. (Bundled mode does send nginx's
  `Server: nginx/1.31.6`, and the export is streamed chunked like upstream.)
- 204 responses carry no `Content-Length: 0` (Express/cors add it; RFC 9110 forbids it and
  hyper strips it).
- HTTPS redirect URLs keep the `/api` prefix; upstream's backend sees the stripped path and
  redirects to `/<path>` without it (an upstream bug behind nginx).
- Express routing quirks not reproduced: case-insensitive paths, and Express's automatic
  `OPTIONS` 200 + `Allow` response for requests from a *disallowed* origin (allowed origins get
  the same 204 preflight as upstream).

**Static frontend (nginx emulation)**
- JS/CSS are stored pre-gzipped in the image (`*.gz` only) and sent compressed to gzip clients
  or inflated on the fly for others; nginx compresses on the fly. Same `Content-Encoding`,
  `Vary`, weak ETag.
- Directory paths without `index.html` fall through to the SPA (nginx would answer 403).
  Range requests support a single range.

**Behavioural details**
- Sanitisation uses ammonia (html5ever) instead of DOMPurify (jsdom) with the same allow/forbid
  lists and post-processing; serialised HTML/SVG can differ in insignificant ways.
- Non-production zod validation `details` arrays are approximations (production bodies,
  which this deployment uses, match exactly).
- Link-share `expiresAt` accepts ISO-8601 variants rather than everything JS `Date` parses.
- OIDC: encrypted ID tokens / JARM are rejected (upstream never configures them). ES512 and
  ES256K are verified with RustCrypto (`p521`, `k256`) since `jsonwebtoken` lacks them.
- S3: only explicit `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` are used (no AWS profile /
  instance-role chain); server-side S3 calls use short-lived presigned URLs; S3 error texts
  come from the service XML rather than the AWS SDK.
- Release check: concurrent `/system/update` requests share one GitHub fetch.
- Resend: like upstream, the idempotency key is not sent.
- A legacy-import BLOB scene column is treated as `{}`.

**Rust-only environment variables**
- `FRONTEND_DIST_DIR` (default `/app/public` when present; `none` = backend-only mode),
  `EXCALIDASH_ENTRYPOINT=1` (docker-entrypoint duties: persisted secrets, migration lock),
  `EXCALIDASH_BACKEND_ROOT` (upstream's `backendRoot`), `EXCALIDASH_BLOCKING_THREADS`
  (default 8), `EXCALIDASH_GITHUB_API_URL` (tests only).
- Upstream's docker-entrypoint variables `RUN_MIGRATIONS`, `MIGRATION_LOCK_TIMEOUT_SECONDS`,
  `DATABASE_PROVIDER` are honoured by the binary itself.

## Heavy crates (justification)

| Crate | Why |
|---|---|
| axum + hyper + tokio (current-thread runtime) | HTTP server; one worker thread, blocking pool for SQLite/bcrypt/scrypt |
| socketioxide | Socket.IO v5 protocol compatible with the unmodified `socket.io-client` |
| rusqlite (bundled SQLite) + r2d2 | Prisma-compatible SQLite access; 4-connection pool, 1 MiB page cache each |
| reqwest + rustls (ring) + webpki-roots | outbound HTTPS (OIDC, Resend, GitHub, S3) without OpenSSL or system certs (scratch image) |
| lettre (rustls) | SMTP password-reset delivery (nodemailer equivalent) |
| rusty-s3 | S3 request signing without the AWS SDK |
| ammonia | HTML/SVG sanitisation (DOMPurify equivalent) |
| jsonwebtoken (rust_crypto) | HS256 sessions + OIDC ID-token verification (RS/PS/ES256/ES384/EdDSA) |
| p521, k256 (ecdsa only) | OIDC ES512 / ES256K ID tokens (not covered by jsonwebtoken) |
| bcrypt, scrypt | Node-compatible password hashes and API-key hashes |
| zip (flate2) | `.excalidash` archives compatible with JSZip/archiver |
| brotli | snapshot field codec (`br1:`), Node zlib-compatible |
