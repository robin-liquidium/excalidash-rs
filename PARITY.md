# Parity matrix — ExcaliDash 0.6.5 (Node) → excalidash-rs

Status legend: ✅ ported + tested · ⚠️ ported with a documented deviation · ⏳ pending.
"Tests" lists the Rust tests that prove the behaviour (`tests/*.rs` unless noted).

## HTTP routes (backend paths; served under `/api` with the bundled frontend)

| Method | Path | Upstream | Rust | Status | Tests |
|---|---|---|---|---|---|
| GET | /health | index.ts | routes/mod.rs | ✅ | core_http::health_and_core_headers |
| GET | /csrf-token | server/csrf.ts | http/csrf.rs | ✅ | core_http::csrf_required_for_mutations |
| POST | /auth/register | auth/coreRoutes.ts | auth/routes/core.rs | ⏳ | |
| POST | /auth/login | auth/coreRoutes.ts | auth/routes/core.rs | ⏳ | |
| POST | /auth/refresh | auth/coreRoutes.ts | auth/routes/core.rs | ⏳ | |
| POST | /auth/logout | auth/coreRoutes.ts | auth/routes/core.rs | ⏳ | |
| POST | /auth/stop-impersonation | auth/coreRoutes.ts | auth/routes/core.rs | ⏳ | |
| GET | /auth/me | auth/coreRoutes.ts | auth/routes/core.rs | ⏳ | |
| GET | /auth/status | auth/coreRoutes.ts | auth/routes/core.rs | ⏳ | |
| POST | /auth/onboarding-choice | auth/coreRoutes.ts | auth/routes/core.rs | ⏳ | |
| POST | /auth/auth-enabled | auth/coreRoutes.ts | auth/routes/core.rs | ⏳ | |
| GET | /auth/oidc/start | auth/oidcRoutes.ts | auth/routes/oidc.rs | ⏳ | |
| GET | /auth/oidc/callback | auth/oidcCallbackRoute.ts | auth/routes/oidc.rs | ⏳ | |
| GET/POST | /auth/api-keys | auth/accountApiKeyRoutes.ts | auth/routes/account.rs | ⏳ | |
| DELETE | /auth/api-keys/:id | auth/accountApiKeyRoutes.ts | auth/routes/account.rs | ⏳ | |
| POST | /auth/change-password | auth/accountPasswordChangeRoutes.ts | auth/routes/account.rs | ⏳ | |
| POST | /auth/must-reset-password | auth/accountPasswordChangeRoutes.ts | auth/routes/account.rs | ⏳ | |
| GET | /auth/password-reset-capability | auth/accountPasswordResetRoutes.ts | auth/routes/account.rs | ⏳ | |
| POST | /auth/password-reset-request | auth/accountPasswordResetRoutes.ts | auth/routes/account.rs | ⏳ | |
| POST | /auth/password-reset-confirm | auth/accountPasswordResetRoutes.ts | auth/routes/account.rs | ⏳ | |
| GET/PUT | /auth/preferences | auth/accountPreferencesRoutes.ts | auth/routes/account.rs | ⏳ | |
| PUT | /auth/profile | auth/accountProfileRoutes.ts | auth/routes/account.rs | ⏳ | |
| PUT | /auth/email | auth/accountProfileRoutes.ts | auth/routes/account.rs | ⏳ | |
| POST | /auth/admins | auth/adminUserRoutes.ts | auth/routes/admin.rs | ⏳ | |
| GET/POST | /auth/users | auth/adminUserRoutes.ts | auth/routes/admin.rs | ⏳ | |
| PATCH | /auth/users/:id | auth/adminUserRoutes.ts | auth/routes/admin.rs | ⏳ | |
| POST | /auth/users/:id/reset-password | auth/adminUserPasswordRoutes.ts | auth/routes/admin.rs | ⏳ | |
| POST | /auth/registration/toggle | auth/adminSettingsRoutes.ts | auth/routes/admin.rs | ⏳ | |
| POST | /auth/oidc/jit-provisioning | auth/adminSettingsRoutes.ts | auth/routes/admin.rs | ⏳ | |
| GET/PUT | /auth/rate-limit/login | auth/adminSettingsRoutes.ts | auth/routes/admin.rs | ⏳ | |
| POST | /auth/rate-limit/login/reset | auth/adminSettingsRoutes.ts | auth/routes/admin.rs | ⏳ | |
| GET | /auth/impersonation-targets | auth/adminImpersonationRoutes.ts | auth/routes/admin.rs | ⏳ | |
| POST | /auth/impersonate | auth/adminImpersonationRoutes.ts | auth/routes/admin.rs | ⏳ | |
| GET | /drawings | routes/dashboard/drawingListRoutes.ts | routes/dashboard | ⏳ | |
| GET | /drawings/shared | routes/dashboard/drawingListRoutes.ts | routes/dashboard | ⏳ | |
| GET | /drawings/:id/preview | routes/dashboard/drawingListRoutes.ts | routes/dashboard | ⏳ | |
| GET | /drawings/:id | routes/dashboard/drawingReadRoutes.ts | routes/dashboard | ⏳ | |
| POST | /drawings | routes/dashboard/drawingCreateUpdateRoutes.ts | routes/dashboard | ⏳ | |
| PUT | /drawings/:id | routes/dashboard/drawingCreateUpdateRoutes.ts + sceneUpdate.ts | routes/dashboard | ⏳ | |
| DELETE | /drawings/:id | routes/dashboard/drawingDeleteDuplicateRoutes.ts | routes/dashboard | ⏳ | |
| POST | /drawings/:id/duplicate | routes/dashboard/drawingDeleteDuplicateRoutes.ts | routes/dashboard | ⏳ | |
| GET | /drawings/:id/history | routes/dashboard/drawingHistoryRoutes.ts | routes/dashboard | ⏳ | |
| GET | /drawings/:id/history/:snapshotId | routes/dashboard/drawingHistoryRoutes.ts | routes/dashboard | ⏳ | |
| POST | /drawings/:id/history/:snapshotId/restore | routes/dashboard/drawingHistoryRoutes.ts | routes/dashboard | ⏳ | |
| PATCH | /drawings/:id/shared-visibility | routes/dashboard/drawingSharedVisibilityRoutes.ts | routes/dashboard | ⏳ | |
| GET | /drawings/:id/share-resolve | routes/dashboard/drawingSharingRoutes.ts | routes/dashboard | ⏳ | |
| GET | /drawings/:id/sharing | routes/dashboard/drawingSharingRoutes.ts | routes/dashboard | ⏳ | |
| POST | /drawings/:id/permissions | routes/dashboard/drawingSharingRoutes.ts | routes/dashboard | ⏳ | |
| DELETE | /drawings/:id/permissions/:permId | routes/dashboard/drawingSharingRoutes.ts | routes/dashboard | ⏳ | |
| POST | /drawings/:id/link-shares | routes/dashboard/drawingSharingRoutes.ts | routes/dashboard | ⏳ | |
| DELETE | /drawings/:id/link-shares/:shareId | routes/dashboard/drawingSharingRoutes.ts | routes/dashboard | ⏳ | |
| GET/POST | /collections | routes/dashboard/collections.ts | routes/dashboard | ⏳ | |
| PUT/DELETE | /collections/:id | routes/dashboard/collections.ts | routes/dashboard | ⏳ | |
| GET/POST | /collections/:id/shares | routes/dashboard/collections.ts | routes/dashboard | ⏳ | |
| PATCH/DELETE | /collections/:id/shares/:userId | routes/dashboard/collections.ts | routes/dashboard | ⏳ | |
| GET | /collections/:id/share-resolve | routes/dashboard/collections.ts | routes/dashboard | ⏳ | |
| GET/PUT | /library | routes/dashboard/library.ts | routes/dashboard | ⏳ | |
| GET | /files/config | routes/files.ts | routes/files.rs | ⏳ | |
| PUT | /drawings/:drawingId/files/:fileId | routes/files.ts | routes/files.rs | ⏳ | |
| GET | /files/:drawingId/:fileId | routes/files.ts | routes/files.rs | ⏳ | |
| POST | /drawings/:id/trim | routes/storage.ts | routes/storage.rs | ⏳ | |
| GET | /drawings/:id/files/diff | routes/storage.ts | routes/storage.rs | ⏳ | |
| DELETE | /drawings/:id/files/orphans | routes/storage.ts | routes/storage.rs | ⏳ | |
| GET | /export/excalidash | routes/importExport/exportRoutes.ts | routes/import_export | ⏳ | |
| POST | /import/excalidash/verify | routes/importExport/excalidashImportRoutes.ts | routes/import_export | ⏳ | |
| POST | /import/excalidash | routes/importExport/excalidashImportRoutes.ts | routes/import_export | ⏳ | |
| POST | /import/sqlite/legacy/verify | routes/importExport/legacySqliteImportRoutes.ts | routes/import_export | ⏳ | |
| POST | /import/sqlite/legacy | routes/importExport/legacySqliteImportRoutes.ts | routes/import_export | ⏳ | |
| GET | /system/update | routes/system/update.ts | routes/system.rs | ⏳ | |

## Cross-cutting behaviour

| Feature | Upstream | Rust | Status | Tests |
|---|---|---|---|---|
| Request id, helmet headers, CORS (incl. preflight), body parsers + limits, request log, general rate limit, ETag/304, finalhandler 404 | index.ts, helmet, cors, express | src/http/mod.rs, src/http/body.rs, src/http/rate_limit.rs | ✅ | core_http::* |
| CSRF tokens (HMAC, cookie client id + legacy id), CSRF middleware | security.ts, server/csrf.ts, security/csrfClient.ts | src/http/csrf.rs | ✅ | core_http::csrf_required_for_mutations |
| HTTPS redirect policy | server/httpsRedirectPolicy.ts | src/http/mod.rs | ✅ | |
| Onboarding gate | index.ts | src/http/mod.rs | ✅ | core_http::onboarding_gate_blocks_app_routes_until_setup |
| requireAuth / optionalAuth (JWT cookie/bearer, API keys + scopes, must-reset, OIDC role reconcile, bootstrap acting user) | middleware/auth.ts, auth/authMode.ts | src/auth/middleware.rs | ✅ | harness_selftest, auth suites |
| JWT format (HS256, claims, ms-style expiries), auth cookies | auth.ts, auth/cookies.ts | src/auth/jwt.rs, src/auth/cookies.rs | ✅ | |
| API key hashing (scrypt N=2^14 r=8 p=1, pepper) | auth/apiKeys.ts | src/auth/api_keys.rs | ✅ | |
| XSS sanitisation (DOMPurify → ammonia), zod element/appState schemas, file dataURL rules | security.ts | src/security.rs | ⚠️ | security::tests (unit) |
| Snapshot codec (brotli `br1:`) | snapshots/snapshotCodec.ts | src/snapshots.rs | ✅ | snapshots::tests (unit) |
| Drawing access (owner/ACL/collection/link policy) | authz/sharing.ts | src/authz.rs | ✅ | |
| Socket.IO collab (join-room, cursor-move, element-update, user-activity, presence, revalidation) | server/socket.ts, server/socketAccess.ts | src/socket.rs | ✅ | |
| Drawings list cache (LRU, TTL, per-user invalidation) | server/drawingsCache.ts | src/drawings_cache.rs | ✅ | |
| Audit log | utils/audit.ts | src/audit.rs | ✅ | |
| Prisma migrations (`migrate deploy` bookkeeping, checksums) | prisma + docker-entrypoint.sh | src/db.rs, src/main.rs | ✅ | schema identical to Prisma's (see Verification) |
| Persisted JWT/CSRF secrets, migration lock, RUN_MIGRATIONS | docker-entrypoint.sh | src/main.rs (`EXCALIDASH_ENTRYPOINT=1`) | ✅ | |
| Static frontend serving (SPA fallback, nginx headers/caching/gzip) | frontend/nginx.conf.template | src/http/static_files.rs | ⚠️ | |
| Snapshot retention sweep | index.ts | src/main.rs | ✅ | |
| Every env var in config/registry | config/** | src/config.rs | ✅ | |

## Deliberate deviations

_(filled in as the port completes)_

## Heavy crates (justification)

_(filled in at the end)_
