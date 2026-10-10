# Porting guide (for everyone writing code in this repo)

Goal: a drop-in Rust replacement for the ExcaliDash **0.6.5** backend. The unmodified
upstream frontend must not notice any difference, and an existing Prisma SQLite
`dev.db` must keep working in both directions (Rust ↔ upstream Node).

## Source of truth

- Upstream checkout (read-only, gitignored): `/home/robin/code/excalidash-rs/upstream-ref/excalidash`
  - backend: `backend/src/**` (port semantics from here), tests: `backend/src/__tests__/*`
  - schema: `backend/prisma/schema.prisma`, migrations vendored in `prisma/migrations`
- Frontend build (for API usage reference only): `frontend/src/**` in the same checkout.
- Port **behaviour**, not style: same status codes, same JSON bodies (keys, value types,
  key order where practical), same error messages, same validation rules (zod), same DB side
  effects (incl. `updatedAt`), same cookies/headers, same `console.log`-style log lines
  (`println!`/`eprintln!`).

## Architecture you plug into

- `src/http/mod.rs` reproduces the Express chain from `index.ts` (request id, https redirect,
  helmet, cors, body parsing, logging, general rate limit, `/csrf-token`, CSRF middleware for
  non-`/auth/` mutations, onboarding gate, ETag/304) and then calls the axum router built in
  `src/routes/mod.rs`. **Handlers never re-implement those.** Paths are backend paths
  (no `/api` prefix), e.g. `/drawings/{id}`. `/auth/*` routes are nested under `/auth`.
- Handler shape:
  ```rust
  async fn handler(State(st): State<AppState>, ctx: Ctx, Path(id): Path<String>, body: Body) -> ApiResult {
      let user = crate::auth::require_auth(&st.db, &ctx).await?;       // requireAuth
      let opt = crate::auth::optional_auth(&st.db, &ctx).await;        // optionalAuth
      ...
      ok(json!({...}))                    // res.json
      // status_json(201, json!(...))     // res.status(201).json
      // Err(ApiError::err(404, "Not found", "Drawing not found"))
      // Err(ApiError::internal("msg"))   // thrown → errorHandler 500 body
  }
  ```
  `Body` = Express `req.body` (`None` when not JSON/urlencoded). `ctx.query_map()` /
  `crate::http::body::parse_query_values` = `req.query`. `ctx.ip`, `ctx.user_agent()`,
  `ctx.secure`, `ctx.cookie(name)`.
- Auth routes call `helpers::require_csrf(&ctx)?` where upstream calls `requireCsrf`, and use
  the rate limiters in `src/auth/routes/helpers.rs`. Rate-limit headers: `decision.apply(res.headers_mut())`.
- Socket.IO: `crate::socket::emit_to_drawing(&st, id, "event", &payload)` and
  `crate::socket::revalidate_drawing_access(&st, id).await`.
- Drawing access: `crate::authz::get_drawing_access(conn, principal, drawing_id, None)`.
- Drawings list cache: `st.drawings_cache` (`invalidate(Some(user_id))` etc.).
- Audit log: `crate::audit::log_audit_event(&st.db, AuditEvent { .. }).await`.
- Sanitizers: `crate::security::*` (already ported: sanitize_text, sanitize_svg,
  sanitize_drawing_data, validate_imported_drawing, sanitize_elements, sanitize_app_state ...).
- Snapshot codec: `crate::snapshots::{encode_field, decode_field}`.
- Trash ids: `crate::trash::*`. Users/system config rows: `crate::models`.

## Database rules (Prisma 5 + SQLite compatibility — critical)

- Use `st.db.call(move |c| { ... })` (blocking pool) or `st.db.tx(...)` for transactions.
- **DateTime**: Prisma writes INTEGER unix **milliseconds** → always write `util::now_ms()`
  (never `CURRENT_TIMESTAMP`/text). Read with `db::dt` / `db::opt_dt` (handles legacy TEXT
  defaults). JSON output: `util::iso_from_ms(ms)` (JS `toISOString`). Compare DateTime columns
  by binding integer ms params exactly like Prisma does.
- **Boolean**: INTEGER 0/1 (`db::boolean`).
- Inserts must set every NOT NULL column Prisma would fill: `id` (`util::uuid_v4()` for
  `@default(uuid())`), `createdAt`, `updatedAt` (both `now_ms()`), and schema defaults.
- **Every UPDATE (incl. `updateMany`) on a model with `@updatedAt` must set `"updatedAt"`**.
- Foreign keys are ON (cascades come from the DDL). Unique violations ≈ Prisma P2002 →
  `DbError::is_unique_violation()`.
- Prisma `contains`/`startsWith` on SQLite compile to `LIKE` (ASCII case-insensitive), with
  `%`, `_` escaped. `orderBy` with ties: add nothing beyond what upstream asks.
- Table/column names are quoted camelCase: `"Drawing"."collectionId"`.

## Express quirks to keep

- Query values are strings or arrays (`req.query.x` can be an array on repeats).
- `typeof x === "string"` checks, `.trim()` (use `security::js_trim`), JS string lengths are
  UTF-16 units (`util::js_len`, `util::js_slice`).
- zod failures: copy the exact response each route sends (often production vs dev bodies differ:
  check `config.nodeEnv` branches). Tests run with `NODE_ENV=production` by default.

## Tests (required)

- Black-box HTTP tests in `tests/<area>_*.rs` using `tests/common/mod.rs` (`TestServer::start`
  spawns the real binary with a temp DB; `TestClient` keeps cookies, sends `Origin`, CSRF).
  Helpers: `bootstrap_admin`, `login`, `wait_for_setup_code`, `server.db()` for direct SQL.
- **Port every upstream test file assigned to you**: same scenarios, same assertions, adapted
  to HTTP (+ direct DB seeding/inspection where upstream used prisma). Where upstream tests a
  pure internal function, write an in-module `#[cfg(test)]` unit test instead.
- Run: `cargo build && cargo test --test <your files>` (and `cargo test --lib`) must pass.
  PATH: `export PATH=$HOME/.cargo/bin:$PATH` (Rust 1.99 via rustup; ignore /usr/bin/cargo).
- To confirm exact upstream behaviour, you may run your **own** throwaway upstream container on
  your assigned port (see your task), e.g.
  `docker run -d --rm --name exrs-<area>-ref -p 127.0.0.1:<PORT>:8000 -e NODE_ENV=production -e AUTH_MODE=local -e JWT_SECRET=ref-jwt-secret-0123456789abcdef0123456789abcdef -e CSRF_SECRET=x -e FRONTEND_URL=http://localhost:16767 -e UPDATE_CHECK_OUTBOUND=false zimengxiong/excalidash-backend:0.6.5`
  and stop/remove it when done.

## Footprint

Minimal deps. Do not add crates without need; prefer what is already in Cargo.toml
(reqwest+rustls/ring, lettre, rusty-s3, zip, flate2, brotli, cron, ammonia, regex, scrypt,
bcrypt, jsonwebtoken). Never add OpenSSL, aws-sdk, or a second async runtime. Heavy CPU work
(bcrypt, scrypt, zip, image work) goes in `spawn_blocking`/`db.call`.

## Safety (hard rules)

- Never touch the live deployment: containers `excalidash-backend-1`/`excalidash-frontend-1`,
  volumes `excalidash_data`/`excalidash_backups`, port 6767, `cloudflared-excali`, DNS, Access.
- Don't use ports 16767/18000/18100 (owned by the coordinator). Don't push, don't create remotes.
- Never print secrets. Clean up any containers/volumes/temp dirs you create.

## Ownership

Edit only the files assigned to you. If a shared file (`src/http/**`, `src/auth/middleware.rs`,
`src/auth/routes/helpers.rs`, `src/db.rs`, `src/models.rs`, `src/util.rs`, `src/security.rs`,
`src/state.rs`, `src/socket.rs`, `Cargo.toml`, `tests/common/mod.rs`) truly needs a change, keep
it minimal and additive, and list it explicitly in your final report.
