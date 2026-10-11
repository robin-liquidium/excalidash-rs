# excalidash-rs

A Rust rewrite of the [ExcaliDash](https://github.com/ZimengXiong/ExcaliDash) **0.6.5** backend.
It ships as one tiny container that also serves the **unmodified upstream frontend**, so it
replaces upstream's two containers (Node backend + nginx frontend) one-for-one: same API, same
Socket.IO collaboration, same SQLite database (opened in place, Prisma-compatible both ways).
PostgreSQL works too, behind the optional `postgres` cargo feature.

## Footprint vs upstream 0.6.5

Measured with `tests/footprint/run.sh --compare` (fresh containers, `AUTH_MODE=local`,
production; RSS summed over every process in the container; collab load = 2 Socket.IO clients
editing one drawing at ~20 events/s each plus a 200-element save every 2 s, 60 s).

| | **excalidash-rs** | upstream (backend + nginx frontend) |
|---|---|---|
| Containers | **1** | 2 |
| Idle RSS | **9.7 MiB** | 140.8 MiB (131.4 + 9.5) |
| Peak RSS under 2-user collab load | **10.6 MiB** (VmHWM 13.0 MiB) | 162.2 MiB |
| RSS 30 s after load | **10.2 MiB** | 162.2 MiB |
| cgroup memory (docker stats), idle | **2.4 MiB** | 83.6 MiB |
| Image content size (`docker image inspect`, compressed layers) | **21.3 MB** | 166.8 MB (127.4 + 39.4) |
| `docker images` SIZE (containerd store: compressed blobs + unpacked snapshot; varies 41–49 MB between builds) | **≈ 41–49 MB** | 657 MB (535 + 122) |
| Binary | 10.9 MB static musl (5.0 MB compressed), `scratch` base | Node 20 + node_modules + Prisma engines |

Of the 21.3 MB image, 13.1 MB is upstream's own font files and 2.9 MB its (gzipped) JS/CSS;
the server binary ≈ 5 MB (compressed). Load test errors: 0 for both. The PostgreSQL build
(`--build-arg FEATURES=postgres`) adds 0.6 MB to the binary.

## Run

```sh
docker build -t excalidash-rs .
docker compose up -d          # compose.yaml: volumes, env, 127.0.0.1:6767 -> 8080
```

The container listens on **8080** (same as upstream's frontend container), runs as uid 1001
(same as upstream's backend, so existing volumes stay writable), stores data in
`/app/prisma` and backups in `/app/backups`. All upstream environment variables are supported
(`backend/src/config/registry/*`); see `PARITY.md` for the few Rust-only ones
(e.g. `FRONTEND_DIST_DIR=none` for backend-only mode). Healthcheck:
`/app/excalidash-rs healthcheck`.

Switching an existing upstream install: see `CUTOVER.md` (backup → swap → rollback).

### PostgreSQL

```sh
docker build --build-arg FEATURES=postgres -t excalidash-rs:pg .
# env: DATABASE_PROVIDER=postgresql DATABASE_URL=postgresql://user:pass@host:5432/excalidash
```

Same as upstream: applies upstream's PostgreSQL migrations with Prisma's bookkeeping (an
existing upstream PostgreSQL database is opened in place), honours Prisma URL arguments
(`schema`, `connection_limit`, `sslmode`, `sslaccept`, `sslcert`, …), and skips the
SQLite-only features (scheduled file backups, auto-vacuum). Details in `PARITY.md`.

## Develop

```sh
export PATH=$HOME/.cargo/bin:$PATH              # Rust 1.99 via rustup
cargo build
cargo test                                       # unit + black-box integration suites
cargo build --release --target x86_64-unknown-linux-musl
```

Layout: `src/http` (Express pipeline + nginx emulation), `src/auth` (sessions, API keys, OIDC,
account/admin routes), `src/routes` (dashboard, files, storage, import/export, system),
`src/socket.rs` (collaboration), `src/db.rs` (Prisma-compatible SQLite + migrations),
`src/sql` (rusqlite-style API over SQLite and PostgreSQL), `prisma/migrations` and
`prisma/migrations-postgresql` (upstream's migrations, embedded at build time),
`vendor/hyper` (two small patches for exact header spellings, see `vendor/README.md`),
`tools/gen_express_routes.py` (regenerates the Express route table from upstream).
Conventions for contributors: `docs/PORTING.md`. Tracking upstream releases: `UPGRADING.md`.

## Verification

All gates were re-run against the final image `excalidash-rs:6a0d6f4` (built from commit `6a0d6f4`);
PostgreSQL gates used the same commit built with `FEATURES=postgres`, against PostgreSQL 17.

| Gate | Result |
|---|---|
| **1. Upstream backend tests ported** | 28 of 29 upstream `backend/src/__tests__` integration files ported to Rust (`tests/*.rs`, black-box against the real binary, plus in-module unit tests where upstream tested internals); the 29th, `image-export.integration.ts`, tests a frontend utility (`frontend/src/utils/rehydrateFiles`), which is unchanged here. **295 tests passing, 0 failing** (`cargo test`); the same suite against PostgreSQL: **296 passing, 0 failing** (`EXCALIDASH_TEST_PG=… cargo test --features postgres`; 2 SQLite-only backup/vacuum tests skip themselves). S3 suites also pass against a real S3-compatible server (`EXRS_TEST_S3=1`), on both databases. Mapping in `PARITY.md`. |
| **2. Upstream Playwright e2e** | Unmodified upstream suite (`tests/e2e/run.sh`, upstream's own layout: Vite dev frontend → Rust backend): **anonymous 70/70 passed, authenticated 6/6 passed**, 1 skipped by upstream design (`ui-review.spec.ts` screenshot capture, opt-in via `UI_REVIEW_SCREENSHOTS`). Upstream's authenticated mode only selects `auth-workflows.spec.ts` + `ui-review.spec.ts` (`playwright.config.ts` testMatch); every other spec runs in anonymous mode. The collaboration and image-collab specs also pass 25/25 with `--repeat-each=5 --retries=0`. On PostgreSQL (`PG=1`): **anonymous 70/70 passed**. Only exception: the authenticated suite can't run on PostgreSQL, because upstream's `global-setup-auth.ts` seeds users through the SQLite Prisma client; authenticated flows on PostgreSQL are covered by the cargo suite and the diff. |
| **3. Differential test vs upstream Node** | `tests/diff/run.sh`: identical 116-step scenario (auth, admin, account, API keys, drawings, collections, sharing, link shares, history, files, storage, library, export, error paths, SPA) against fresh Node 0.6.5 and Rust stacks: **116/116 steps identical** on SQLite and **116/116 with both stacks on PostgreSQL** (`DIFF_DB=postgres`), in status, headers (names compared case-sensitively, incl. `Server`, framing, Socket.IO engine responses, Express case-insensitive routing and auto-`OPTIONS`, nginx static rules: SPA, assets, gzip, 304, 404/301/403/405) and JSON bodies (incl. key order), after normalising per-run values (ids, dates, tokens). |
| **4. Real data (copy of the live volume)** | `tests/realdata/run.sh` on copies of `excalidash_data`. The live data had no images, snapshots or API keys yet, so upstream Node first adds them to the copy (two edits of the real drawing → history snapshots, an image drawing → DrawingFile bytes, a library item, an API key). Node and Rust then return **identical** results: **24/24** (account, status, preferences, API keys, collections, library, drawings, previews, sharing, history snapshots, image bytes, and the Node-created API key authenticating against Rust). Rust then wrote a drawing + snapshot + preference, and **upstream Node started on that volume with no pending migrations and read it back**. Live secrets injected via agent-secrets, never printed; original volume mounted read-only. |
| Upstream-captured behaviour fixtures | Sanitiser output byte-identical to upstream's DOMPurify on 127 texts × 2 lengths + 14 SVGs (+ the live data's previews); dev-mode zod validation bodies identical on 37 create/update cases; JS `Date` parsing identical to Node on 41 inputs; nginx Range handling identical on 40 requests (single/multi/suffix/416). |
| S3 (real S3-compatible server) | 6/6 on SQLite and on PostgreSQL, incl. the AWS default credential chain (profile file, container endpoint, SDK's no-provider error), S3 copy on duplicate, cleanup on delete. |
| **5. Footprint** | See table above (`tests/footprint/run.sh --compare`). |
| Image-level feature checks | Scheduled backups: a container with `BACKUP_SCHEDULE="*/2 * * * * *"` wrote a backup every 2 s (0600, uid 1001, `PRAGMA integrity_check` ok). Password reset: from the container, the reset mail arrived at an SMTP server with upstream's subject and link; confirming it and logging in with the new password succeeded. |

Database compatibility details: the migration runner reproduces `prisma migrate deploy`
(`_prisma_migrations` rows with Prisma's checksums); the resulting schema is object-for-object
identical to Prisma's. Dates are written as integer milliseconds like Prisma, and legacy TEXT
dates are read. Password hashes (bcrypt), API keys (scrypt + pepper), JWT sessions (same
secret/claims) and refresh tokens (sha256 lookup) created by Node keep working, and vice versa.
