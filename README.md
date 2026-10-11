# excalidash-rs

A Rust rewrite of the [ExcaliDash](https://github.com/ZimengXiong/ExcaliDash) **0.6.5** backend.
It ships as one tiny container that also serves the **unmodified upstream frontend**, so it
replaces upstream's two containers (Node backend + nginx frontend) one-for-one: same API, same
Socket.IO collaboration, same SQLite database (opened in place, Prisma-compatible both ways).

## Footprint vs upstream 0.6.5

Measured with `tests/footprint/run.sh --compare` (fresh containers, `AUTH_MODE=local`,
production; RSS summed over every process in the container; collab load = 2 Socket.IO clients
editing one drawing at ~20 events/s each plus a 200-element save every 2 s, 60 s).

| | **excalidash-rs** | upstream (backend + nginx frontend) |
|---|---|---|
| Containers | **1** | 2 |
| Idle RSS | **9.7 MiB** | 140.6 MiB (131.1 + 9.5) |
| Peak RSS under 2-user collab load | **10.5 MiB** (VmHWM 12.7 MiB) | 162.9 MiB |
| RSS 30 s after load | **10.0 MiB** | 163.0 MiB |
| cgroup memory (docker stats), idle | **2.4 MiB** | 81.6 MiB |
| Image content size (`docker image inspect`) | **21.1 MB** | 166.8 MB (127.4 + 39.4) |
| `docker images` SIZE (containerd store: compressed blobs + unpacked snapshot; varies 41–49 MB between builds) | **≈ 41–49 MB** | 657 MB (535 + 122) |
| Binary | 5.3 MB static musl, `scratch` base | Node 20 + node_modules + Prisma engines |

Of the 21.1 MB image, 13.1 MB is upstream's own font files and 2.9 MB its (gzipped) JS/CSS;
the server binary is 5.3 MB. Load test errors: 0 for both.

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
`prisma/migrations` (upstream's SQLite migrations, embedded at build time).
Conventions for contributors: `docs/PORTING.md`. Tracking upstream releases: `UPGRADING.md`.

## Verification

All gates were re-run against the final image `excalidash-rs:0128d03` (built from this repo at commit `0128d03`).

| Gate | Result |
|---|---|
| **1. Upstream backend tests ported** | 28 of 29 upstream `backend/src/__tests__` integration files ported to Rust (`tests/*.rs`, black-box against the real binary, plus in-module unit tests where upstream tested internals); the 29th, `image-export.integration.ts`, tests a frontend utility (`frontend/src/utils/rehydrateFiles`), which is unchanged here. **284 tests passing (89 unit + 195 integration), 0 failing** (`cargo test`). S3 suites also pass against a real S3-compatible server (`EXRS_TEST_S3=1`). Mapping in `PARITY.md`. |
| **2. Upstream Playwright e2e** | Unmodified upstream suite (`tests/e2e/run.sh`, upstream's own layout: Vite dev frontend → Rust backend): **anonymous 70/70 passed, authenticated 6/6 passed**, 1 skipped by upstream design (`ui-review.spec.ts` screenshot capture, opt-in via `UI_REVIEW_SCREENSHOTS`). No exceptions. |
| **3. Differential test vs upstream Node** | `tests/diff/run.sh`: identical 92-step API scenario (auth, admin, account, API keys, drawings, collections, sharing, link shares, history, files, storage, library, export, error paths, SPA) against fresh Node 0.6.5 and Rust stacks: **92/92 steps identical** in status, headers and JSON bodies (incl. key order), after normalising per-run values (ids, dates, tokens). |
| **4. Real data (copy of the live volume)** | `tests/realdata/run.sh` on two copies of `excalidash_data`: Node and Rust return **identical** results for every endpoint of the account (15/15: me, status, preferences, API keys, collections, library, drawings, previews, sharing, history, files); Rust then wrote a drawing + snapshot + preference, and **upstream Node started on that volume with no pending migrations and read it back**. Live secrets injected via agent-secrets, never printed; original volume mounted read-only. |
| **5. Footprint** | See table above (`tests/footprint/run.sh --compare`). |

Database compatibility details: the migration runner reproduces `prisma migrate deploy`
(`_prisma_migrations` rows with Prisma's checksums); the resulting schema is object-for-object
identical to Prisma's. Dates are written as integer milliseconds like Prisma, and legacy TEXT
dates are read. Password hashes (bcrypt), API keys (scrypt + pepper), JWT sessions (same
secret/claims) and refresh tokens (sha256 lookup) created by Node keep working, and vice versa.
