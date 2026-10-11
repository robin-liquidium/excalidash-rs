# excalidash-rs: self-hosted Excalidraw in 10 MB of RAM

**A drop-in Rust rewrite of the [ExcaliDash](https://github.com/ZimengXiong/ExcaliDash) backend.**
ExcaliDash is a self-hosted [Excalidraw](https://excalidraw.com) whiteboard with multiple
drawings, collections, version history, sharing and real-time collaboration. excalidash-rs
runs the same thing in **one 21 MB container using about 10 MB of RAM**, instead of two
containers using about 140 MB.

- **Drop-in replacement** for ExcaliDash 0.6.5. It uses the same API, the same live
  collaboration and the same database, opened in place. Switching back to upstream works at
  any time.
- **Unmodified upstream frontend**, bundled into the image. The UI is exactly ExcaliDash's.
- **Tiny:** a static musl binary on a `scratch` image. No Node.js, no nginx, no Prisma engines.
- **Verified, not approximated:** upstream's backend tests are ported, and upstream's Playwright
  end-to-end suite passes unmodified. A 116-step differential test returns byte-identical
  responses to upstream Node.
- **SQLite or PostgreSQL**, local disk or S3 for images, local accounts or OIDC/SSO, API keys,
  scheduled backups.

> Unofficial community project, not affiliated with ExcaliDash or Excalidraw. It tracks
> upstream releases; see [UPGRADING.md](UPGRADING.md).

## Benchmarks

Measured with [`tests/footprint/run.sh --compare`](tests/footprint/run.sh) on fresh containers
in production mode. RSS is summed over every process in the container. Collaboration load =
2 Socket.IO clients editing one drawing at ~20 events/s each, plus a 200-element save every
2 s, for 60 s.

| | **excalidash-rs** | ExcaliDash 0.6.5 (Node backend + nginx frontend) | |
|---|---|---|---|
| Containers | **1** | 2 | |
| Memory, idle | **9.7 MiB** | 140.8 MiB | **14× less** |
| Memory, peak during 2-user collaboration | **10.6 MiB** | 162.2 MiB | **15× less** |
| Memory, 30 s after load | **10.2 MiB** | 162.2 MiB | |
| cgroup memory (`docker stats`), idle | **2.4 MiB** | 83.6 MiB | |
| Image size (compressed) | **21.3 MB** | 166.8 MB | **8× smaller** |
| Image size on disk (`docker images`) | **≈ 49 MB** | 657 MB | **13× smaller** |
| Server binary | 10.9 MB static musl (5 MB compressed) | Node 20 + node_modules + Prisma engines | |
| Errors under load | 0 | 0 | |

Most of the image is upstream's frontend: 13 MB of fonts and 3 MB of gzipped JS/CSS. The
PostgreSQL build adds 0.6 MB.

It runs comfortably on a Raspberry Pi, a mini PC or the smallest VPS. Memory stays flat under
collaboration instead of growing with the V8 heap.

## Quick start

```sh
git clone <this repo> excalidash-rs && cd excalidash-rs
docker build -t excalidash-rs .
docker compose up -d        # see compose.yaml: data volume, secrets, 127.0.0.1:6767 -> 8080
```

Open http://localhost:6767 (the default `FRONTEND_URL`) and follow the first-run setup. The admin setup code is printed in
the logs: `docker compose logs app | grep 'BOOTSTRAP SETUP'`.

- The container listens on **8080** and runs as uid **1001**. Data lives in `/app/prisma`,
  backups in `/app/backups`.
- **All upstream environment variables are supported**, e.g. `AUTH_MODE`, `FRONTEND_URL`,
  `TRUST_PROXY`, OIDC, S3, mail and backups. See [PARITY.md](PARITY.md) for the few Rust-only
  ones (e.g. `FRONTEND_DIST_DIR=none` for API-only mode).
- Healthcheck built in: `/app/excalidash-rs healthcheck`.

### Already running ExcaliDash?

Point excalidash-rs at your existing data volume with the same secrets. Sessions, passwords and
API keys keep working, and no migration is needed. Step by step, with backup and switch-back:
[MIGRATING.md](MIGRATING.md).

### PostgreSQL

```sh
docker build --build-arg FEATURES=postgres -t excalidash-rs:pg .
# DATABASE_PROVIDER=postgresql DATABASE_URL=postgresql://user:pass@host:5432/excalidash
```

This works the same way as upstream:
- It applies upstream's PostgreSQL migrations with Prisma's bookkeeping, so an existing upstream
  PostgreSQL database opens in place.
- It honours Prisma URL arguments (`schema`, `connection_limit`, `sslmode`, `sslaccept`,
  `sslcert`, …).
- It skips the SQLite-only features (file backups, auto-vacuum).

## Features

Everything ExcaliDash 0.6.5 does, including:

- Drawings, collections, trash, search, sorting, previews, version history and snapshots
- Real-time collaboration (Socket.IO, compatible with the unmodified client): cursors, presence,
  live edits
- Sharing: per-user permissions, collection sharing, expiring view/edit links
- Auth: local accounts with bootstrap setup code, JWT + refresh tokens, OIDC/SSO (PKCE, JIT
  provisioning, group→role mapping), API keys with scopes, admin user management and
  impersonation, password reset by SMTP or Resend
- Images stored in the database or S3 (incl. the AWS default credential chain)
- `.excalidash` import/export, legacy SQLite import, libraries
- Scheduled SQLite backups, audit log, rate limits, CSRF, upstream's security headers and CSP

The full route-by-route and feature-by-feature matrix, plus every known difference, is in
[PARITY.md](PARITY.md).

## How it's verified

| Check | Result |
|---|---|
| Upstream backend test suite (28 of 29 files ported; the 29th tests frontend code) | **295/295** on SQLite, **296/296** on PostgreSQL 17 |
| Upstream Playwright e2e suite, unmodified | **76/76** on SQLite, **70/70** on PostgreSQL ([details](#verification-details)) |
| Differential test: same 116-step scenario against upstream Node and excalidash-rs, comparing status, headers (case-sensitive) and JSON bodies | **116/116 identical** on SQLite and on PostgreSQL |
| Real data: a production volume copy read through both servers, then upstream reopening what Rust wrote | **24/24 identical**, switch-back OK |
| Captured behaviour fixtures: sanitiser vs DOMPurify, zod validation errors, JS `Date` parsing, nginx Range handling | byte-identical |
| S3 against a real S3-compatible server | 6/6 on both databases |

## Develop

```sh
cargo build
cargo test                                         # unit + black-box integration suites
EXCALIDASH_TEST_PG=postgresql://… cargo test --features postgres
tests/diff/run.sh                                  # differential test vs upstream Node (Docker)
tests/e2e/run.sh all                               # upstream Playwright suite (Docker)
```

Code layout:
- `src/http`: the Express pipeline and nginx emulation
- `src/auth`: sessions, API keys, OIDC, account and admin routes
- `src/routes`: dashboard, files, storage, import/export, system
- `src/socket.rs`: collaboration
- `src/db.rs` and `src/sql`: Prisma-compatible SQLite/PostgreSQL access and migrations
- `prisma/`: upstream's migrations, embedded at build time
- `vendor/hyper`: two small patches for exact header spellings ([vendor/README.md](vendor/README.md))

Contributor conventions are in [docs/PORTING.md](docs/PORTING.md). Porting a new upstream
release is covered in [UPGRADING.md](UPGRADING.md).

## Verification details

All checks ran against the image built from commit `6a0d6f4`. The PostgreSQL checks used the
same commit built with `FEATURES=postgres`, against PostgreSQL 17.

- **Ported tests:** 28 of 29 upstream `backend/src/__tests__` integration files are ported to
  Rust (`tests/*.rs`). They run black-box against the real binary, with in-module unit tests
  where upstream tested internals. `image-export.integration.ts` tests a frontend utility, and
  the frontend is unchanged here. On PostgreSQL, 2 SQLite-only backup/vacuum tests skip
  themselves. The test mapping is in [PARITY.md](PARITY.md).
- **Playwright e2e:** `tests/e2e/run.sh` runs the unmodified upstream suite in upstream's own
  layout (Vite dev frontend → Rust backend).
  - Results: anonymous 70/70 and authenticated 6/6, plus 1 skipped by upstream design (opt-in
    screenshot capture).
  - The collaboration specs also pass 25/25 with `--repeat-each=5 --retries=0`.
  - On PostgreSQL only the anonymous suite runs. Upstream's authenticated global setup seeds
    users through the SQLite Prisma client; those flows are covered by the cargo suite and the
    differential test.
- **Differential test:** `tests/diff/run.sh` runs auth, admin, account, API keys, drawings,
  collections, sharing, link shares, history, files, storage, library, export, error paths,
  Socket.IO engine responses and static/SPA serving against fresh upstream and Rust stacks.
  - Header names are compared case-sensitively, and JSON bodies including key order.
  - Per-run values (ids, dates, tokens) are normalised first.
  - `DIFF_DB=postgres` runs both stacks on PostgreSQL.
- **Real data:** `tests/realdata/run.sh` works on copies of a real data volume.
  - Upstream first adds history snapshots, an image, a library item and an API key to the copy.
  - Both servers then return identical results for every account, drawing, collection,
    snapshot, file and API-key view.
  - Rust then writes data, and upstream Node starts on that volume with no pending migrations
    and reads it back.
- **Database compatibility:**
  - The migration runner reproduces `prisma migrate deploy`, including `_prisma_migrations`
    rows with Prisma's checksums. The resulting schema is object-for-object identical.
  - Dates are written as integer milliseconds like Prisma, and legacy TEXT dates are read.
  - bcrypt password hashes, scrypt API keys, JWT sessions and refresh tokens are
    interchangeable with upstream in both directions.

## License and credits

excalidash-rs is a port of [ExcaliDash](https://github.com/ZimengXiong/ExcaliDash) by Zimeng
Xiong and contributors, and is licensed like upstream under the
[GNU LGPL v3.0](LICENSE). The bundled frontend is upstream's unmodified build of ExcaliDash,
which is built on [Excalidraw](https://github.com/excalidraw/excalidraw) (MIT).
`vendor/hyper` is [hyper](https://github.com/hyperium/hyper) (MIT) with two small patches.
