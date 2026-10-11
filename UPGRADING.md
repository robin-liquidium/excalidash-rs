# Tracking upstream ExcaliDash releases

This backend mirrors ExcaliDash **0.6.5** (`31f82f4`). The frontend is never forked: the
image copies the upstream frontend build, so a new release mostly means porting backend
changes and bumping two pins.

## 1. See what changed

```sh
cd upstream-ref/excalidash            # gitignored checkout (re-clone if missing)
git fetch --tags
OLD=v0.6.5 NEW=v0.6.6                 # example
git diff --stat $OLD $NEW -- backend/src backend/prisma frontend/nginx.conf.template e2e
git log --oneline $OLD..$NEW -- backend
```

Triage the diff into buckets:

| Upstream path | Rust counterpart |
|---|---|
| `backend/prisma/migrations/sqlite/*` | copy new folders into `prisma/migrations/` (embedded at build time, applied with Prisma-identical bookkeeping) |
| `backend/prisma/migrations/postgresql/*` | copy new folders into `prisma/migrations-postgresql/`; new BOOLEAN or TIMESTAMP(3) columns go into `BOOL_COLUMNS` / `TIMESTAMP_COLUMNS` in `src/sql/pg.rs` (literal 0/1 and ms translation) |
| `backend/prisma/schema.prisma` | `prisma/schema.prisma` (reference) + affected row structs/queries |
| `backend/src/config/**`, `config.ts` | `src/config.rs` |
| `backend/src/index.ts`, `server/csrf.ts`, `middleware/**`, `security.ts` | `src/http/**`, `src/security.rs` |
| `backend/src/auth/**` | `src/auth/**`, `src/bootstrap.rs`, `src/mail.rs` |
| `backend/src/routes/dashboard/**` | `src/routes/dashboard/**` |
| `backend/src/routes/files.ts`, `routes/storage*`, `s3.ts`, `fileProcessing.ts` | `src/routes/files.rs`, `src/routes/storage.rs`, `src/s3.rs`, `src/files.rs` |
| `backend/src/routes/importExport/**` | `src/routes/import_export/**` |
| `backend/src/server/socket*.ts`, `authz/**` | `src/socket.rs`, `src/authz.rs` |
| `backups/`, `db/sqliteMaintenance.ts`, `server/storageDoctor.ts`, `routes/system/**` | `src/backups.rs`, `src/sqlite_maintenance.rs`, `src/storage_doctor.rs`, `src/routes/system.rs` |
| `frontend/nginx.conf.template` | `src/http/static_files.rs` (headers, cache rules) |
| `backend/src/__tests__/*` | `tests/*.rs` (port new/changed cases) |

`PARITY.md` maps every route and feature to its Rust module and test; update it as you go.

## 2. Port

- Follow `docs/PORTING.md` (Prisma date/bool encoding, `updatedAt`, Express quirks). Write SQL
  in the SQLite dialect with `?N` placeholders through `crate::sql`; it runs unchanged on
  PostgreSQL (see `src/sql/pg.rs` for what the translator handles).
- New, removed or renamed routes: regenerate the Express route table (case-insensitive
  matching + automatic `OPTIONS`):
  `python3 -I tools/gen_express_routes.py upstream-ref/excalidash > src/http/express_routes.rs`.
- New migration: copy the folder, then `cargo test` — the migration runner test applies all
  migrations on an empty DB, and `tests/diff` checks the schema against Prisma's.
- Bump `VERSION` and the frontend pin `FRONTEND_IMAGE` in `Dockerfile` (and `tests/diff/compose.yaml`,
  `tests/e2e/run.sh` defaults) to the new upstream tag.

## 3. Verify (all must pass before release)

```sh
export PATH=$HOME/.cargo/bin:$PATH
cargo test                                   # unit + black-box integration tests
docker build -t excalidash-rs:dev .
tests/diff/run.sh                            # Node vs Rust differential scenario (bump image tags inside)
tests/e2e/run.sh all                         # upstream Playwright suite against the Rust image

# PostgreSQL (throwaway server on a loopback port)
docker run -d --name exrs-pg -p 127.0.0.1:55432:5432 -e POSTGRES_PASSWORD=test --tmpfs /var/lib/postgresql/data \
  postgres:17-alpine -c max_connections=500
EXCALIDASH_TEST_PG=postgresql://postgres:test@127.0.0.1:55432 cargo test --features postgres
docker build --build-arg FEATURES=postgres -t excalidash-rs:dev-pg .
DIFF_DB=postgres RUST_IMAGE=excalidash-rs:dev-pg tests/diff/run.sh
PG=1 RUST_IMAGE=excalidash-rs:dev-pg tests/e2e/run.sh anonymous
docker rm -f exrs-pg
tests/realdata/run.sh                        # copy of the live DB: Rust → upstream round trip
tests/footprint/run.sh                       # RAM/image size vs targets
```

## Vendored hyper

`vendor/hyper` carries two small patches (exact header-name spellings, `Content-Length: 0` on
204). When bumping hyper in `Cargo.lock`, replace the vendored copy with the new version and
re-apply the patches marked `excalidash-rs patch` (see `vendor/README.md`); `tests/diff`
compares header names case-sensitively and fails if they are lost.

## 4. Release

Tag the commit, build the image, then follow `MIGRATING.md` (backup first, rollback = previous
image tag).
