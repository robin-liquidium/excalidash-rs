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

- Follow `docs/PORTING.md` (Prisma date/bool encoding, `updatedAt`, Express quirks).
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
tests/realdata/run.sh                        # copy of the live DB: Rust → upstream round trip
tests/footprint/run.sh                       # RAM/image size vs targets
```

## 4. Release

Tag the commit, build the image, then follow `CUTOVER.md` (backup first, rollback = previous
image tag).
