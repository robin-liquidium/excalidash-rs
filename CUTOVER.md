# Cutover plan: live ExcaliDash (Node 0.6.5) → excalidash-rs

**Status: proposal. Do not execute without Robin's approval.**

Live today: `~/workspace/docker/excalidash/compose.yaml` (project `excalidash`), started via
`~/workspace/scripts/excalidash.sh` which injects `tools/excalidash/{jwt-secret,csrf-secret,api-key-hash-pepper}`.
`cloudflared-excali` → `127.0.0.1:6767` → nginx frontend → Node backend. Data in volumes
`excalidash_data` (SQLite) and `excalidash_backups`.

The Rust image replaces **both** containers and listens on container port 8080, so the
host port mapping, tunnel, DNS and Access app stay exactly as they are.

## 0. Preconditions

- All verification gates green on the image tag being deployed (`README.md` → Verification).
- Build and tag the image locally on BMAX: `docker build -t excalidash-rs:64bca37 ~/code/excalidash-rs`
  (no registry needed; the tag pins the exact build).

## 1. Backup (before touching anything)

```sh
ts=$(date -u +%Y%m%dT%H%M%SZ)
mkdir -p ~/workspace/.tmp/excalidash-cutover/$ts
scripts/excalidash.sh stop backend            # quiesce writes (frontend shows errors for ~1 min)
docker run --rm -v excalidash_data:/src:ro -v ~/workspace/.tmp/excalidash-cutover/$ts:/dst alpine \
  sh -c 'cp -a /src/. /dst/ && ls -la /dst'
docker run --rm -v excalidash_data:/src -v ~/workspace/.tmp/excalidash-cutover/$ts:/dst alpine \
  sh -c 'apk add -q sqlite && sqlite3 /dst/dev.db "PRAGMA integrity_check; PRAGMA wal_checkpoint(TRUNCATE);"'
```

The copy includes `dev.db`, `-wal`, `-shm` and the persisted secret files. The volume itself is
not modified by the Rust image other than normal application writes (no schema changes: it
uses the same Prisma migrations and bookkeeping).

## 2. Swap

Replace `docker/excalidash/compose.yaml` with (keeping the same volume names, secrets and env):

```yaml
# ExcaliDash at https://excali.robin.build (runbook: docs/operations/excalidash.md).
# Rust backend + bundled upstream 0.6.5 frontend in one container (~5 MB RAM idle).
services:
  app:
    image: excalidash-rs:64bca37
    restart: unless-stopped
    environment:
      DATABASE_URL: file:/app/prisma/dev.db
      NODE_ENV: production
      AUTH_MODE: local
      FRONTEND_URL: https://excali.robin.build
      # cloudflared -> app (the bundled nginx emulation adds the proxy hop internally)
      TRUST_PROXY: "1"
      JWT_SECRET: ${EXCALIDASH_JWT_SECRET:?}
      CSRF_SECRET: ${EXCALIDASH_CSRF_SECRET:?}
      API_KEY_HASH_PEPPER: ${EXCALIDASH_API_KEY_HASH_PEPPER:?}
      BACKUP_SCHEDULE: "0 0 4 * * *"
      BACKUP_DIR: /app/backups
      BACKUP_RETENTION_DAYS: "14"
    volumes:
      - data:/app/prisma
      - backups:/app/backups
    ports:
      - "127.0.0.1:6767:8080"
volumes:
  data:
    name: excalidash_data
  backups:
    name: excalidash_backups
```

Then:

```sh
cp docker/excalidash/compose.yaml docker/excalidash/compose.node.yaml   # rollback copy
# write the new compose.yaml (above)
scripts/excalidash.sh up -d --remove-orphans   # removes the old backend/frontend containers
scripts/excalidash.sh logs --tail=60 app       # expect: "No pending migrations", "Server running on port 8080"
curl -s http://127.0.0.1:6767/api/health       # {"status":"ok","database":"ok"}
```

`scripts/excalidash.sh` needs no change (same secret names). Both images run as uid 1001, so the
volume ownership is already correct.

## 3. Post-checks (5 minutes)

- Open https://excali.robin.build: existing session still logged in (same JWT secret), drawings
  list, open a drawing, edit, reload, history panel, image renders.
- Two tabs on one drawing: live cursors/edits appear (Socket.IO).
- `docker stats --no-stream` → app ≈ 5–15 MB.
- Next morning: `docker run --rm -v excalidash_backups:/b alpine ls -la /b` shows the 04:00 backup.

## 4. Rollback (any time, ~1 minute)

```sh
scripts/excalidash.sh down
cp docker/excalidash/compose.node.yaml docker/excalidash/compose.yaml
scripts/excalidash.sh up -d
```

Upstream reads everything the Rust build writes (verified by `tests/realdata/run.sh`: Node 0.6.5
started on a volume the Rust build had written to). If anything looks wrong with data, stop the
app and restore the step-1 copy into `excalidash_data` before starting the Node stack.

## 5. Afterwards

- Update `~/workspace/docs/operations/excalidash.md` (single container, image tag, memory) and
  remove `compose.node.yaml` after a week without issues.
- Delete the step-1 backup copy only after the first successful scheduled backup.
