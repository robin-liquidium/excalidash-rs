# Switching an upstream ExcaliDash install to excalidash-rs

excalidash-rs replaces upstream's **two** containers (Node backend + nginx frontend) with one.
It opens the same data volume in place: same SQLite database, same Prisma migrations and
bookkeeping, same password hashes, JWT sessions, refresh tokens and API keys. Upstream can
open the volume again afterwards, so switching back is just restarting the old stack.

## 0. Before you start

- Build the image: `docker build -t excalidash-rs:<tag> .` (add `--build-arg FEATURES=postgres`
  for PostgreSQL installs).
- Use the **same** `JWT_SECRET`, `CSRF_SECRET` and `API_KEY_HASH_PEPPER` as your upstream
  backend, or sessions and API keys stop working. If you never set them, upstream's entrypoint
  persisted generated ones as `.jwt_secret` / `.csrf_secret` in the data volume; the Rust image
  reads those the same way.
- The Rust image listens on **8080** (like upstream's frontend container) and runs as uid
  **1001** (like upstream's backend), so existing volumes stay writable.

## 1. Back up

Stop the upstream backend so the database is quiescent, then copy the data volume:

```sh
docker compose stop backend
docker run --rm -v excalidash_data:/src:ro -v "$PWD/excalidash-backup":/dst alpine cp -a /src/. /dst/
```

## 2. Swap

Replace the two services with one, keeping your volumes, secrets and settings:

```yaml
services:
  app:
    image: excalidash-rs:<tag>
    restart: unless-stopped
    environment:
      DATABASE_URL: file:/app/prisma/dev.db
      NODE_ENV: production
      AUTH_MODE: local
      FRONTEND_URL: https://draw.example.com
      TRUST_PROXY: "1"                 # when behind a reverse proxy / tunnel
      JWT_SECRET: ${JWT_SECRET:?}
      CSRF_SECRET: ${CSRF_SECRET:?}
      API_KEY_HASH_PEPPER: ${API_KEY_HASH_PEPPER:?}
      BACKUP_SCHEDULE: "0 0 4 * * *"   # optional, as upstream
    volumes:
      - excalidash_data:/app/prisma
      - excalidash_backups:/app/backups
    ports:
      - "127.0.0.1:6767:8080"          # wherever your frontend was published
volumes:
  excalidash_data:
    external: true
  excalidash_backups:
    external: true
```

```sh
docker compose up -d --remove-orphans     # removes the old backend/frontend containers
docker compose logs --tail=40 app         # expect "No pending migrations to apply." and "Server running on port 8080"
curl -s http://127.0.0.1:6767/api/health  # {"status":"ok","database":"ok"}
```

## 3. Check

- Existing sessions stay logged in; drawings, collections, history and images load.
- Two browser tabs on one drawing show live cursors and edits (Socket.IO).
- `docker stats --no-stream`: about 10 MB.

## 4. Switching back

Restore the previous compose file and `docker compose up -d --remove-orphans`. Upstream reads
everything excalidash-rs writes (verified by `tests/realdata/run.sh`). If data looks wrong,
stop the app and restore the step-1 copy into the volume first.
