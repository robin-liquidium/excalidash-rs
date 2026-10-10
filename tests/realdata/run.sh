#!/usr/bin/env bash
# Real-data verification on COPIES of the live ExcaliDash volume (never the original):
#  1. copy excalidash_data (read-only mount) into two throwaway volumes
#  2. run upstream Node 0.6.5 on copy A and the Rust image on copy B (live secrets)
#  3. read every account/drawing/collection/snapshot/file through both and diff
#  4. write through Rust on copy B, then start upstream Node on copy B (switch-back check)
# Secrets come from agent-secrets and are never printed.
set -euo pipefail
here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
image="${RUST_IMAGE:-excalidash-rs:dev}"
work="$(mktemp -d)"
vols=(exrs-real-a exrs-real-b)
cleanup() {
  docker rm -f exrs-real-node exrs-real-rust exrs-real-node-b >/dev/null 2>&1 || true
  docker volume rm "${vols[@]}" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT
cleanup; work="$(mktemp -d)"

for v in "${vols[@]}"; do
  docker volume create "$v" >/dev/null
  docker run --rm -v excalidash_data:/src:ro -v "$v":/dst alpine sh -c 'cp -a /src/. /dst/'
done
# Host-side read-only copy of the DB for listing ids (not secret data).
docker run --rm -v exrs-real-a:/src:ro -v "$work":/dst alpine sh -c 'cp /src/dev.db* /dst/ && chmod 644 /dst/*'

wait_up() { for _ in $(seq 1 90); do curl -sf -o /dev/null -H 'X-Forwarded-Proto: https' "$1" && return 0; sleep 1; done; docker logs "$2" | tail -40; return 1; }

secrets_env=(--env EXCALIDASH_JWT_SECRET=tools/excalidash/jwt-secret
             --env EXCALIDASH_CSRF_SECRET=tools/excalidash/csrf-secret
             --env EXCALIDASH_API_KEY_HASH_PEPPER=tools/excalidash/api-key-hash-pepper)

"$HOME/.local/bin/secrets" run "${secrets_env[@]}" -- bash -s "$image" "$work" "$here" <<'INNER'
set -euo pipefail
image="$1"; work="$2"; here="$3"
common=(-e NODE_ENV=production -e AUTH_MODE=local -e TRUST_PROXY=1 -e FRONTEND_URL=https://excali.robin.build
        -e UPDATE_CHECK_OUTBOUND=false -e JWT_SECRET -e CSRF_SECRET -e API_KEY_HASH_PEPPER
        -e RATE_LIMIT_MAX_REQUESTS=100000 -e CSRF_MAX_REQUESTS=100000)
export JWT_SECRET="$EXCALIDASH_JWT_SECRET" CSRF_SECRET="$EXCALIDASH_CSRF_SECRET" API_KEY_HASH_PEPPER="$EXCALIDASH_API_KEY_HASH_PEPPER"
wait_up() { for _ in $(seq 1 90); do curl -sf -o /dev/null -H 'X-Forwarded-Proto: https' "$1" && return 0; sleep 1; done; docker logs "$2" | tail -40; return 1; }

docker run -d --name exrs-real-node --init "${common[@]}" -e DATABASE_PROVIDER=sqlite -e DATABASE_URL=file:/app/prisma/dev.db \
  -v exrs-real-a:/app/prisma -p 127.0.0.1:16831:8000 zimengxiong/excalidash-backend:0.6.5 >/dev/null
docker run -d --name exrs-real-rust "${common[@]}" -v exrs-real-b:/app/prisma -p 127.0.0.1:16832:8080 "$image" >/dev/null
wait_up http://127.0.0.1:16831/health exrs-real-node
wait_up http://127.0.0.1:16832/api/health exrs-real-rust

python3 -I "$here/verify.py" read "$work/dev.db" http://127.0.0.1:16831 http://127.0.0.1:16832/api
python3 -I "$here/verify.py" write "$work/dev.db" http://127.0.0.1:16832/api

# Switch-back: upstream Node on the volume Rust has written to.
docker rm -f exrs-real-rust >/dev/null
docker run -d --name exrs-real-node-b --init "${common[@]}" -e DATABASE_PROVIDER=sqlite -e DATABASE_URL=file:/app/prisma/dev.db \
  -v exrs-real-b:/app/prisma -p 127.0.0.1:16833:8000 zimengxiong/excalidash-backend:0.6.5 >/dev/null
wait_up http://127.0.0.1:16833/health exrs-real-node-b
docker logs exrs-real-node-b 2>&1 | grep -E "migration|Migration" | tail -3 || true
python3 -I "$here/verify.py" readback "$work/dev.db" http://127.0.0.1:16833
INNER
