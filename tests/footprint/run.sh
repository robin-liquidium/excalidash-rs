#!/usr/bin/env bash
# Measure image size and RAM (idle / 2-user collab load) for the Rust image and,
# with --compare, the upstream Node stack. Fresh throwaway containers only.
set -euo pipefail
here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
image="${RUST_IMAGE:-excalidash-rs:dev}"
secs="${LOAD_SECONDS:-60}"
env=(-e NODE_ENV=production -e AUTH_MODE=local -e TRUST_PROXY=1 -e UPDATE_CHECK_OUTBOUND=false
     -e JWT_SECRET=footprint-jwt-secret-0123456789abcdef0123456789 -e CSRF_SECRET=footprint-csrf
     -e API_KEY_HASH_PEPPER=footprint-pepper)
cleanup() { docker rm -f exrs-fp-rust exrs-fp-node-backend exrs-fp-node-frontend >/dev/null 2>&1 || true; docker network rm exrs-fp >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup
wait_up() { for _ in $(seq 1 90); do curl -sf -o /dev/null "$1" && return 0; sleep 1; done; return 1; }

echo "== image sizes"
docker image inspect -f '{{.Size}}' "$image" | awk -v i="$image" '{printf "%s: %.1f MB\n", i, $1/1e6}'

echo "== rust ($image)"
docker run -d --name exrs-fp-rust -p 127.0.0.1:16812:8080 "${env[@]}" -e FRONTEND_URL=http://127.0.0.1:16812 "$image" >/dev/null
wait_up http://127.0.0.1:16812/api/health
python3 -I "$here/measure.py" http://127.0.0.1:16812 exrs-fp-rust "$secs" | tee "$here/../../.tmp/footprint-rust.log"

if [ "${1:-}" = "--compare" ]; then
  echo "== upstream node stack (0.6.5)"
  for i in zimengxiong/excalidash-backend:0.6.5 zimengxiong/excalidash-frontend:0.6.5; do
    docker image inspect -f '{{.Size}}' "$i" | awk -v i="$i" '{printf "%s: %.1f MB\n", i, $1/1e6}'
  done
  docker network create exrs-fp >/dev/null
  docker run -d --name exrs-fp-node-backend --network exrs-fp --network-alias backend --init "${env[@]}" \
    -e DATABASE_PROVIDER=sqlite -e DATABASE_URL=file:/app/prisma/dev.db -e FRONTEND_URL=http://127.0.0.1:16811 \
    zimengxiong/excalidash-backend:0.6.5 >/dev/null
  docker run -d --name exrs-fp-node-frontend --network exrs-fp -p 127.0.0.1:16811:8080 zimengxiong/excalidash-frontend:0.6.5 >/dev/null
  wait_up http://127.0.0.1:16811/api/health
  python3 -I "$here/measure.py" http://127.0.0.1:16811 exrs-fp-node-backend,exrs-fp-node-frontend "$secs" | tee "$here/../../.tmp/footprint-node.log"
fi
