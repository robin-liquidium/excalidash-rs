#!/usr/bin/env bash
# Real-data verification on COPIES of a live ExcaliDash data volume (never the original):
#  1. copy $SOURCE_VOLUME (default excalidash_data, read-only mount) into throwaway volume A
#  2. seed with upstream Node 0.6.5 on A: an image (DrawingFile bytes), history snapshots of
#     the existing real drawing, an API key and a library item, so files/history/keys exist
#  3. clone A into B; run upstream Node on A and the Rust image on B (live secrets)
#  4. read every account/drawing/collection/snapshot/file/API-key view through both and diff
#  5. write through Rust on B, then start upstream Node on B (switch-back check)
# Needs the instance's secrets and URL in the environment (never printed):
#   JWT_SECRET, CSRF_SECRET, API_KEY_HASH_PEPPER, FRONTEND_URL (e.g. https://draw.example.com)
set -euo pipefail
here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
image="${RUST_IMAGE:-excalidash-rs:dev}"
source_volume="${SOURCE_VOLUME:-excalidash_data}"
: "${JWT_SECRET:?}" "${CSRF_SECRET:?}" "${API_KEY_HASH_PEPPER:?}" "${FRONTEND_URL:?}"
export JWT_SECRET CSRF_SECRET API_KEY_HASH_PEPPER FRONTEND_URL
work="$(mktemp -d)"
vols=(exrs-real-a exrs-real-b)
cleanup() {
  docker rm -f exrs-real-node exrs-real-rust exrs-real-node-b exrs-real-seed >/dev/null 2>&1 || true
  docker volume rm "${vols[@]}" >/dev/null 2>&1 || true
  rm -rf "$work" /tmp/exrs-realdata-state.json
}
trap cleanup EXIT
docker rm -f exrs-real-node exrs-real-rust exrs-real-node-b exrs-real-seed >/dev/null 2>&1 || true
docker volume rm "${vols[@]}" >/dev/null 2>&1 || true

docker volume create exrs-real-a >/dev/null
docker run --rm -v "$source_volume":/src:ro -v exrs-real-a:/dst alpine sh -c 'cp -a /src/. /dst/'

bash -s "$image" "$work" "$here" <<'INNER'
set -euo pipefail
image="$1"; work="$2"; here="$3"
common=(-e NODE_ENV=production -e AUTH_MODE=local -e TRUST_PROXY=1 -e FRONTEND_URL
        -e UPDATE_CHECK_OUTBOUND=false -e JWT_SECRET -e CSRF_SECRET -e API_KEY_HASH_PEPPER
        -e RATE_LIMIT_MAX_REQUESTS=100000 -e CSRF_MAX_REQUESTS=100000)
node_on() { # $1 name, $2 volume, $3 host port
  docker run -d --name "$1" --init "${common[@]}" -e DATABASE_PROVIDER=sqlite -e DATABASE_URL=file:/app/prisma/dev.db \
    -v "$2":/app/prisma -p "127.0.0.1:$3:8000" zimengxiong/excalidash-backend:0.6.5 >/dev/null
}
wait_up() { for _ in $(seq 1 90); do curl -sf -o /dev/null -H 'X-Forwarded-Proto: https' "$1" && return 0; sleep 1; done; docker logs "$2" | tail -40; return 1; }
snapshot_db() { docker run --rm -v "$1":/src:ro -v "$work":/dst alpine sh -c 'cp /src/dev.db* /dst/ && chmod 644 /dst/*'; }

# 2. seed through upstream Node (so the data is exactly what Node writes)
node_on exrs-real-seed exrs-real-a 16830
wait_up http://127.0.0.1:16830/health exrs-real-seed
snapshot_db exrs-real-a
python3 -I "$here/verify.py" seed "$work/dev.db" http://127.0.0.1:16830
docker stop exrs-real-seed >/dev/null; docker rm exrs-real-seed >/dev/null

# 3. clone A -> B
docker volume create exrs-real-b >/dev/null
docker run --rm -v exrs-real-a:/src:ro -v exrs-real-b:/dst alpine sh -c 'cp -a /src/. /dst/'
snapshot_db exrs-real-a

node_on exrs-real-node exrs-real-a 16831
docker run -d --name exrs-real-rust "${common[@]}" -v exrs-real-b:/app/prisma -p 127.0.0.1:16832:8080 "$image" >/dev/null
wait_up http://127.0.0.1:16831/health exrs-real-node
wait_up http://127.0.0.1:16832/api/health exrs-real-rust

# 4. compare
python3 -I "$here/verify.py" read "$work/dev.db" http://127.0.0.1:16831 http://127.0.0.1:16832/api
# 5. Rust writes, upstream reads back
python3 -I "$here/verify.py" write "$work/dev.db" http://127.0.0.1:16832/api
docker rm -f exrs-real-rust >/dev/null
node_on exrs-real-node-b exrs-real-b 16833
wait_up http://127.0.0.1:16833/health exrs-real-node-b
docker logs exrs-real-node-b 2>&1 | grep -E "pending migrations|Applying" | tail -2 || true
python3 -I "$here/verify.py" readback "$work/dev.db" http://127.0.0.1:16833
INNER
