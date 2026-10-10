#!/usr/bin/env bash
# Run the upstream ExcaliDash Playwright suite (unmodified) against the Rust image,
# which serves the bundled upstream frontend and the API on one port.
#   tests/e2e/run.sh [anonymous|authenticated|all] [extra playwright args...]
set -euo pipefail
repo="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
upstream="$repo/upstream-ref/excalidash"
image="${RUST_IMAGE:-excalidash-rs:dev}"
pw_image="mcr.microsoft.com/playwright:v1.57.0-noble"
mode="${1:-all}"; shift || true
port=26767
results="$repo/.tmp/e2e"
mkdir -p "$results"

pw() {
  docker run --rm --network host --ipc=host --user "$(id -u):$(id -g)" \
    -e HOME=/tmp -e npm_config_cache=/tmp/.npm \
    -v "$upstream:/work" -w /work/e2e "$@"
}

# One-time deps: e2e runner + upstream backend (bcrypt + Prisma client used by the auth global setup).
if [ ! -d "$upstream/e2e/node_modules/@playwright/test" ]; then
  pw "$pw_image" npm ci --no-audit --no-fund
fi
if [ ! -d "$upstream/backend/src/generated/client" ]; then
  pw -w /work/backend "$pw_image" sh -c 'npm ci --no-audit --no-fund && npx prisma generate'
fi

start_rust() { # $1 = auth mode, $2 = data dir (bind mount), $3 = db file name
  docker rm -f exrs-e2e-rust >/dev/null 2>&1 || true
  docker run -d --name exrs-e2e-rust --user "$(id -u):$(id -g)" -p 127.0.0.1:$port:8080 \
    -e NODE_ENV=development -e AUTH_MODE="$1" \
    -e FRONTEND_URL="http://127.0.0.1:$port" \
    -e CSRF_MAX_REQUESTS=100000 -e RATE_LIMIT_MAX_REQUESTS=100000 \
    -e CSRF_SECRET=e2e-csrf-secret -e JWT_SECRET=e2e-jwt-secret-that-is-long-enough-for-tests \
    -e UPDATE_CHECK_OUTBOUND=false -e DATABASE_URL="file:/app/prisma/$3" \
    -v "$2:/app/prisma" "$image" >/dev/null
  for _ in $(seq 1 60); do curl -sf -o /dev/null "http://127.0.0.1:$port/api/health" && return 0; sleep 1; done
  docker logs exrs-e2e-rust; return 1
}

run_suite() { # $1 = anonymous|authenticated
  local auth=false data
  [ "$1" = authenticated ] && auth=true
  if [ "$auth" = true ]; then
    data="$upstream/backend/prisma"; rm -f "$data"/auth-e2e.db*
    start_rust local "$data" auth-e2e.db
  else
    data="$(mktemp -d)"; start_rust disabled "$data" e2e-test.db
  fi
  set +e
  pw -e CI=true -e NO_SERVER=true -e E2E_AUTH=$auth \
     -e BASE_URL="http://127.0.0.1:$port" -e API_URL="http://127.0.0.1:$port/api" \
     -e PLAYWRIGHT_OUTPUT_DIR="/work/e2e/test-results/$1" -e PLAYWRIGHT_REPORT_DIR="/work/e2e/playwright-report/$1" \
     "$pw_image" npx playwright test "${@:2}" 2>&1 | tee "$results/$1.log"
  local rc=${PIPESTATUS[0]}
  set -e
  docker logs exrs-e2e-rust > "$results/$1.server.log" 2>&1 || true
  docker rm -f exrs-e2e-rust >/dev/null 2>&1 || true
  [ "$auth" = true ] && rm -f "$data"/auth-e2e.db* || rm -rf "$data"
  return $rc
}

status=0
case "$mode" in
  anonymous|authenticated) run_suite "$mode" "$@" || status=$? ;;
  all) run_suite anonymous "$@" || status=$?; run_suite authenticated "$@" || status=$? ;;
esac
exit $status
