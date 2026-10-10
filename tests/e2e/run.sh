#!/usr/bin/env bash
# Run the upstream ExcaliDash Playwright suite (unmodified) against the Rust backend.
#   tests/e2e/run.sh [anonymous|authenticated|all] [playwright args...]
# Layout mirrors upstream's own e2e setup (playwright.config.ts webServer): the
# frontend runs as the Vite dev server on :26767 (proxying /api and /socket.io),
# the backend listens on :28000. Dev-only test hooks (window.__EXCALIDASH_*__)
# only exist in that dev build, so the production bundle can't run the suite.
#   BASELINE=1   same suite against the upstream Node 0.6.5 backend
#   BUNDLE=1     production bundle served by the Rust image itself (smoke mode)
set -euo pipefail
repo="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
upstream="$repo/upstream-ref/excalidash"
image="${RUST_IMAGE:-excalidash-rs:dev}"
pw_image="mcr.microsoft.com/playwright:v1.57.0-noble"
mode="${1:-all}"; shift || true
fe_port=26767; be_port=28000
results="$repo/.tmp/e2e"; mkdir -p "$results"

pw() {
  docker run --rm --network host --ipc=host --user "$(id -u):$(id -g)" \
    -e HOME=/tmp -e npm_config_cache=/tmp/.npm -v "$upstream:/work" -w /work/e2e "$@"
}
[ -d "$upstream/e2e/node_modules/@playwright/test" ] || pw "$pw_image" npm ci --no-audit --no-fund
[ -d "$upstream/backend/src/generated/client" ] || pw -w /work/backend "$pw_image" sh -c 'npm ci --no-audit --no-fund && npx prisma generate'
[ "${BUNDLE:-}" = 1 ] || [ -d "$upstream/frontend/node_modules/vite" ] || pw -w /work/frontend "$pw_image" npm ci --no-audit --no-fund

common_env=(-e NODE_ENV=development -e CSRF_MAX_REQUESTS=100000 -e RATE_LIMIT_MAX_REQUESTS=100000
            -e CSRF_SECRET=e2e-csrf-secret -e JWT_SECRET=e2e-jwt-secret-that-is-long-enough-for-tests
            -e UPDATE_CHECK_OUTBOUND=false -e S3_BUCKET=)

stop_all() { docker rm -f exrs-e2e-backend exrs-e2e-vite >/dev/null 2>&1 || true; }

start_backend() { # $1 auth mode, $2 data dir, $3 db file
  stop_all
  local fe_url="http://127.0.0.1:$fe_port" port_map="127.0.0.1:$be_port:8080" extra=(-e FRONTEND_DIST_DIR=none)
  if [ "${BUNDLE:-}" = 1 ]; then port_map="127.0.0.1:$fe_port:8080"; extra=(); fi
  if [ "${BASELINE:-}" = 1 ]; then
    docker run -d --name exrs-e2e-backend --init --user "$(id -u):$(id -g)" -p "127.0.0.1:$be_port:8000" \
      --tmpfs /app/uploads:mode=1777 "${common_env[@]}" -e AUTH_MODE="$1" -e FRONTEND_URL="$fe_url" \
      -e DATABASE_PROVIDER=sqlite -e DATABASE_URL="file:/app/prisma/$3" -v "$2:/app/prisma" \
      zimengxiong/excalidash-backend:0.6.5 >/dev/null
  else
    docker run -d --name exrs-e2e-backend --user "$(id -u):$(id -g)" -p "$port_map" \
      --tmpfs /app/uploads:mode=1777 --tmpfs /app/backups:mode=1777 "${common_env[@]}" "${extra[@]}" \
      -e AUTH_MODE="$1" -e FRONTEND_URL="$fe_url" -e DATABASE_URL="file:/app/prisma/$3" -v "$2:/app/prisma" \
      "$image" >/dev/null
  fi
  local health="http://127.0.0.1:$be_port/health"; [ "${BUNDLE:-}" = 1 ] && health="http://127.0.0.1:$fe_port/api/health"
  for _ in $(seq 1 120); do curl -sf -o /dev/null "$health" && break; sleep 1; done
  if [ "${BUNDLE:-}" != 1 ]; then
    docker run -d --name exrs-e2e-vite --network host --user "$(id -u):$(id -g)" -e HOME=/tmp \
      -e VITE_DEV_BACKEND_URL="http://127.0.0.1:$be_port" -v "$upstream:/work" -w /work/frontend \
      "$pw_image" npx vite --host 127.0.0.1 --port "$fe_port" --strictPort >/dev/null
    for _ in $(seq 1 120); do curl -sf -o /dev/null "http://127.0.0.1:$fe_port/" && break; sleep 1; done
  fi
}

run_suite() { # $1 anonymous|authenticated
  local auth=false data tag="$1" api="http://127.0.0.1:$be_port"
  [ "${BASELINE:-}" = 1 ] && tag="$1-baseline"
  [ "${BUNDLE:-}" = 1 ] && { tag="$1-bundle"; api="http://127.0.0.1:$fe_port/api"; }
  [ "$1" = authenticated ] && auth=true
  if [ "$auth" = true ]; then
    data="$upstream/backend/prisma"; rm -f "$data"/auth-e2e.db*; start_backend local "$data" auth-e2e.db
  else
    data="$(mktemp -d)"; start_backend disabled "$data" e2e-test.db
  fi
  set +e
  pw -e CI=true -e NO_SERVER=true -e E2E_AUTH=$auth -e BASE_URL="http://127.0.0.1:$fe_port" -e API_URL="$api" \
     -e PLAYWRIGHT_OUTPUT_DIR="/work/e2e/test-results/$tag" -e PLAYWRIGHT_REPORT_DIR="/work/e2e/playwright-report/$tag" \
     "$pw_image" npx playwright test "${@:2}" 2>&1 | tee "$results/$tag.log"
  local rc=${PIPESTATUS[0]}
  set -e
  docker logs exrs-e2e-backend > "$results/$tag.server.log" 2>&1 || true
  stop_all
  if [ "$auth" = true ]; then rm -f "$data"/auth-e2e.db*; else rm -rf "$data"; fi
  return $rc
}

status=0
case "$mode" in
  anonymous|authenticated) run_suite "$mode" "$@" || status=$? ;;
  all) run_suite anonymous "$@" || status=$?; run_suite authenticated "$@" || status=$? ;;
esac
exit $status
