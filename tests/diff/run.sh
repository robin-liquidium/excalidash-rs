#!/usr/bin/env bash
# Start fresh Node + Rust stacks, run the differential scenario, tear down.
set -euo pipefail
here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
compose=(docker compose -f "$here/compose.yaml")
# DIFF_DB=postgres runs both stacks on PostgreSQL (RUST_IMAGE needs the postgres feature).
if [ "${DIFF_DB:-sqlite}" = postgres ]; then compose+=(-f "$here/compose.postgres.yaml"); fi
"${compose[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
"${compose[@]}" up -d >/dev/null
trap '"${compose[@]}" down -v --remove-orphans >/dev/null 2>&1 || true' EXIT
for url in http://127.0.0.1:16801/api/health http://127.0.0.1:16802/api/health; do
  for _ in $(seq 1 120); do curl -sf -o /dev/null "$url" && break; sleep 1; done
done
python3 -I "$here/diff.py" "$@"
