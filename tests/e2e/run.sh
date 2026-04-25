#!/usr/bin/env bash
# End-to-end release gate for VulnForge.
# See tests/e2e/README.md for details.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
COMPOSE_FILE="$HERE/compose.yml"
PROJECT="vulnforge-e2e"
IMAGE="vulnforge:e2e"
APP_PORT=8787

dc() { docker compose -p "$PROJECT" -f "$COMPOSE_FILE" "$@"; }

teardown() {
  local rc=$?
  if [[ "${E2E_KEEP:-0}" == "1" && $rc -ne 0 ]]; then
    echo
    echo "[e2e] E2E_KEEP=1 + failure — leaving stack up. bash $HERE/teardown.sh when done."
    exit $rc
  fi
  echo
  echo "[e2e] Tearing down..."
  dc down -v --remove-orphans >/dev/null 2>&1 || true
  exit $rc
}
trap teardown EXIT

echo "[e2e] Repo: $REPO_ROOT"
echo "[e2e] Project: $PROJECT"
echo

dc down -v --remove-orphans >/dev/null 2>&1 || true

if [[ "${E2E_NO_BUILD:-0}" != "1" ]]; then
  echo "[e2e] Building $IMAGE from $REPO_ROOT ..."
  docker build -t "$IMAGE" "$REPO_ROOT" >/dev/null
  echo "[e2e] Build OK"
fi

echo "[e2e] Bringing up docker-proxy + app..."
dc up -d docker-proxy app

echo "[e2e] Waiting for app to report healthy (up to 90s)..."
deadline=$(( $(date +%s) + 90 ))
while true; do
  state=$(docker inspect --format '{{.State.Health.Status}}' "${PROJECT}-app" 2>/dev/null || echo "unknown")
  if [[ "$state" == "healthy" ]]; then
    echo "[e2e] Healthy."
    break
  fi
  if (( $(date +%s) > deadline )); then
    echo "[e2e] ✗ Timeout waiting for healthy. state=$state"
    docker logs --tail 60 "${PROJECT}-app" 2>&1 || true
    exit 1
  fi
  sleep 2
done

# Migration sanity check.
expected=$(ls "$REPO_ROOT/backend/app/migrations/"[0-9]*.py 2>/dev/null | wc -l)
echo "[e2e] Expecting $expected migrations applied."

count=$(docker exec "${PROJECT}-app" sh -c "python -c \"import sqlite3; print(sqlite3.connect('/data/vulnforge.db').execute('SELECT COUNT(*) FROM schema_migrations').fetchone()[0])\"" 2>/dev/null | tr -d '[:space:]' || echo "0")
echo "[e2e]   applied: $count"

if [[ "$count" != "$expected" ]]; then
  echo "[e2e] ✗ Migration count $count != expected $expected"
  docker logs --tail 80 "${PROJECT}-app" 2>&1 | grep -iE "migration|error|fail" || true
  exit 1
fi
echo "[e2e] ✓ All migrations applied."

echo
echo "[e2e] === Smoke test ==="
dc run --rm smoke "http://app:${APP_PORT}"

echo
echo "[e2e] ✓ All checks passed."
