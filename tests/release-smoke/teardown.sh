#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
docker compose -p vulnforge-e2e -f "$HERE/compose.yml" down -v --remove-orphans
