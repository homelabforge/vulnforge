#!/usr/bin/env bash
# Security tripwire: VulnForge is single-user — every route file with
# mutation endpoints (POST/PUT/DELETE/PATCH) MUST use Depends(require_admin).
# Exempt files: user_auth.py (login/setup), system.py, activity.py,
# widget.py (read-only public endpoints only).
set -euo pipefail

FOUND=0
for f in backend/app/routes/*.py; do
  basename=$(basename "$f")
  case "$basename" in
    user_auth.py|system.py|activity.py|widget.py|__init__.py) continue ;;
  esac
  if grep -qP '@router\.(post|put|delete|patch)\(' "$f"; then
    if ! grep -q 'require_admin' "$f"; then
      echo "ERROR: $f has mutation endpoints but does not use require_admin"
      FOUND=1
    fi
  fi
done
exit $FOUND
