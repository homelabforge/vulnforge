"""Export OpenAPI schema from FastAPI app for frontend type generation.

Usage: PYTHONPATH=. python3 scripts/export_openapi.py <output_path>

Sets dummy env vars to avoid side effects from /data/ or Docker socket.
"""

import json
import logging
import os
import sys
import tempfile

# Suppress app startup logs but preserve errors
logging.disable(logging.WARNING)

# Dummy env vars so the app can import without real infrastructure
_tmp = tempfile.mkdtemp(prefix="vulnforge-openapi-")
os.environ.setdefault("DATABASE_URL", f"sqlite+aiosqlite:///{_tmp}/openapi.db")
os.environ.setdefault("DOCKER_SOCKET_PROXY", "unix:///dev/null")
os.environ.setdefault("STRICT_MIGRATIONS", "false")

try:
    from app.main import app

    schema = app.openapi()
except Exception as e:
    print(f"ERROR: Failed to generate OpenAPI schema: {e}", file=sys.stderr)
    sys.exit(1)

# Pin info.version to a constant so the committed openapi.json doesn't drift
# every time pyproject.toml is bumped. The runtime FastAPI app still serves
# the real version via app.openapi(); this strip only affects the file fed
# into openapi-typescript, which doesn't read info.version. Without this,
# every release fails the api-types-freshness CI gate until someone
# remembers to regenerate.
schema.setdefault("info", {})["version"] = "0.0.0"

output = json.dumps(schema, indent=2, sort_keys=True) + "\n"

if len(sys.argv) < 2:
    print(output, end="")
    sys.exit(0)

output_path = os.path.abspath(sys.argv[1])
output_dir = os.path.dirname(output_path)

tmp_path: str | None = None
try:
    fd, tmp_path = tempfile.mkstemp(dir=output_dir, suffix=".json.tmp")
    with os.fdopen(fd, "w") as f:
        f.write(output)
    os.replace(tmp_path, output_path)
except Exception as e:
    if tmp_path is not None and os.path.exists(tmp_path):
        os.unlink(tmp_path)
    print(f"ERROR: Failed to write {output_path}: {e}", file=sys.stderr)
    sys.exit(1)
