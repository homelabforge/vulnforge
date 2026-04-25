# VulnForge E2E

Hard release gate. Builds the production image, brings up a docker-socket-proxy
+ a SQLite-backed VulnForge instance, and runs an HTTP smoke test.

## Run

```bash
bash tests/e2e/run.sh
```

Takes ~90 seconds on a warm Docker cache. Always tears down on exit.

## What it covers

- All migrations apply cleanly on a fresh SQLite DB.
- Health endpoint responds.
- Auth setup (with bootstrap token) → login → authenticated GET round-trip.

VulnForge's image is SQLite-only (no `asyncpg`/`psycopg2` in the production
deps), so the gate doesn't exercise PostgreSQL. The bootstrap token is
hardcoded as `e2e-bootstrap-token` in both `compose.yml` and `smoke.py`.

## Knobs

- `E2E_KEEP=1` — on failure, leave the stack up so you can poke at it.
  Run `bash tests/e2e/teardown.sh` when done.
- `E2E_NO_BUILD=1` — reuse the existing `vulnforge:e2e` image.
