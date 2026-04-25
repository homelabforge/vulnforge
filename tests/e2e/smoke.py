"""End-to-end smoke test for VulnForge.

Verifies the high-value paths that unit tests can't catch:

- Health endpoint responds.
- Auth setup flow: POST /api/v1/user-auth/setup creates first admin
  (bootstrap token comes from VULNFORGE_BOOTSTRAP_TOKEN env on the app
  container; smoke.py uses the same fixed value).
- Login flow: POST /api/v1/user-auth/login returns a token.
- Authenticated GET /api/v1/scans/queue/status validates the auth → DB →
  JSON path end-to-end without needing Docker access or any prior data.

Usage:
    python smoke.py http://app:8787
"""

from __future__ import annotations

import sys

import httpx

BOOTSTRAP_TOKEN = "e2e-bootstrap-token"  # must match compose.yml


def banner(msg: str) -> None:
    print(f"\n=== {msg} ===")


def main(base: str) -> int:
    fails = 0
    with httpx.Client(base_url=base, timeout=20.0, follow_redirects=True) as c:
        banner("Health check")
        r = c.get("/health")
        print(f"  GET /health -> {r.status_code}")
        if r.status_code != 200:
            print("  body:", r.text[:200])
            return 1

        banner("Setup admin (first-time)")
        r = c.post(
            "/api/v1/user-auth/setup",
            json={
                "bootstrap_token": BOOTSTRAP_TOKEN,
                "username": "smoke",
                "email": "smoke@example.com",
                "password": "SmokePass123!",
                "full_name": "Smoke Test",
            },
        )
        print(f"  POST /api/v1/user-auth/setup -> {r.status_code}")
        if r.status_code != 201:
            print("  body:", r.text[:300])
            return 1

        banner("Login")
        r = c.post(
            "/api/v1/user-auth/login",
            json={"username": "smoke", "password": "SmokePass123!"},
        )
        print(f"  POST /api/v1/user-auth/login -> {r.status_code}")
        if r.status_code != 200:
            print("  body:", r.text[:200])
            return 1
        token = r.json().get("access_token")
        if not token:
            print("  ✗ no access_token in response")
            return 1
        print(f"  ✓ token len: {len(token)}")
        c.headers["Authorization"] = f"Bearer {token}"

        banner("Authenticated GET /api/v1/scans/queue/status")
        r = c.get("/api/v1/scans/queue/status")
        print(f"  GET /api/v1/scans/queue/status -> {r.status_code}")
        if r.status_code != 200:
            print("  body:", r.text[:200])
            fails += 1
        else:
            print("  ✓ scans endpoint reachable")

    banner("RESULT")
    if fails:
        print(f"  ✗ {fails} check(s) failed")
        return 1
    print("  ✓ all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8787"))
