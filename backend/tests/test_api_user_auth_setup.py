"""N3: bootstrap setup-token constant-time compare (plan §9).

The /setup and /cancel-setup endpoints must reject a wrong (or absent)
bootstrap token, comparing with ``hmac.compare_digest`` rather than ``!=``.
"""

from unittest.mock import patch

import pytest
from fastapi import status

_VALID_BODY = {
    "username": "admin",
    "email": "admin@example.com",
    "password": "Abcdef1!",
    "full_name": "Admin",
}


@pytest.mark.asyncio
async def test_setup_rejects_wrong_bootstrap_token(client):
    with patch("app.routes.user_auth.get_bootstrap_token", return_value="the-real-token"):
        resp = await client.post(
            "/api/v1/user-auth/setup",
            json={**_VALID_BODY, "bootstrap_token": "wrong-token"},
        )
    assert resp.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.asyncio
async def test_setup_rejects_when_no_token_configured(client):
    with patch("app.routes.user_auth.get_bootstrap_token", return_value=None):
        resp = await client.post(
            "/api/v1/user-auth/setup",
            json={**_VALID_BODY, "bootstrap_token": "anything"},
        )
    assert resp.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.asyncio
async def test_setup_accepts_correct_bootstrap_token(client):
    with (
        patch("app.routes.user_auth.get_bootstrap_token", return_value="the-real-token"),
        patch("app.routes.user_auth.consume_bootstrap_token"),
    ):
        resp = await client.post(
            "/api/v1/user-auth/setup",
            json={**_VALID_BODY, "bootstrap_token": "the-real-token"},
        )
    assert resp.status_code == status.HTTP_201_CREATED


@pytest.mark.asyncio
async def test_cancel_setup_rejects_wrong_bootstrap_token(client):
    with patch("app.routes.user_auth.get_bootstrap_token", return_value="the-real-token"):
        resp = await client.post(
            "/api/v1/user-auth/cancel-setup",
            json={"bootstrap_token": "wrong-token"},
        )
    assert resp.status_code == status.HTTP_403_FORBIDDEN
