"""C1: OIDC admin subject binding — trust-on-first-use + enforce (plan §4).

The unauthenticated ``/oidc/callback`` must bind the first IdP subject it sees
as the admin, then reject any *different* subject thereafter (so an arbitrary
account at the IdP can no longer be minted an admin JWT). An authenticated admin
can clear the binding via ``PUT /oidc/config/admin`` with ``reset_subject=true``.
"""

from contextlib import contextmanager
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import status
from sqlalchemy.ext.asyncio import AsyncSession

from app.services.settings_manager import SettingsManager
from app.services.user_auth import JWT_COOKIE_NAME

_OIDC_CONFIG = {
    "enabled": "true",
    "issuer_url": "https://auth.example.com",
    "client_id": "client",
    "provider_name": "Authentik",
    "username_claim": "preferred_username",
    "email_claim": "email",
}


@pytest.fixture
async def admin_local(db_session: AsyncSession):
    sm = SettingsManager(db_session)
    await sm.set("user_auth_mode", "local")
    await sm.set("user_auth_admin_username", "admin")
    await sm.set("user_auth_admin_email", "admin@example.com")
    await sm.set("user_auth_admin_auth_method", "local")
    return sm


@contextmanager
def _patched_oidc(claims: dict):
    """Patch the oidc_service calls oidc_callback makes (state already consumed)."""
    with patch.multiple(
        "app.services.oidc",
        validate_and_consume_state=AsyncMock(
            return_value={
                "redirect_uri": "https://app.example.com/cb",
                "nonce": "nonce-value",
                "code_verifier": "verifier",
            }
        ),
        get_oidc_config=AsyncMock(return_value=dict(_OIDC_CONFIG)),
        get_provider_metadata=AsyncMock(return_value={"issuer": "https://auth.example.com"}),
        exchange_code_for_tokens=AsyncMock(
            return_value={"id_token": "idtok", "access_token": "acc"}
        ),
        verify_id_token=AsyncMock(return_value=claims),
        get_userinfo=AsyncMock(return_value=None),
    ):
        yield


async def _callback(client):
    return await client.get(
        "/api/v1/user-auth/oidc/callback",
        params={"code": "code", "state": "state"},
        follow_redirects=False,
    )


def _jwt_cookie_set(resp) -> bool:
    return any(JWT_COOKIE_NAME in c for c in resp.headers.get_list("set-cookie"))


@pytest.mark.asyncio
class TestOidcSubjectBinding:
    async def test_first_link_binds_subject_and_mints_jwt(self, client, admin_local):
        claims = {"sub": "sub-123", "preferred_username": "admin", "email": "admin@example.com"}
        with _patched_oidc(claims):
            resp = await _callback(client)

        assert resp.status_code == status.HTTP_302_FOUND
        assert _jwt_cookie_set(resp)
        assert await admin_local.get("user_auth_admin_oidc_subject") == "sub-123"

    async def test_matching_subject_succeeds(self, client, admin_local):
        await admin_local.set("user_auth_admin_oidc_subject", "sub-123")
        claims = {"sub": "sub-123", "preferred_username": "admin", "email": "admin@example.com"}
        with _patched_oidc(claims):
            resp = await _callback(client)

        assert resp.status_code == status.HTTP_302_FOUND
        assert _jwt_cookie_set(resp)

    async def test_mismatched_subject_rejected(self, client, admin_local):
        await admin_local.set("user_auth_admin_oidc_subject", "sub-123")
        claims = {"sub": "evil-456", "preferred_username": "attacker", "email": "evil@example.com"}
        with _patched_oidc(claims):
            resp = await _callback(client)

        assert resp.status_code == status.HTTP_403_FORBIDDEN
        assert not _jwt_cookie_set(resp)
        # The bound subject and the admin identity must be untouched.
        assert await admin_local.get("user_auth_admin_oidc_subject") == "sub-123"
        assert await admin_local.get("user_auth_admin_username") == "admin"

    async def test_missing_subject_claim_rejected(self, client, admin_local):
        claims = {"preferred_username": "admin", "email": "admin@example.com"}  # no "sub"
        with _patched_oidc(claims):
            resp = await _callback(client)

        assert resp.status_code == status.HTTP_401_UNAUTHORIZED
        assert not _jwt_cookie_set(resp)

    async def test_relink_clears_binding_and_rebinds(
        self, client, authenticated_client, admin_local
    ):
        await admin_local.set("user_auth_admin_oidc_subject", "old-sub")

        # Authenticated admin resets the OIDC link.
        payload = {
            "enabled": True,
            "provider_name": "Authentik",
            "issuer_url": "https://auth.example.com",
            "client_id": "client",
            "client_secret": "",
            "scopes": "openid profile email",
            "username_claim": "preferred_username",
            "email_claim": "email",
            "reset_subject": True,
        }
        put = await authenticated_client.put("/api/v1/user-auth/oidc/config/admin", json=payload)
        assert put.status_code == status.HTTP_200_OK
        assert await admin_local.get("user_auth_admin_oidc_subject") == ""

        # The next callback re-binds the new subject (TOFU re-armed).
        claims = {"sub": "new-sub", "preferred_username": "admin", "email": "admin@example.com"}
        with _patched_oidc(claims):
            resp = await _callback(client)

        assert resp.status_code == status.HTTP_302_FOUND
        assert await admin_local.get("user_auth_admin_oidc_subject") == "new-sub"
