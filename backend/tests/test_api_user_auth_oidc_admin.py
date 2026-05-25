"""Tests for the dedicated admin OIDC endpoints (plan §5.4 contract).

Covers:
- GET /api/v1/user-auth/oidc/config/admin
- PUT /api/v1/user-auth/oidc/config/admin
- POST /api/v1/user-auth/oidc/test (new canonical envelope)
"""

from unittest.mock import AsyncMock, patch

import pytest
from fastapi import status


@pytest.fixture(autouse=True)
async def enable_user_auth(db_session):
    """Flip user_auth_mode to 'local' so require_user_auth enforces auth in these tests."""
    from app.services.settings_manager import SettingsManager

    sm = SettingsManager(db_session)
    await sm.set("user_auth_mode", "local")
    await sm.set("user_auth_admin_username", "admin")
    await sm.set("user_auth_admin_email", "admin@example.com")
    yield


@pytest.mark.asyncio
class TestUserAuthOidcAdminConfig:
    """GET / PUT /api/v1/user-auth/oidc/config/admin enforce the canonical OIDC contract."""

    async def test_get_returns_masked_secret_when_stored(self, authenticated_client, db_session):
        from app.services.settings_manager import SettingsManager

        sm = SettingsManager(db_session)
        await sm.set("user_auth_oidc_enabled", "true")
        await sm.set("user_auth_oidc_provider_name", "Authentik")
        await sm.set("user_auth_oidc_issuer_url", "https://auth.example.com")
        await sm.set("user_auth_oidc_client_id", "client")
        await sm.set("user_auth_oidc_client_secret", "real-secret")

        response = await authenticated_client.get("/api/v1/user-auth/oidc/config/admin")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["enabled"] is True
        assert data["client_id"] == "client"
        assert data["client_secret"] == "********"

    async def test_get_returns_empty_when_no_secret(self, authenticated_client, db_session):
        from app.services.settings_manager import SettingsManager

        sm = SettingsManager(db_session)
        await sm.set("user_auth_oidc_client_secret", "")

        response = await authenticated_client.get("/api/v1/user-auth/oidc/config/admin")
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["client_secret"] == ""

    async def test_put_preserves_secret_on_empty(self, authenticated_client, db_session):
        from app.services.settings_manager import SettingsManager

        sm = SettingsManager(db_session)
        await sm.set("user_auth_oidc_client_secret", "preserved-secret")

        payload = {
            "enabled": True,
            "provider_name": "Authentik",
            "issuer_url": "https://auth.example.com",
            "client_id": "client",
            "client_secret": "",
            "scopes": "openid",
            "username_claim": "preferred_username",
            "email_claim": "email",
        }
        response = await authenticated_client.put(
            "/api/v1/user-auth/oidc/config/admin", json=payload
        )
        assert response.status_code == status.HTTP_200_OK

        stored = await sm.get("user_auth_oidc_client_secret")
        assert stored == "preserved-secret"

    async def test_put_strips_issuer_trailing_slash(self, authenticated_client, db_session):
        from app.services.settings_manager import SettingsManager

        sm = SettingsManager(db_session)
        payload = {
            "enabled": True,
            "provider_name": "Authentik",
            "issuer_url": "https://auth.example.com/auth/v1/",
            "client_id": "client",
            "client_secret": "newsecret",
            "scopes": "openid",
            "username_claim": "preferred_username",
            "email_claim": "email",
        }
        response = await authenticated_client.put(
            "/api/v1/user-auth/oidc/config/admin", json=payload
        )
        assert response.status_code == status.HTTP_200_OK

        stored = await sm.get("user_auth_oidc_issuer_url")
        assert stored == "https://auth.example.com/auth/v1"

    async def test_get_requires_auth(self, client):
        response = await client.get("/api/v1/user-auth/oidc/config/admin")
        assert response.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.asyncio
class TestUserAuthOidcTestEndpoint:
    """POST /api/v1/user-auth/oidc/test returns canonical {ok, error, detail, issuer, ...}."""

    async def test_success_returns_canonical_envelope(self, authenticated_client):
        class _Response:
            def raise_for_status(self) -> None:
                return None

            def json(self) -> dict:
                return {
                    "issuer": "https://auth.example.com",
                    "authorization_endpoint": "https://auth.example.com/authorize",
                    "token_endpoint": "https://auth.example.com/token",
                    "userinfo_endpoint": "https://auth.example.com/userinfo",
                    "jwks_uri": "https://auth.example.com/jwks",
                    "id_token_signing_alg_values_supported": ["EdDSA", "RS256"],
                }

        class _Client:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *_):
                return False

            async def get(self, *_args, **_kwargs):
                return _Response()

        with patch("httpx.AsyncClient", lambda *a, **k: _Client()):
            response = await authenticated_client.post(
                "/api/v1/user-auth/oidc/test",
                json={
                    "issuer_url": "https://auth.example.com/",
                    "client_id": "client",
                    "client_secret": "any",
                },
            )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["ok"] is True
        assert data["issuer"] == "https://auth.example.com"
        assert data["algorithms_supported"] == ["EdDSA", "RS256"]

    async def test_unreachable_returns_canonical_error(self, authenticated_client):
        import httpx

        class _Client:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *_):
                return False

            async def get(self, *_args, **_kwargs):
                raise httpx.TimeoutException("timed out")

        with patch("httpx.AsyncClient", lambda *a, **k: _Client()):
            response = await authenticated_client.post(
                "/api/v1/user-auth/oidc/test",
                json={
                    "issuer_url": "https://bad.example.com",
                    "client_id": "client",
                    "client_secret": "any",
                },
            )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["ok"] is False
        assert data["error"] == "unreachable"
        assert "timeout" in (data.get("detail") or "").lower()

    async def test_test_uses_stored_secret_on_empty_input(self, authenticated_client, db_session):
        """Empty client_secret on /oidc/test falls back to the stored value (§5.4(2))."""
        from app.services.settings_manager import SettingsManager

        sm = SettingsManager(db_session)
        await sm.set("user_auth_oidc_client_secret", "fallback-secret")

        # Patch get_oidc_config to capture whether the fallback path runs.
        original_get = AsyncMock()

        with patch("app.services.oidc.get_oidc_config", new=original_get) as mocked:
            mocked.return_value = {"client_secret": "fallback-secret"}

            class _Client:
                async def __aenter__(self):
                    return self

                async def __aexit__(self, *_):
                    return False

                async def get(self, *_args, **_kwargs):
                    raise RuntimeError("network unused; we only assert the fallback ran")

            with patch("httpx.AsyncClient", lambda *a, **k: _Client()):
                response = await authenticated_client.post(
                    "/api/v1/user-auth/oidc/test",
                    json={
                        "issuer_url": "https://auth.example.com",
                        "client_id": "client",
                        "client_secret": "",
                    },
                )

            assert response.status_code == status.HTTP_200_OK
            # Function must have been invoked to honor the fallback contract.
            mocked.assert_called_once()
