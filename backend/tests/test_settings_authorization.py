"""Tests for settings API authorization."""

import json

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Setting
from app.middleware import auth as auth_middleware


API_KEY_CONFIG = [
    {"key": "admin-token", "name": "admin-user", "admin": True},
    {"key": "user-token", "name": "regular-user", "admin": False},
]
API_KEY_JSON = json.dumps(API_KEY_CONFIG)


@pytest.fixture
async def db_with_auth_enabled(db_session: AsyncSession) -> AsyncSession:
    """Create database session with auth enabled."""
    from app.services.settings_manager import SettingsManager

    # Add default settings with auth ENABLED
    for key, value in SettingsManager.DEFAULTS.items():
        await db_session.merge(Setting(key=key, value=value))

    # Enable authentication using API key provider
    await db_session.merge(Setting(key="auth_enabled", value="true"))
    await db_session.merge(Setting(key="auth_provider", value="api_key"))
    await db_session.merge(Setting(key="auth_api_keys", value=API_KEY_JSON, is_sensitive=True))

    await db_session.commit()
    return db_session


@pytest.fixture
def _force_api_key_auth(monkeypatch):
    """Ensure authentication middleware uses API key provider during tests."""

    async def _fake_get_cached_settings(_db):
        return {
            "auth_enabled": "true",
            "auth_provider": "api_key",
            "auth_api_keys": API_KEY_JSON,
        }

    monkeypatch.setattr(auth_middleware, "_get_cached_settings", _fake_get_cached_settings)
    auth_middleware._settings_cache = None
    auth_middleware._settings_cache_time = 0.0

    yield

    auth_middleware._settings_cache = None
    auth_middleware._settings_cache_time = 0.0


@pytest.mark.usefixtures("_force_api_key_auth")
class TestSettingsAuthorization:
    """Tests for settings endpoint authorization."""

    async def test_list_settings_requires_auth(self, client, db_with_auth_enabled):
        """Test that listing settings requires authentication."""
        from app.db import get_db

        async def override_get_db():
            yield db_with_auth_enabled

        from app.main import app
        app.dependency_overrides[get_db] = override_get_db

        response = await client.get("/api/v1/settings")

        assert response.status_code == 401
        assert "Authentication required" in response.json()["detail"]

        app.dependency_overrides.clear()

    async def test_list_settings_requires_admin(self, client, db_with_auth_enabled):
        """Test that listing settings requires admin privileges."""
        from app.db import get_db

        async def override_get_db():
            yield db_with_auth_enabled

        from app.main import app
        app.dependency_overrides[get_db] = override_get_db

        response = await client.get(
            "/api/v1/settings",
            headers={"Authorization": "Bearer user-token"},
        )

        assert response.status_code == 403
        assert response.json()["detail"].startswith("Admin privileges required")

        app.dependency_overrides.clear()

    async def test_list_settings_allows_admin(self, client, db_with_auth_enabled):
        """Test that admin users can list settings."""
        from app.db import get_db

        async def override_get_db():
            yield db_with_auth_enabled

        from app.main import app
        app.dependency_overrides[get_db] = override_get_db

        response = await client.get(
            "/api/v1/settings",
            headers={"Authorization": "Bearer admin-token"},
        )

        assert response.status_code == 200
        assert isinstance(response.json(), list)

        app.dependency_overrides.clear()

    async def test_get_setting_requires_admin(self, client, db_with_auth_enabled):
        """Test that getting individual setting requires admin."""
        from app.db import get_db

        async def override_get_db():
            yield db_with_auth_enabled

        from app.main import app
        app.dependency_overrides[get_db] = override_get_db

        response = await client.get(
            "/api/v1/settings/auth_enabled",
            headers={"Authorization": "Bearer user-token"},
        )

        assert response.status_code == 403

        app.dependency_overrides.clear()

    async def test_update_setting_requires_admin(self, client, db_with_auth_enabled):
        """Test that updating settings requires admin privileges."""
        from app.db import get_db

        async def override_get_db():
            yield db_with_auth_enabled

        from app.main import app
        app.dependency_overrides[get_db] = override_get_db

        response = await client.put(
            "/api/v1/settings/auth_enabled",
            json={"value": "true"},
            headers={"Authorization": "Bearer user-token"},
        )

        assert response.status_code == 403

        app.dependency_overrides.clear()

    async def test_update_setting_allows_admin(self, client, db_with_auth_enabled):
        """Test that admin users can update settings."""
        from app.db import get_db

        async def override_get_db():
            yield db_with_auth_enabled

        from app.main import app
        app.dependency_overrides[get_db] = override_get_db

        response = await client.put(
            "/api/v1/settings/auth_enabled",
            json={"value": "true"},
            headers={"Authorization": "Bearer admin-token"},
        )

        assert response.status_code == 200
        assert response.json()["key"] == "auth_enabled"
        assert response.json()["value"] == "true"

        app.dependency_overrides.clear()

    async def test_bulk_update_settings_requires_admin(self, client, db_with_auth_enabled):
        """Test that bulk updating settings requires admin privileges."""
        from app.db import get_db

        async def override_get_db():
            yield db_with_auth_enabled

        from app.main import app
        app.dependency_overrides[get_db] = override_get_db

        # Use POST (correct HTTP verb) instead of PUT
        response = await client.post(
            "/api/v1/settings/bulk",
            json={
                "settings": [
                    {"key": "auth_enabled", "value": "false"},
                    {"key": "auth_provider", "value": "none"}
                ]
            },
            headers={"Authorization": "Bearer user-token"},
        )

        assert response.status_code == 403

        app.dependency_overrides.clear()

    async def test_privilege_escalation_prevention(self, client, db_with_auth_enabled):
        """Test that non-admin cannot disable auth or modify security settings."""
        from app.db import get_db

        async def override_get_db():
            yield db_with_auth_enabled

        from app.main import app
        app.dependency_overrides[get_db] = override_get_db

        # Try to disable authentication
        response = await client.put(
            "/api/v1/settings/auth_enabled",
            json={"value": "false"},
            headers={"Authorization": "Bearer user-token"},
        )
        assert response.status_code == 403

        # Try to change auth provider
        response = await client.put(
            "/api/v1/settings/auth_provider",
            json={"value": "none"},
            headers={"Authorization": "Bearer user-token"},
        )
        assert response.status_code == 403

        # Try to modify API keys
        response = await client.put(
            "/api/v1/settings/auth_api_keys",
            json={"value": '[{"key": "backdoor", "name": "evil", "admin": true}]'},
            headers={"Authorization": "Bearer user-token"},
        )
        assert response.status_code == 403

        app.dependency_overrides.clear()


class TestSettingsCacheMutability:
    """Tests for settings cache immutability."""

    async def test_cache_returns_copy(self, db_with_settings):
        """Test that settings cache returns a copy, not reference."""
        from app.middleware.auth import _get_cached_settings

        # Get settings twice
        settings1 = await _get_cached_settings(db_with_settings)
        settings2 = await _get_cached_settings(db_with_settings)
        original_value = settings2.get("auth_enabled")

        # Modify first copy
        settings1["auth_enabled"] = "modified"

        # Second copy should be unchanged
        assert settings2["auth_enabled"] != "modified"
        assert settings2["auth_enabled"] == original_value

    async def test_cache_mutation_does_not_affect_global(self, db_with_settings):
        """Test that mutating returned settings doesn't affect global cache."""
        from app.middleware.auth import _get_cached_settings

        # Get settings and modify
        settings1 = await _get_cached_settings(db_with_settings)
        settings1["auth_enabled"] = "evil_modification"

        # Get settings again
        settings2 = await _get_cached_settings(db_with_settings)

        # Should still have original value
        assert settings2["auth_enabled"] != "evil_modification"
