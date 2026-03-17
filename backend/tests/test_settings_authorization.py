"""Tests for settings API authorization."""

import pytest


@pytest.fixture(autouse=True)
async def local_auth_mode(db_with_settings):
    """Enable local auth for all settings-authorization tests.

    Authorization tests assert 401 when unauthenticated.  That only holds
    when user_auth_mode == 'local'; the test-environment default is 'none'
    (open access), which would cause these tests to see 200 instead.
    """
    from app.models import Setting
    from app.services.settings_manager import SettingsManager

    db_with_settings.add(Setting(key="user_auth_mode", value="local"))
    await db_with_settings.commit()
    SettingsManager.invalidate_cache("user_auth_mode")
    yield
    SettingsManager.invalidate_cache("user_auth_mode")


class TestSettingsAuthorization:
    """Tests for settings endpoint authorization."""

    async def test_list_settings_requires_auth(self, client, db_with_settings):
        """Test that listing settings requires authentication."""
        from app.database import get_db
        from app.main import app

        async def override_get_db():
            yield db_with_settings

        app.dependency_overrides[get_db] = override_get_db

        response = await client.get("/api/v1/settings")

        assert response.status_code == 401
        assert "Authentication required" in response.json()["detail"]

        app.dependency_overrides.clear()

    async def test_list_settings_allows_authenticated(self, authenticated_client, db_with_settings):
        """Test that authenticated users can list settings."""
        from app.database import get_db
        from app.main import app

        async def override_get_db():
            yield db_with_settings

        app.dependency_overrides[get_db] = override_get_db

        response = await authenticated_client.get("/api/v1/settings")

        assert response.status_code == 200
        assert isinstance(response.json(), list)

        app.dependency_overrides.clear()

    async def test_get_setting_requires_auth(self, client, db_with_settings):
        """Test that getting individual setting requires authentication."""
        from app.database import get_db
        from app.main import app

        async def override_get_db():
            yield db_with_settings

        app.dependency_overrides[get_db] = override_get_db

        response = await client.get("/api/v1/settings/scan_on_startup")

        assert response.status_code == 401

        app.dependency_overrides.clear()

    async def test_update_setting_requires_auth(self, client, db_with_settings):
        """Test that updating settings requires authentication."""
        from app.database import get_db
        from app.main import app

        async def override_get_db():
            yield db_with_settings

        app.dependency_overrides[get_db] = override_get_db

        response = await client.put(
            "/api/v1/settings/scan_on_startup",
            json={"value": "true"},
        )

        assert response.status_code == 401

        app.dependency_overrides.clear()

    async def test_update_setting_allows_authenticated(
        self, authenticated_client, db_with_settings
    ):
        """Test that authenticated users can update settings."""
        from app.database import get_db
        from app.main import app

        async def override_get_db():
            yield db_with_settings

        app.dependency_overrides[get_db] = override_get_db

        response = await authenticated_client.put(
            "/api/v1/settings/scan_on_startup",
            json={"value": "true"},
        )

        assert response.status_code == 200
        assert response.json()["key"] == "scan_on_startup"
        assert response.json()["value"] == "true"

        app.dependency_overrides.clear()

    async def test_bulk_update_settings_requires_auth(self, client, db_with_settings):
        """Test that bulk updating settings requires authentication."""
        from app.database import get_db
        from app.main import app

        async def override_get_db():
            yield db_with_settings

        app.dependency_overrides[get_db] = override_get_db

        response = await client.post(
            "/api/v1/settings/bulk",
            json={
                "settings": [
                    {"key": "scan_on_startup", "value": "true"},
                ]
            },
        )

        assert response.status_code == 401

        app.dependency_overrides.clear()

    async def test_api_key_authentication(self, api_key_client, db_with_settings):
        """Test that API key authentication works for settings access."""
        from app.database import get_db
        from app.main import app

        async def override_get_db():
            yield db_with_settings

        app.dependency_overrides[get_db] = override_get_db

        # API key should work for authentication
        response = await api_key_client.get("/api/v1/settings")

        assert response.status_code == 200
        assert isinstance(response.json(), list)

        app.dependency_overrides.clear()
