"""Tests for settings API authorization."""


class TestSettingsAuthorization:
    """Tests for settings endpoint authorization."""

    async def test_list_settings_requires_auth(self, client, db_with_settings):
        """Test that listing settings requires authentication."""
        from app.db import get_db
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
        from app.db import get_db
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
        from app.db import get_db
        from app.main import app

        async def override_get_db():
            yield db_with_settings

        app.dependency_overrides[get_db] = override_get_db

        response = await client.get("/api/v1/settings/scan_on_startup")

        assert response.status_code == 401

        app.dependency_overrides.clear()

    async def test_update_setting_requires_auth(self, client, db_with_settings):
        """Test that updating settings requires authentication."""
        from app.db import get_db
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
        from app.db import get_db
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
        from app.db import get_db
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
        from app.db import get_db
        from app.main import app

        async def override_get_db():
            yield db_with_settings

        app.dependency_overrides[get_db] = override_get_db

        # API key should work for authentication
        response = await api_key_client.get("/api/v1/settings")

        assert response.status_code == 200
        assert isinstance(response.json(), list)

        app.dependency_overrides.clear()
