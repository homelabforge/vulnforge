"""Tests for API key management endpoints.

This module tests the API key CRUD routes at /api/v1/api-keys:
- Create API keys (POST "")
- List API keys (GET "")
- Get single API key (GET "/{key_id}")
- Revoke API key (DELETE "/{key_id}")
"""

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession


class TestCreateApiKey:
    """Test POST /api/v1/api-keys endpoint."""

    @pytest.mark.asyncio
    async def test_create_api_key(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test creating an API key returns 201 with key and prefix."""
        # Act
        response = await authenticated_client.post(
            "/api/v1/api-keys",
            json={"name": "My Test Key"},
        )

        # Assert
        assert response.status_code == 201
        data = response.json()
        assert data["name"] == "My Test Key"
        assert "key" in data
        assert data["key"].startswith("vf_")
        assert "key_prefix" in data
        assert len(data["key_prefix"]) > 0
        assert data["id"] is not None

    @pytest.mark.asyncio
    async def test_create_api_key_returns_full_key(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test that the response includes the full key (shown only once)."""
        # Act
        response = await authenticated_client.post(
            "/api/v1/api-keys",
            json={"name": "Full Key Test"},
        )

        # Assert
        assert response.status_code == 201
        data = response.json()
        full_key = data["key"]
        # Full key should be substantially longer than just the prefix
        assert len(full_key) > 12
        assert full_key.startswith("vf_")
        # The key_prefix should be the beginning of the full key
        assert full_key.startswith(data["key_prefix"][:8])

    @pytest.mark.asyncio
    async def test_create_api_key_with_description(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test creating an API key with an optional description."""
        # Act
        response = await authenticated_client.post(
            "/api/v1/api-keys",
            json={"name": "Described Key", "description": "Used for CI/CD pipeline"},
        )

        # Assert
        assert response.status_code == 201
        data = response.json()
        assert data["name"] == "Described Key"
        assert data["description"] == "Used for CI/CD pipeline"

    @pytest.mark.asyncio
    async def test_create_api_key_empty_name(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test creating an API key with empty name returns 422."""
        # Act
        response = await authenticated_client.post(
            "/api/v1/api-keys",
            json={"name": ""},
        )

        # Assert
        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_create_api_key_name_too_long(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test creating an API key with >255 char name returns 422."""
        # Act
        response = await authenticated_client.post(
            "/api/v1/api-keys",
            json={"name": "x" * 256},
        )

        # Assert
        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_create_key_does_not_expose_hash(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test that the creation response does not leak the key_hash."""
        # Act
        response = await authenticated_client.post(
            "/api/v1/api-keys",
            json={"name": "Hash Check Key"},
        )

        # Assert
        assert response.status_code == 201
        data = response.json()
        assert "key_hash" not in data
        # Also verify the raw text body does not contain a 64-char hex hash
        body_text = response.text
        import re

        # SHA256 hex hashes are exactly 64 hex chars; ensure none appear
        potential_hashes = re.findall(r"[0-9a-f]{64}", body_text)
        assert len(potential_hashes) == 0, "Response body should not contain a SHA256 hash"


class TestListApiKeys:
    """Test GET /api/v1/api-keys endpoint."""

    @pytest.mark.asyncio
    async def test_list_api_keys(self, authenticated_client: AsyncClient, db_session: AsyncSession):
        """Test listing API keys after creating two."""
        # Arrange - create two keys
        await authenticated_client.post("/api/v1/api-keys", json={"name": "Key Alpha"})
        await authenticated_client.post("/api/v1/api-keys", json={"name": "Key Beta"})

        # Act
        response = await authenticated_client.get("/api/v1/api-keys")

        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["total"] >= 2
        names = [k["name"] for k in data["keys"]]
        assert "Key Alpha" in names
        assert "Key Beta" in names

    @pytest.mark.asyncio
    async def test_list_api_keys_empty(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test listing when no keys exist returns empty list."""
        # Act
        response = await authenticated_client.get("/api/v1/api-keys")

        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 0
        assert data["keys"] == []

    @pytest.mark.asyncio
    async def test_list_api_keys_excludes_revoked(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test that revoked keys are excluded from default listing."""
        # Arrange - create and revoke a key
        create_resp = await authenticated_client.post(
            "/api/v1/api-keys", json={"name": "Soon Revoked"}
        )
        key_id = create_resp.json()["id"]
        await authenticated_client.delete(f"/api/v1/api-keys/{key_id}")

        # Act - list without include_revoked
        response = await authenticated_client.get("/api/v1/api-keys")

        # Assert
        assert response.status_code == 200
        data = response.json()
        key_ids = [k["id"] for k in data["keys"]]
        assert key_id not in key_ids

    @pytest.mark.asyncio
    async def test_list_api_keys_includes_revoked(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test that include_revoked=true shows revoked keys."""
        # Arrange - create and revoke a key
        create_resp = await authenticated_client.post(
            "/api/v1/api-keys", json={"name": "Revoked But Visible"}
        )
        key_id = create_resp.json()["id"]
        await authenticated_client.delete(f"/api/v1/api-keys/{key_id}")

        # Act
        response = await authenticated_client.get("/api/v1/api-keys?include_revoked=true")

        # Assert
        assert response.status_code == 200
        data = response.json()
        key_ids = [k["id"] for k in data["keys"]]
        assert key_id in key_ids


class TestGetApiKey:
    """Test GET /api/v1/api-keys/{key_id} endpoint."""

    @pytest.mark.asyncio
    async def test_get_api_key(self, authenticated_client: AsyncClient, db_session: AsyncSession):
        """Test retrieving a specific API key by ID."""
        # Arrange
        create_resp = await authenticated_client.post(
            "/api/v1/api-keys", json={"name": "Retrievable Key"}
        )
        key_id = create_resp.json()["id"]

        # Act
        response = await authenticated_client.get(f"/api/v1/api-keys/{key_id}")

        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == key_id
        assert data["name"] == "Retrievable Key"
        assert "key_prefix" in data
        assert data["is_active"] is True

    @pytest.mark.asyncio
    async def test_get_api_key_not_found(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test getting a non-existent API key returns 404."""
        # Act
        response = await authenticated_client.get("/api/v1/api-keys/999")

        # Assert
        assert response.status_code == 404


class TestRevokeApiKey:
    """Test DELETE /api/v1/api-keys/{key_id} endpoint."""

    @pytest.mark.asyncio
    async def test_revoke_api_key(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test revoking an API key sets revoked_at."""
        # Arrange
        create_resp = await authenticated_client.post(
            "/api/v1/api-keys", json={"name": "To Be Revoked"}
        )
        key_id = create_resp.json()["id"]

        # Act
        response = await authenticated_client.delete(f"/api/v1/api-keys/{key_id}")

        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["revoked_at"] is not None

    @pytest.mark.asyncio
    async def test_revoke_api_key_not_found(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test revoking a non-existent key returns 404."""
        # Act
        response = await authenticated_client.delete("/api/v1/api-keys/999")

        # Assert
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_revoked_key_is_not_active(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test that a revoked key reports is_active=False."""
        # Arrange
        create_resp = await authenticated_client.post(
            "/api/v1/api-keys", json={"name": "Check Active Flag"}
        )
        key_id = create_resp.json()["id"]

        # Act - revoke the key
        revoke_resp = await authenticated_client.delete(f"/api/v1/api-keys/{key_id}")

        # Assert
        assert revoke_resp.status_code == 200
        data = revoke_resp.json()
        assert data["is_active"] is False

        # Double-check via GET
        get_resp = await authenticated_client.get(f"/api/v1/api-keys/{key_id}")
        assert get_resp.status_code == 200
        assert get_resp.json()["is_active"] is False
