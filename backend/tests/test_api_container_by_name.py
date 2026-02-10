"""Tests for GET /api/v1/containers/by-name/{name} endpoint."""

from app.models.user import User
from app.repositories.container_repository import ContainerRepository


class TestContainerByName:
    """Tests for the O(1) container lookup by name."""

    async def _create_container(self, db, name="nginx", image="nginx:latest"):
        """Helper to create a test container via the repository."""
        repo = ContainerRepository(db)
        return await repo.create(
            container_id=f"sha256:{name}",
            name=name,
            image=image,
            status="running",
        )

    async def test_get_container_by_name_found(self, authenticated_client, db_with_settings):
        """Test retrieving an existing container by name."""
        from app.dependencies.auth import get_current_user
        from app.main import app

        async def override_get_current_user():
            return User(username="admin", provider="test", is_admin=True)

        app.dependency_overrides[get_current_user] = override_get_current_user

        await self._create_container(db_with_settings, "sonarr", "sonarr:latest")

        response = await authenticated_client.get("/api/v1/containers/by-name/sonarr")
        assert response.status_code == 200

        data = response.json()
        assert data["name"] == "sonarr"
        assert "id" in data
        assert "vulnerability_summary" in data

        app.dependency_overrides.clear()

    async def test_get_container_by_name_not_found(self, authenticated_client, db_with_settings):
        """Test 404 when container name doesn't exist."""
        from app.dependencies.auth import get_current_user
        from app.main import app

        async def override_get_current_user():
            return User(username="admin", provider="test", is_admin=True)

        app.dependency_overrides[get_current_user] = override_get_current_user

        response = await authenticated_client.get("/api/v1/containers/by-name/nonexistent")
        assert response.status_code == 404

        app.dependency_overrides.clear()

    async def test_get_container_by_name_includes_vuln_summary(
        self, authenticated_client, db_with_settings
    ):
        """Test that response includes vulnerability summary."""
        from app.dependencies.auth import get_current_user
        from app.main import app

        async def override_get_current_user():
            return User(username="admin", provider="test", is_admin=True)

        app.dependency_overrides[get_current_user] = override_get_current_user

        await self._create_container(db_with_settings, "traefik", "traefik:v3.0")

        response = await authenticated_client.get("/api/v1/containers/by-name/traefik")
        assert response.status_code == 200

        data = response.json()
        vs = data["vulnerability_summary"]
        assert vs["total"] == 0
        assert vs["critical"] == 0
        assert vs["high"] == 0
        assert vs["medium"] == 0
        assert vs["low"] == 0

        app.dependency_overrides.clear()

    async def test_get_container_by_name_does_not_match_by_id(
        self, authenticated_client, db_with_settings
    ):
        """Ensure numeric names don't accidentally match container_id routes."""
        from app.dependencies.auth import get_current_user
        from app.main import app

        async def override_get_current_user():
            return User(username="admin", provider="test", is_admin=True)

        app.dependency_overrides[get_current_user] = override_get_current_user

        # by-name with a numeric string should NOT hit /{container_id}
        response = await authenticated_client.get("/api/v1/containers/by-name/999")
        assert response.status_code == 404

        app.dependency_overrides.clear()
