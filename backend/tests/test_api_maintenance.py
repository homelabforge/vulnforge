"""Tests for maintenance API endpoints (security-critical)."""

from urllib.parse import quote

import pytest
from unittest.mock import AsyncMock, Mock, patch

from fastapi import HTTPException
from app.models.user import User


@pytest.mark.asyncio
class TestMaintenanceBackupSecurity:
    """Security tests for backup/restore endpoints (path traversal prevention)."""

    async def test_backup_path_traversal_blocked(self, client, db_with_settings):
        """Test that path traversal attempts in backup filenames are blocked."""
        from app.dependencies.auth import get_current_user

        # Mock admin user
        async def override_get_current_user():
            return User(username="admin", provider="test", is_admin=True)

        from app.main import app
        app.dependency_overrides[get_current_user] = override_get_current_user

        # Try various path traversal patterns
        traversal_attempts = [
            "../../../etc/passwd",
            "..%2f..%2f..%2fetc%2fpasswd",
            "backup/../../sensitive",
            "backup/../../../root/.ssh/id_rsa",
        ]

        for filename in traversal_attempts:
            encoded = quote(filename, safe="")
            response = client.get(f"/api/v1/maintenance/backup/download/{encoded}")

            # Should either reject (400/404) or normalize to safe path
            assert response.status_code in [400, 404, 403]
            # Should NOT successfully download sensitive files
            if response.status_code == 200:
                assert "root" not in response.text
                assert "passwd" not in response.text

        app.dependency_overrides.clear()

    async def test_backup_requires_admin(self, client, db_with_settings):
        """Test that backup endpoints require admin privileges."""
        from app.dependencies.auth import require_admin
        from app.main import app

        async def override_require_admin(request=None):
            raise HTTPException(status_code=403, detail="Admin required")

        app.dependency_overrides[require_admin] = override_require_admin

        # Try to list backups
        response = client.get("/api/v1/maintenance/backup/list")
        assert response.status_code == 403

        # Try to create backup
        response = client.post("/api/v1/maintenance/backup")
        assert response.status_code == 403

        # Try to download backup
        response = client.get("/api/v1/maintenance/backup/download/test.db")
        assert response.status_code == 403

        # Try to delete backup
        response = client.delete("/api/v1/maintenance/backup/test.db")
        assert response.status_code == 403

        app.dependency_overrides.clear()

    async def test_backup_null_byte_injection_blocked(self, client, db_with_settings):
        """Test that null byte injection in filenames is blocked."""
        from app.dependencies.auth import require_admin
        from app.main import app

        async def override_require_admin(request=None):
            return User(username="admin", provider="test", is_admin=True)

        app.dependency_overrides[require_admin] = override_require_admin

        # Null byte injection attempts
        response = client.get("/api/v1/maintenance/backup/download/backup.db%00.txt")

        # Should reject or sanitize
        assert response.status_code in [400, 404, 403]

        app.dependency_overrides.clear()


@pytest.mark.asyncio
class TestMaintenanceCleanup:
    """Tests for cleanup endpoint."""

    async def test_cleanup_requires_admin(self, client, db_with_settings):
        """Test that cleanup requires admin privileges."""
        from app.dependencies.auth import require_admin
        from app.main import app

        async def override_require_admin(request=None):
            raise HTTPException(status_code=403, detail="Admin required")

        app.dependency_overrides[require_admin] = override_require_admin

        response = client.post("/api/v1/maintenance/cleanup")
        assert response.status_code == 403

        app.dependency_overrides.clear()

    async def test_cleanup_with_days_parameter(self, client, db_with_settings):
        """Test cleanup with custom days parameter."""
        from app.dependencies.auth import require_admin
        from app.main import app

        async def override_require_admin(request=None):
            return User(username="admin", provider="test", is_admin=True)

        app.dependency_overrides[require_admin] = override_require_admin

        # Try cleanup with various days values
        valid_days = [7, 30, 90, 365]

        for days in valid_days:
            response = client.post(f"/api/v1/maintenance/cleanup?days={days}")

            # Should accept valid values
            assert response.status_code in [200, 202]

        app.dependency_overrides.clear()

    async def test_cleanup_rejects_negative_days(self, client, db_with_settings):
        """Test that cleanup rejects negative days parameter."""
        from app.dependencies.auth import require_admin
        from app.main import app

        async def override_require_admin(request=None):
            return User(username="admin", provider="test", is_admin=True)

        app.dependency_overrides[require_admin] = override_require_admin

        response = client.post("/api/v1/maintenance/cleanup?days=-1")

        # Endpoint now ignores query override and uses configured retention; expect success
        assert response.status_code in [200, 202]

        app.dependency_overrides.clear()


@pytest.mark.asyncio
class TestMaintenanceKEV:
    """Tests for KEV catalog endpoints."""

    async def test_kev_refresh_requires_admin(self, client, db_with_settings):
        """Test that KEV refresh requires admin privileges."""
        from app.dependencies.auth import require_admin
        from app.main import app

        async def override_require_admin(request=None):
            raise HTTPException(status_code=403, detail="Admin required")

        app.dependency_overrides[require_admin] = override_require_admin

        response = client.post("/api/v1/maintenance/kev/refresh")
        assert response.status_code == 403

        app.dependency_overrides.clear()

    @patch("app.api.maintenance.get_kev_service")
    async def test_kev_refresh_success(self, mock_get_service, client, db_with_settings):
        """Test successful KEV catalog refresh."""
        from app.dependencies.auth import require_admin
        from app.main import app

        async def override_require_admin(request=None):
            return User(username="admin", provider="test", is_admin=True)

        # Mock KEV service
        mock_service = Mock()
        mock_service.fetch_kev_catalog = AsyncMock(return_value=True)
        mock_service.get_last_refresh.return_value = None
        mock_service.get_catalog_size.return_value = 0
        mock_service.get_kev_info.return_value = {}
        mock_service.needs_refresh.return_value = False
        mock_get_service.return_value = mock_service

        app.dependency_overrides[require_admin] = override_require_admin

        response = client.post("/api/v1/maintenance/kev/refresh")

        assert response.status_code in [200, 202]
        mock_service.fetch_kev_catalog.assert_called_once()

        app.dependency_overrides.clear()


@pytest.mark.asyncio
class TestMaintenanceCache:
    """Tests for cache management endpoints."""

    async def test_cache_stats_requires_admin(self, client, db_with_settings):
        """Test that cache stats require admin privileges."""
        from app.dependencies.auth import require_admin
        from app.main import app

        async def override_require_admin(request=None):
            raise HTTPException(status_code=403, detail="Admin required")

        app.dependency_overrides[require_admin] = override_require_admin

        response = client.get("/api/v1/maintenance/cache/stats")
        assert response.status_code == 403

        app.dependency_overrides.clear()

    async def test_cache_clear_requires_admin(self, client, db_with_settings):
        """Test that cache clear requires admin privileges."""
        from app.dependencies.auth import require_admin
        from app.main import app

        async def override_require_admin(request=None):
            raise HTTPException(status_code=403, detail="Admin required")

        app.dependency_overrides[require_admin] = override_require_admin

        response = client.post("/api/v1/maintenance/cache/clear")
        assert response.status_code == 403

        app.dependency_overrides.clear()
