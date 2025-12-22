"""Tests for system API endpoints.

This module tests the system management API which provides:
- Trivy database information
- Scanner status and version information
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import AsyncClient


class TestTrivyDatabaseInfo:
    """Test GET /api/v1/system/trivy-db-info endpoint."""

    @pytest.mark.asyncio
    async def test_get_trivy_db_info_success(self, authenticated_client: AsyncClient):
        """Test getting Trivy database info when available."""
        # Mock the scanner to return database info
        mock_db_info = {
            "db_version": "2",
            "updated_at": "2025-12-20T10:00:00Z",
            "next_update": "2025-12-21T10:00:00Z",
            "downloaded_at": "2025-12-20T09:00:00Z",
        }

        with patch("app.api.system.TrivyScanner") as mock_scanner_class:
            mock_scanner = AsyncMock()
            mock_scanner.get_database_info.return_value = mock_db_info
            mock_scanner_class.return_value = mock_scanner

            # Act
            response = await authenticated_client.get("/api/v1/system/trivy-db-info")

            # Assert
            assert response.status_code == 200
            data = response.json()
            assert data["db_version"] == "2"
            assert data["updated_at"] == "2025-12-20T10:00:00Z"

    @pytest.mark.asyncio
    async def test_get_trivy_db_info_no_database(self, authenticated_client: AsyncClient):
        """Test getting Trivy database info when DB not available."""
        # Mock the scanner to return None (no database)
        with patch("app.api.system.TrivyScanner") as mock_scanner_class:
            mock_scanner = AsyncMock()
            mock_scanner.get_database_info.return_value = None
            mock_scanner_class.return_value = mock_scanner

            # Act
            response = await authenticated_client.get("/api/v1/system/trivy-db-info")

            # Assert
            assert response.status_code == 200
            data = response.json()
            assert data["db_version"] is None
            assert data["updated_at"] is None
            assert data["next_update"] is None
            assert data["downloaded_at"] is None

    @pytest.mark.asyncio
    async def test_trivy_db_info_structure(self, authenticated_client: AsyncClient):
        """Test Trivy DB info response has expected structure."""
        with patch("app.api.system.TrivyScanner") as mock_scanner_class:
            mock_scanner = AsyncMock()
            mock_scanner.get_database_info.return_value = {
                "db_version": "2",
                "updated_at": "2025-12-20T10:00:00Z",
                "next_update": None,
                "downloaded_at": None,
            }
            mock_scanner_class.return_value = mock_scanner

            # Act
            response = await authenticated_client.get("/api/v1/system/trivy-db-info")

            # Assert
            assert response.status_code == 200
            data = response.json()
            assert "db_version" in data
            assert "updated_at" in data
            assert "next_update" in data
            assert "downloaded_at" in data


class TestScannersInfo:
    """Test GET /api/v1/system/scanners endpoint."""

    @pytest.mark.asyncio
    async def test_get_scanners_info(self, authenticated_client: AsyncClient):
        """Test getting all scanners information."""
        # Mock Docker service
        with (
            patch("app.api.system.DockerService") as mock_docker_service_class,
            patch("app.api.system.get_docker_hub_client") as mock_docker_hub,
            patch("app.api.system.TrivyScanner") as mock_trivy_scanner_class,
            patch("app.api.system.DockerBenchService") as mock_bench_service_class,
        ):
            # Setup mocks
            mock_docker_service = MagicMock()
            mock_docker_service.get_trivy_container.return_value = MagicMock()
            mock_docker_service.client.images.get.side_effect = Exception("Not found")
            mock_docker_service.client.containers.get.side_effect = Exception("Not found")
            mock_docker_service_class.return_value = mock_docker_service

            mock_hub = AsyncMock()
            mock_hub.get_latest_tag.return_value = None
            mock_hub.get_github_release_version.return_value = None
            mock_docker_hub.return_value = mock_hub

            mock_trivy = AsyncMock()
            mock_trivy.get_scanner_version.return_value = "0.67.2"
            mock_trivy.get_database_info.return_value = None
            mock_trivy.check_db_freshness.return_value = (True, 2)
            mock_trivy_scanner_class.return_value = mock_trivy

            mock_bench = AsyncMock()
            mock_bench.get_scanner_version.return_value = None
            mock_bench_service_class.return_value = mock_bench

            # Act
            response = await authenticated_client.get("/api/v1/system/scanners")

            # Assert
            assert response.status_code == 200
            data = response.json()
            assert "scanners" in data
            assert isinstance(data["scanners"], list)

    @pytest.mark.asyncio
    async def test_scanners_info_includes_trivy(self, authenticated_client: AsyncClient):
        """Test scanners info includes Trivy scanner."""
        with (
            patch("app.api.system.DockerService") as mock_docker_service_class,
            patch("app.api.system.get_docker_hub_client") as mock_docker_hub,
            patch("app.api.system.TrivyScanner") as mock_trivy_scanner_class,
            patch("app.api.system.DockerBenchService") as mock_bench_service_class,
        ):
            # Setup mocks
            mock_docker_service = MagicMock()
            mock_docker_service.get_trivy_container.return_value = MagicMock()
            mock_docker_service.client.images.get.side_effect = Exception("Not found")
            mock_docker_service.client.containers.get.side_effect = Exception("Not found")
            mock_docker_service_class.return_value = mock_docker_service

            mock_hub = AsyncMock()
            mock_hub.get_latest_tag.return_value = None
            mock_hub.get_github_release_version.return_value = None
            mock_docker_hub.return_value = mock_hub

            mock_trivy = AsyncMock()
            mock_trivy.get_scanner_version.return_value = "0.67.2"
            mock_trivy.get_database_info.return_value = None
            mock_trivy.check_db_freshness.return_value = (True, 2)
            mock_trivy_scanner_class.return_value = mock_trivy

            mock_bench = AsyncMock()
            mock_bench.get_scanner_version.return_value = None
            mock_bench_service_class.return_value = mock_bench

            # Act
            response = await authenticated_client.get("/api/v1/system/scanners")

            # Assert
            assert response.status_code == 200
            data = response.json()
            scanner_names = [s["name"] for s in data["scanners"]]
            assert "Trivy" in scanner_names

    @pytest.mark.asyncio
    async def test_scanners_info_includes_docker_bench(self, authenticated_client: AsyncClient):
        """Test scanners info includes Docker Bench scanner."""
        with (
            patch("app.api.system.DockerService") as mock_docker_service_class,
            patch("app.api.system.get_docker_hub_client") as mock_docker_hub,
            patch("app.api.system.TrivyScanner") as mock_trivy_scanner_class,
            patch("app.api.system.DockerBenchService") as mock_bench_service_class,
        ):
            # Setup mocks
            mock_docker_service = MagicMock()
            mock_docker_service.get_trivy_container.return_value = MagicMock()
            mock_docker_service.client.images.get.side_effect = Exception("Not found")
            mock_docker_service.client.containers.get.side_effect = Exception("Not found")
            mock_docker_service_class.return_value = mock_docker_service

            mock_hub = AsyncMock()
            mock_hub.get_latest_tag.return_value = None
            mock_hub.get_github_release_version.return_value = None
            mock_docker_hub.return_value = mock_hub

            mock_trivy = AsyncMock()
            mock_trivy.get_scanner_version.return_value = "0.67.2"
            mock_trivy.get_database_info.return_value = None
            mock_trivy.check_db_freshness.return_value = (True, 2)
            mock_trivy_scanner_class.return_value = mock_trivy

            mock_bench = AsyncMock()
            mock_bench.get_scanner_version.return_value = None
            mock_bench_service_class.return_value = mock_bench

            # Act
            response = await authenticated_client.get("/api/v1/system/scanners")

            # Assert
            assert response.status_code == 200
            data = response.json()
            scanner_names = [s["name"] for s in data["scanners"]]
            assert "Docker Bench" in scanner_names

    @pytest.mark.asyncio
    async def test_scanners_info_includes_dive(self, authenticated_client: AsyncClient):
        """Test scanners info includes Dive scanner."""
        with (
            patch("app.api.system.DockerService") as mock_docker_service_class,
            patch("app.api.system.get_docker_hub_client") as mock_docker_hub,
            patch("app.api.system.TrivyScanner") as mock_trivy_scanner_class,
            patch("app.api.system.DockerBenchService") as mock_bench_service_class,
        ):
            # Setup mocks
            mock_docker_service = MagicMock()
            mock_docker_service.get_trivy_container.return_value = MagicMock()
            mock_docker_service.client.images.get.side_effect = Exception("Not found")
            mock_docker_service.client.containers.get.side_effect = Exception("Not found")
            mock_docker_service_class.return_value = mock_docker_service

            mock_hub = AsyncMock()
            mock_hub.get_latest_tag.return_value = None
            mock_hub.get_github_release_version.return_value = None
            mock_docker_hub.return_value = mock_hub

            mock_trivy = AsyncMock()
            mock_trivy.get_scanner_version.return_value = "0.67.2"
            mock_trivy.get_database_info.return_value = None
            mock_trivy.check_db_freshness.return_value = (True, 2)
            mock_trivy_scanner_class.return_value = mock_trivy

            mock_bench = AsyncMock()
            mock_bench.get_scanner_version.return_value = None
            mock_bench_service_class.return_value = mock_bench

            # Act
            response = await authenticated_client.get("/api/v1/system/scanners")

            # Assert
            assert response.status_code == 200
            data = response.json()
            scanner_names = [s["name"] for s in data["scanners"]]
            assert "Dive" in scanner_names

    @pytest.mark.asyncio
    async def test_scanner_info_structure(self, authenticated_client: AsyncClient):
        """Test each scanner has expected structure."""
        with (
            patch("app.api.system.DockerService") as mock_docker_service_class,
            patch("app.api.system.get_docker_hub_client") as mock_docker_hub,
            patch("app.api.system.TrivyScanner") as mock_trivy_scanner_class,
            patch("app.api.system.DockerBenchService") as mock_bench_service_class,
        ):
            # Setup mocks
            mock_docker_service = MagicMock()
            mock_docker_service.get_trivy_container.return_value = MagicMock()
            mock_docker_service.client.images.get.side_effect = Exception("Not found")
            mock_docker_service.client.containers.get.side_effect = Exception("Not found")
            mock_docker_service_class.return_value = mock_docker_service

            mock_hub = AsyncMock()
            mock_hub.get_latest_tag.return_value = None
            mock_hub.get_github_release_version.return_value = None
            mock_docker_hub.return_value = mock_hub

            mock_trivy = AsyncMock()
            mock_trivy.get_scanner_version.return_value = "0.67.2"
            mock_trivy.get_database_info.return_value = None
            mock_trivy.check_db_freshness.return_value = (True, 2)
            mock_trivy_scanner_class.return_value = mock_trivy

            mock_bench = AsyncMock()
            mock_bench.get_scanner_version.return_value = None
            mock_bench_service_class.return_value = mock_bench

            # Act
            response = await authenticated_client.get("/api/v1/system/scanners")

            # Assert
            assert response.status_code == 200
            data = response.json()
            for scanner in data["scanners"]:
                assert "name" in scanner
                assert "enabled" in scanner
                assert "available" in scanner
                assert isinstance(scanner["enabled"], bool)
                assert isinstance(scanner["available"], bool)

    @pytest.mark.asyncio
    async def test_trivy_scanner_available_with_version(self, authenticated_client: AsyncClient):
        """Test Trivy scanner shows version when available."""
        with (
            patch("app.api.system.DockerService") as mock_docker_service_class,
            patch("app.api.system.get_docker_hub_client") as mock_docker_hub,
            patch("app.api.system.TrivyScanner") as mock_trivy_scanner_class,
            patch("app.api.system.DockerBenchService") as mock_bench_service_class,
        ):
            # Setup mocks
            mock_docker_service = MagicMock()
            mock_docker_service.get_trivy_container.return_value = MagicMock()
            mock_docker_service.client.images.get.side_effect = Exception("Not found")
            mock_docker_service.client.containers.get.side_effect = Exception("Not found")
            mock_docker_service_class.return_value = mock_docker_service

            mock_hub = AsyncMock()
            mock_hub.get_latest_tag.return_value = "0.68.0"
            mock_hub.get_github_release_version.return_value = None
            mock_docker_hub.return_value = mock_hub

            mock_trivy = AsyncMock()
            mock_trivy.get_scanner_version.return_value = "0.67.2"
            mock_trivy.get_database_info.return_value = {
                "db_version": "2",
                "updated_at": "2025-12-20T10:00:00Z",
            }
            mock_trivy.check_db_freshness.return_value = (True, 2)
            mock_trivy_scanner_class.return_value = mock_trivy

            mock_bench = AsyncMock()
            mock_bench.get_scanner_version.return_value = None
            mock_bench_service_class.return_value = mock_bench

            # Act
            response = await authenticated_client.get("/api/v1/system/scanners")

            # Assert
            assert response.status_code == 200
            data = response.json()
            trivy_scanner = next(s for s in data["scanners"] if s["name"] == "Trivy")
            assert trivy_scanner["version"] == "0.67.2"
            assert trivy_scanner["latest_version"] == "0.68.0"
            assert trivy_scanner["update_available"] is True

    @pytest.mark.asyncio
    async def test_trivy_scanner_db_info(self, authenticated_client: AsyncClient):
        """Test Trivy scanner includes database information."""
        with (
            patch("app.api.system.DockerService") as mock_docker_service_class,
            patch("app.api.system.get_docker_hub_client") as mock_docker_hub,
            patch("app.api.system.TrivyScanner") as mock_trivy_scanner_class,
            patch("app.api.system.DockerBenchService") as mock_bench_service_class,
        ):
            # Setup mocks
            mock_docker_service = MagicMock()
            mock_docker_service.get_trivy_container.return_value = MagicMock()
            mock_docker_service.client.images.get.side_effect = Exception("Not found")
            mock_docker_service.client.containers.get.side_effect = Exception("Not found")
            mock_docker_service_class.return_value = mock_docker_service

            mock_hub = AsyncMock()
            mock_hub.get_latest_tag.return_value = None
            mock_hub.get_github_release_version.return_value = None
            mock_docker_hub.return_value = mock_hub

            mock_trivy = AsyncMock()
            mock_trivy.get_scanner_version.return_value = "0.67.2"
            mock_trivy.get_database_info.return_value = {
                "db_version": 2,
                "updated_at": "2025-12-20T10:00:00Z",
            }
            mock_trivy.check_db_freshness.return_value = (True, 5)
            mock_trivy_scanner_class.return_value = mock_trivy

            mock_bench = AsyncMock()
            mock_bench.get_scanner_version.return_value = None
            mock_bench_service_class.return_value = mock_bench

            # Act
            response = await authenticated_client.get("/api/v1/system/scanners")

            # Assert
            assert response.status_code == 200
            data = response.json()
            trivy_scanner = next(s for s in data["scanners"] if s["name"] == "Trivy")
            assert trivy_scanner["db_version"] == "2"
            assert trivy_scanner["db_updated_at"] == "2025-12-20T10:00:00Z"
            assert trivy_scanner["db_age_hours"] == 5


class TestVersionComparison:
    """Test the _compare_versions function logic."""

    @pytest.mark.asyncio
    async def test_version_comparison_update_available(self, authenticated_client: AsyncClient):
        """Test version comparison detects updates."""
        with (
            patch("app.api.system.DockerService") as mock_docker_service_class,
            patch("app.api.system.get_docker_hub_client") as mock_docker_hub,
            patch("app.api.system.TrivyScanner") as mock_trivy_scanner_class,
            patch("app.api.system.DockerBenchService") as mock_bench_service_class,
        ):
            # Setup mocks
            mock_docker_service = MagicMock()
            mock_docker_service.get_trivy_container.return_value = MagicMock()
            mock_docker_service.client.images.get.side_effect = Exception("Not found")
            mock_docker_service.client.containers.get.side_effect = Exception("Not found")
            mock_docker_service_class.return_value = mock_docker_service

            mock_hub = AsyncMock()
            # Latest version is newer (0.68.0 > 0.67.2)
            mock_hub.get_latest_tag.return_value = "0.68.0"
            mock_hub.get_github_release_version.return_value = None
            mock_docker_hub.return_value = mock_hub

            mock_trivy = AsyncMock()
            mock_trivy.get_scanner_version.return_value = "0.67.2"
            mock_trivy.get_database_info.return_value = None
            mock_trivy.check_db_freshness.return_value = (True, 2)
            mock_trivy_scanner_class.return_value = mock_trivy

            mock_bench = AsyncMock()
            mock_bench.get_scanner_version.return_value = None
            mock_bench_service_class.return_value = mock_bench

            # Act
            response = await authenticated_client.get("/api/v1/system/scanners")

            # Assert
            assert response.status_code == 200
            data = response.json()
            trivy_scanner = next(s for s in data["scanners"] if s["name"] == "Trivy")
            assert trivy_scanner["update_available"] is True

    @pytest.mark.asyncio
    async def test_version_comparison_no_update(self, authenticated_client: AsyncClient):
        """Test version comparison when no update available."""
        with (
            patch("app.api.system.DockerService") as mock_docker_service_class,
            patch("app.api.system.get_docker_hub_client") as mock_docker_hub,
            patch("app.api.system.TrivyScanner") as mock_trivy_scanner_class,
            patch("app.api.system.DockerBenchService") as mock_bench_service_class,
        ):
            # Setup mocks
            mock_docker_service = MagicMock()
            mock_docker_service.get_trivy_container.return_value = MagicMock()
            mock_docker_service.client.images.get.side_effect = Exception("Not found")
            mock_docker_service.client.containers.get.side_effect = Exception("Not found")
            mock_docker_service_class.return_value = mock_docker_service

            mock_hub = AsyncMock()
            # Same version (0.67.2 == 0.67.2)
            mock_hub.get_latest_tag.return_value = "0.67.2"
            mock_hub.get_github_release_version.return_value = None
            mock_docker_hub.return_value = mock_hub

            mock_trivy = AsyncMock()
            mock_trivy.get_scanner_version.return_value = "0.67.2"
            mock_trivy.get_database_info.return_value = None
            mock_trivy.check_db_freshness.return_value = (True, 2)
            mock_trivy_scanner_class.return_value = mock_trivy

            mock_bench = AsyncMock()
            mock_bench.get_scanner_version.return_value = None
            mock_bench_service_class.return_value = mock_bench

            # Act
            response = await authenticated_client.get("/api/v1/system/scanners")

            # Assert
            assert response.status_code == 200
            data = response.json()
            trivy_scanner = next(s for s in data["scanners"] if s["name"] == "Trivy")
            assert trivy_scanner["update_available"] is False
