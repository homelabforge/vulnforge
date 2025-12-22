"""Tests for Docker client service.

This module tests the DockerService which provides:
- Docker connection management with fallbacks
- Container listing and discovery
- Container inspection
- Trivy container access
"""

import sys
from unittest.mock import MagicMock, patch

from docker.errors import NotFound


class TestDockerServiceInit:
    """Test DockerService initialization and connection."""

    def test_init_creates_client(self):
        """Test initialization creates Docker client."""
        # Remove module if already loaded
        if "app.services.docker_client" in sys.modules:
            del sys.modules["app.services.docker_client"]

        with patch(
            "app.services.docker_client.DockerService._connect_with_fallbacks"
        ) as mock_connect:
            mock_client = MagicMock()
            mock_connect.return_value = mock_client

            from app.services.docker_client import DockerService

            service = DockerService()

            assert service.client is not None
            mock_connect.assert_called_once()


class TestListContainers:
    """Test list_containers method."""

    def test_list_containers_all(self):
        """Test listing all containers including stopped."""
        if "app.services.docker_client" in sys.modules:
            del sys.modules["app.services.docker_client"]

        with patch(
            "app.services.docker_client.DockerService._connect_with_fallbacks"
        ) as mock_connect:
            # Mock container
            mock_container = MagicMock()
            mock_container.id = "abc123"
            mock_container.name = "nginx-prod"
            mock_container.status = "running"

            mock_image = MagicMock()
            mock_image.tags = ["nginx:1.25"]
            mock_image.id = "sha256:abc123"
            mock_container.image = mock_image

            # Set up the client mock properly
            mock_client = MagicMock()
            mock_client.containers.list.return_value = [mock_container]
            mock_connect.return_value = mock_client

            from app.services.docker_client import DockerService

            service = DockerService()

            # Act
            result = service.list_containers(all_containers=True)

            # Assert
            assert len(result) == 1
            service.client.containers.list.assert_called_once_with(all=True)

            container_data = result[0]
            assert container_data["name"] == "nginx-prod"
            assert container_data["image"] == "nginx"
            assert container_data["image_tag"] == "1.25"
            assert container_data["status"] == "running"

    def test_list_containers_running_only(self):
        """Test listing only running containers."""
        if "app.services.docker_client" in sys.modules:
            del sys.modules["app.services.docker_client"]

        with patch(
            "app.services.docker_client.DockerService._connect_with_fallbacks"
        ) as mock_connect:
            mock_client = MagicMock()
            mock_client.containers.list.return_value = []
            mock_connect.return_value = mock_client

            from app.services.docker_client import DockerService

            service = DockerService()

            # Act
            result = service.list_containers(all_containers=False)

            # Assert
            service.client.containers.list.assert_called_once_with(all=False)
            assert isinstance(result, list)
            assert len(result) == 0


class TestGetContainer:
    """Test get_container method."""

    def test_get_container_success(self):
        """Test getting container by name."""
        with patch("app.services.docker_client.DockerService._connect_with_fallbacks"):
            from app.services.docker_client import DockerService

            service = DockerService()

            mock_container = MagicMock()
            mock_container.id = "abc123"
            mock_container.name = "test-container"
            mock_container.status = "running"

            mock_image = MagicMock()
            mock_image.tags = ["nginx:latest"]
            mock_image.id = "sha256:abc123"
            mock_container.image = mock_image

            service.client = MagicMock()
            service.client.containers.get.return_value = mock_container

            # Act
            result = service.get_container("test-container")

            # Assert
            assert result is not None
            assert result["id"] == "abc123"
            assert result["name"] == "test-container"
            assert result["image"] == "nginx"
            assert result["image_tag"] == "latest"

    def test_get_container_not_found(self):
        """Test getting non-existent container."""
        with patch("app.services.docker_client.DockerService._connect_with_fallbacks"):
            from app.services.docker_client import DockerService

            service = DockerService()
            service.client = MagicMock()
            service.client.containers.get.side_effect = NotFound("Container not found")

            # Act
            result = service.get_container("nonexistent")

            # Assert
            assert result is None


class TestGetTrivyContainer:
    """Test get_trivy_container method."""

    def test_get_trivy_container_found(self):
        """Test finding Trivy container."""
        with patch("app.services.docker_client.DockerService._connect_with_fallbacks"):
            with patch("app.config.settings.trivy_container_name", "trivy"):
                from app.services.docker_client import DockerService

                service = DockerService()

                # Mock Trivy container
                mock_trivy = MagicMock()
                mock_trivy.name = "trivy"
                mock_trivy.status = "running"

                service.client = MagicMock()
                service.client.containers.get.return_value = mock_trivy

                # Act
                result = service.get_trivy_container()

                # Assert
                assert result is not None
                assert result.name == "trivy"

    def test_get_trivy_container_not_found(self):
        """Test when Trivy container doesn't exist."""
        with patch("app.services.docker_client.DockerService._connect_with_fallbacks"):
            with patch("app.config.settings.trivy_container_name", "trivy"):
                from app.services.docker_client import DockerService

                service = DockerService()
                service.client = MagicMock()
                service.client.containers.get.side_effect = NotFound("Container not found")

                # Act
                result = service.get_trivy_container()

                # Assert
                assert result is None


class TestHelperMethods:
    """Test helper methods."""

    def test_parse_image_tag_with_tag(self):
        """Test parsing image name with tag."""
        from app.services.docker_client import DockerService

        # Act
        name, tag = DockerService._parse_image_tag("nginx:1.25")

        # Assert
        assert name == "nginx"
        assert tag == "1.25"

    def test_parse_image_tag_no_tag(self):
        """Test parsing image name without tag."""
        from app.services.docker_client import DockerService

        # Act
        name, tag = DockerService._parse_image_tag("alpine")

        # Assert
        assert name == "alpine"
        assert tag == "latest"

    def test_parse_image_tag_with_registry(self):
        """Test parsing image with registry prefix."""
        from app.services.docker_client import DockerService

        # Act
        name, tag = DockerService._parse_image_tag("ghcr.io/myorg/myapp:v1.0.0")

        # Assert
        assert "myapp" in name
        assert tag == "v1.0.0"
