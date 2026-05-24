"""Tests for Dive image analysis service.

This module tests the Dive service which provides:
- Docker image layer efficiency analysis
- Wasted space detection
- Image size metrics
"""

from unittest.mock import MagicMock, patch

import pytest


class TestDiveService:
    """Test Dive service basic operations."""

    @pytest.mark.asyncio
    async def test_create_dive_service(self, mock_docker_service):
        """Test creating Dive service instance."""
        from app.services.dive_service import DiveService

        service = DiveService(mock_docker_service)
        assert service is not None
        assert service.docker_service == mock_docker_service

    @pytest.mark.asyncio
    async def test_analyze_image_success(self, mock_docker_service):
        """Test analyzing image successfully."""
        import io
        import json
        import tarfile

        from app.services.dive_service import DiveService

        # Mock dive container
        mock_container = MagicMock()
        mock_container.id = "dive-container-id"

        # exec_run is used for stale-output cleanup; return success.
        mock_container.exec_run.return_value = (0, b"")

        # Low-level api drives the dive exec (detached + polled).
        mock_docker_service.client.api.exec_create.return_value = {"Id": "exec-id"}
        mock_docker_service.client.api.exec_start.return_value = None
        mock_docker_service.client.api.exec_inspect.return_value = {
            "Running": False,
            "ExitCode": 0,
        }

        # Mock dive output data
        dive_output = {
            "layer": [
                {"id": "layer1", "Size": 1000000},
                {"id": "layer2", "Size": 500000},
            ],
            "image": {
                "sizeBytes": 1500000,
                "inefficientBytes": 100000,
                "efficiencyScore": 0.93,
            },
        }

        # Create a tar archive with the JSON data
        tar_buffer = io.BytesIO()
        with tarfile.open(fileobj=tar_buffer, mode="w") as tar:
            json_data = json.dumps(dive_output).encode()
            info = tarfile.TarInfo(name="result.json")
            info.size = len(json_data)
            tar.addfile(info, io.BytesIO(json_data))
        tar_buffer.seek(0)

        # get_archive returns (tar_stream_iter, stats_dict)
        mock_container.get_archive.return_value = ([tar_buffer.read()], {})

        mock_docker_service.client.containers.get.return_value = mock_container

        service = DiveService(mock_docker_service)

        # Act
        result = await service.analyze_image("nginx:latest")

        # Assert
        assert result is not None
        assert "efficiency_score" in result
        assert "inefficient_bytes" in result
        assert "image_size_bytes" in result
        assert "layer_count" in result
        assert "analysis_duration" in result
        assert isinstance(result["efficiency_score"], float)
        assert 0 <= result["efficiency_score"] <= 1.0

    @pytest.mark.asyncio
    async def test_analyze_image_timeout_kills_dive(self, mock_docker_service):
        """A dive run that never finishes must time out and have its process killed."""
        from app.services.dive_service import DiveError, DiveService

        mock_container = MagicMock()
        mock_container.id = "dive-container-id"
        # rm cleanup + killall + pgrep all go through exec_run; return success
        # for everything (pgrep exit 1 = no match left after killall).
        mock_container.exec_run.return_value = (1, b"")

        mock_docker_service.client.api.exec_create.return_value = {"Id": "exec-id"}
        mock_docker_service.client.api.exec_start.return_value = None
        # Always Running -> forces the timeout path
        mock_docker_service.client.api.exec_inspect.return_value = {
            "Running": True,
            "ExitCode": None,
        }
        mock_docker_service.client.containers.get.return_value = mock_container

        service = DiveService(mock_docker_service)

        with pytest.raises(DiveError, match="timed out after 1s"):
            await service.analyze_image("nginx:latest", timeout=1)

        # Verify SIGTERM was attempted on the runaway dive process
        kill_calls = [
            call.args[0]
            for call in mock_container.exec_run.call_args_list
            if call.args and call.args[0] == ["killall", "dive"]
        ]
        assert kill_calls, "Expected killall dive to be invoked on timeout"

    @pytest.mark.asyncio
    async def test_analyze_nonexistent_image(self, mock_docker_service):
        """Test analyzing non-existent image raises DiveError."""
        from app.services.dive_service import DiveError, DiveService

        # Mock Docker error
        mock_docker_service.client.containers.run.side_effect = Exception("Image not found")

        service = DiveService(mock_docker_service)

        # Act/Assert
        with pytest.raises(DiveError):
            await service.analyze_image("nonexistent:latest")

    @pytest.mark.asyncio
    async def test_socket_proxy_timeout_wrapped_as_dive_error(self, mock_docker_service):
        """Socket-proxy read timeouts on containers.get() must surface as DiveError.

        Regression: a raw requests.exceptions.ReadTimeout used to bubble past the
        non-blocking Dive guard in scan_queue._run_dive_analysis and fail the
        whole scan even though Trivy had already succeeded.
        """
        from requests.exceptions import ReadTimeout

        from app.services.dive_service import DiveError, DiveService

        mock_docker_service.client.containers.get.side_effect = ReadTimeout(
            "HTTPConnectionPool(host='socket-proxy-rw', port=2375): Read timed out."
        )

        service = DiveService(mock_docker_service)

        with pytest.raises(DiveError, match="Failed to connect to Dive container"):
            await service.analyze_image("nginx:latest")

    @pytest.mark.skip(reason="Complex Docker SDK mock - tested in integration tests")
    async def test_analyze_image_calculates_layer_count(self, mock_docker_service):
        """Test that analysis includes layer count (integration test)."""
        pass

    @pytest.mark.skip(reason="Complex Docker SDK mock - tested in integration tests")
    async def test_analyze_image_perfect_efficiency(self, mock_docker_service):
        """Test analyzing image with perfect efficiency (integration test)."""
        pass

    @pytest.mark.skip(reason="Complex Docker SDK mock - tested in integration tests")
    async def test_analyze_image_poor_efficiency(self, mock_docker_service):
        """Test analyzing image with poor efficiency (integration test)."""
        pass


class TestDiveErrorHandling:
    """Test Dive service error handling."""

    @pytest.mark.asyncio
    async def test_dive_error_exception(self, mock_docker_service):
        """Test that DiveError is raised on failures."""
        from app.services.dive_service import DiveError, DiveService

        # Mock container failure
        mock_container = MagicMock()
        mock_container.wait.return_value = {"StatusCode": 1}
        mock_docker_service.client.containers.run.return_value = mock_container

        service = DiveService(mock_docker_service)

        with pytest.raises(DiveError):
            await service.analyze_image("test:latest")

    @pytest.mark.asyncio
    async def test_dive_error_on_missing_export(self, mock_docker_service):
        """Test that DiveError is raised when export file is missing."""
        from app.services.dive_service import DiveError, DiveService

        mock_container = MagicMock()
        mock_container.wait.return_value = {"StatusCode": 0}
        mock_docker_service.client.containers.run.return_value = mock_container

        # Mock tarfile not finding the export file
        with patch("tarfile.open") as mock_tarfile:
            mock_tar = MagicMock()
            mock_tar.extractfile.return_value = None
            mock_tarfile.return_value.__enter__.return_value = mock_tar

            service = DiveService(mock_docker_service)

            with pytest.raises(DiveError):
                await service.analyze_image("test:latest")
