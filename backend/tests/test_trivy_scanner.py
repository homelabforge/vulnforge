"""Tests for Trivy scanner service."""

import asyncio
import json
from unittest.mock import MagicMock, patch

import pytest
from docker.errors import DockerException


def _make_trivy_container(exit_code: int, payload: dict | str):
    """Helper to create a mocked Trivy container exec result."""
    container = MagicMock()
    output_str = payload if isinstance(payload, str) else json.dumps(payload)
    output = output_str.encode("utf-8")
    container.exec_run.return_value = (exit_code, output)
    return container


@pytest.mark.asyncio
class TestTrivyScanner:
    """Tests for core Trivy scanner behaviour."""

    @patch("app.services.trivy_scanner.DockerService")
    async def test_scan_image_success(self, mock_docker_service):
        """Successful scans return parsed vulnerability metadata."""
        from app.services.trivy_scanner import TrivyScanner

        trivy_output = {
            "Results": [
                {
                    "Target": "nginx:latest",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2024-0001",
                            "PkgName": "openssl",
                            "Severity": "HIGH",
                            "InstalledVersion": "1.0.0",
                            "FixedVersion": "1.0.2",
                            "Title": "OpenSSL issue",
                            "References": ["https://example.com/cve"],
                        }
                    ],
                }
            ]
        }

        trivy_container = _make_trivy_container(0, trivy_output)
        docker_service = MagicMock()
        docker_service.get_trivy_container.return_value = trivy_container
        mock_docker_service.return_value = docker_service

        scanner = TrivyScanner(docker_service)
        result = await scanner.scan_image("nginx:latest")

        assert result is not None
        assert result["total_count"] == 1
        assert result["high_count"] == 1
        assert result["vulnerabilities"][0]["cve_id"] == "CVE-2024-0001"
        trivy_container.exec_run.assert_called_once()

    @patch("app.services.trivy_scanner.DockerService")
    async def test_scan_image_handles_invalid_json(self, mock_docker_service):
        """Invalid JSON output should return None rather than raising."""
        from app.services.trivy_scanner import TrivyScanner

        trivy_container = _make_trivy_container(0, "not valid json{")
        docker_service = MagicMock()
        docker_service.get_trivy_container.return_value = trivy_container
        mock_docker_service.return_value = docker_service

        scanner = TrivyScanner(docker_service)
        result = await scanner.scan_image("nginx:latest")

        assert result is None

    @patch("app.services.trivy_scanner.DockerService")
    async def test_scan_image_handles_docker_errors(self, mock_docker_service):
        """Docker errors should be swallowed and reported as None."""
        from app.services.trivy_scanner import TrivyScanner

        docker_service = MagicMock()
        docker_service.get_trivy_container.side_effect = DockerException("not available")
        mock_docker_service.return_value = docker_service

        scanner = TrivyScanner(docker_service)
        result = await scanner.scan_image("nginx:latest")

        assert result is None

    @patch("app.services.trivy_scanner.DockerService")
    async def test_scan_image_respects_skip_db_update_flag(self, mock_docker_service):
        """Setting skip_db_update adds the proper CLI flag."""
        from app.services.trivy_scanner import TrivyScanner

        trivy_container = _make_trivy_container(0, {"Results": []})
        docker_service = MagicMock()
        docker_service.get_trivy_container.return_value = trivy_container
        mock_docker_service.return_value = docker_service

        scanner = TrivyScanner(docker_service)
        await scanner.scan_image("nginx:latest", skip_db_update=True)

        exec_args = trivy_container.exec_run.call_args[0][0]
        assert "--skip-db-update" in exec_args

    @patch("app.services.trivy_scanner.DockerService")
    async def test_scan_image_parses_and_redacts_secrets(self, mock_docker_service):
        """Secrets are parsed and redacted from Trivy output."""
        from app.services.trivy_scanner import TrivyScanner

        trivy_output = {
            "Results": [
                {
                    "Target": "/app/config.py",
                    "Secrets": [
                        {
                            "RuleID": "generic-api-key",
                            "Category": "general",
                            "Severity": "HIGH",
                            "Title": "API Key",
                            "Match": "api_key=supersecret",
                            "Code": {
                                "Lines": [
                                    {
                                        "Number": 10,
                                        "Content": "api_key=supersecret",
                                        "IsCause": True,
                                    }
                                ]
                            },
                        }
                    ],
                }
            ]
        }

        trivy_container = _make_trivy_container(0, trivy_output)
        docker_service = MagicMock()
        docker_service.get_trivy_container.return_value = trivy_container
        mock_docker_service.return_value = docker_service

        scanner = TrivyScanner(docker_service)
        result = await scanner.scan_image("nginx:latest")

        assert result is not None
        assert result["secrets"]
        secret = result["secrets"][0]
        assert secret["match"] == "***REDACTED***"
        assert "***REDACTED***" in secret["code_snippet"]

    @patch("app.services.trivy_scanner.DockerService")
    async def test_scan_image_returns_none_when_trivy_container_missing(self, mock_docker_service):
        """Missing Trivy container should cancel the scan."""
        from app.services.trivy_scanner import TrivyScanner

        docker_service = MagicMock()
        docker_service.get_trivy_container.return_value = None
        mock_docker_service.return_value = docker_service

        scanner = TrivyScanner(docker_service)
        result = await scanner.scan_image("nginx:latest")

        assert result is None


@pytest.mark.asyncio
class TestTrivyDatabaseInfo:
    """Tests for Trivy database metadata inspection."""

    @patch("app.services.trivy_scanner.DockerService")
    async def test_get_database_info_parses_version_output(self, mock_docker_service):
        """Database info should parse structured version output."""
        from app.services.trivy_scanner import TrivyScanner

        version_output = (
            "Version: 0.47.0\n"
            "Vulnerability DB:\n"
            "  Version: 123\n"
            "  UpdatedAt: 2024-11-01T12:00:00Z\n"
            "  NextUpdate: 2024-11-01T18:00:00Z\n"
        )

        trivy_container = _make_trivy_container(0, version_output)
        docker_service = MagicMock()
        docker_service.get_trivy_container.return_value = trivy_container
        mock_docker_service.return_value = docker_service

        scanner = TrivyScanner(docker_service)
        info = await scanner.get_database_info()

        assert info is not None
        assert info["db_version"] == 123
        assert info["updated_at"] == "2024-11-01T12:00:00Z"
        assert info["next_update"] == "2024-11-01T18:00:00Z"

    @patch("app.services.trivy_scanner.DockerService")
    async def test_get_database_info_handles_failures(self, mock_docker_service):
        """Failures to read database info should return None."""
        from app.services.trivy_scanner import TrivyScanner

        trivy_container = _make_trivy_container(1, "")
        docker_service = MagicMock()
        docker_service.get_trivy_container.return_value = trivy_container
        mock_docker_service.return_value = docker_service

        scanner = TrivyScanner(docker_service)
        info = await scanner.get_database_info()

        assert info is None


def _make_server_mode_scanner(docker_service):
    """Create a TrivyScanner configured for client/server mode."""
    from app.services.trivy_scanner import TrivyScanner

    with patch("app.services.trivy_scanner.settings") as mock_settings:
        mock_settings.trivy_server = "http://trivy:8080"
        mock_settings.trivy_container_name = "trivy"
        mock_settings.parallel_scans = 3
        mock_settings.scan_timeout = 300
        mock_settings.trivy_max_lock_retries = 3
        mock_settings.trivy_max_corruption_retries = 1
        mock_settings.trivy_lock_retry_base_wait = 2
        mock_settings.trivy_lock_retry_backoff_multiplier = 2
        scanner = TrivyScanner(docker_service)
    return scanner


@pytest.mark.asyncio
class TestTrivyConcurrency:
    """Tests for parallel scanning concurrency control."""

    @patch("app.services.trivy_scanner.DockerService")
    async def test_client_mode_passes_use_server_true(self, mock_docker_service):
        """Client/server mode should pass use_server=True to _exec_trivy_command."""
        trivy_output = json.dumps({"Results": []}).encode()
        docker_service = MagicMock()
        trivy_container = MagicMock()
        docker_service.get_trivy_container.return_value = trivy_container
        mock_docker_service.return_value = docker_service

        scanner = _make_server_mode_scanner(docker_service)

        use_server_values = []

        async def capture_exec(container, cmd, *, use_server=False, **kwargs):
            use_server_values.append(use_server)
            return (0, trivy_output)

        scanner._exec_trivy_command = capture_exec  # type: ignore[assignment]

        await scanner.scan_image("nginx:latest")

        assert any(use_server_values), "Client mode should pass use_server=True"

    @patch("app.services.trivy_scanner.DockerService")
    async def test_exec_mode_passes_use_server_false(self, mock_docker_service):
        """Exec mode should pass use_server=False to _exec_trivy_command."""
        from app.services.trivy_scanner import TrivyScanner

        trivy_output = json.dumps({"Results": []}).encode()
        docker_service = MagicMock()
        trivy_container = MagicMock()
        docker_service.get_trivy_container.return_value = trivy_container
        mock_docker_service.return_value = docker_service

        scanner = TrivyScanner(docker_service)

        use_server_values = []

        async def capture_exec(container, cmd, *, use_server=False, **kwargs):
            use_server_values.append(use_server)
            return (0, trivy_output)

        scanner._exec_trivy_command = capture_exec  # type: ignore[assignment]

        await scanner.scan_image("nginx:latest")

        assert not any(use_server_values), "Exec mode should pass use_server=False"

    @patch("app.services.trivy_scanner.DockerService")
    async def test_client_mode_appends_skip_db_update(self, mock_docker_service):
        """Client mode should always pass --skip-db-update to the client CLI."""
        trivy_output = {"Results": []}
        trivy_container = _make_trivy_container(0, trivy_output)
        docker_service = MagicMock()
        docker_service.get_trivy_container.return_value = trivy_container
        mock_docker_service.return_value = docker_service

        scanner = _make_server_mode_scanner(docker_service)
        # Even without explicit skip_db_update=True, client mode should force it
        await scanner.scan_image("nginx:latest", skip_db_update=False)

        exec_args = trivy_container.exec_run.call_args[0][0]
        assert "--skip-db-update" in exec_args
        assert "--server" in exec_args

    @patch("app.services.trivy_scanner.DockerService")
    async def test_fallback_increments_counter(self, mock_docker_service):
        """Fallback from client to exec mode should increment fallback_count."""
        trivy_output = {"Results": []}
        # First call (client mode) fails, second call (exec fallback) succeeds
        trivy_container = MagicMock()
        trivy_container.exec_run.side_effect = [
            (1, b"server unavailable"),  # client mode fails
            (0, json.dumps(trivy_output).encode()),  # exec fallback succeeds
        ]
        docker_service = MagicMock()
        docker_service.get_trivy_container.return_value = trivy_container
        mock_docker_service.return_value = docker_service

        scanner = _make_server_mode_scanner(docker_service)
        await scanner.scan_image("nginx:latest")

        stats = scanner.get_scan_stats()
        assert stats["fallback_count"] == 1
        assert stats["exec_mode_count"] == 1
        assert stats["client_mode_count"] == 0

    @patch("app.services.trivy_scanner.DockerService")
    async def test_successful_client_scan_increments_client_count(self, mock_docker_service):
        """Successful client mode scan should increment client_mode_count."""
        trivy_output = {"Results": []}
        trivy_container = _make_trivy_container(0, trivy_output)
        docker_service = MagicMock()
        docker_service.get_trivy_container.return_value = trivy_container
        mock_docker_service.return_value = docker_service

        scanner = _make_server_mode_scanner(docker_service)
        await scanner.scan_image("nginx:latest")

        stats = scanner.get_scan_stats()
        assert stats["client_mode_count"] == 1
        assert stats["exec_mode_count"] == 0
        assert stats["fallback_count"] == 0

    @patch("app.services.trivy_scanner.DockerService")
    async def test_reset_scan_stats_clears_counters(self, mock_docker_service):
        """reset_scan_stats should zero all counters."""
        trivy_output = {"Results": []}
        trivy_container = _make_trivy_container(0, trivy_output)
        docker_service = MagicMock()
        docker_service.get_trivy_container.return_value = trivy_container
        mock_docker_service.return_value = docker_service

        scanner = _make_server_mode_scanner(docker_service)
        await scanner.scan_image("nginx:latest")
        assert scanner.get_scan_stats()["client_mode_count"] == 1

        scanner.reset_scan_stats()
        stats = scanner.get_scan_stats()
        assert stats["client_mode_count"] == 0
        assert stats["exec_mode_count"] == 0
        assert stats["fallback_count"] == 0

    @patch("app.services.trivy_scanner.DockerService")
    async def test_concurrent_client_scans_not_serialized(self, mock_docker_service):
        """Multiple client-mode scans should run concurrently, not serialize."""
        trivy_output = json.dumps({"Results": []}).encode()

        trivy_container = MagicMock()
        docker_service = MagicMock()
        docker_service.get_trivy_container.return_value = trivy_container
        mock_docker_service.return_value = docker_service

        scanner = _make_server_mode_scanner(docker_service)

        # Override _exec_trivy_command to simulate slow scans and track concurrency
        max_concurrent = 0
        current_concurrent = 0
        concurrency_lock = asyncio.Lock()

        async def tracked_exec(container, cmd, *, use_server=False, **kwargs):
            nonlocal max_concurrent, current_concurrent
            async with concurrency_lock:
                current_concurrent += 1
                if current_concurrent > max_concurrent:
                    max_concurrent = current_concurrent
            # Yield to allow other tasks to enter
            await asyncio.sleep(0.01)
            try:
                return (0, trivy_output)
            finally:
                async with concurrency_lock:
                    current_concurrent -= 1

        scanner._exec_trivy_command = tracked_exec  # type: ignore[assignment]

        # Launch 3 scans concurrently
        tasks = [asyncio.create_task(scanner.scan_image(f"image-{i}:latest")) for i in range(3)]
        await asyncio.gather(*tasks)

        assert max_concurrent >= 2, (
            f"Expected concurrent execution but max_concurrent={max_concurrent}. "
            "Client mode should use semaphore, not exclusive lock."
        )
