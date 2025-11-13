"""Tests for Trivy scanner service."""

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
                                    {"Number": 10, "Content": "api_key=supersecret", "IsCause": True}
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
