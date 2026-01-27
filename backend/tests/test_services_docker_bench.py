"""DEPRECATED: Tests for Docker Bench Security service.

These tests are for the deprecated docker_bench_service.py. The native
VulnForge compliance checker (compliance_checker.py) is now used instead.
These tests are kept for reference only.

Original functionality tested:
- CIS Docker Benchmark compliance scanning
- Compliance scoring based on findings
- Category-specific score calculation
- Scanner version detection
"""

from unittest.mock import MagicMock

import pytest


class TestDockerBenchService:
    """Test Docker Bench service basic operations."""

    @pytest.mark.asyncio
    async def test_create_docker_bench_service(self, mock_docker_service):
        """Test creating Docker Bench service instance."""
        from app.services.docker_bench_service import DockerBenchService

        service = DockerBenchService(mock_docker_service)
        assert service is not None
        assert service.docker_service == mock_docker_service

    @pytest.mark.asyncio
    async def test_run_compliance_scan_success(self, mock_docker_service):
        """Test running successful compliance scan."""
        from app.services.docker_bench_service import DockerBenchService

        # Mock Docker container execution
        mock_container = MagicMock()
        mock_container.wait.return_value = {"StatusCode": 0}
        # logs() returns an iterator of log lines
        log_output = [
            "[PASS] 1.1.1 Ensure a separate partition for containers has been created",
            "[WARN] 1.2.1 Ensure the container host has been Hardened",
            "[FAIL] 2.1 Ensure network traffic is restricted between containers on the default bridge",
        ]
        mock_container.logs.return_value = iter(log_output)
        mock_docker_service.client.containers.run.return_value = mock_container

        service = DockerBenchService(mock_docker_service)

        # Act
        result = await service.run_compliance_scan()

        # Assert
        assert result is not None
        assert "findings" in result
        assert "scan_duration_seconds" in result
        assert "raw_output" in result
        assert isinstance(result["findings"], list)
        assert len(result["findings"]) >= 3

    @pytest.mark.asyncio
    async def test_run_compliance_scan_returns_none_on_error(self, mock_docker_service):
        """Test compliance scan returns None on Docker error."""
        from app.services.docker_bench_service import DockerBenchService

        # Mock Docker error
        mock_docker_service.client.containers.run.side_effect = Exception("Docker error")

        service = DockerBenchService(mock_docker_service)

        # Act
        result = await service.run_compliance_scan()

        # Assert
        assert result is None

    @pytest.mark.asyncio
    async def test_calculate_compliance_score(self, mock_docker_service):
        """Test calculating compliance score from findings."""
        from app.services.docker_bench_service import DockerBenchService

        service = DockerBenchService(mock_docker_service)

        # Arrange - findings with different statuses
        findings = [
            {"status": "PASS"},
            {"status": "PASS"},
            {"status": "PASS"},
            {"status": "WARN"},
            {"status": "FAIL"},
        ]

        # Act
        score = service.calculate_compliance_score(findings)

        # Assert
        assert isinstance(score, float)
        assert 0 <= score <= 100
        # 3 PASS out of 5 total = 60% base score
        assert 50 <= score <= 70  # Allow some variance for WARN partial credit

    @pytest.mark.asyncio
    async def test_calculate_compliance_score_all_pass(self, mock_docker_service):
        """Test perfect compliance score."""
        from app.services.docker_bench_service import DockerBenchService

        service = DockerBenchService(mock_docker_service)

        findings = [{"status": "PASS"} for _ in range(10)]

        score = service.calculate_compliance_score(findings)

        assert score == 100.0

    @pytest.mark.asyncio
    async def test_calculate_compliance_score_all_fail(self, mock_docker_service):
        """Test zero compliance score."""
        from app.services.docker_bench_service import DockerBenchService

        service = DockerBenchService(mock_docker_service)

        findings = [{"status": "FAIL"} for _ in range(10)]

        score = service.calculate_compliance_score(findings)

        assert score == 0.0

    @pytest.mark.asyncio
    async def test_calculate_category_scores(self, mock_docker_service):
        """Test calculating scores by category."""
        from app.services.docker_bench_service import DockerBenchService

        service = DockerBenchService(mock_docker_service)

        # Arrange - findings from different categories
        findings = [
            {"check_id": "1.1.1", "status": "PASS", "category": "Host Configuration"},
            {"check_id": "1.2.1", "status": "FAIL", "category": "Host Configuration"},
            {"check_id": "2.1", "status": "PASS", "category": "Docker daemon configuration"},
            {"check_id": "2.2", "status": "PASS", "category": "Docker daemon configuration"},
            {"check_id": "3.1", "status": "WARN", "category": "Docker daemon configuration files"},
        ]

        # Act
        category_scores = service.calculate_category_scores(findings)

        # Assert
        assert isinstance(category_scores, dict)
        assert len(category_scores) >= 2  # At least categories 1, 2, 3
        # Each score should be 0-100
        for score in category_scores.values():
            assert 0 <= score <= 100

    @pytest.mark.asyncio
    async def test_get_scanner_version(self, mock_docker_service):
        """Test getting Docker Bench scanner version."""
        from app.services.docker_bench_service import DockerBenchService

        # Mock Docker image inspection
        mock_image = MagicMock()
        mock_image.labels = {"version": "1.3.6"}
        mock_docker_service.client.images.get.return_value = mock_image

        service = DockerBenchService(mock_docker_service)

        # Act
        version = await service.get_scanner_version()

        # Assert
        assert version is not None
        assert isinstance(version, str)

    @pytest.mark.asyncio
    async def test_get_scanner_version_returns_none_on_error(self, mock_docker_service):
        """Test scanner version returns None on error."""
        from app.services.docker_bench_service import DockerBenchService

        # Mock Docker error
        mock_docker_service.client.images.get.side_effect = Exception("Image not found")

        service = DockerBenchService(mock_docker_service)

        # Act
        version = await service.get_scanner_version()

        # Assert
        assert version is None


class TestDockerBenchParsing:
    """Test Docker Bench output parsing."""

    @pytest.mark.asyncio
    async def test_parse_pass_finding(self, mock_docker_service):
        """Test parsing PASS finding from output."""
        from app.services.docker_bench_service import DockerBenchService

        mock_container = MagicMock()
        mock_container.wait.return_value = {"StatusCode": 0}
        mock_container.logs.return_value = iter(
            ["[PASS] 1.1.1 Ensure a separate partition for containers has been created"]
        )
        mock_docker_service.client.containers.run.return_value = mock_container

        service = DockerBenchService(mock_docker_service)
        result = await service.run_compliance_scan()

        assert result is not None
        findings = result["findings"]
        assert len(findings) >= 1
        assert findings[0]["status"] == "PASS"
        assert "1.1.1" in findings[0]["check_id"]

    @pytest.mark.asyncio
    async def test_parse_warn_finding(self, mock_docker_service):
        """Test parsing WARN finding from output."""
        from app.services.docker_bench_service import DockerBenchService

        mock_container = MagicMock()
        mock_container.wait.return_value = {"StatusCode": 0}
        mock_container.logs.return_value = iter(
            ["[WARN] 1.2.1 Ensure the container host has been Hardened"]
        )
        mock_docker_service.client.containers.run.return_value = mock_container

        service = DockerBenchService(mock_docker_service)
        result = await service.run_compliance_scan()

        assert result is not None
        findings = result["findings"]
        assert len(findings) >= 1
        assert findings[0]["status"] == "WARN"
        assert "1.2.1" in findings[0]["check_id"]

    @pytest.mark.asyncio
    async def test_parse_fail_finding(self, mock_docker_service):
        """Test parsing FAIL finding from output."""
        from app.services.docker_bench_service import DockerBenchService

        mock_container = MagicMock()
        mock_container.wait.return_value = {"StatusCode": 0}
        mock_container.logs.return_value = iter(
            ["[FAIL] 2.1 Ensure network traffic is restricted between containers"]
        )
        mock_docker_service.client.containers.run.return_value = mock_container

        service = DockerBenchService(mock_docker_service)
        result = await service.run_compliance_scan()

        assert result is not None
        findings = result["findings"]
        assert len(findings) >= 1
        assert findings[0]["status"] == "FAIL"
        assert "2.1" in findings[0]["check_id"]
