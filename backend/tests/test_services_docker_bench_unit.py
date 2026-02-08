"""Unit tests for Docker Bench service — parsing and scoring logic.

Tests pure functions that don't require Docker:
- Single line parsing (_parse_single_check_line)
- Output parsing (_parse_docker_bench_output)
- Category determination (_determine_category)
- Severity determination (_determine_severity)
- Compliance score calculation (calculate_compliance_score)
- Category score calculation (calculate_category_scores)
"""

from unittest.mock import MagicMock

import pytest

from app.services.docker_bench_service import DockerBenchService


@pytest.fixture
def service():
    """Create a DockerBenchService with a mocked DockerService."""
    mock_docker = MagicMock()
    return DockerBenchService(mock_docker)


# ============================================================
# _parse_single_check_line
# ============================================================


class TestParseSingleCheckLine:
    """Test single line parsing."""

    def test_parse_pass_line(self, service):
        line = "[PASS] 1.1.1 - Ensure a separate partition for containers has been created"
        result = service._parse_single_check_line(line)
        assert result is not None
        assert result["check_id"] == "1.1.1"
        assert result["status"] == "PASS"
        assert "separate partition" in result["title"]

    def test_parse_warn_line(self, service):
        line = "[WARN] 2.1 - Ensure network traffic is restricted between containers"
        result = service._parse_single_check_line(line)
        assert result is not None
        assert result["check_id"] == "2.1"
        assert result["status"] == "WARN"
        assert result["severity"] == "MEDIUM"

    def test_parse_fail_line(self, service):
        line = "[FAIL] 4.5 - Ensure Content trust for Docker is Enabled"
        result = service._parse_single_check_line(line)
        assert result is not None
        assert result["check_id"] == "4.5"
        assert result["status"] == "FAIL"
        assert result["severity"] == "HIGH"

    def test_parse_info_line(self, service):
        line = "[INFO] 1.1.3 - Ensure auditing is configured for the Docker daemon"
        result = service._parse_single_check_line(line)
        assert result is not None
        assert result["check_id"] == "1.1.3"
        assert result["status"] == "INFO"
        assert result["severity"] == "INFO"

    def test_parse_note_line(self, service):
        line = "[NOTE] 1.1.4 - Some informational note about configuration"
        result = service._parse_single_check_line(line)
        assert result is not None
        assert result["status"] == "NOTE"
        assert result["severity"] == "LOW"

    def test_parse_ansi_stripped(self, service):
        """ANSI color codes should be stripped before parsing."""
        line = "\x1b[1;32m[PASS]\x1b[0m 1.1.1 - Ensure separate partition"
        result = service._parse_single_check_line(line)
        assert result is not None
        assert result["check_id"] == "1.1.1"
        assert result["status"] == "PASS"

    def test_parse_non_check_line(self, service):
        result = service._parse_single_check_line("This is just a log message")
        assert result is None

    def test_parse_empty_line(self, service):
        result = service._parse_single_check_line("")
        assert result is None

    def test_parse_section_header(self, service):
        """Section headers like '1 - Host Configuration' should not match."""
        result = service._parse_single_check_line("1 - Host Configuration")
        assert result is None


# ============================================================
# _determine_category
# ============================================================


class TestDetermineCategory:
    """Test category mapping from check ID prefix."""

    def test_category_1_host(self, service):
        assert service._determine_category("1.1.1") == "Host Configuration"

    def test_category_2_daemon(self, service):
        assert service._determine_category("2.3") == "Docker Daemon Configuration"

    def test_category_3_files(self, service):
        assert service._determine_category("3.1") == "Docker Daemon Files"

    def test_category_4_images(self, service):
        assert service._determine_category("4.5") == "Container Images"

    def test_category_5_runtime(self, service):
        assert service._determine_category("5.2.1") == "Container Runtime"

    def test_category_6_operations(self, service):
        assert service._determine_category("6.1") == "Docker Security Operations"

    def test_category_7_swarm(self, service):
        assert service._determine_category("7.1") == "Docker Swarm Configuration"

    def test_category_unknown_digit(self, service):
        assert service._determine_category("9.1") == "Unknown"

    def test_category_non_numeric(self, service):
        assert service._determine_category("abc") == "Unknown"

    def test_category_empty(self, service):
        assert service._determine_category("") == "Unknown"


# ============================================================
# _determine_severity
# ============================================================


class TestDetermineSeverity:
    """Test severity mapping from check status."""

    def test_severity_fail(self, service):
        assert service._determine_severity("FAIL") == "HIGH"

    def test_severity_warn(self, service):
        assert service._determine_severity("WARN") == "MEDIUM"

    def test_severity_pass(self, service):
        assert service._determine_severity("PASS") == "INFO"

    def test_severity_info(self, service):
        assert service._determine_severity("INFO") == "INFO"

    def test_severity_note(self, service):
        assert service._determine_severity("NOTE") == "LOW"

    def test_severity_unknown(self, service):
        assert service._determine_severity("XYZ") == "INFO"


# ============================================================
# calculate_compliance_score
# ============================================================


class TestCalculateComplianceScore:
    """Test compliance score calculation."""

    def test_score_all_passed(self, service):
        findings = [
            {"status": "PASS"},
            {"status": "PASS"},
            {"status": "PASS"},
        ]
        assert service.calculate_compliance_score(findings) == 100.0

    def test_score_all_failed(self, service):
        findings = [
            {"status": "FAIL"},
            {"status": "FAIL"},
        ]
        assert service.calculate_compliance_score(findings) == 0.0

    def test_score_mixed(self, service):
        findings = [
            {"status": "PASS"},
            {"status": "PASS"},
            {"status": "PASS"},
            {"status": "WARN"},
            {"status": "FAIL"},
        ]
        # 3 passed / 5 total = 60%
        assert service.calculate_compliance_score(findings) == 60.0

    def test_score_empty(self, service):
        assert service.calculate_compliance_score([]) == 0.0

    def test_score_excludes_info(self, service):
        """INFO and NOTE findings should not count toward total checks."""
        findings = [
            {"status": "PASS"},
            {"status": "FAIL"},
            {"status": "INFO"},
            {"status": "NOTE"},
        ]
        # Only PASS+FAIL count: 1 passed / 2 total = 50%
        assert service.calculate_compliance_score(findings) == 50.0

    def test_score_only_info(self, service):
        """If only INFO/NOTE findings, score should be 100%."""
        findings = [
            {"status": "INFO"},
            {"status": "NOTE"},
        ]
        assert service.calculate_compliance_score(findings) == 100.0


# ============================================================
# calculate_category_scores
# ============================================================


class TestCalculateCategoryScores:
    """Test per-category scoring."""

    def test_category_scores(self, service):
        findings = [
            {"status": "PASS", "category": "Host Configuration"},
            {"status": "FAIL", "category": "Host Configuration"},
            {"status": "PASS", "category": "Container Runtime"},
            {"status": "PASS", "category": "Container Runtime"},
        ]
        scores = service.calculate_category_scores(findings)
        assert scores["Host Configuration"] == 50.0
        assert scores["Container Runtime"] == 100.0

    def test_category_scores_empty(self, service):
        scores = service.calculate_category_scores([])
        assert scores == {}

    def test_category_scores_single_category(self, service):
        findings = [
            {"status": "PASS", "category": "Docker Daemon Configuration"},
            {"status": "WARN", "category": "Docker Daemon Configuration"},
            {"status": "PASS", "category": "Docker Daemon Configuration"},
        ]
        scores = service.calculate_category_scores(findings)
        assert len(scores) == 1
        # 2 passed / 3 total = 66.67%
        assert scores["Docker Daemon Configuration"] == 66.67


# ============================================================
# _parse_docker_bench_output (full output parsing)
# ============================================================


class TestParseDockerBenchOutput:
    """Test full Docker Bench output parsing."""

    def test_parse_multiple_lines(self, service):
        output = (
            "[PASS] 1.1.1 - Ensure separate partition for containers\n"
            "[WARN] 2.1 - Restrict network traffic between containers\n"
            "[FAIL] 4.5 - Ensure Content trust enabled\n"
            "[INFO] 1.1.3 - Auditing configured\n"
        )
        findings = service._parse_docker_bench_output(output)
        assert len(findings) == 4
        statuses = [f["status"] for f in findings]
        assert statuses == ["PASS", "WARN", "FAIL", "INFO"]

    def test_parse_output_with_ansi(self, service):
        output = (
            "\x1b[1;32m[PASS]\x1b[0m 1.1.1  - Ensure separate partition\n"
            "\x1b[1;33m[WARN]\x1b[0m 2.1    - Restrict network traffic\n"
        )
        findings = service._parse_docker_bench_output(output)
        assert len(findings) == 2

    def test_parse_empty_output(self, service):
        findings = service._parse_docker_bench_output("")
        assert findings == []

    def test_parse_no_check_output(self, service):
        output = "Docker Bench starting...\nCompleted scan.\n"
        findings = service._parse_docker_bench_output(output)
        assert findings == []


# ============================================================
# _extract_remediation
# ============================================================


class TestExtractRemediation:
    """Test remediation extraction."""

    def test_returns_none(self, service):
        """Currently always returns None (placeholder for future enhancement)."""
        assert service._extract_remediation("some output", "1.1.1") is None
