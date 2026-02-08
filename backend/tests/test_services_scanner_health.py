"""Tests for scanner health monitoring abstractions.

This module tests the scanner-agnostic health monitoring base classes:
- ScannerStatus enum
- DatabaseFreshness enum
- DatabaseHealth dataclass
- ScannerHealthMonitor abstract base class
"""

from datetime import UTC, datetime
from unittest.mock import patch

import pytest

from app.services.scanner_health import (
    DatabaseFreshness,
    DatabaseHealth,
    ScannerHealthMonitor,
    ScannerStatus,
)


class MockScanner(ScannerHealthMonitor):
    """Concrete implementation of ScannerHealthMonitor for testing."""

    def __init__(
        self,
        name: str = "test-scanner",
        available: bool = True,
        offline_support: bool = True,
    ):
        super().__init__(name)
        self._available = available
        self._offline_support = offline_support

    async def check_database_health(
        self, max_age_hours: int = 24, stale_warning_hours: int = 72
    ) -> DatabaseHealth:
        """Return a healthy database health result."""
        return DatabaseHealth(
            scanner_name=self.scanner_name,
            status=ScannerStatus.AVAILABLE,
            freshness=DatabaseFreshness.FRESH,
            age_hours=2,
            version="1.0.0",
            updated_at="2026-02-07T00:00:00Z",
            next_update="2026-02-08T00:00:00Z",
            can_skip_update=True,
            warnings=[],
        )

    async def get_database_version(self) -> str | None:
        """Return a test version string."""
        return "1.0.0"

    async def get_database_updated_at(self) -> datetime | None:
        """Return a test datetime."""
        return datetime.now(UTC)

    async def is_available(self) -> bool:
        """Return configured availability."""
        return self._available

    async def supports_offline_mode(self) -> bool:
        """Return configured offline support."""
        return self._offline_support


class TestScannerStatus:
    """Test ScannerStatus enum."""

    def test_status_values(self):
        """Verify all 4 status values exist with correct string representations."""
        assert ScannerStatus.AVAILABLE.value == "available"
        assert ScannerStatus.DEGRADED.value == "degraded"
        assert ScannerStatus.UNAVAILABLE.value == "unavailable"
        assert ScannerStatus.UNKNOWN.value == "unknown"
        assert len(ScannerStatus) == 4


class TestDatabaseFreshness:
    """Test DatabaseFreshness enum."""

    def test_freshness_values(self):
        """Verify all 4 freshness values exist with correct string representations."""
        assert DatabaseFreshness.FRESH.value == "fresh"
        assert DatabaseFreshness.STALE.value == "stale"
        assert DatabaseFreshness.EXPIRED.value == "expired"
        assert DatabaseFreshness.UNKNOWN.value == "unknown"
        assert len(DatabaseFreshness) == 4


class TestDatabaseHealth:
    """Test DatabaseHealth dataclass."""

    def test_database_health_to_dict(self):
        """Create DatabaseHealth instance and verify to_dict() output."""
        health = DatabaseHealth(
            scanner_name="trivy",
            status=ScannerStatus.AVAILABLE,
            freshness=DatabaseFreshness.FRESH,
            age_hours=6,
            version="2.0.0",
            updated_at="2026-02-07T12:00:00Z",
            next_update="2026-02-08T12:00:00Z",
            can_skip_update=True,
            warnings=["test warning"],
        )

        result = health.to_dict()

        assert result == {
            "scanner_name": "trivy",
            "status": "available",
            "freshness": "fresh",
            "age_hours": 6,
            "version": "2.0.0",
            "updated_at": "2026-02-07T12:00:00Z",
            "next_update": "2026-02-08T12:00:00Z",
            "can_skip_update": True,
            "warnings": ["test warning"],
        }

    def test_database_health_fields(self):
        """Verify all fields are set correctly on the dataclass."""
        health = DatabaseHealth(
            scanner_name="grype",
            status=ScannerStatus.DEGRADED,
            freshness=DatabaseFreshness.STALE,
            age_hours=48,
            version=None,
            updated_at=None,
            next_update=None,
            can_skip_update=False,
            warnings=["Database is stale", "Update recommended"],
        )

        assert health.scanner_name == "grype"
        assert health.status == ScannerStatus.DEGRADED
        assert health.freshness == DatabaseFreshness.STALE
        assert health.age_hours == 48
        assert health.version is None
        assert health.updated_at is None
        assert health.next_update is None
        assert health.can_skip_update is False
        assert len(health.warnings) == 2
        assert "Database is stale" in health.warnings


class TestScannerHealthMonitor:
    """Test abstract base class behavior."""

    def test_cannot_instantiate_abstract(self):
        """Verify ScannerHealthMonitor cannot be instantiated directly."""
        with pytest.raises(TypeError):
            ScannerHealthMonitor("should-fail")  # type: ignore[abstract]

    def test_concrete_implementation(self):
        """Create a concrete subclass and verify it instantiates correctly."""
        scanner = MockScanner("my-scanner")
        assert scanner.scanner_name == "my-scanner"

    @pytest.mark.asyncio
    async def test_get_status_summary_success(self):
        """Mock the abstract methods and verify get_status_summary output format."""
        scanner = MockScanner("healthy-scanner", available=True, offline_support=True)
        summary = await scanner.get_status_summary(max_age_hours=24)

        assert summary["scanner"] == "healthy-scanner"
        assert summary["available"] is True
        assert summary["supports_offline"] is True
        assert "health" in summary
        assert summary["health"]["status"] == "available"
        assert summary["health"]["freshness"] == "fresh"
        assert summary["health"]["scanner_name"] == "healthy-scanner"
        assert "error" not in summary

    @pytest.mark.asyncio
    async def test_get_status_summary_error(self):
        """Mock abstract method raising exception and verify error dict."""
        scanner = MockScanner("broken-scanner")

        # Patch check_database_health to raise an exception
        with patch.object(
            scanner,
            "check_database_health",
            side_effect=RuntimeError("database corrupted"),
        ):
            summary = await scanner.get_status_summary(max_age_hours=24)

        assert summary["scanner"] == "broken-scanner"
        assert summary["available"] is False
        assert summary["supports_offline"] is False
        assert "error" in summary
        assert "database corrupted" in summary["error"]
        assert "health" not in summary
