"""Abstract base classes for scanner health monitoring."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from enum import Enum


class ScannerStatus(Enum):
    """Scanner availability status."""

    AVAILABLE = "available"  # Scanner is operational
    DEGRADED = "degraded"  # Scanner working but DB is stale
    UNAVAILABLE = "unavailable"  # Scanner cannot be used
    UNKNOWN = "unknown"  # Status cannot be determined


class DatabaseFreshness(Enum):
    """Database freshness levels."""

    FRESH = "fresh"  # DB is within max_age threshold
    STALE = "stale"  # DB is older than max_age but usable
    EXPIRED = "expired"  # DB is too old and should not be used
    UNKNOWN = "unknown"  # DB age cannot be determined


@dataclass
class DatabaseHealth:
    """Health information for a scanner database."""

    scanner_name: str
    status: ScannerStatus
    freshness: DatabaseFreshness
    age_hours: int | None
    version: str | None
    updated_at: str | None
    next_update: str | None
    can_skip_update: bool
    warnings: list[str]

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "scanner_name": self.scanner_name,
            "status": self.status.value,
            "freshness": self.freshness.value,
            "age_hours": self.age_hours,
            "version": self.version,
            "updated_at": self.updated_at,
            "next_update": self.next_update,
            "can_skip_update": self.can_skip_update,
            "warnings": self.warnings,
        }


class ScannerHealthMonitor(ABC):
    """
    Abstract base class for scanner health monitoring.

    This provides a scanner-agnostic interface for checking database
    health, determining if updates can be skipped, and assessing
    scanner availability.
    """

    def __init__(self, scanner_name: str):
        """Initialize scanner health monitor."""
        self.scanner_name = scanner_name

    @abstractmethod
    async def check_database_health(
        self, max_age_hours: int = 24, stale_warning_hours: int = 72
    ) -> DatabaseHealth:
        """
        Check the health of the scanner's vulnerability database.

        Args:
            max_age_hours: Maximum age in hours for database to be considered fresh
            stale_warning_hours: Age threshold for stale database warning

        Returns:
            DatabaseHealth object with status, freshness, and metadata
        """
        pass

    @abstractmethod
    async def get_database_version(self) -> str | None:
        """Get the current database version."""
        pass

    @abstractmethod
    async def get_database_updated_at(self) -> datetime | None:
        """Get when the database was last updated."""
        pass

    @abstractmethod
    async def is_available(self) -> bool:
        """Check if the scanner is available and functional."""
        pass

    @abstractmethod
    async def supports_offline_mode(self) -> bool:
        """Check if the scanner supports offline scanning (skip DB updates)."""
        pass

    async def get_status_summary(self, max_age_hours: int = 24) -> dict:
        """
        Get a summary of scanner status.

        Args:
            max_age_hours: Maximum age for database freshness

        Returns:
            Dictionary with scanner status summary
        """
        try:
            health = await self.check_database_health(max_age_hours)
            is_avail = await self.is_available()
            offline_support = await self.supports_offline_mode()

            return {
                "scanner": self.scanner_name,
                "available": is_avail,
                "supports_offline": offline_support,
                "health": health.to_dict(),
            }
        except Exception as e:
            return {
                "scanner": self.scanner_name,
                "available": False,
                "supports_offline": False,
                "error": str(e),
            }
