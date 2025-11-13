"""Trivy scanner health monitoring implementation."""

import logging
from datetime import datetime, timezone
from typing import Optional

from app.services.scanner_health import (
    DatabaseFreshness,
    DatabaseHealth,
    ScannerHealthMonitor,
    ScannerStatus,
)
from app.services.trivy_scanner import TrivyScanner

logger = logging.getLogger(__name__)


class TrivyHealthMonitor(ScannerHealthMonitor):
    """Health monitor for Trivy vulnerability scanner."""

    def __init__(self, trivy_scanner: TrivyScanner):
        """Initialize Trivy health monitor."""
        super().__init__("trivy")
        self.scanner = trivy_scanner

    async def check_database_health(
        self, max_age_hours: int = 24, stale_warning_hours: int = 72
    ) -> DatabaseHealth:
        """
        Check Trivy database health.

        Args:
            max_age_hours: Maximum age for database to be considered fresh
            stale_warning_hours: Age threshold for stale database warning

        Returns:
            DatabaseHealth with Trivy DB status
        """
        warnings = []

        try:
            # Get database info from Trivy
            db_info = await self.scanner.get_database_info()

            if not db_info:
                return DatabaseHealth(
                    scanner_name=self.scanner_name,
                    status=ScannerStatus.UNAVAILABLE,
                    freshness=DatabaseFreshness.UNKNOWN,
                    age_hours=None,
                    version=None,
                    updated_at=None,
                    next_update=None,
                    can_skip_update=False,
                    warnings=["Trivy database info unavailable"],
                )

            # Check DB freshness
            is_fresh, age_hours = await self.scanner.check_db_freshness(max_age_hours)

            # Determine freshness level
            if age_hours is None:
                freshness = DatabaseFreshness.UNKNOWN
                status = ScannerStatus.DEGRADED
                warnings.append("Cannot determine database age")
            elif age_hours < max_age_hours:
                freshness = DatabaseFreshness.FRESH
                status = ScannerStatus.AVAILABLE
            elif age_hours < stale_warning_hours:
                freshness = DatabaseFreshness.STALE
                status = ScannerStatus.DEGRADED
                warnings.append(
                    f"Database is {age_hours}h old (threshold: {max_age_hours}h)"
                )
            else:
                freshness = DatabaseFreshness.EXPIRED
                status = ScannerStatus.DEGRADED
                warnings.append(
                    f"Database is {age_hours}h old and may contain outdated CVE data"
                )

            return DatabaseHealth(
                scanner_name=self.scanner_name,
                status=status,
                freshness=freshness,
                age_hours=age_hours,
                version=db_info.get("db_version"),
                updated_at=db_info.get("updated_at"),
                next_update=db_info.get("next_update"),
                can_skip_update=is_fresh,
                warnings=warnings,
            )

        except Exception as e:
            logger.error(f"Error checking Trivy database health: {e}")
            return DatabaseHealth(
                scanner_name=self.scanner_name,
                status=ScannerStatus.UNAVAILABLE,
                freshness=DatabaseFreshness.UNKNOWN,
                age_hours=None,
                version=None,
                updated_at=None,
                next_update=None,
                can_skip_update=False,
                warnings=[f"Health check failed: {str(e)}"],
            )

    async def get_database_version(self) -> Optional[str]:
        """Get Trivy database version."""
        try:
            db_info = await self.scanner.get_database_info()
            return str(db_info.get("db_version")) if db_info else None
        except Exception as e:
            logger.error(f"Error getting Trivy DB version: {e}")
            return None

    async def get_database_updated_at(self) -> Optional[datetime]:
        """Get when Trivy database was last updated."""
        try:
            db_info = await self.scanner.get_database_info()
            if not db_info or "updated_at" not in db_info:
                return None

            updated_at_str = db_info["updated_at"]

            # Parse timestamp (same logic as in trivy_scanner.py)
            try:
                return datetime.fromisoformat(updated_at_str.replace("Z", "+00:00"))
            except ValueError:
                if " UTC" in updated_at_str:
                    import re

                    updated_at_str = updated_at_str.replace(" UTC", "")
                    match = re.match(
                        r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\.(\d+) (.+)",
                        updated_at_str,
                    )
                    if match:
                        date_time = match.group(1)
                        nanos = match.group(2)[:6]
                        tz = match.group(3)
                        updated_at_str = f"{date_time}.{nanos} {tz}"
                    return datetime.strptime(updated_at_str, "%Y-%m-%d %H:%M:%S.%f %z")

            return None

        except Exception as e:
            logger.error(f"Error parsing Trivy DB updated_at: {e}")
            return None

    async def is_available(self) -> bool:
        """Check if Trivy scanner is available."""
        try:
            db_info = await self.scanner.get_database_info()
            return db_info is not None
        except Exception:
            return False

    async def supports_offline_mode(self) -> bool:
        """Trivy supports offline mode via --skip-db-update flag."""
        return True
