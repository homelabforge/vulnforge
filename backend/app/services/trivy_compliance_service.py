"""Service for executing Trivy compliance scans (CIS, NSA, etc.)."""

import logging
from typing import Any

from app.services.trivy_scanner import TrivyScanner

logger = logging.getLogger(__name__)


class TrivyComplianceService:
    """Service for running Trivy-based compliance scans."""

    def __init__(self, trivy_scanner: TrivyScanner):
        """Initialize Trivy compliance service."""
        self.trivy_scanner = trivy_scanner

    async def run_compliance_scan(
        self, target: str, profile: str = "docker-cis-1.6.0"
    ) -> dict[str, Any] | None:
        """
        Run a Trivy compliance scan for the given target.

        Args:
            target: Image or target identifier.
            profile: Compliance profile ID (e.g., docker-cis, k8s-cis).

        Returns:
            Parsed compliance results or None on failure.
        """
        logger.info(f"Starting Trivy compliance scan: target={target}, profile={profile}")
        data = await self.trivy_scanner.scan_compliance(target=target, compliance_id=profile)

        if not data:
            logger.error("Trivy compliance scan returned no data")
            return None

        return data
