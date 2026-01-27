"""System information API endpoints."""

from fastapi import APIRouter
from pydantic import BaseModel

from app.config import settings
from app.services.docker_client import DockerService
from app.services.docker_hub import get_docker_hub_client
from app.services.trivy_scanner import TrivyScanner

router = APIRouter()


class ScannerInfo(BaseModel):
    """Scanner information model."""

    name: str
    enabled: bool
    available: bool
    version: str | None = None
    latest_version: str | None = None
    update_available: bool = False
    db_version: str | None = None
    db_latest_version: str | None = None
    db_update_available: bool = False
    db_updated_at: str | None = None
    db_age_hours: int | None = None


class ScannersInfoResponse(BaseModel):
    """Response model for all scanners info."""

    scanners: list[ScannerInfo]


@router.get("/trivy-db-info")
async def get_trivy_db_info():
    """Get Trivy vulnerability database information."""
    docker_service = DockerService()

    try:
        scanner = TrivyScanner(docker_service)
        db_info = await scanner.get_database_info()

        if not db_info:
            return {
                "db_version": None,
                "updated_at": None,
                "next_update": None,
                "downloaded_at": None,
            }

        return db_info
    finally:
        docker_service.close()


@router.get("/scanners", response_model=ScannersInfoResponse)
async def get_scanners_info():
    """Get information about all configured scanners."""
    docker_service = DockerService()
    docker_hub = get_docker_hub_client()
    scanners = []

    try:
        # Trivy Scanner
        trivy_scanner = TrivyScanner(docker_service)
        trivy_available = docker_service.get_trivy_container() is not None

        trivy_info = ScannerInfo(
            name="Trivy",
            enabled=True,  # Trivy is always enabled
            available=trivy_available,
            version=None,
            latest_version=None,
            update_available=False,
            db_version=None,
            db_latest_version=None,
            db_update_available=False,
            db_updated_at=None,
            db_age_hours=None,
        )

        if trivy_available:
            # Get scanner version
            trivy_info.version = await trivy_scanner.get_scanner_version()

            # Check for updates from Docker Hub
            latest_version = await docker_hub.get_latest_tag("aquasec/trivy")
            if latest_version:
                trivy_info.latest_version = latest_version
                # Compare versions if both are available
                if trivy_info.version and latest_version:
                    trivy_info.update_available = _compare_versions(
                        trivy_info.version, latest_version
                    )

            # Get database info
            db_info = await trivy_scanner.get_database_info()
            if db_info:
                trivy_info.db_version = (
                    str(db_info.get("db_version")) if db_info.get("db_version") else None
                )
                trivy_info.db_updated_at = db_info.get("updated_at")

                # Calculate DB age
                is_fresh, age_hours = await trivy_scanner.check_db_freshness()
                trivy_info.db_age_hours = age_hours

                # Check for database updates from GHCR
                db_latest_version = await docker_hub.get_latest_tag(
                    "aquasecurity/trivy-db", registry="ghcr.io"
                )
                if db_latest_version:
                    trivy_info.db_latest_version = db_latest_version
                    # Compare database versions if both are available
                    if trivy_info.db_version and db_latest_version:
                        trivy_info.db_update_available = _compare_versions(
                            trivy_info.db_version, db_latest_version
                        )

        scanners.append(trivy_info)

        # VulnForge Native Compliance Checker
        # Always available since it's built into VulnForge
        compliance_info = ScannerInfo(
            name="VulnForge Checker",
            enabled=settings.compliance_enabled,
            available=True,  # Always available (native Python implementation)
            version="native",  # Built into VulnForge
            latest_version=None,  # Uses VulnForge's version
            update_available=False,
            db_version=None,  # No separate database
            db_latest_version=None,
            db_update_available=False,
            db_updated_at=None,
            db_age_hours=None,
        )

        scanners.append(compliance_info)

        # Dive - Image Efficiency Analysis
        dive_available = False
        try:
            docker_service.client.containers.get(settings.dive_container_name)
            dive_available = True
        except Exception:
            dive_available = (
                False  # INTENTIONAL: Container not found or Docker error means unavailable.
            )

        dive_info = ScannerInfo(
            name="Dive",
            enabled=True,  # Dive is always enabled
            available=dive_available,
            version=None,
            latest_version=None,
            update_available=False,
            db_version=None,
            db_latest_version=None,
            db_update_available=False,
            db_updated_at=None,
            db_age_hours=None,
        )

        if dive_available:
            # Dive doesn't have a database or version API, so we just show it as available
            # Version could be extracted from container image tag if needed
            pass

        scanners.append(dive_info)

        return ScannersInfoResponse(scanners=scanners)

    finally:
        docker_service.close()


def _compare_versions(current: str, latest: str) -> bool:
    """
    Compare two semantic versions to determine if an update is available.

    Args:
        current: Current version string (e.g., "0.67.2")
        latest: Latest version string (e.g., "0.68.0")

    Returns:
        True if latest > current, False otherwise
    """
    try:
        # Parse versions as tuples of integers
        current_parts = [int(x) for x in current.split(".")]
        latest_parts = [int(x) for x in latest.split(".")]

        # Compare tuples (Python does this lexicographically)
        return tuple(latest_parts) > tuple(current_parts)
    except (ValueError, AttributeError):
        # If parsing fails, assume no update
        return False
