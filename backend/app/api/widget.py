"""Homepage widget API endpoints."""

from fastapi import APIRouter, Depends

from app.repositories.dependencies import (
    get_container_repository,
    get_secret_repository,
    get_vulnerability_repository,
)
from app.repositories.container_repository import ContainerRepository
from app.repositories.secret_repository import SecretRepository
from app.repositories.vulnerability_repository import VulnerabilityRepository
from app.schemas import (
    ContainerVulnCount,
    RemediationItem,
    WidgetCritical,
    WidgetRemediation,
    WidgetSummary,
    WidgetTopContainers,
)
from app.services.cache_manager import get_cache

router = APIRouter()


async def _compute_widget_summary(
    container_repo: ContainerRepository,
    secret_repo: SecretRepository,
) -> WidgetSummary:
    """Compute widget summary (called when cache misses)."""
    # Count total and scanned containers
    total_containers = await container_repo.count_total()
    scanned_containers = await container_repo.count_scanned()

    # Get last scan date
    last_scan = await container_repo.get_last_scan_date()

    # Aggregate vulnerability counts from all containers
    vuln_stats = await container_repo.get_vulnerability_stats()

    # Get total secret count (excluding false positives)
    total_secrets = await secret_repo.count_total()

    return WidgetSummary(
        total_containers=total_containers,
        scanned_containers=scanned_containers,
        last_scan=last_scan,
        total_vulnerabilities=vuln_stats["total_vulnerabilities"],
        fixable_vulnerabilities=vuln_stats["fixable_vulnerabilities"],
        critical_count=vuln_stats["critical_count"],
        high_count=vuln_stats["high_count"],
        medium_count=vuln_stats["medium_count"],
        low_count=vuln_stats["low_count"],
        total_secrets=total_secrets,
    )


@router.get("/summary", response_model=WidgetSummary)
async def get_widget_summary(
    container_repo: ContainerRepository = Depends(get_container_repository),
    secret_repo: SecretRepository = Depends(get_secret_repository),
):
    """
    Get summary statistics for Homepage widget (cached).

    Returns:
        Widget summary data with overall vulnerability and secret counts
    """
    cache = get_cache()

    # Use cache with 30-second TTL
    return await cache.get_or_compute(
        key="widget:summary",
        compute_fn=lambda: _compute_widget_summary(container_repo, secret_repo),
        ttl_seconds=30,
    )


@router.get("/critical", response_model=WidgetCritical)
async def get_widget_critical(
    container_repo: ContainerRepository = Depends(get_container_repository),
    vuln_repo: VulnerabilityRepository = Depends(get_vulnerability_repository),
):
    """
    Get critical vulnerability focus for Homepage widget.

    Returns:
        Critical and high vulnerability statistics
    """
    # Aggregate critical and high counts from containers
    vuln_stats = await container_repo.get_vulnerability_stats()
    critical_total = vuln_stats["critical_count"]
    high_total = vuln_stats["high_count"]

    # Count fixable critical and high
    critical_fixable = await vuln_repo.count_by_severity("CRITICAL")
    high_fixable = await vuln_repo.count_by_severity("HIGH")

    # Get most vulnerable container
    most_vuln_name, most_vuln_count = await container_repo.get_most_vulnerable()

    return WidgetCritical(
        critical_total=critical_total,
        critical_fixable=critical_fixable,
        high_total=high_total,
        high_fixable=high_fixable,
        most_vulnerable_container=most_vuln_name,
        most_vulnerable_count=most_vuln_count,
    )


@router.get("/top-containers", response_model=WidgetTopContainers)
async def get_widget_top_containers(
    limit: int = 10,
    container_repo: ContainerRepository = Depends(get_container_repository),
):
    """
    Get top vulnerable containers for Homepage widget.

    Args:
        limit: Number of containers to return

    Returns:
        List of most vulnerable containers
    """
    top_containers = await container_repo.get_top_vulnerable(limit=limit)

    containers = [ContainerVulnCount(**c) for c in top_containers]

    return WidgetTopContainers(containers=containers)


@router.get("/remediation", response_model=WidgetRemediation)
async def get_widget_remediation(
    limit: int = 5,
    vuln_repo: VulnerabilityRepository = Depends(get_vulnerability_repository),
):
    """
    Get actionable remediation information for Homepage widget.

    Args:
        limit: Number of top remediation items to return

    Returns:
        Remediation summary with package update recommendations
    """
    # Count total fixable vulnerabilities
    total_fixable = await vuln_repo.count_fixable()
    critical_fixable = await vuln_repo.count_by_severity("CRITICAL")
    high_fixable = await vuln_repo.count_by_severity("HIGH")

    # Get top packages that need updating (grouped by package + fixed version)
    remediation_groups = await vuln_repo.get_remediation_groups()

    # Limit to top N
    top_remediations = [
        RemediationItem(
            package=g["package_name"],
            current_version=g["installed_version"],
            fixed_version=g["fixed_version"],
            fixes_count=g["cve_count"],
            fixes_critical=g["critical_count"],
            fixes_high=g["high_count"],
        )
        for g in remediation_groups[:limit]
    ]

    # Count unique packages that need updating
    total_packages = len(remediation_groups)

    # Generate impact message
    impact_message = f"Update {total_packages} packages to fix {total_fixable} CVEs"
    if critical_fixable > 0:
        impact_message += f" ({critical_fixable} critical)"

    return WidgetRemediation(
        total_packages_to_update=total_packages,
        total_cves_fixable=total_fixable,
        critical_cves_fixable=critical_fixable,
        high_cves_fixable=high_fixable,
        impact_message=impact_message,
        top_remediations=top_remediations,
    )
