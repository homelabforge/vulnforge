"""Container API endpoints."""

import logging
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_db
from app.repositories.container_repository import ContainerRepository
from app.repositories.dependencies import get_container_repository
from app.schemas import (
    Container as ContainerSchema,
)
from app.schemas import (
    ContainerLastScan,
    ContainerList,
    ContainerScanVulnerability,
    ContainerSummary,
    ContainerUpdate,
    ContainerVulnerabilitySummary,
)
from app.services.activity_logger import ActivityLogger
from app.services.docker_client import DockerService
from app.utils.timezone import get_now

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/", response_model=ContainerList)
async def list_containers(
    limit: int | None = None,
    offset: int = 0,
    container_repo: ContainerRepository = Depends(get_container_repository),
):
    """List all containers with optional pagination."""
    containers, total, scanned, never_scanned = await container_repo.get_all(
        limit=limit, offset=offset
    )

    container_ids = [container.id for container in containers]
    latest_scans = await container_repo.get_latest_scans_with_vulnerabilities(container_ids)

    summaries: list[ContainerSummary] = []
    for container in containers:
        summary = ContainerSummary.model_validate(container)
        summary.vulnerability_summary = ContainerVulnerabilitySummary(
            total=container.total_vulns,
            fixable=container.fixable_vulns,
            critical=container.critical_count,
            high=container.high_count,
            medium=container.medium_count,
            low=container.low_count,
        )

        scan_tuple = latest_scans.get(container.id)
        if scan_tuple:
            scan, vulnerabilities = scan_tuple

            finished_at = None
            if scan.scan_date:
                finished_at = scan.scan_date
                if scan.scan_duration_seconds is not None:
                    finished_at = scan.scan_date + timedelta(seconds=scan.scan_duration_seconds)

            seen_cves: set[str] = set()
            cves: list[str] = []
            vuln_summaries: list[ContainerScanVulnerability] = []

            # Sort vulnerabilities by severity (critical -> low) then CVE for stable ordering
            severity_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
            sorted_vulns = sorted(
                vulnerabilities,
                key=lambda v: (
                    severity_rank.get((v.severity or "").upper(), 9),
                    v.cve_id or "",
                ),
            )

            max_vulns = 200
            for vuln in sorted_vulns[:max_vulns]:
                vuln_summaries.append(
                    ContainerScanVulnerability(
                        cve_id=vuln.cve_id,
                        severity=vuln.severity,
                        package_name=vuln.package_name,
                        installed_version=vuln.installed_version,
                        fixed_version=vuln.fixed_version,
                        is_fixable=vuln.is_fixable,
                        cvss_score=vuln.cvss_score,
                        title=vuln.title,
                    )
                )

                if vuln.cve_id and vuln.cve_id not in seen_cves:
                    cves.append(vuln.cve_id)
                    seen_cves.add(vuln.cve_id)

            summary.last_scan = ContainerLastScan(
                id=scan.id,
                status=scan.scan_status,
                started_at=scan.scan_date,
                finished_at=finished_at,
                total_vulns=scan.total_vulns,
                critical=scan.critical_count,
                high=scan.high_count,
                medium=scan.medium_count,
                low=scan.low_count,
                vulnerabilities=vuln_summaries,
                cves=cves,
            )

        summaries.append(summary)

    return ContainerList(
        containers=summaries,
        total=total,
        scanned=scanned,
        never_scanned=never_scanned,
    )


@router.get("/{container_id}", response_model=ContainerSchema)
async def get_container(
    container_id: int,
    container_repo: ContainerRepository = Depends(get_container_repository),
):
    """Get container by ID."""
    container = await container_repo.get_by_id(container_id)

    if not container:
        raise HTTPException(status_code=404, detail="Container not found")

    container_schema = ContainerSchema.model_validate(container)

    container_schema.vulnerability_summary = ContainerVulnerabilitySummary(
        total=container.total_vulns,
        fixable=container.fixable_vulns,
        critical=container.critical_count,
        high=container.high_count,
        medium=container.medium_count,
        low=container.low_count,
    )

    latest_scan = await container_repo.get_latest_scans_with_vulnerabilities([container.id])
    scan_tuple = latest_scan.get(container.id)
    if scan_tuple:
        scan, vulnerabilities = scan_tuple

        finished_at = None
        if scan.scan_date:
            finished_at = scan.scan_date
            if scan.scan_duration_seconds is not None:
                finished_at = scan.scan_date + timedelta(seconds=scan.scan_duration_seconds)

        seen_cves: set[str] = set()
        cves: list[str] = []
        severity_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

        sorted_vulns = sorted(
            vulnerabilities,
            key=lambda v: (
                severity_rank.get((v.severity or "").upper(), 9),
                v.cve_id or "",
            ),
        )

        vuln_summaries: list[ContainerScanVulnerability] = []
        max_vulns = 200
        for vuln in sorted_vulns[:max_vulns]:
            vuln_summaries.append(
                ContainerScanVulnerability(
                    cve_id=vuln.cve_id,
                    severity=vuln.severity,
                    package_name=vuln.package_name,
                    installed_version=vuln.installed_version,
                    fixed_version=vuln.fixed_version,
                    is_fixable=vuln.is_fixable,
                    cvss_score=vuln.cvss_score,
                    title=vuln.title,
                )
            )

            if vuln.cve_id and vuln.cve_id not in seen_cves:
                cves.append(vuln.cve_id)
                seen_cves.add(vuln.cve_id)

        container_schema.last_scan = ContainerLastScan(
            id=scan.id,
            status=scan.scan_status,
            started_at=scan.scan_date,
            finished_at=finished_at,
            total_vulns=scan.total_vulns,
            critical=scan.critical_count,
            high=scan.high_count,
            medium=scan.medium_count,
            low=scan.low_count,
            vulnerabilities=vuln_summaries,
            cves=cves,
        )

    return container_schema


@router.patch("/{container_id}", response_model=ContainerSchema)
async def update_container(
    container_id: int,
    container_update: ContainerUpdate,
    container_repo: ContainerRepository = Depends(get_container_repository),
    db: AsyncSession = Depends(get_db),
):
    """Update container fields (e.g., toggle is_my_project)."""
    container = await container_repo.get_by_id(container_id)

    if not container:
        raise HTTPException(status_code=404, detail="Container not found")

    # Update fields
    update_data = container_update.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(container, field, value)

    await container_repo.update(container)
    await db.commit()
    await db.refresh(container)

    # Return updated container
    return await get_container(container_id, container_repo)


@router.post("/discover")
async def discover_containers(
    container_repo: ContainerRepository = Depends(get_container_repository),
    db: AsyncSession = Depends(get_db),
):
    """Discover containers from Docker and update database."""
    docker_service = DockerService()

    def _is_internal_scanner_container(container_data: dict) -> bool:
        """Identify short-lived scanner containers we don't want to persist."""
        image_name = (container_data.get("image") or "").lower()
        image_full = (container_data.get("image_full") or "").lower()

        # Ignore one-off compliance/scanner helpers
        transient_prefixes = ("docker/docker-bench-security",)
        if any(
            image_name.startswith(prefix) or image_full.startswith(prefix)
            for prefix in transient_prefixes
        ):
            return True

        return False

    try:
        docker_containers = docker_service.list_containers(all_containers=True)
        discovered = []
        newly_discovered_containers = []  # Track new containers for activity logging
        active_container_names: set[str] = set()
        active_container_ids: set[str] = set()
        processed = 0
        seen_at = get_now()

        for dc in docker_containers:
            if _is_internal_scanner_container(dc):
                logger.debug(
                    "Skipping transient scanner container: %s (%s)",
                    dc.get("name"),
                    dc.get("image_full"),
                )
                continue

            processed += 1
            active_container_names.add(dc["name"])
            container_id_value = dc.get("container_id") or dc.get("id")
            if container_id_value:
                active_container_ids.add(container_id_value)
            # Create or update container
            container = await container_repo.create_or_update(
                {
                    "name": dc["name"],
                    "image": dc["image"],
                    "image_tag": dc["image_tag"],
                    "image_id": dc["image_id"],
                    "is_running": dc["is_running"],
                    "container_id": dc.get("container_id") or dc.get("id"),
                    "last_seen": seen_at,
                }
            )

            # Track if this was a new container
            if container.created_at == container.updated_at:
                discovered.append(dc["name"])
                newly_discovered_containers.append(
                    {
                        "container": container,
                        "docker_info": dc,
                    }
                )

        # Log activity for newly discovered containers (non-invasive)
        if newly_discovered_containers:
            try:
                activity_logger = ActivityLogger(db)
                for item in newly_discovered_containers:
                    container = item["container"]
                    dc = item["docker_info"]
                    await activity_logger.log_container_discovered(
                        container_name=container.name,
                        container_id=container.id,
                        image=dc["image"],
                        image_tag=dc["image_tag"],
                        is_running=dc["is_running"],
                    )
            except Exception as e:
                # INTENTIONAL: Activity logging must never crash container discovery.
                # We catch all exceptions to ensure the main operation succeeds.
                logger.error(f"Failed to log container discovery activity: {e}", exc_info=True)

        removed = await container_repo.remove_missing(active_container_names, active_container_ids)
        if removed:
            logger.info(f"Removed {removed} containers no longer reported by Docker")

        message_parts = [f"Discovered {len(discovered)} new containers"]
        if removed:
            plural = "s" if removed != 1 else ""
            message_parts.append(f"removed {removed} stale container{plural}")

        return {
            "total": processed,
            "discovered": discovered,
            "removed": removed,
            "message": ", ".join(message_parts),
        }

    except TimeoutError as e:
        logger.error(f"Docker connection timeout: {e}")
        raise HTTPException(status_code=504, detail="Docker daemon connection timeout")
    except PermissionError as e:
        logger.error(f"Docker permission denied: {e}")
        raise HTTPException(
            status_code=403, detail="Docker daemon permission denied - check socket permissions"
        )
    except ConnectionError as e:
        logger.error(f"Docker connection error: {e}")
        raise HTTPException(
            status_code=503, detail="Docker daemon unavailable - check if Docker is running"
        )
    except OSError as e:
        logger.error(f"Docker socket error: {e}")
        raise HTTPException(status_code=503, detail=f"Docker socket error: {e}")
    except Exception as e:
        logger.error(f"Docker service error: {e}")
        raise HTTPException(status_code=503, detail=f"Docker service unavailable: {str(e)}")
    finally:
        docker_service.close()
