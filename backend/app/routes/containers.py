"""Container API endpoints."""

import logging

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.repositories.container_repository import ContainerRepository
from app.repositories.dependencies import get_container_repository
from app.schemas import (
    Container as ContainerSchema,
)
from app.schemas import (
    ContainerList,
    ContainerSummary,
    ContainerUpdate,
)
from app.services.activity_logger import ActivityLogger
from app.services.container_schema_builder import build_last_scan, build_vuln_summary
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
        summary.vulnerability_summary = build_vuln_summary(container)

        scan_tuple = latest_scans.get(container.id)
        if scan_tuple:
            scan, vulnerabilities = scan_tuple
            summary.last_scan = build_last_scan(scan, vulnerabilities)

        summaries.append(summary)

    return ContainerList(
        containers=summaries,
        total=total,
        scanned=scanned,
        never_scanned=never_scanned,
    )


@router.get("/by-name/{name}", response_model=ContainerSchema)
async def get_container_by_name(
    name: str,
    container_repo: ContainerRepository = Depends(get_container_repository),
):
    """Get container by name (O(1) lookup).

    Used by TideWatch for efficient container ID resolution without
    fetching the full container list.
    """
    container = await container_repo.get_by_name(name)

    if not container:
        raise HTTPException(status_code=404, detail="Container not found")

    container_schema = ContainerSchema.model_validate(container)
    container_schema.vulnerability_summary = build_vuln_summary(container)

    latest_scan = await container_repo.get_latest_scans_with_vulnerabilities([container.id])
    scan_tuple = latest_scan.get(container.id)
    if scan_tuple:
        scan, vulnerabilities = scan_tuple
        container_schema.last_scan = build_last_scan(scan, vulnerabilities)

    return container_schema


@router.get("/by-image", response_model=list[ContainerSchema])
async def get_containers_by_image(
    image: str,
    tag: str | None = None,
    container_repo: ContainerRepository = Depends(get_container_repository),
):
    """Get containers matching an image name and optional tag.

    Returns a list because multiple containers may share the same image+tag
    (e.g. two containers running nginx:latest). Results are ordered by
    last_scan_date DESC so the most recently scanned container is first.

    Used by TideWatch for image-based vulnerability lookups.

    Args:
        image: Image repository name (e.g. "nginx", "ghcr.io/org/app").
        tag: Optional image tag filter. If omitted, returns all tags.
    """
    containers = await container_repo.get_by_image(image, tag)

    if not containers:
        raise HTTPException(
            status_code=404,
            detail="No containers found for this image",
        )

    result = []
    container_ids = [c.id for c in containers]
    latest_scans = await container_repo.get_latest_scans_with_vulnerabilities(container_ids)

    for container in containers:
        schema = ContainerSchema.model_validate(container)
        schema.vulnerability_summary = build_vuln_summary(container)
        scan_tuple = latest_scans.get(container.id)
        if scan_tuple:
            scan, vulnerabilities = scan_tuple
            schema.last_scan = build_last_scan(scan, vulnerabilities)
        result.append(schema)

    return result


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
    container_schema.vulnerability_summary = build_vuln_summary(container)

    latest_scan = await container_repo.get_latest_scans_with_vulnerabilities([container.id])
    scan_tuple = latest_scan.get(container.id)
    if scan_tuple:
        scan, vulnerabilities = scan_tuple
        container_schema.last_scan = build_last_scan(scan, vulnerabilities)

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
