"""Scan API endpoints."""

import asyncio
import json
import logging
import subprocess

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_db
from app.models import Container, Scan, Vulnerability
from app.schemas import Scan as ScanSchema
from app.schemas import ScanRequest
from app.services.docker_client import DockerService
from app.services.kev import get_kev_service
from app.services.notifications import NotificationDispatcher
from app.services.scan_errors import get_error_classifier
from app.services.scan_events import scan_events
from app.services.scan_queue import ScanPriority, get_scan_queue
from app.services.scan_state import scan_state
from app.services.scan_trends import build_scan_trends
from app.services.settings_manager import SettingsManager
from app.services.trivy_scanner import TrivyScanner
from app.utils.timezone import get_now

logger = logging.getLogger(__name__)

router = APIRouter()

# Create limiter instance
limiter = Limiter(key_func=get_remote_address)


def _format_sse(payload: dict, event: str = "scan-status") -> str:
    """Format a payload for Server-Sent Events."""
    return f"event: {event}\ndata: {json.dumps(payload)}\n\n"


async def perform_scan(container_id: int, db: AsyncSession, docker_service: DockerService):
    """Perform a single container scan."""
    # Get container
    result = await db.execute(select(Container).where(Container.id == container_id))
    container = result.scalar_one_or_none()

    if not container:
        return

    # Create scan record
    scan = Scan(
        container_id=container.id,
        image_scanned=f"{container.image}:{container.image_tag}",
        scan_status="in_progress",
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    try:
        # Execute Trivy scan
        scanner = TrivyScanner(docker_service)
        scan_data = await scanner.scan_image(f"{container.image}:{container.image_tag}")

        if scan_data is None:
            # Scan failed
            scan.scan_status = "failed"
            scan.error_message = "Trivy scan returned no data"
            await db.commit()
            return

        # Update scan with results
        scan.scan_status = "completed"
        scan.scan_duration_seconds = scan_data["scan_duration_seconds"]
        scan.total_vulns = scan_data["total_count"]
        scan.fixable_vulns = scan_data["fixable_count"]
        scan.critical_count = scan_data["critical_count"]
        scan.high_count = scan_data["high_count"]
        scan.medium_count = scan_data["medium_count"]
        scan.low_count = scan_data["low_count"]

        # Check if KEV checking is enabled
        settings_manager = SettingsManager(db)
        kev_enabled = await settings_manager.get_bool("kev_checking_enabled", default=True)

        # Get KEV service and ensure catalog is loaded
        kev_service = get_kev_service()
        if kev_enabled:
            await kev_service.ensure_catalog_loaded()

        # Store vulnerabilities
        kev_count = 0
        for vuln_data in scan_data["vulnerabilities"]:
            # Check KEV status
            is_kev = False
            kev_added_date = None
            kev_due_date = None

            if kev_enabled:
                kev_info = kev_service.get_kev_info(vuln_data["cve_id"])
                if kev_info:
                    is_kev = True
                    kev_added_date = kev_info.get("date_added")
                    kev_due_date = kev_info.get("due_date")
                    kev_count += 1

            vuln = Vulnerability(
                scan_id=scan.id,
                cve_id=vuln_data["cve_id"],
                package_name=vuln_data["package_name"],
                severity=vuln_data["severity"],
                cvss_score=vuln_data["cvss_score"],
                title=vuln_data.get("title"),
                description=vuln_data.get("description"),
                installed_version=vuln_data["installed_version"],
                fixed_version=vuln_data.get("fixed_version"),
                is_fixable=vuln_data["is_fixable"],
                primary_url=vuln_data.get("primary_url"),
                references=vuln_data.get("references"),
                is_kev=is_kev,
                kev_added_date=kev_added_date,
                kev_due_date=kev_due_date,
            )
            db.add(vuln)

        # Update container summary
        container.last_scan_date = get_now()
        container.last_scan_status = "completed"
        container.total_vulns = scan.total_vulns
        container.fixable_vulns = scan.fixable_vulns
        container.critical_count = scan.critical_count
        container.high_count = scan.high_count
        container.medium_count = scan.medium_count
        container.low_count = scan.low_count

        await db.commit()

        # Send notifications via multi-service dispatcher
        dispatcher = NotificationDispatcher(db)

        # Send notification if KEV vulnerabilities found (highest priority)
        if kev_count > 0:
            await dispatcher.notify_kev_detected(container.name, kev_count)

        # Send notification if critical vulnerabilities found
        if scan.critical_count > 0:
            fixable_critical = sum(
                1
                for v in scan_data["vulnerabilities"]
                if v["severity"] == "CRITICAL" and v["is_fixable"]
            )
            await dispatcher.notify_critical_vulnerabilities(
                container.name, scan.critical_count, fixable_critical
            )

    except subprocess.TimeoutExpired as e:
        logger.error(f"Scan timed out for container {container.name}: {e}")
        scan.scan_status = "failed"
        scan.error_message = "Scan timed out"
        await db.commit()
        dispatcher = NotificationDispatcher(db)
        await dispatcher.notify_scan_failed(
            container.name, "Scan timed out - try increasing timeout in settings"
        )
    except subprocess.CalledProcessError as e:
        logger.error(f"Scanner process failed for {container.name}: exit code {e.returncode}")
        error_classifier = get_error_classifier()
        classified = error_classifier.classify_error("Trivy", str(e.stderr) if e.stderr else str(e))
        scan.scan_status = "failed"
        scan.error_message = classified.user_message
        await db.commit()
        dispatcher = NotificationDispatcher(db)
        await dispatcher.notify_scan_failed(container.name, classified.user_message)
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse scan output for {container.name}: {e}")
        scan.scan_status = "failed"
        scan.error_message = "Invalid scan output format"
        await db.commit()
        dispatcher = NotificationDispatcher(db)
        await dispatcher.notify_scan_failed(container.name, "Scanner returned invalid output")
    except FileNotFoundError as e:
        logger.error(f"Scanner binary not found: {e}")
        scan.scan_status = "failed"
        scan.error_message = "Scanner binary not found"
        await db.commit()
        dispatcher = NotificationDispatcher(db)
        await dispatcher.notify_scan_failed(container.name, "Trivy scanner not installed")
    except Exception as e:
        # INTENTIONAL: Catch-all for unexpected scanner errors to ensure scan record is updated.
        # The error is classified for user-friendly messaging.
        logger.error(f"Unexpected scan error for {container.name}: {e}", exc_info=True)
        error_classifier = get_error_classifier()
        classified = error_classifier.classify_error("Trivy", str(e))
        scan.scan_status = "failed"
        scan.error_message = classified.user_message
        await db.commit()
        dispatcher = NotificationDispatcher(db)
        await dispatcher.notify_scan_failed(container.name, classified.user_message)


async def run_scans_sequentially(container_ids: list[int], db: AsyncSession):
    """Run scans sequentially with progress tracking."""
    docker_service = DockerService()

    # Start scan tracking
    scan_state.start_scan(len(container_ids))

    try:
        for idx, container_id in enumerate(container_ids, 1):
            # Get container name for progress
            result = await db.execute(select(Container).where(Container.id == container_id))
            container = result.scalar_one_or_none()

            if container:
                # Update progress
                scan_state.update_progress(container.name, idx - 1)

                # Perform scan
                await perform_scan(container_id, db, docker_service)

                # Update progress after completion
                scan_state.update_progress(container.name, idx)
    finally:
        # Always finish scan state
        scan_state.finish_scan()
        docker_service.close()


@router.post("/scan", response_model=dict)
@limiter.limit("10/minute")
async def scan_containers(
    scan_request: ScanRequest, request: Request, db: AsyncSession = Depends(get_db)
):
    """
    Trigger a scan of containers using the scan queue.

    Rate limit: 10 requests per minute to prevent scan spam.
    """
    container_ids = scan_request.container_ids
    scan_queue = get_scan_queue()

    # Get containers to scan
    if not container_ids:
        # Scan all containers
        result = await db.execute(select(Container.id, Container.name))
        containers = result.fetchall()
    else:
        # Scan specific containers
        result = await db.execute(
            select(Container.id, Container.name).where(Container.id.in_(container_ids))
        )
        containers = result.fetchall()

    if not containers:
        raise HTTPException(status_code=404, detail="No containers found to scan")

    # Determine priority based on number of containers
    priority = ScanPriority.HIGH if len(containers) <= 3 else ScanPriority.NORMAL

    # Start batch tracking for progress
    scan_queue.start_batch(len(containers))

    # Enqueue all containers
    queued_count = 0
    skipped_count = 0

    for container_id, container_name in containers:
        if await scan_queue.enqueue(container_id, container_name, priority):
            queued_count += 1
        else:
            skipped_count += 1

    return {
        "message": f"Queued {queued_count} containers for scanning",
        "queued": queued_count,
        "skipped": skipped_count,
        "total_requested": len(containers),
    }


@router.get("/history/{container_id}", response_model=list[ScanSchema])
@limiter.limit("60/minute")
async def get_scan_history(
    container_id: int, limit: int = 10, request: Request = None, db: AsyncSession = Depends(get_db)
):
    """Get scan history for a container."""
    result = await db.execute(
        select(Scan)
        .where(Scan.container_id == container_id)
        .order_by(Scan.scan_date.desc())
        .limit(limit)
    )
    scans = result.scalars().all()

    return [ScanSchema.model_validate(s) for s in scans]


@router.get("/current")
@limiter.limit("120/minute")
async def get_current_scan(request: Request = None):
    """
    Get currently running scan status with queue information.

    This endpoint does NOT require database access - it returns cached state
    from the scan_queue singleton for maximum performance during polling.
    """
    scan_queue = get_scan_queue()
    return scan_queue.get_progress_snapshot()


@router.get("/stream", response_class=StreamingResponse)
@limiter.limit("10/minute")
async def stream_scan_status(request: Request):
    """Stream scan status updates over Server-Sent Events."""
    scan_queue = get_scan_queue()
    subscriber_queue = await scan_events.subscribe()

    async def event_generator():
        try:
            # Send immediate snapshot for new subscribers
            yield _format_sse(scan_queue.get_progress_snapshot())

            while True:
                if await request.is_disconnected():
                    break

                try:
                    event = await asyncio.wait_for(subscriber_queue.get(), timeout=15)
                    yield _format_sse(event)
                except TimeoutError:
                    # Heartbeat to keep connection alive behind proxies
                    yield ": heartbeat\n\n"
        except asyncio.CancelledError:
            raise
        finally:
            await scan_events.unsubscribe(subscriber_queue)

    headers = {
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        "X-Accel-Buffering": "no",
    }
    return StreamingResponse(event_generator(), media_type="text/event-stream", headers=headers)


@router.get("/trends")
@limiter.limit("30/minute")
async def get_scan_trends(
    window_days: int = Query(30, ge=1, le=90),
    request: Request = None,
    db: AsyncSession = Depends(get_db),
):
    """Return aggregated scan trends for dashboards."""
    return await build_scan_trends(db, window_days=window_days)


@router.get("/queue/status")
@limiter.limit("120/minute")
async def get_queue_status(request: Request = None):
    """Get scan queue status."""
    scan_queue = get_scan_queue()
    return scan_queue.get_status()


@router.get("/scanner/health")
@limiter.limit("30/minute")
async def get_scanner_health(request: Request = None):
    """
    Get health status of Trivy scanner.

    Returns information about Trivy scanner availability,
    database freshness, and offline resilience status.
    """
    scan_queue = get_scan_queue()
    return await scan_queue.get_scanner_health()


@router.post("/{scan_id}/abort")
@limiter.limit("20/minute")
async def abort_scan(scan_id: int, request: Request = None, db: AsyncSession = Depends(get_db)):
    """
    Abort a running or queued scan.

    Args:
        scan_id: ID of the scan to abort

    Returns:
        Success message if scan was aborted
    """
    # Get the scan to find container_id
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.scan_status not in ["in_progress", "pending"]:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot abort scan with status: {scan.scan_status}",
        )

    # Request abort from scan queue
    scan_queue = get_scan_queue()
    success = await scan_queue.abort_scan(scan.container_id)

    if success:
        # Update scan status
        scan.scan_status = "aborted"
        scan.error_message = "Scan aborted by user"
        await db.commit()

        return {"message": "Scan abort requested", "scan_id": scan_id}
    else:
        raise HTTPException(status_code=404, detail="Scan not active or queued")


@router.post("/{scan_id}/retry")
@limiter.limit("20/minute")
async def retry_scan(scan_id: int, request: Request = None, db: AsyncSession = Depends(get_db)):
    """
    Retry a failed scan.

    Args:
        scan_id: ID of the scan to retry

    Returns:
        Success message if scan was queued for retry
    """
    # Get the scan to find container
    result = await db.execute(
        select(Scan, Container)
        .join(Container, Scan.container_id == Container.id)
        .where(Scan.id == scan_id)
    )
    row = result.one_or_none()

    if not row:
        raise HTTPException(status_code=404, detail="Scan not found")

    scan, container = row

    if scan.scan_status not in ["failed", "aborted"]:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot retry scan with status: {scan.scan_status}",
        )

    # Queue retry with high priority
    scan_queue = get_scan_queue()
    success = await scan_queue.retry_scan(
        container_id=container.id,
        container_name=container.name,
        priority=ScanPriority.HIGH,
    )

    if success:
        return {
            "message": "Scan queued for retry",
            "scan_id": scan_id,
            "container": container.name,
        }
    else:
        raise HTTPException(status_code=409, detail="Container is already being scanned")


@router.get("/cve-delta")
async def get_cve_delta(
    db: AsyncSession = Depends(get_db),
    since_hours: int = Query(
        default=24, ge=1, le=720, description="Hours to look back for scan deltas"
    ),
    container_name: str | None = Query(default=None, description="Filter by container name"),
):
    """
    Get CVE delta information from recent scans.

    Returns a summary of CVEs fixed and introduced across all containers
    within the specified time window. Used by TideWatch for integration.

    Args:
        since_hours: Number of hours to look back (default 24, max 720/30 days)
        container_name: Optional filter for specific container

    Returns:
        List of scan deltas with container info, cves_fixed, and cves_introduced
    """
    from datetime import timedelta

    cutoff_time = get_now() - timedelta(hours=since_hours)

    # Build query for completed scans with delta info
    query = (
        select(
            Scan.id,
            Scan.scan_date,
            Scan.cves_fixed,
            Scan.cves_introduced,
            Scan.total_vulns,
            Container.name.label("container_name"),
            Container.image,
            Container.image_tag,
        )
        .join(Container, Scan.container_id == Container.id)
        .where(
            Scan.scan_status == "completed",
            Scan.scan_date >= cutoff_time,
        )
        .order_by(Scan.scan_date.desc())
    )

    if container_name:
        query = query.where(Container.name == container_name)

    result = await db.execute(query)
    rows = result.fetchall()

    # Format response
    deltas = []
    total_fixed = 0
    total_introduced = 0

    for row in rows:
        cves_fixed = json.loads(row.cves_fixed) if row.cves_fixed else []
        cves_introduced = json.loads(row.cves_introduced) if row.cves_introduced else []

        total_fixed += len(cves_fixed)
        total_introduced += len(cves_introduced)

        deltas.append(
            {
                "scan_id": row.id,
                "scan_date": row.scan_date.isoformat(),
                "container_name": row.container_name,
                "image": f"{row.image}:{row.image_tag}",
                "total_vulns": row.total_vulns,
                "cves_fixed": cves_fixed,
                "cves_fixed_count": len(cves_fixed),
                "cves_introduced": cves_introduced,
                "cves_introduced_count": len(cves_introduced),
            }
        )

    return {
        "since_hours": since_hours,
        "cutoff_time": cutoff_time.isoformat(),
        "total_scans": len(deltas),
        "summary": {
            "total_cves_fixed": total_fixed,
            "total_cves_introduced": total_introduced,
            "net_change": total_introduced - total_fixed,
        },
        "scans": deltas,
    }
