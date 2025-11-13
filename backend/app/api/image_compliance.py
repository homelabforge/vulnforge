"""Image Compliance API endpoints for Dockle image security checks."""

import asyncio
import csv
import io
import json
import logging
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import db_session, get_db
from app.dependencies.auth import require_admin
from app.models import ImageComplianceFinding, ImageComplianceScan
from app.models.user import User
from app.repositories.dependencies import get_activity_logger
from app.services.activity_logger import ActivityLogger
from app.services.dockle_service import DockleService
from app.services.docker_client import DockerService
from app.services.image_compliance_state import image_compliance_state
from app.utils.timezone import get_now

router = APIRouter()
logger = logging.getLogger(__name__)

# Track current scan state
_current_scan_task: asyncio.Task | None = None
_current_scan_id: int | None = None


async def perform_image_compliance_scan(
    docker_service: DockerService,
    image_name: str,
    trigger_type: str = "manual",
    affected_containers: list[str] | None = None,
) -> None:
    """
    Perform a Dockle image compliance scan.

    Args:
        docker_service: Docker service instance
        image_name: Image name or ID to scan
        trigger_type: Scan trigger type (manual, scheduled, post-vulnerability-scan)
    """

    global _current_scan_id

    # Create new database session for background task
    async with db_session() as db:
        # Create scan record
        scan = ImageComplianceScan(
            scan_date=get_now(),
            scan_status="in_progress",
            image_name=image_name,
            trigger_type=trigger_type,
        )
        db.add(scan)
        await db.commit()
        await db.refresh(scan)

        _current_scan_id = scan.id

        image_compliance_state.update_current_image(image_name)

        success = False
        error_message = None

        try:
            # Execute Dockle scan
            dockle_service = DockleService(docker_service)
            scan_data = await dockle_service.run_image_scan(image_name)

            if scan_data is None:
                # Scan failed
                scan.scan_status = "failed"
                scan.error_message = "Dockle scan returned no data"
                await db.commit()
                return

            # Calculate scores
            findings = scan_data["findings"]
            compliance_score = dockle_service.calculate_image_score(findings)
            category_scores = dockle_service.calculate_category_scores(findings)
            raw_summary = scan_data.get("raw_data", {}).get("summary", {})
            summary = (
                {str(k).lower(): v for k, v in raw_summary.items()}
                if isinstance(raw_summary, dict)
                else {}
            )

            def _as_int(value):
                if value is None:
                    return None
                try:
                    return int(value)
                except (TypeError, ValueError):
                    return None

            # Derive counts directly from the findings we store
            fatal = sum(1 for f in findings if f["severity"] == "CRITICAL")
            warn = sum(1 for f in findings if f["severity"] == "HIGH")
            info = sum(1 for f in findings if f["status"] == "INFO")
            skip = sum(1 for f in findings if f["status"] == "SKIP")
            fail_count = sum(1 for f in findings if f["status"] == "FAIL")

            summary_total = _as_int(summary.get("total"))
            summary_pass = _as_int(summary.get("pass"))

            if summary_total is not None:
                total_checks = summary_total
            else:
                total_checks = fail_count + info + skip
                if summary_pass is not None:
                    total_checks += summary_pass

            if summary_pass is not None:
                passed = summary_pass
            else:
                derived = total_checks - fail_count - info - skip
                passed = derived if derived >= 0 else 0

            failed = fail_count

            # Ensure totals stay non-negative
            if total_checks < passed + failed + info + skip:
                total_checks = passed + failed + info + skip

            # Update scan record
            scan.scan_status = "completed"
            scan.scan_duration_seconds = scan_data["scan_duration_seconds"]
            scan.total_checks = total_checks
            scan.passed_checks = passed
            scan.failed_checks = failed
            scan.info_checks = info
            scan.skip_checks = skip
            scan.compliance_score = compliance_score
            scan.category_scores = json.dumps(category_scores)
            scan.fatal_count = fatal
            scan.warn_count = warn

            # Get affected containers
            containers_for_image = affected_containers or []
            if not containers_for_image and "affected_containers" in scan_data:
                containers_for_image = scan_data["affected_containers"] or []

            if containers_for_image:
                scan.affected_containers = json.dumps(containers_for_image)

            # Store findings
            for finding_data in findings:
                # Check if this finding already exists (by check_id + image_name)
                result = await db.execute(
                    select(ImageComplianceFinding).where(
                        ImageComplianceFinding.check_id == finding_data["check_id"],
                        ImageComplianceFinding.image_name == image_name,
                    )
                )
                existing_finding = result.scalar_one_or_none()

                if existing_finding:
                    # Update existing finding
                    existing_finding.status = finding_data["status"]
                    existing_finding.severity = finding_data["severity"]
                    existing_finding.last_seen = get_now()
                    existing_finding.scan_date = get_now()
                    # Don't change ignore status if it was previously ignored
                else:
                    # Create new finding
                    finding = ImageComplianceFinding(
                        check_id=finding_data["check_id"],
                        check_number=finding_data.get("check_number"),
                        title=finding_data["title"],
                        description=finding_data.get("description"),
                        image_name=image_name,
                        status=finding_data["status"],
                        severity=finding_data["severity"],
                        category=finding_data["category"],
                        remediation=finding_data.get("remediation"),
                        alerts=json.dumps(finding_data.get("alerts", [])),
                        first_seen=get_now(),
                        last_seen=get_now(),
                        scan_date=get_now(),
                    )
                    db.add(finding)

            await db.commit()
            logger.info(
                f"Image compliance scan completed: {image_name} - {compliance_score:.1f}% score, "
                f"{failed} failed, {passed} passed"
            )

            success = True

        except Exception as e:
            logger.error(f"Image compliance scan failed: {e}", exc_info=True)
            scan.scan_status = "failed"
            scan.error_message = str(e)
            error_message = str(e)
            await db.commit()
        finally:
            _current_scan_id = None
            image_compliance_state.record_result(
                image_name=image_name,
                success=success,
                error_message=error_message,
            )


def _normalize_image_reference(container: dict) -> str | None:
    """Derive a Dockle-friendly image reference from container metadata."""
    image_full = container.get("image_full")
    if image_full and not image_full.startswith("<none>"):
        return image_full

    image = container.get("image")
    image_tag = container.get("image_tag")
    if image and image_tag and image_tag != "<none>":
        return f"{image}:{image_tag}"

    return container.get("image_id")


def _resolve_unique_images(docker_service: DockerService) -> dict[str, list[str]]:
    """Collect unique image references and their running containers."""
    containers = docker_service.list_containers(all_containers=True)
    image_map: dict[str, list[str]] = {}

    for container in containers:
        if not container.get("is_running"):
            continue
        image_ref = _normalize_image_reference(container)
        if not image_ref:
            continue
        image_map.setdefault(image_ref, []).append(container.get("name"))

    return image_map


async def _run_single_image_scan_task(
    docker_service: DockerService,
    image_name: str,
    trigger_type: str,
):
    """Background task wrapper for a single Dockle scan."""
    global _current_scan_task
    try:
        image_compliance_state.start_scan(
            total_images=1,
            mode="single",
            targets=[image_name],
        )
        containers_map = _resolve_unique_images(docker_service)
        await perform_image_compliance_scan(
            docker_service,
            image_name,
            trigger_type,
            affected_containers=containers_map.get(image_name, []),
        )
    except Exception as exc:  # pragma: no cover - defensive logging
        logger.error("Image compliance scan task failed: %s", exc, exc_info=True)
    finally:
        image_compliance_state.finish_scan()
        _current_scan_task = None


async def _run_batch_image_scan_task(
    docker_service: DockerService,
    image_map: dict[str, list[str]],
    trigger_type: str,
):
    """Background task wrapper that sequentially scans a list of images."""
    global _current_scan_task

    if not image_map:
        image_compliance_state.finish_scan()
        _current_scan_task = None
        return

    try:
        image_names = list(image_map.keys())
        image_compliance_state.start_scan(
            total_images=len(image_names),
            mode="batch",
            targets=image_names,
        )
        for image, containers in image_map.items():
            await perform_image_compliance_scan(
                docker_service,
                image,
                trigger_type,
                affected_containers=containers,
            )
    except Exception as exc:  # pragma: no cover - defensive logging
        logger.error("Batch image compliance scan aborted: %s", exc, exc_info=True)
    finally:
        image_compliance_state.finish_scan()
        _current_scan_task = None


@router.post("/scan", response_model=dict)
async def trigger_image_scan(
    image_name: str,
    user: User = Depends(require_admin),
):
    """
    Trigger a Dockle image compliance scan. Admin only.

    Args:
        image_name: Name or ID of Docker image to scan

    Returns:
        Message confirming scan trigger
    """
    global _current_scan_task

    if not image_name or not image_name.strip():
        raise HTTPException(status_code=400, detail="Image name is required")

    # Check if a scan (single or batch) is already in progress
    if _current_scan_task and not _current_scan_task.done():
        raise HTTPException(status_code=409, detail="Image compliance scan already in progress")

    docker_service = DockerService()
    normalized_image = image_name.strip()

    _current_scan_task = asyncio.create_task(
        _run_single_image_scan_task(docker_service, normalized_image, "manual"),
        name=f"dockle-scan-{normalized_image}",
    )

    logger.info("Triggered image compliance scan for %s by %s", normalized_image, user.username)

    return {"message": "Image compliance scan started", "image_name": normalized_image}


@router.post("/scan-all", response_model=dict)
async def trigger_image_scan_all(
    user: User = Depends(require_admin),
):
    """
    Trigger Dockle scans for all unique images used by current containers.

    Returns:
        Summary with number of queued images.
    """
    global _current_scan_task

    if _current_scan_task and not _current_scan_task.done():
        raise HTTPException(status_code=409, detail="Image compliance scan already in progress")

    docker_service = DockerService()
    image_map = _resolve_unique_images(docker_service)

    if not image_map:
        raise HTTPException(status_code=404, detail="No container images found to scan")

    _current_scan_task = asyncio.create_task(
        _run_batch_image_scan_task(docker_service, image_map, "manual"),
        name="dockle-scan-batch",
    )

    logger.info(
        "Triggered batch image compliance scan for %d images by %s",
        len(image_map),
        user.username,
    )

    return {"message": "Batch image compliance scan started", "image_count": len(image_map)}


@router.get("/current", response_model=dict)
async def get_current_image_scan_status():
    """
    Poll current image compliance scan status for UI updates.
    """
    return image_compliance_state.get_status()


@router.get("/summary", response_model=dict)
async def get_image_compliance_summary(db: AsyncSession = Depends(get_db)):
    """
    Get image compliance summary aggregated across all scanned images.

    Args:
        db: Database session

    Returns:
        Image compliance summary with aggregated data
    """
    # Get latest scan for each unique image
    subquery = (
        select(
            ImageComplianceScan.image_name,
            func.max(ImageComplianceScan.id).label("max_id"),
        )
        .where(ImageComplianceScan.scan_status == "completed")
        .group_by(ImageComplianceScan.image_name)
        .subquery()
    )

    # Get all latest scans
    result = await db.execute(
        select(ImageComplianceScan)
        .join(subquery, ImageComplianceScan.id == subquery.c.max_id)
    )
    latest_scans = result.scalars().all()

    if not latest_scans:
        return {
            "total_images_scanned": 0,
            "average_compliance_score": None,
            "critical_findings": 0,
            "total_active_failures": 0,
        }

    # Calculate aggregated metrics
    total_images = len(latest_scans)
    total_compliance = sum(scan.compliance_score for scan in latest_scans if scan.compliance_score is not None)
    avg_compliance = total_compliance / total_images if total_images > 0 else 0

    # Sum up critical findings and active failures across all images
    total_critical = sum(scan.fatal_count for scan in latest_scans)
    total_failures = sum(scan.failed_checks for scan in latest_scans)

    return {
        "total_images_scanned": total_images,
        "average_compliance_score": avg_compliance,
        "critical_findings": total_critical,
        "total_active_failures": total_failures,
    }


@router.get("/images", response_model=list[dict])
async def list_scanned_images(db: AsyncSession = Depends(get_db)):
    """
    List all scanned images with their latest scores.

    Args:
        db: Database session

    Returns:
        List of scanned images with compliance data
    """
    # Get latest scan for each unique image
    subquery = (
        select(
            ImageComplianceScan.image_name,
            func.max(ImageComplianceScan.id).label("max_id"),
        )
        .where(ImageComplianceScan.scan_status == "completed")
        .group_by(ImageComplianceScan.image_name)
        .subquery()
    )

    result = await db.execute(
        select(ImageComplianceScan)
        .join(subquery, ImageComplianceScan.id == subquery.c.max_id)
        .order_by(ImageComplianceScan.compliance_score.asc())  # Worst scores first
    )
    scans = result.scalars().all()

    images = []
    for scan in scans:
        # Get finding counts for this image
        result = await db.execute(
            select(func.count(ImageComplianceFinding.id))
            .where(
                ImageComplianceFinding.image_name == scan.image_name,
                ImageComplianceFinding.status == "FAIL",
                ImageComplianceFinding.is_ignored == False,
            )
        )
        active_failures = result.scalar() or 0

        # Parse affected containers
        affected_containers = []
        if scan.affected_containers:
            try:
                affected_containers = json.loads(scan.affected_containers)
            except json.JSONDecodeError:
                pass

        images.append({
            "image_name": scan.image_name,
            "compliance_score": scan.compliance_score,
            "total_checks": scan.total_checks,
            "passed_checks": scan.passed_checks,
            "failed_checks": scan.failed_checks,
            "active_failures": active_failures,
            "fatal_count": scan.fatal_count,
            "warn_count": scan.warn_count,
            "last_scan_date": scan.scan_date,
            "affected_containers": affected_containers,
        })

    return images


@router.get("/findings/{image_name:path}", response_model=list[dict])
async def get_image_findings(
    image_name: str,
    include_ignored: bool = False,
    status_filter: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    """
    Get compliance findings for a specific image.

    Args:
        image_name: Image name
        include_ignored: Whether to include ignored findings
        status_filter: Filter by status (PASS, FAIL, INFO, SKIP)
        db: Database session

    Returns:
        List of compliance findings
    """
    query = select(ImageComplianceFinding).where(
        ImageComplianceFinding.image_name == image_name
    )

    # Filter ignored
    if not include_ignored:
        query = query.where(ImageComplianceFinding.is_ignored == False)

    # Filter by status
    if status_filter:
        query = query.where(ImageComplianceFinding.status == status_filter.upper())

    # Order by severity and check_id
    query = query.order_by(
        ImageComplianceFinding.severity.desc(), ImageComplianceFinding.check_id
    )

    result = await db.execute(query)
    findings = result.scalars().all()

    findings_list = []
    for f in findings:
        # Parse alerts
        alerts = []
        if f.alerts:
            try:
                alerts = json.loads(f.alerts)
            except json.JSONDecodeError:
                pass

        findings_list.append({
            "id": f.id,
            "check_id": f.check_id,
            "title": f.title,
            "description": f.description,
            "status": f.status,
            "severity": f.severity,
            "category": f.category,
            "remediation": f.remediation,
            "alerts": alerts,
            "is_ignored": f.is_ignored,
            "ignored_reason": f.ignored_reason,
            "ignored_by": f.ignored_by,
            "first_seen": f.first_seen,
            "last_seen": f.last_seen,
        })

    return findings_list


@router.post("/findings/{finding_id}/ignore", response_model=dict)
async def ignore_image_finding(
    finding_id: int,
    reason: str,
    db: AsyncSession = Depends(get_db),
    activity_logger: ActivityLogger = Depends(get_activity_logger),
    user: User = Depends(require_admin),
):
    """
    Mark an image compliance finding as ignored/false positive. Admin only.

    Args:
        finding_id: Finding ID
        reason: Reason for ignoring
        db: Database session

    Returns:
        Updated finding
    """
    # Get finding
    result = await db.execute(
        select(ImageComplianceFinding).where(ImageComplianceFinding.id == finding_id)
    )
    finding = result.scalar_one_or_none()

    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    # Mark as ignored
    finding.is_ignored = True
    finding.ignored_reason = reason
    finding.ignored_by = user.username  # Use authenticated user
    finding.ignored_at = get_now()

    await db.commit()
    await db.refresh(finding)

    logger.info(
        f"Marked image compliance finding {finding.check_id} for {finding.image_name} as ignored by {user.username}"
    )

    return {
        "id": finding.id,
        "check_id": finding.check_id,
        "is_ignored": finding.is_ignored,
        "ignored_by": finding.ignored_by,
        "ignored_at": finding.ignored_at,
    }


@router.post("/findings/{finding_id}/unignore", response_model=dict)
async def unignore_image_finding(
    finding_id: int,
    db: AsyncSession = Depends(get_db),
    activity_logger: ActivityLogger = Depends(get_activity_logger),
    user: User = Depends(require_admin),
):
    """
    Unmark an image compliance finding as ignored. Admin only.

    Args:
        finding_id: Finding ID
        db: Database session

    Returns:
        Updated finding
    """
    # Get finding
    result = await db.execute(
        select(ImageComplianceFinding).where(ImageComplianceFinding.id == finding_id)
    )
    finding = result.scalar_one_or_none()

    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    # Unmark as ignored
    finding.is_ignored = False
    finding.ignored_reason = None
    finding.ignored_by = None
    finding.ignored_at = None

    await db.commit()
    await db.refresh(finding)

    logger.info(
        f"Unmarked image compliance finding {finding.check_id} for {finding.image_name} as ignored by {user.username}"
    )

    return {
        "id": finding.id,
        "check_id": finding.check_id,
        "is_ignored": finding.is_ignored,
    }


@router.get("/scans/history", response_model=list[dict])
async def get_scan_history(limit: int = 10, db: AsyncSession = Depends(get_db)):
    """
    Get image compliance scan history.

    Args:
        limit: Maximum number of scans to return
        db: Database session

    Returns:
        List of image compliance scans
    """
    result = await db.execute(
        select(ImageComplianceScan)
        .order_by(ImageComplianceScan.scan_date.desc())
        .limit(limit)
    )
    scans = result.scalars().all()

    scan_list = []
    for s in scans:
        scan_list.append({
            "id": s.id,
            "scan_date": s.scan_date,
            "scan_status": s.scan_status,
            "image_name": s.image_name,
            "compliance_score": s.compliance_score,
            "total_checks": s.total_checks,
            "passed_checks": s.passed_checks,
            "failed_checks": s.failed_checks,
            "scan_duration_seconds": s.scan_duration_seconds,
            "error_message": s.error_message,
        })

    return scan_list


@router.get("/export/csv")
async def export_image_compliance_csv(
    image_name: str | None = None,
    include_ignored: bool = False,
    db: AsyncSession = Depends(get_db),
):
    """
    Export image compliance findings to CSV.

    Args:
        image_name: Optional filter by image name
        include_ignored: Whether to include ignored findings
        db: Database session

    Returns:
        CSV file stream
    """
    # Build query
    query = select(ImageComplianceFinding)

    if image_name:
        query = query.where(ImageComplianceFinding.image_name == image_name)

    if not include_ignored:
        query = query.where(ImageComplianceFinding.is_ignored == False)

    query = query.order_by(
        ImageComplianceFinding.severity.desc(), ImageComplianceFinding.check_id
    )

    result = await db.execute(query)
    findings = result.scalars().all()

    # Create CSV in memory
    output = io.StringIO()
    writer = csv.writer(output)

    # Write header
    writer.writerow([
        "Check ID",
        "Image Name",
        "Title",
        "Status",
        "Severity",
        "Category",
        "Description",
        "Remediation",
        "First Seen",
        "Last Seen",
        "Is Ignored",
        "Ignored Reason",
        "Ignored By",
    ])

    # Write findings
    for finding in findings:
        writer.writerow([
            finding.check_id,
            finding.image_name,
            finding.title,
            finding.status,
            finding.severity,
            finding.category,
            finding.description or "",
            finding.remediation or "",
            finding.first_seen.isoformat() if finding.first_seen else "",
            finding.last_seen.isoformat() if finding.last_seen else "",
            "Yes" if finding.is_ignored else "No",
            finding.ignored_reason or "",
            finding.ignored_by or "",
        ])

    # Reset stream position
    output.seek(0)

    # Generate filename with timestamp
    timestamp = get_now().strftime("%Y%m%d_%H%M%S")
    filename = f"image_compliance_{timestamp}.csv"

    # Return as streaming response
    return StreamingResponse(
        io.BytesIO(output.getvalue().encode("utf-8")),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )
