"""Compliance API endpoints for Docker Bench security checks."""

import asyncio
import csv
import io
import json
import logging
import subprocess
from datetime import datetime

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import db_session, get_db
from app.dependencies.auth import require_admin
from app.models import ComplianceFinding, ComplianceScan
from app.models.user import User
from app.repositories.dependencies import get_activity_logger
from app.schemas.compliance import (
    ComplianceCurrentScan,
    ComplianceFinding as ComplianceFindingSchema,
    ComplianceFindingIgnoreRequest,
    ComplianceFindingUnignoreRequest,
    ComplianceScan as ComplianceScanSchema,
    ComplianceSummary,
    ComplianceTriggerRequest,
)
from app.services.activity_logger import ActivityLogger
from app.services.docker_bench_service import DockerBenchService
from app.services.docker_client import DockerService
from app.services.trivy_scanner import TrivyScanner
from app.services.trivy_compliance_service import TrivyComplianceService
from app.services.enhanced_notifier import get_enhanced_notifier
from app.services.settings_manager import SettingsManager
from app.services.compliance_state import compliance_state
from app.utils.timezone import get_now

router = APIRouter()
logger = logging.getLogger(__name__)

# Track current scan state
_current_scan_task: asyncio.Task | None = None
_current_scan_id: int | None = None
_last_scan_id: int | None = None  # Track most recent completed scan
_completion_poll_count: int = 0  # Count polls since completion


async def perform_compliance_scan(docker_service: DockerService, trigger_type: str = "manual"):
    """
    Perform a compliance scan using Trivy (primary) with Docker Bench in legacy validation mode.

    Args:
        docker_service: Docker service instance
        trigger_type: Scan trigger type (manual or scheduled)
    """
    global _current_scan_id, _last_scan_id

    # Create new database session for background task
    async with db_session() as db:
        # Create scan record
        scan = ComplianceScan(
            scan_date=get_now(),
            scan_status="in_progress",
            trigger_type=trigger_type,
        )
        db.add(scan)
        await db.commit()
        await db.refresh(scan)

        _current_scan_id = scan.id

        try:
            # Track scan start time for duration calculation
            import time
            scan_start_time = time.time()

            # Run Docker Bench Security scan for Docker host compliance.
            # Note: Trivy's --compliance flag is for scanning container images against
            # compliance benchmarks, not for scanning the Docker daemon/host itself.
            # For Docker daemon compliance (CIS Docker Benchmark), we use Docker Bench.
            bench_service = DockerBenchService(docker_service)

            scan_data = await bench_service.run_compliance_scan()

            if scan_data is None:
                # Scanner failed
                scan.scan_status = "failed"
                scan.error_message = "Docker Bench scan returned no data"
                await db.commit()
                return

            # Use Docker Bench results
            findings = scan_data["findings"]
            compliance_score = bench_service.calculate_compliance_score(findings)
            category_scores = bench_service.calculate_category_scores(findings)

            # Count statuses from Docker Bench findings
            passed = sum(1 for f in findings if f["status"] == "PASS")
            warned = sum(1 for f in findings if f["status"] == "WARN")
            failed = sum(1 for f in findings if f["status"] == "FAIL")
            info = sum(1 for f in findings if f["status"] == "INFO")
            note = sum(1 for f in findings if f["status"] == "NOTE")

            # TODO: Future enhancement - add Trivy image compliance scanning
            # (scanning individual container images for compliance, not the Docker host)

            # Calculate scan duration
            scan_duration_seconds = int(time.time() - scan_start_time)

            # Use Docker Bench duration if available, otherwise use calculated duration
            if scan_data is not None and "scan_duration_seconds" in scan_data:
                scan_duration_seconds = scan_data["scan_duration_seconds"]

            # Update scan record
            scan.scan_status = "completed"
            scan.scan_duration_seconds = scan_duration_seconds
            scan.total_checks = len(findings)
            scan.passed_checks = passed
            scan.warned_checks = warned
            scan.failed_checks = failed
            scan.info_checks = info
            scan.note_checks = note
            scan.compliance_score = compliance_score
            scan.category_scores = json.dumps(category_scores)

            # Store findings
            for finding_data in findings:
                # Check if this finding already exists (by check_id)
                result = await db.execute(
                    select(ComplianceFinding).where(
                        ComplianceFinding.check_id == finding_data["check_id"]
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
                    finding = ComplianceFinding(
                        check_id=finding_data["check_id"],
                        check_number=finding_data.get("check_number"),
                        title=finding_data["title"],
                        description=finding_data.get("description"),
                        status=finding_data["status"],
                        severity=finding_data["severity"],
                        category=finding_data["category"],
                        remediation=finding_data.get("remediation"),
                        actual_value=finding_data.get("actual_value"),
                        expected_value=finding_data.get("expected_value"),
                        first_seen=get_now(),
                        last_seen=get_now(),
                        scan_date=get_now(),
                    )
                    db.add(finding)

            await db.commit()
            logger.info(
                f"Compliance scan completed: {compliance_score:.1f}% score, "
                f"{failed} failed, {warned} warned, {passed} passed"
            )

            # Send notifications if enabled
            try:
                settings_manager = SettingsManager(db)
                notify_on_scan = await settings_manager.get_bool("compliance_notify_on_scan", default=True)
                notify_on_failures = await settings_manager.get_bool("compliance_notify_on_failures", default=True)

                notifier = get_enhanced_notifier()

                # Send scan complete notification
                if notify_on_scan:
                    await notifier.send_notification_with_logging(
                        notification_type="compliance_scan_complete",
                        title="VulnForge: Compliance Scan Complete",
                        message=(
                            "Docker Bench scan completed\n"
                            f"Compliance Score: {compliance_score:.1f}%\n"
                            f"Checks: {passed} passed, {warned} warned, {failed} failed"
                        ),
                        priority=3,
                        tags=["shield", "VulnForge", "compliance"],
                        scan_id=scan.id,
                    )

                # Send failure notification if there are critical failures
                if notify_on_failures and failed > 0:
                    await notifier.send_notification_with_logging(
                        notification_type="compliance_failures",
                        title="VulnForge: Compliance Failures Detected",
                        message=(
                            f"Docker Bench found {failed} critical failures\n"
                            f"Compliance Score: {compliance_score:.1f}%\n"
                            "Review required on Compliance page"
                        ),
                        priority=4,
                        tags=["warning", "VulnForge", "compliance"],
                        scan_id=scan.id,
                    )

            except Exception as notif_error:
                # INTENTIONAL: Notification failures should not affect scan success.
                logger.error(f"Failed to send compliance notifications: {notif_error}")

        except subprocess.TimeoutExpired as e:
            logger.error(f"Compliance scan timed out: {e}")
            scan.scan_status = "failed"
            scan.error_message = "Compliance scan timed out - Docker Bench may need longer"
            await db.commit()
        except subprocess.CalledProcessError as e:
            logger.error(f"Docker Bench process failed with exit code {e.returncode}")
            scan.scan_status = "failed"
            scan.error_message = f"Docker Bench scan failed with exit code {e.returncode}"
            await db.commit()
        except PermissionError as e:
            logger.error(f"Permission denied running compliance scan: {e}")
            scan.scan_status = "failed"
            scan.error_message = "Permission denied - Docker socket access required"
            await db.commit()
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Docker Bench output: {e}")
            scan.scan_status = "failed"
            scan.error_message = "Invalid compliance scan output format"
            await db.commit()
        except Exception as e:
            # INTENTIONAL: Catch-all for unexpected compliance scan errors.
            # We must update the scan record to prevent orphaned in_progress scans.
            logger.error(f"Unexpected compliance scan error: {e}", exc_info=True)
            scan.scan_status = "failed"
            scan.error_message = str(e)
            await db.commit()
        finally:
            # Store last scan ID before clearing current
            if _current_scan_id is not None:
                _last_scan_id = _current_scan_id

            # Finish progress tracking AFTER all DB operations complete
            compliance_state.finish_scan()
            _current_scan_id = None


@router.post("/scan", response_model=dict)
async def trigger_compliance_scan(
    request: ComplianceTriggerRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_admin),
):
    """
    Trigger a compliance scan. Admin only.

    Args:
        request: Trigger request with scan type
        background_tasks: FastAPI background tasks
        db: Database session

    Returns:
        Message confirming scan trigger
    """
    global _current_scan_task, _completion_poll_count

    # Check if scan already running
    if _current_scan_task and not _current_scan_task.done():
        raise HTTPException(status_code=409, detail="Compliance scan already in progress")

    # Reset completion poll count for new scan
    _completion_poll_count = 0

    # Create docker service
    docker_service = DockerService()

    # Run scan in background (creates its own DB session)
    _current_scan_task = asyncio.create_task(
        perform_compliance_scan(docker_service, request.trigger_type)
    )

    logger.debug(f"trigger_scan: Created task {_current_scan_task}, done={_current_scan_task.done()}")

    return {
        "message": "Compliance scan started (Trivy compliance with Docker Bench legacy validation)",
        "trigger_type": request.trigger_type,
    }


@router.get("/current", response_model=ComplianceCurrentScan)
async def get_current_scan():
    """
    Get currently running compliance scan status with real-time progress.

    This endpoint does NOT require database access - it returns cached state
    from the compliance_state singleton for maximum performance during polling.

    Returns:
        Current scan status with detailed progress
    """
    global _current_scan_task, _current_scan_id, _last_scan_id, _completion_poll_count

    # Log task state for debugging
    task_exists = _current_scan_task is not None
    task_done = _current_scan_task.done() if _current_scan_task else None
    logger.debug(f"get_current_scan: task_exists={task_exists}, task_done={task_done}, scan_id={_current_scan_id}, last_scan_id={_last_scan_id}, poll_count={_completion_poll_count}")

    if _current_scan_task and not _current_scan_task.done():
        # Scan in progress - get real-time progress from compliance_state
        state_status = compliance_state.get_status()

        # Log compliance state for debugging
        logger.debug(f"get_current_scan: compliance_state.get_status() = {state_status}")

        if state_status["status"] == "scanning":
            # Get scan record if available
            scan_id = _current_scan_id
            started_at = state_status.get("started_at")

            # Build progress message
            if state_status.get("current_check_id"):
                progress_msg = f"Running check {state_status['current_check_id']}: {state_status['current_check']}"
            else:
                progress_msg = state_status.get("current_check", "Initializing compliance scan...")

            return ComplianceCurrentScan(
                status="scanning",
                scan_id=scan_id,
                started_at=started_at,
                progress=progress_msg,
                current_check=state_status.get("current_check"),
                current_check_id=state_status.get("current_check_id"),
                progress_current=state_status.get("progress_current"),
                progress_total=state_status.get("progress_total"),
            )

        # Task running but state says idle (transitional state)
        return ComplianceCurrentScan(
            status="scanning",
            scan_id=_current_scan_id,
            started_at=None,
            progress="Initializing compliance scan...",
            current_check="Starting Trivy compliance scan...",
            current_check_id="",
            progress_current=0,
            progress_total=150,
        )

    # No scan running - check if we just finished one
    if _current_scan_task and _current_scan_task.done() and _last_scan_id:
        # Scan just completed - return completed status with scan_id for result retrieval
        # Allow frontend to poll for "completed" status a few times (3 seconds at 1s intervals)
        # then transition back to idle
        _completion_poll_count += 1

        if _completion_poll_count <= 3:
            logger.debug(f"get_current_scan: Scan completed, returning last_scan_id={_last_scan_id} (poll {_completion_poll_count}/3)")
            return ComplianceCurrentScan(
                status="completed",
                scan_id=_last_scan_id,
                started_at=None,
                progress="Scan completed",
                current_check=None,
                current_check_id=None,
                progress_current=None,
                progress_total=None,
            )
        else:
            # Clear the task reference after frontend has had time to process
            logger.debug(f"get_current_scan: Clearing task after {_completion_poll_count} polls")
            _current_scan_task = None
            _last_scan_id = None
            _completion_poll_count = 0

    # No scan running and no recent completion
    return ComplianceCurrentScan(
        status="idle",
        scan_id=None,
        started_at=None,
        progress=None,
        current_check=None,
        current_check_id=None,
        progress_current=None,
        progress_total=None,
    )


@router.get("/summary", response_model=ComplianceSummary)
async def get_compliance_summary(db: AsyncSession = Depends(get_db)):
    """
    Get compliance summary with latest scan results.

    Args:
        db: Database session

    Returns:
        Compliance summary
    """
    # Get latest scan
    result = await db.execute(
        select(ComplianceScan)
        .where(ComplianceScan.scan_status == "completed")
        .order_by(ComplianceScan.scan_date.desc())
        .limit(1)
    )
    latest_scan = result.scalar_one_or_none()

    if not latest_scan:
        return ComplianceSummary()

    # Get severity breakdown for failures
    result = await db.execute(
        select(
            ComplianceFinding.severity,
            func.count(ComplianceFinding.id).label("count")
        )
        .where(ComplianceFinding.status == "FAIL")
        .where(ComplianceFinding.is_ignored == False)
        .group_by(ComplianceFinding.severity)
    )
    severity_counts = {row.severity: row.count for row in result}

    # Get ignored findings count
    result = await db.execute(
        select(func.count(ComplianceFinding.id))
        .where(ComplianceFinding.is_ignored == True)
    )
    ignored_count = result.scalar() or 0

    # Parse category scores
    category_breakdown = None
    if latest_scan.category_scores:
        try:
            category_breakdown = json.loads(latest_scan.category_scores)
        except json.JSONDecodeError:
            pass

    return ComplianceSummary(
        last_scan_date=latest_scan.scan_date,
        last_scan_status=latest_scan.scan_status,
        compliance_score=latest_scan.compliance_score,
        total_checks=latest_scan.total_checks,
        passed_checks=latest_scan.passed_checks,
        warned_checks=latest_scan.warned_checks,
        failed_checks=latest_scan.failed_checks,
        info_checks=latest_scan.info_checks,
        note_checks=latest_scan.note_checks,
        high_severity_failures=severity_counts.get("HIGH", 0),
        medium_severity_failures=severity_counts.get("MEDIUM", 0),
        low_severity_failures=severity_counts.get("LOW", 0),
        ignored_findings_count=ignored_count,
        category_breakdown=category_breakdown,
    )


@router.get("/findings", response_model=list[ComplianceFindingSchema])
async def get_compliance_findings(
    include_ignored: bool = False,
    status_filter: str | None = None,
    category_filter: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    """
    Get compliance findings with optional filters.

    Args:
        include_ignored: Whether to include ignored findings
        status_filter: Filter by status (PASS, WARN, FAIL, INFO, NOTE)
        category_filter: Filter by category
        db: Database session

    Returns:
        List of compliance findings
    """
    query = select(ComplianceFinding)

    # Filter ignored
    if not include_ignored:
        query = query.where(ComplianceFinding.is_ignored == False)

    # Filter by status
    if status_filter:
        query = query.where(ComplianceFinding.status == status_filter.upper())

    # Filter by category
    if category_filter:
        query = query.where(ComplianceFinding.category == category_filter)

    # Order by severity and check_id
    query = query.order_by(
        ComplianceFinding.severity.desc(),
        ComplianceFinding.check_id
    )

    result = await db.execute(query)
    findings = result.scalars().all()

    return [ComplianceFindingSchema.model_validate(f) for f in findings]


@router.post("/findings/ignore", response_model=ComplianceFindingSchema)
async def ignore_compliance_finding(
    request: ComplianceFindingIgnoreRequest,
    db: AsyncSession = Depends(get_db),
    activity_logger: ActivityLogger = Depends(get_activity_logger),
    user: User = Depends(require_admin),
):
    """
    Mark a compliance finding as ignored/false positive. Admin only.

    Args:
        request: Ignore request with finding ID and reason
        db: Database session

    Returns:
        Updated finding
    """
    # Get finding
    result = await db.execute(
        select(ComplianceFinding).where(ComplianceFinding.id == request.finding_id)
    )
    finding = result.scalar_one_or_none()

    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    # Mark as ignored - use authenticated username, NOT request payload
    finding.is_ignored = True
    finding.ignored_reason = request.reason
    finding.ignored_by = user.username  # SECURITY FIX: Use authenticated user
    finding.ignored_at = get_now()

    await db.commit()
    await db.refresh(finding)

    # Log the admin action for audit trail
    await activity_logger.log_compliance_finding_ignored(
        finding_id=finding.id,
        check_id=finding.check_id,
        check_title=finding.title,
        username=user.username,
        reason=request.reason,
    )

    logger.info(f"Marked compliance finding {finding.check_id} as ignored by {user.username}: {request.reason}")

    return ComplianceFindingSchema.model_validate(finding)


@router.post("/findings/unignore", response_model=ComplianceFindingSchema)
async def unignore_compliance_finding(
    request: ComplianceFindingUnignoreRequest,
    db: AsyncSession = Depends(get_db),
    activity_logger: ActivityLogger = Depends(get_activity_logger),
    user: User = Depends(require_admin),
):
    """
    Unmark a compliance finding as ignored. Admin only.

    Args:
        request: Unignore request with finding ID
        db: Database session

    Returns:
        Updated finding
    """
    # Get finding
    result = await db.execute(
        select(ComplianceFinding).where(ComplianceFinding.id == request.finding_id)
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

    # Log the admin action for audit trail
    await activity_logger.log_compliance_finding_unignored(
        finding_id=finding.id,
        check_id=finding.check_id,
        check_title=finding.title,
        username=user.username,
    )

    logger.info(f"Unmarked compliance finding {finding.check_id} as ignored by {user.username}")

    return ComplianceFindingSchema.model_validate(finding)


@router.get("/scans/history", response_model=list[ComplianceScanSchema])
async def get_scan_history(limit: int = 10, db: AsyncSession = Depends(get_db)):
    """
    Get compliance scan history.

    Args:
        limit: Maximum number of scans to return
        db: Database session

    Returns:
        List of compliance scans
    """
    result = await db.execute(
        select(ComplianceScan)
        .order_by(ComplianceScan.scan_date.desc())
        .limit(limit)
    )
    scans = result.scalars().all()

    return [ComplianceScanSchema.model_validate(s) for s in scans]


@router.get("/scans/trend")
async def get_compliance_trend(days: int = 30, db: AsyncSession = Depends(get_db)):
    """
    Get compliance score trend over time.

    Args:
        days: Number of days to include in trend
        db: Database session

    Returns:
        Trend data with timestamps and scores
    """
    from datetime import timedelta

    cutoff_date = get_now() - timedelta(days=days)

    result = await db.execute(
        select(ComplianceScan)
        .where(
            ComplianceScan.scan_date >= cutoff_date,
            ComplianceScan.scan_status == "completed",
        )
        .order_by(ComplianceScan.scan_date.asc())
    )
    scans = result.scalars().all()

    # Format for charting
    trend_data = []
    for scan in scans:
        category_scores = json.loads(scan.category_scores) if scan.category_scores else {}
        trend_data.append({
            "date": scan.scan_date.isoformat(),
            "compliance_score": scan.compliance_score,
            "passed_checks": scan.passed_checks,
            "warned_checks": scan.warned_checks,
            "failed_checks": scan.failed_checks,
            "total_checks": scan.total_checks,
            "category_scores": category_scores,
        })

    return trend_data


@router.get("/export/csv")
async def export_compliance_csv(
    include_ignored: bool = False,
    status_filter: str | None = None,
    category_filter: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    """
    Export compliance findings to CSV.

    Args:
        include_ignored: Whether to include ignored findings
        status_filter: Filter by status
        category_filter: Filter by category
        db: Database session

    Returns:
        CSV file stream
    """
    # Build query with same filters as findings endpoint
    query = select(ComplianceFinding)

    if not include_ignored:
        query = query.where(ComplianceFinding.is_ignored == False)

    if status_filter:
        query = query.where(ComplianceFinding.status == status_filter.upper())

    if category_filter:
        query = query.where(ComplianceFinding.category == category_filter)

    query = query.order_by(
        ComplianceFinding.severity.desc(),
        ComplianceFinding.check_id
    )

    result = await db.execute(query)
    findings = result.scalars().all()

    # Create CSV in memory
    output = io.StringIO()
    writer = csv.writer(output)

    # Write header
    writer.writerow([
        "Check ID",
        "Check Number",
        "Title",
        "Status",
        "Severity",
        "Category",
        "Description",
        "Remediation",
        "Actual Value",
        "Expected Value",
        "First Seen",
        "Last Seen",
        "Is Ignored",
        "Ignored Reason",
        "Ignored By",
        "Ignored At",
    ])

    # Write findings
    for finding in findings:
        writer.writerow([
            finding.check_id,
            finding.check_number or "",
            finding.title,
            finding.status,
            finding.severity,
            finding.category,
            finding.description or "",
            finding.remediation or "",
            finding.actual_value or "",
            finding.expected_value or "",
            finding.first_seen.isoformat() if finding.first_seen else "",
            finding.last_seen.isoformat() if finding.last_seen else "",
            "Yes" if finding.is_ignored else "No",
            finding.ignored_reason or "",
            finding.ignored_by or "",
            finding.ignored_at.isoformat() if finding.ignored_at else "",
        ])

    # Reset stream position
    output.seek(0)

    # Generate filename with timestamp
    timestamp = get_now().strftime("%Y%m%d_%H%M%S")
    filename = f"compliance_report_{timestamp}.csv"

    # Return as streaming response
    return StreamingResponse(
        io.BytesIO(output.getvalue().encode("utf-8")),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )
