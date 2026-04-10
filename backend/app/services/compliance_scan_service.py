"""Service for executing compliance scans.

Extracted from routes/compliance.py to fix the layer violation where
scheduler.py imported from a route module. Both the route and the scheduler
now call this service.

Process-local state tracking (compliance_state) is managed here. The route
module retains asyncio.Task lifecycle and polling-endpoint globals.
"""

import json
import logging
from collections.abc import Callable

from app.database import db_session
from app.models import ComplianceFinding, ComplianceScan
from app.services.compliance_checker import ComplianceChecker
from app.services.compliance_state import compliance_state
from app.services.docker_client import DockerService
from app.services.enhanced_notifier import get_enhanced_notifier
from app.services.settings_manager import SettingsManager
from app.utils.timezone import get_now

logger = logging.getLogger(__name__)


async def perform_compliance_scan(
    docker_service: DockerService,
    trigger_type: str = "manual",
    on_scan_created: Callable[[int], None] | None = None,
) -> int | None:
    """Execute a compliance scan using VulnForge native compliance checker.

    Creates its own database session (designed to run as a background task).

    Args:
        docker_service: Docker service instance
        trigger_type: Scan trigger type ("manual" or "scheduled")
        on_scan_created: Optional callback invoked with the scan ID once
            the scan record is created. Used by the route to track the
            current scan for the polling endpoint.

    Returns:
        The scan ID if successful, None on failure.
    """
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

        if on_scan_created:
            on_scan_created(scan.id)

        try:
            # Run native compliance checker
            checker = ComplianceChecker(docker_service)
            scan_result = await checker.run_scan()

            # Update scan record with results
            scan.scan_status = "completed"
            scan.scan_duration_seconds = scan_result.duration_seconds
            scan.total_checks = scan_result.total_checks
            scan.passed_checks = scan_result.passed
            scan.warned_checks = scan_result.warned
            scan.failed_checks = scan_result.failed
            scan.info_checks = scan_result.info
            scan.note_checks = scan_result.skipped
            scan.compliance_score = scan_result.compliance_score
            scan.category_scores = json.dumps(scan_result.category_scores)

            # Store findings
            await _store_findings(db, scan_result)

            await db.commit()
            logger.info(
                "Compliance scan completed: %.1f%% score, %d failed, %d warned, %d passed",
                scan_result.compliance_score,
                scan_result.failed,
                scan_result.warned,
                scan_result.passed,
            )

            # Send notifications
            await _send_notifications(db, scan, scan_result)

            return scan.id

        except PermissionError as e:
            logger.error("Permission denied running compliance scan: %s", e)
            scan.scan_status = "failed"
            scan.error_message = "Permission denied - Docker socket access required"
            await db.commit()
        except ConnectionError as e:
            logger.error("Docker connection error: %s", e)
            scan.scan_status = "failed"
            scan.error_message = "Could not connect to Docker - check DOCKER_HOST setting"
            await db.commit()
        except Exception as e:
            # INTENTIONAL: Catch-all for unexpected compliance scan errors.
            # We must update the scan record to prevent orphaned in_progress scans.
            logger.error("Unexpected compliance scan error: %s", e, exc_info=True)
            scan.scan_status = "failed"
            scan.error_message = str(e)
            await db.commit()
        finally:
            compliance_state.finish_scan()

        return None


async def _store_findings(db, scan_result) -> None:
    """Store compliance findings from scan results."""
    from sqlalchemy import select

    for finding_result in scan_result.findings:
        # For per-target checks, use check_id + target as unique key
        if finding_result.target:
            result = await db.execute(
                select(ComplianceFinding).where(
                    ComplianceFinding.check_id == finding_result.check_id,
                    ComplianceFinding.target == finding_result.target,
                )
            )
        else:
            result = await db.execute(
                select(ComplianceFinding).where(
                    ComplianceFinding.check_id == finding_result.check_id,
                    ComplianceFinding.target.is_(None),
                )
            )
        existing_finding = result.scalar_one_or_none()

        remediation_json = (
            json.dumps(finding_result.remediation) if finding_result.remediation else None
        )

        if existing_finding:
            existing_finding.status = finding_result.status.value
            existing_finding.severity = finding_result.severity.value
            existing_finding.actual_value = finding_result.actual_value
            existing_finding.expected_value = finding_result.expected_value
            existing_finding.remediation = remediation_json
            existing_finding.last_seen = get_now()
            existing_finding.scan_date = get_now()
        else:
            finding = ComplianceFinding(
                check_id=finding_result.check_id,
                check_number=None,
                title=finding_result.title,
                description=finding_result.description,
                status=finding_result.status.value,
                severity=finding_result.severity.value,
                category=finding_result.category,
                target=finding_result.target,
                remediation=remediation_json,
                actual_value=finding_result.actual_value,
                expected_value=finding_result.expected_value,
                first_seen=get_now(),
                last_seen=get_now(),
                scan_date=get_now(),
            )
            db.add(finding)


async def _send_notifications(db, scan, scan_result) -> None:
    """Send compliance scan notifications if enabled."""
    try:
        settings_manager = SettingsManager(db)
        notify_on_scan = await settings_manager.get_bool("compliance_notify_on_scan", default=True)
        notify_on_failures = await settings_manager.get_bool(
            "compliance_notify_on_failures", default=True
        )

        notifier = get_enhanced_notifier()

        if notify_on_scan:
            await notifier.send_notification_with_logging(
                notification_type="compliance_scan_complete",
                title="VulnForge: Compliance Scan Complete",
                message=(
                    "Compliance scan completed\n"
                    f"Compliance Score: {scan_result.compliance_score:.1f}%\n"
                    f"Checks: {scan_result.passed} passed, "
                    f"{scan_result.warned} warned, {scan_result.failed} failed"
                ),
                priority=3,
                tags=["shield", "VulnForge", "compliance"],
                scan_id=scan.id,
            )

        if notify_on_failures and scan_result.failed > 0:
            await notifier.send_notification_with_logging(
                notification_type="compliance_failures",
                title="VulnForge: Compliance Failures Detected",
                message=(
                    f"Compliance scan found {scan_result.failed} failures\n"
                    f"Compliance Score: {scan_result.compliance_score:.1f}%\n"
                    "Review required on Compliance page"
                ),
                priority=4,
                tags=["warning", "VulnForge", "compliance"],
                scan_id=scan.id,
            )

    except Exception as notif_error:
        # INTENTIONAL: Notification failures should not affect scan success.
        logger.error("Failed to send compliance notifications: %s", notif_error)
