"""Service for executing image misconfiguration scans.

Extracted from routes/image_compliance.py to match the compliance_scan_service
pattern and prevent future layer violations.

Process-local state tracking (image_misconfig_state) is managed here. The route
module retains asyncio.Task lifecycle and polling-endpoint globals.
"""

import json
import logging
import subprocess
from collections.abc import Callable

from sqlalchemy import select

from app.database import db_session
from app.models import ImageComplianceFinding, ImageComplianceScan
from app.services.docker_client import DockerService
from app.services.image_misconfig_state import image_misconfig_state
from app.services.trivy_misconfig_service import TrivyMisconfigService
from app.utils.log_redaction import sanitize_for_log
from app.utils.timezone import get_now

logger = logging.getLogger(__name__)


async def perform_image_compliance_scan(
    docker_service: DockerService,
    image_name: str,
    trigger_type: str = "manual",
    affected_containers: list[str] | None = None,
    on_scan_created: Callable[[int], None] | None = None,
) -> int | None:
    """Execute a Trivy image misconfiguration scan.

    Creates its own database session (designed to run as a background task).

    Args:
        docker_service: Docker service instance
        image_name: Image name or ID to scan
        trigger_type: Scan trigger type (manual, scheduled, post-vulnerability-scan)
        affected_containers: List of container names using this image
        on_scan_created: Optional callback invoked with the scan ID once
            the scan record is created.

    Returns:
        The scan ID if successful, None on failure.
    """
    async with db_session() as db:
        scan = ImageComplianceScan(
            scan_date=get_now(),
            scan_status="in_progress",
            image_name=image_name,
            trigger_type=trigger_type,
        )
        db.add(scan)
        await db.commit()
        await db.refresh(scan)

        if on_scan_created:
            on_scan_created(scan.id)

        image_misconfig_state.update_current_image(image_name)

        try:
            trivy_service = TrivyMisconfigService(docker_service)
            scan_data = await trivy_service.run_misconfig_scan(image_name)

            if scan_data is None:
                scan.scan_status = "failed"
                scan.error_message = "Trivy misconfiguration scan returned no data"
                await db.commit()
                return None

            findings = scan_data["findings"]
            compliance_score = trivy_service.calculate_compliance_score(findings)

            fatal = scan_data["critical_count"]
            warn = scan_data["high_count"]
            medium = scan_data["medium_count"]
            low = scan_data["low_count"]
            failed = fatal + warn
            info = medium + low

            scan.scan_status = "completed"
            scan.scan_duration_seconds = scan_data["scan_duration_seconds"]
            scan.total_checks = scan_data["total_count"]
            scan.passed_checks = 0
            scan.failed_checks = failed
            scan.info_checks = info
            scan.skip_checks = 0
            scan.compliance_score = compliance_score
            scan.category_scores = None
            scan.fatal_count = fatal
            scan.warn_count = warn

            containers_for_image = affected_containers or []
            if containers_for_image:
                scan.affected_containers = json.dumps(containers_for_image)

            await _store_findings(db, image_name, findings)

            await db.commit()
            logger.info(
                "Image misconfiguration scan completed: %s - %.1f%% score, "
                "%d critical/high, %d medium/low",
                sanitize_for_log(image_name),
                compliance_score,
                failed,
                info,
            )

            image_misconfig_state.record_result(
                image_name=image_name, success=True, error_message=None
            )
            return scan.id

        except subprocess.TimeoutExpired as e:
            logger.error("Image scan timed out for %s: %s", sanitize_for_log(image_name), e)
            scan.scan_status = "failed"
            scan.error_message = "Scan timed out - image may be too large"
            await db.commit()
        except subprocess.CalledProcessError as e:
            logger.error(
                "Trivy process failed for %s: exit code %d",
                sanitize_for_log(image_name),
                e.returncode,
            )
            scan.scan_status = "failed"
            scan.error_message = f"Trivy scan failed with exit code {e.returncode}"
            await db.commit()
        except json.JSONDecodeError as e:
            logger.error("Failed to parse Trivy output for %s: %s", sanitize_for_log(image_name), e)
            scan.scan_status = "failed"
            scan.error_message = "Invalid scan output format"
            await db.commit()
        except Exception as e:
            # INTENTIONAL: Catch-all for unexpected scan errors.
            logger.error(
                "Unexpected image scan error for %s: %s",
                sanitize_for_log(image_name),
                e,
                exc_info=True,
            )
            scan.scan_status = "failed"
            scan.error_message = str(e)
            await db.commit()

        # Failure path
        image_misconfig_state.record_result(
            image_name=image_name, success=False, error_message=scan.error_message
        )
        return None


async def _store_findings(db, image_name: str, findings: list[dict]) -> None:
    """Store image compliance findings from scan results."""
    for finding_data in findings:
        result = await db.execute(
            select(ImageComplianceFinding).where(
                ImageComplianceFinding.check_id == finding_data["check_id"],
                ImageComplianceFinding.image_name == image_name,
            )
        )
        existing_finding = result.scalar_one_or_none()

        if finding_data["severity"] in ("CRITICAL", "HIGH"):
            status = "FAIL"
        else:
            status = "INFO"

        if existing_finding:
            existing_finding.status = status
            existing_finding.severity = finding_data["severity"]
            existing_finding.last_seen = get_now()
            existing_finding.scan_date = get_now()
            existing_finding.title = finding_data["title"]
            existing_finding.description = finding_data.get("description")
            existing_finding.remediation = finding_data.get("resolution")
        else:
            alerts = []
            if finding_data.get("code_snippet"):
                alerts.append(
                    {"code": finding_data["code_snippet"], "line": finding_data.get("start_line")}
                )

            finding = ImageComplianceFinding(
                check_id=finding_data["check_id"],
                check_number=None,
                title=finding_data["title"],
                description=finding_data.get("description"),
                image_name=image_name,
                status=status,
                severity=finding_data["severity"],
                category=finding_data.get("service", "general"),
                remediation=finding_data.get("resolution"),
                alerts=json.dumps(alerts) if alerts else None,
                first_seen=get_now(),
                last_seen=get_now(),
                scan_date=get_now(),
            )
            db.add(finding)
