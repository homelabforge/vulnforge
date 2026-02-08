"""Activity logger service for centralized activity logging."""

import logging

from sqlalchemy.ext.asyncio import AsyncSession

from app.repositories.activity_log_repository import ActivityLogRepository
from app.utils.log_redaction import sanitize_for_log

logger = logging.getLogger(__name__)


class ActivityLogger:
    """Service for logging system activities."""

    def __init__(self, db: AsyncSession):
        """
        Initialize activity logger.

        Args:
            db: Database session
        """
        self.db = db
        self.repository = ActivityLogRepository(db)

    async def log_scan_completed(
        self,
        container_name: str,
        container_id: int,
        scan_id: int,
        duration: float,
        total_vulns: int,
        fixable_vulns: int,
        critical_count: int,
        high_count: int,
        medium_count: int,
        low_count: int,
    ):
        """
        Log a successful scan completion.

        Args:
            container_name: Name of scanned container
            container_id: Container ID
            scan_id: Scan record ID
            duration: Scan duration in seconds
            total_vulns: Total vulnerabilities found
            fixable_vulns: Number of fixable vulnerabilities
            critical_count: Critical vulnerabilities
            high_count: High severity vulnerabilities
            medium_count: Medium severity vulnerabilities
            low_count: Low severity vulnerabilities
        """
        try:
            # Determine severity based on critical/high counts
            severity = "info"
            if critical_count > 0:
                severity = "critical"
            elif high_count > 10:  # Threshold for high severity events
                severity = "warning"

            title = f"Scan completed: {container_name}"
            description = (
                f"Found {total_vulns} vulnerabilities ({fixable_vulns} fixable) in {duration:.1f}s"
            )

            metadata = {
                "scan_id": scan_id,
                "duration_seconds": round(duration, 2),
                "total_vulns": total_vulns,
                "fixable_vulns": fixable_vulns,
                "critical_count": critical_count,
                "high_count": high_count,
                "medium_count": medium_count,
                "low_count": low_count,
            }

            await self.repository.create(
                event_type="scan_completed",
                severity=severity,
                title=title,
                description=description,
                container_id=container_id,
                container_name=container_name,
                metadata=metadata,
            )

            logger.debug(f"Logged scan completion for {sanitize_for_log(container_name)}")

        except Exception as e:
            logger.error(f"Failed to log scan completion: {e}", exc_info=True)

    async def log_scan_failed(
        self,
        container_name: str,
        container_id: int,
        error_message: str,
        scan_id: int | None = None,
    ):
        """
        Log a failed scan.

        Args:
            container_name: Name of container
            container_id: Container ID
            error_message: Error message
            scan_id: Scan record ID (if created)
        """
        try:
            title = f"Scan failed: {container_name}"
            description = f"Error: {error_message}"

            metadata = {"error_message": error_message}
            if scan_id:
                metadata["scan_id"] = str(scan_id)

            await self.repository.create(
                event_type="scan_failed",
                severity="warning",
                title=title,
                description=description,
                container_id=container_id,
                container_name=container_name,
                metadata=metadata,
            )

            logger.debug(f"Logged scan failure for {sanitize_for_log(container_name)}")

        except Exception as e:
            logger.error(f"Failed to log scan failure: {e}", exc_info=True)

    async def log_secret_detected(
        self,
        container_name: str,
        container_id: int,
        scan_id: int,
        total_secrets: int,
        critical_count: int,
        high_count: int,
        categories: list[str],
    ):
        """
        Log secret detection event.

        Args:
            container_name: Name of container
            container_id: Container ID
            scan_id: Scan record ID
            total_secrets: Total secrets found
            critical_count: Critical severity secrets
            high_count: High severity secrets
            categories: List of secret categories detected
        """
        try:
            # Determine severity based on secret severity
            severity = "critical" if critical_count > 0 else "warning"

            title = f"Secrets detected: {container_name}"
            description = (
                f"Found {total_secrets} secrets ({critical_count} critical, {high_count} high)"
            )

            metadata = {
                "scan_id": scan_id,
                "total_secrets": total_secrets,
                "critical_count": critical_count,
                "high_count": high_count,
                "categories": categories,
            }

            await self.repository.create(
                event_type="secret_detected",
                severity=severity,
                title=title,
                description=description,
                container_id=container_id,
                container_name=container_name,
                metadata=metadata,
            )

            logger.debug(f"Logged secret detection for {sanitize_for_log(container_name)}")

        except Exception as e:
            logger.error(f"Failed to log secret detection: {e}", exc_info=True)

    async def log_high_severity_found(
        self,
        container_name: str,
        container_id: int,
        scan_id: int,
        critical_count: int,
        high_count: int,
    ):
        """
        Log high-severity vulnerability discovery.

        Args:
            container_name: Name of container
            container_id: Container ID
            scan_id: Scan record ID
            critical_count: Critical vulnerabilities found
            high_count: High vulnerabilities found
        """
        try:
            title = f"High-severity vulnerabilities: {container_name}"
            description = (
                f"Found {critical_count} critical and {high_count} high severity vulnerabilities"
            )

            metadata = {
                "scan_id": scan_id,
                "critical_count": critical_count,
                "high_count": high_count,
            }

            await self.repository.create(
                event_type="high_severity_found",
                severity="critical",
                title=title,
                description=description,
                container_id=container_id,
                container_name=container_name,
                metadata=metadata,
            )

            logger.debug(
                f"Logged high-severity vulnerabilities for {sanitize_for_log(container_name)}"
            )

        except Exception as e:
            logger.error(f"Failed to log high-severity vulnerabilities: {e}", exc_info=True)

    async def log_container_discovered(
        self,
        container_name: str,
        container_id: int,
        image: str,
        image_tag: str,
        is_running: bool,
    ):
        """
        Log container discovery.

        Args:
            container_name: Name of discovered container
            container_id: Container ID
            image: Container image name
            image_tag: Image tag
            is_running: Whether container is running
        """
        try:
            title = f"Container discovered: {container_name}"
            description = (
                f"Image: {image}:{image_tag}, Status: {'running' if is_running else 'stopped'}"
            )

            metadata = {
                "image": image,
                "image_tag": image_tag,
                "is_running": is_running,
            }

            await self.repository.create(
                event_type="container_discovered",
                severity="info",
                title=title,
                description=description,
                container_id=container_id,
                container_name=container_name,
                metadata=metadata,
            )

            logger.debug(f"Logged container discovery: {sanitize_for_log(container_name)}")

        except Exception as e:
            logger.error(f"Failed to log container discovery: {e}", exc_info=True)

    async def log_batch_scan_completed(
        self,
        containers_count: int,
        total_vulns: int,
        duration: float,
        failed_count: int = 0,
    ):
        """
        Log batch scan completion.

        Args:
            containers_count: Number of containers scanned
            total_vulns: Total vulnerabilities found across all containers
            duration: Total scan duration in seconds
            failed_count: Number of failed scans
        """
        try:
            title = f"Batch scan completed: {containers_count} containers"
            description = (
                f"Scanned {containers_count} containers in {duration:.1f}s, "
                f"found {total_vulns} total vulnerabilities"
            )
            if failed_count > 0:
                description += f", {failed_count} scans failed"

            metadata = {
                "containers_count": containers_count,
                "total_vulns": total_vulns,
                "duration_seconds": round(duration, 2),
                "failed_count": failed_count,
            }

            severity = "warning" if failed_count > 0 else "info"

            await self.repository.create(
                event_type="batch_scan_completed",
                severity=severity,
                title=title,
                description=description,
                container_id=None,
                container_name=None,
                metadata=metadata,
            )

            logger.debug(f"Logged batch scan completion: {containers_count} containers")

        except Exception as e:
            logger.error(f"Failed to log batch scan completion: {e}", exc_info=True)

    async def log_container_status_changed(
        self,
        container_name: str,
        container_id: int,
        old_status: str,
        new_status: str,
    ):
        """
        Log container status change.

        Args:
            container_name: Name of container
            container_id: Container ID
            old_status: Previous status
            new_status: New status
        """
        try:
            title = f"Container status changed: {container_name}"
            description = f"Status: {old_status} → {new_status}"

            metadata = {"old_status": old_status, "new_status": new_status}

            await self.repository.create(
                event_type="container_status_changed",
                severity="info",
                title=title,
                description=description,
                container_id=container_id,
                container_name=container_name,
                metadata=metadata,
            )

            logger.debug(
                f"Logged status change for {sanitize_for_log(container_name)}: {sanitize_for_log(old_status)} → {sanitize_for_log(new_status)}"
            )

        except Exception as e:
            logger.error(f"Failed to log container status change: {e}", exc_info=True)

    async def log_false_positive_created(
        self,
        pattern_id: int,
        container_name: str,
        file_path: str,
        rule_id: str,
        username: str,
        reason: str | None = None,
    ):
        """
        Log creation of false positive pattern by admin.

        Args:
            pattern_id: ID of created pattern
            container_name: Container name
            file_path: File path where secret was found
            rule_id: Secret detection rule ID
            username: Username of admin who created pattern
            reason: Optional reason for false positive
        """
        try:
            title = f"False positive pattern created by {username}"
            description = f"Pattern for {rule_id} in {container_name}:{file_path}"
            if reason:
                description += f" - Reason: {reason}"

            metadata = {
                "pattern_id": pattern_id,
                "file_path": file_path,
                "rule_id": rule_id,
                "username": username,
                "reason": reason,
                "action": "create_false_positive_pattern",
            }

            await self.repository.create(
                event_type="admin_action",
                severity="info",
                title=title,
                description=description,
                container_id=None,
                container_name=container_name,
                metadata=metadata,
            )

            logger.info(f"Logged false positive pattern creation by {sanitize_for_log(username)}")

        except Exception as e:
            logger.error(f"Failed to log false positive creation: {e}", exc_info=True)

    async def log_compliance_finding_ignored(
        self,
        finding_id: int,
        check_id: str,
        check_title: str,
        username: str,
        reason: str,
    ):
        """
        Log admin ignoring compliance finding.

        Args:
            finding_id: ID of compliance finding
            check_id: CIS check ID (e.g., "5.2")
            check_title: Check title
            username: Username of admin who ignored finding
            reason: Reason for ignoring
        """
        try:
            title = f"Compliance finding ignored by {username}"
            description = f"{check_id}: {check_title} - Reason: {reason}"

            metadata = {
                "finding_id": finding_id,
                "check_id": check_id,
                "check_title": check_title,
                "username": username,
                "reason": reason,
                "action": "ignore_compliance_finding",
            }

            await self.repository.create(
                event_type="admin_action",
                severity="warning",
                title=title,
                description=description,
                container_id=None,
                container_name=None,
                metadata=metadata,
            )

            logger.info(
                f"Logged compliance finding ignore by {sanitize_for_log(username)}: {sanitize_for_log(check_id)}"
            )

        except Exception as e:
            logger.error(f"Failed to log compliance finding ignore: {e}", exc_info=True)

    async def log_compliance_finding_unignored(
        self,
        finding_id: int,
        check_id: str,
        check_title: str,
        username: str,
    ):
        """
        Log admin un-ignoring compliance finding.

        Args:
            finding_id: ID of compliance finding
            check_id: CIS check ID
            check_title: Check title
            username: Username of admin who un-ignored finding
        """
        try:
            title = f"Compliance finding un-ignored by {username}"
            description = f"{check_id}: {check_title}"

            metadata = {
                "finding_id": finding_id,
                "check_id": check_id,
                "check_title": check_title,
                "username": username,
                "action": "unignore_compliance_finding",
            }

            await self.repository.create(
                event_type="admin_action",
                severity="info",
                title=title,
                description=description,
                container_id=None,
                container_name=None,
                metadata=metadata,
            )

            logger.info(
                f"Logged compliance finding unignore by {sanitize_for_log(username)}: {sanitize_for_log(check_id)}"
            )

        except Exception as e:
            logger.error(f"Failed to log compliance finding unignore: {e}", exc_info=True)

    async def log_secret_status_changed(
        self,
        secret_id: int,
        container_name: str,
        old_status: str,
        new_status: str,
        username: str,
        notes: str | None = None,
    ):
        """
        Log admin changing secret status.

        Args:
            secret_id: ID of secret
            container_name: Container name where secret was found
            old_status: Previous status
            new_status: New status
            username: Username of admin who changed status
            notes: Optional notes about the change
        """
        try:
            title = f"Secret status changed by {username}"
            description = f"Secret #{secret_id} in {container_name}: {old_status} → {new_status}"
            if notes:
                description += f" - Notes: {notes}"

            metadata = {
                "secret_id": secret_id,
                "old_status": old_status,
                "new_status": new_status,
                "username": username,
                "notes": notes,
                "action": "change_secret_status",
            }

            # Determine severity based on new status
            severity = "warning" if new_status == "false_positive" else "info"

            await self.repository.create(
                event_type="admin_action",
                severity=severity,
                title=title,
                description=description,
                container_id=None,
                container_name=container_name,
                metadata=metadata,
            )

            logger.info(
                f"Logged secret status change by {sanitize_for_log(username)}: {sanitize_for_log(old_status)} → {sanitize_for_log(new_status)}"
            )

        except Exception as e:
            logger.error(f"Failed to log secret status change: {e}", exc_info=True)

    async def log_vulnerability_status_changed(
        self,
        vuln_id: int,
        cve_id: str,
        container_name: str,
        old_status: str,
        new_status: str,
        username: str,
        notes: str | None = None,
    ):
        """
        Log admin changing vulnerability status.

        Args:
            vuln_id: ID of vulnerability
            cve_id: CVE identifier
            container_name: Container name
            old_status: Previous status
            new_status: New status
            username: Username of admin who changed status
            notes: Optional notes
        """
        try:
            title = f"Vulnerability status changed by {username}"
            description = f"{cve_id} in {container_name}: {old_status} → {new_status}"
            if notes:
                description += f" - Notes: {notes}"

            metadata = {
                "vuln_id": vuln_id,
                "cve_id": cve_id,
                "old_status": old_status,
                "new_status": new_status,
                "username": username,
                "notes": notes,
                "action": "change_vulnerability_status",
            }

            # More severe if accepting/ignoring vulnerabilities
            severity = "warning" if new_status in ["accepted", "ignored"] else "info"

            await self.repository.create(
                event_type="admin_action",
                severity=severity,
                title=title,
                description=description,
                container_id=None,
                container_name=container_name,
                metadata=metadata,
            )

            logger.info(
                f"Logged vulnerability status change by {sanitize_for_log(username)}: {sanitize_for_log(cve_id)}"
            )

        except Exception as e:
            logger.error(f"Failed to log vulnerability status change: {e}", exc_info=True)

    async def log_bulk_vulnerability_status_changed(
        self,
        vuln_ids: list[int],
        new_status: str,
        username: str,
        notes: str | None = None,
    ):
        """
        Log admin bulk changing vulnerability statuses.

        Args:
            vuln_ids: List of vulnerability IDs
            new_status: New status
            username: Username of admin who changed statuses
            notes: Optional notes
        """
        try:
            title = f"Bulk vulnerability status change by {username}"
            description = f"Changed {len(vuln_ids)} vulnerabilities to {new_status}"
            if notes:
                description += f" - Notes: {notes}"

            metadata = {
                "vuln_ids": vuln_ids,
                "vuln_count": len(vuln_ids),
                "new_status": new_status,
                "username": username,
                "notes": notes,
                "action": "bulk_change_vulnerability_status",
            }

            severity = "warning" if new_status in ["accepted", "ignored"] else "info"

            await self.repository.create(
                event_type="admin_action",
                severity=severity,
                title=title,
                description=description,
                container_id=None,
                container_name=None,
                metadata=metadata,
            )

            logger.info(
                f"Logged bulk vulnerability status change by {username}: {len(vuln_ids)} vulnerabilities"
            )

        except Exception as e:
            logger.error(f"Failed to log bulk vulnerability status change: {e}", exc_info=True)
