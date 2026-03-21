"""Activity logger service for centralized activity logging."""

import logging
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.repositories.activity_log_repository import ActivityLogRepository

logger = logging.getLogger(__name__)


class ActivityLogger:
    """Service for logging system activities.

    All public methods preserve typed entry points for call-site clarity.
    The shared _log() builder handles the common try/except/repository pattern.
    """

    def __init__(self, db: AsyncSession):
        self.db = db
        self.repository = ActivityLogRepository(db)

    async def _log(
        self,
        event_type: str,
        severity: str,
        title: str,
        description: str,
        container_id: int | None = None,
        container_name: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Shared builder for all activity log entries.

        Handles the repository call and swallows exceptions so callers
        never fail due to logging issues.
        """
        try:
            await self.repository.create(
                event_type=event_type,
                severity=severity,
                title=title,
                description=description,
                container_id=container_id,
                container_name=container_name,
                metadata=metadata or {},
            )
        except Exception as e:
            logger.error("Failed to log activity %s: %s", event_type, e, exc_info=True)

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
    ) -> None:
        """Log a successful scan completion."""
        severity = "critical" if critical_count > 0 else ("warning" if high_count > 10 else "info")
        await self._log(
            event_type="scan_completed",
            severity=severity,
            title=f"Scan completed: {container_name}",
            description=f"Found {total_vulns} vulnerabilities ({fixable_vulns} fixable) in {duration:.1f}s",
            container_id=container_id,
            container_name=container_name,
            metadata={
                "scan_id": scan_id,
                "duration_seconds": round(duration, 2),
                "total_vulns": total_vulns,
                "fixable_vulns": fixable_vulns,
                "critical_count": critical_count,
                "high_count": high_count,
                "medium_count": medium_count,
                "low_count": low_count,
            },
        )

    async def log_scan_failed(
        self,
        container_name: str,
        container_id: int,
        error_message: str,
        scan_id: int | None = None,
    ) -> None:
        """Log a failed scan."""
        metadata: dict[str, Any] = {"error_message": error_message}
        if scan_id:
            metadata["scan_id"] = str(scan_id)
        await self._log(
            event_type="scan_failed",
            severity="warning",
            title=f"Scan failed: {container_name}",
            description=f"Error: {error_message}",
            container_id=container_id,
            container_name=container_name,
            metadata=metadata,
        )

    async def log_secret_detected(
        self,
        container_name: str,
        container_id: int,
        scan_id: int,
        total_secrets: int,
        critical_count: int,
        high_count: int,
        categories: list[str],
    ) -> None:
        """Log secret detection event."""
        await self._log(
            event_type="secret_detected",
            severity="critical" if critical_count > 0 else "warning",
            title=f"Secrets detected: {container_name}",
            description=f"Found {total_secrets} secrets ({critical_count} critical, {high_count} high)",
            container_id=container_id,
            container_name=container_name,
            metadata={
                "scan_id": scan_id,
                "total_secrets": total_secrets,
                "critical_count": critical_count,
                "high_count": high_count,
                "categories": categories,
            },
        )

    async def log_high_severity_found(
        self,
        container_name: str,
        container_id: int,
        scan_id: int,
        critical_count: int,
        high_count: int,
    ) -> None:
        """Log high-severity vulnerability discovery."""
        await self._log(
            event_type="high_severity_found",
            severity="critical",
            title=f"High-severity vulnerabilities: {container_name}",
            description=f"Found {critical_count} critical and {high_count} high severity vulnerabilities",
            container_id=container_id,
            container_name=container_name,
            metadata={
                "scan_id": scan_id,
                "critical_count": critical_count,
                "high_count": high_count,
            },
        )

    async def log_container_discovered(
        self,
        container_name: str,
        container_id: int,
        image: str,
        image_tag: str,
        is_running: bool,
    ) -> None:
        """Log container discovery."""
        await self._log(
            event_type="container_discovered",
            severity="info",
            title=f"Container discovered: {container_name}",
            description=f"Image: {image}:{image_tag}, Status: {'running' if is_running else 'stopped'}",
            container_id=container_id,
            container_name=container_name,
            metadata={"image": image, "image_tag": image_tag, "is_running": is_running},
        )

    async def log_batch_scan_completed(
        self,
        containers_count: int,
        total_vulns: int,
        duration: float,
        failed_count: int = 0,
    ) -> None:
        """Log batch scan completion."""
        description = (
            f"Scanned {containers_count} containers in {duration:.1f}s, "
            f"found {total_vulns} total vulnerabilities"
        )
        if failed_count > 0:
            description += f", {failed_count} scans failed"
        await self._log(
            event_type="batch_scan_completed",
            severity="warning" if failed_count > 0 else "info",
            title=f"Batch scan completed: {containers_count} containers",
            description=description,
            metadata={
                "containers_count": containers_count,
                "total_vulns": total_vulns,
                "duration_seconds": round(duration, 2),
                "failed_count": failed_count,
            },
        )

    async def log_container_status_changed(
        self,
        container_name: str,
        container_id: int,
        old_status: str,
        new_status: str,
    ) -> None:
        """Log container status change."""
        await self._log(
            event_type="container_status_changed",
            severity="info",
            title=f"Container status changed: {container_name}",
            description=f"Status: {old_status} → {new_status}",
            container_id=container_id,
            container_name=container_name,
            metadata={"old_status": old_status, "new_status": new_status},
        )

    async def log_false_positive_created(
        self,
        pattern_id: int,
        container_name: str,
        file_path: str,
        rule_id: str,
        username: str,
        reason: str | None = None,
    ) -> None:
        """Log creation of false positive pattern by admin."""
        description = f"Pattern for {rule_id} in {container_name}:{file_path}"
        if reason:
            description += f" - Reason: {reason}"
        await self._log(
            event_type="admin_action",
            severity="info",
            title=f"False positive pattern created by {username}",
            description=description,
            container_name=container_name,
            metadata={
                "pattern_id": pattern_id,
                "file_path": file_path,
                "rule_id": rule_id,
                "username": username,
                "reason": reason,
                "action": "create_false_positive_pattern",
            },
        )

    async def log_false_positive_deleted(
        self,
        pattern_id: int,
        container_name: str,
        file_path: str,
        rule_id: str,
        username: str,
        unsuppressed_count: int = 0,
    ) -> None:
        """Log deletion of false positive pattern and any unsuppressed secrets."""
        description = f"Pattern #{pattern_id} for {rule_id} in {container_name}:{file_path}"
        if unsuppressed_count > 0:
            description += f" — {unsuppressed_count} secret(s) reverted to to_review"
        await self._log(
            event_type="admin_action",
            severity="warning" if unsuppressed_count > 0 else "info",
            title=f"False positive pattern deleted by {username}",
            description=description,
            container_name=container_name,
            metadata={
                "pattern_id": pattern_id,
                "file_path": file_path,
                "rule_id": rule_id,
                "username": username,
                "unsuppressed_count": unsuppressed_count,
                "action": "delete_false_positive_pattern",
            },
        )

    async def log_compliance_finding_ignored(
        self,
        finding_id: int,
        check_id: str,
        check_title: str,
        username: str,
        reason: str,
    ) -> None:
        """Log admin ignoring compliance finding."""
        await self._log(
            event_type="admin_action",
            severity="warning",
            title=f"Compliance finding ignored by {username}",
            description=f"{check_id}: {check_title} - Reason: {reason}",
            metadata={
                "finding_id": finding_id,
                "check_id": check_id,
                "check_title": check_title,
                "username": username,
                "reason": reason,
                "action": "ignore_compliance_finding",
            },
        )

    async def log_compliance_finding_unignored(
        self,
        finding_id: int,
        check_id: str,
        check_title: str,
        username: str,
    ) -> None:
        """Log admin un-ignoring compliance finding."""
        await self._log(
            event_type="admin_action",
            severity="info",
            title=f"Compliance finding un-ignored by {username}",
            description=f"{check_id}: {check_title}",
            metadata={
                "finding_id": finding_id,
                "check_id": check_id,
                "check_title": check_title,
                "username": username,
                "action": "unignore_compliance_finding",
            },
        )

    async def log_secret_status_changed(
        self,
        secret_id: int,
        container_name: str,
        old_status: str,
        new_status: str,
        username: str,
        notes: str | None = None,
    ) -> None:
        """Log admin changing secret status."""
        description = f"Secret #{secret_id} in {container_name}: {old_status} → {new_status}"
        if notes:
            description += f" - Notes: {notes}"
        await self._log(
            event_type="admin_action",
            severity="warning" if new_status == "false_positive" else "info",
            title=f"Secret status changed by {username}",
            description=description,
            container_name=container_name,
            metadata={
                "secret_id": secret_id,
                "old_status": old_status,
                "new_status": new_status,
                "username": username,
                "notes": notes,
                "action": "change_secret_status",
            },
        )

    async def log_vulnerability_status_changed(
        self,
        vuln_id: int,
        cve_id: str,
        container_name: str,
        old_status: str,
        new_status: str,
        username: str,
        notes: str | None = None,
    ) -> None:
        """Log admin changing vulnerability status."""
        description = f"{cve_id} in {container_name}: {old_status} → {new_status}"
        if notes:
            description += f" - Notes: {notes}"
        await self._log(
            event_type="admin_action",
            severity="warning" if new_status in ["accepted", "ignored"] else "info",
            title=f"Vulnerability status changed by {username}",
            description=description,
            container_name=container_name,
            metadata={
                "vuln_id": vuln_id,
                "cve_id": cve_id,
                "old_status": old_status,
                "new_status": new_status,
                "username": username,
                "notes": notes,
                "action": "change_vulnerability_status",
            },
        )

    async def log_bulk_vulnerability_status_changed(
        self,
        vuln_ids: list[int],
        new_status: str,
        username: str,
        notes: str | None = None,
    ) -> None:
        """Log admin bulk changing vulnerability statuses."""
        description = f"Changed {len(vuln_ids)} vulnerabilities to {new_status}"
        if notes:
            description += f" - Notes: {notes}"
        await self._log(
            event_type="admin_action",
            severity="warning" if new_status in ["accepted", "ignored"] else "info",
            title=f"Bulk vulnerability status change by {username}",
            description=description,
            metadata={
                "vuln_ids": vuln_ids,
                "vuln_count": len(vuln_ids),
                "new_status": new_status,
                "username": username,
                "notes": notes,
                "action": "bulk_change_vulnerability_status",
            },
        )
