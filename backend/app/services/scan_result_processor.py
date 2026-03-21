"""Service for processing scan results: vulnerability storage, secret handling, notifications.

Extracted from scan_queue.py to separate result persistence from queue management.
"""

import logging

from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Container, Scan, Secret, Vulnerability
from app.repositories.false_positive_pattern_repository import FalsePositivePatternRepository
from app.services.activity_logger import ActivityLogger
from app.services.settings_manager import SettingsManager

logger = logging.getLogger(__name__)


class ScanResultProcessor:
    """Process and persist scan results (vulnerabilities, secrets, notifications)."""

    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def store_vulnerabilities_with_kev(
        self,
        scan: Scan,
        vulnerabilities: list[dict],
    ) -> int:
        """Store vulnerabilities with KEV enrichment. Returns KEV match count."""
        settings_manager = SettingsManager(self.db)
        kev_enabled = await settings_manager.get_bool("kev_checking_enabled", default=True)

        from app.services.kev import get_kev_service

        kev_service = get_kev_service()
        if kev_enabled:
            await kev_service.ensure_catalog_loaded()

        kev_count = 0
        for vuln_data in vulnerabilities:
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
                cvss_score=vuln_data.get("cvss_score"),
                title=vuln_data.get("title"),
                description=vuln_data.get("description"),
                installed_version=vuln_data["installed_version"],
                fixed_version=vuln_data.get("fixed_version"),
                is_fixable=vuln_data["is_fixable"],
                primary_url=vuln_data.get("primary_url"),
                references=vuln_data.get("references"),
                scanner=vuln_data.get("scanner", "trivy"),
                confidence=vuln_data.get("confidence"),
                found_by_scanners=vuln_data.get("found_by_scanners"),
                is_kev=is_kev,
                kev_added_date=kev_added_date,
                kev_due_date=kev_due_date,
            )
            self.db.add(vuln)

        return kev_count

    async def store_secrets_with_fp_matching(
        self,
        scan: Scan,
        container: Container,
        secrets_data: list[dict],
    ) -> list[dict]:
        """Store secrets with false-positive pattern matching. Returns non-FP secrets."""
        fp_repo = FalsePositivePatternRepository(self.db)
        non_fp_secrets: list[dict] = []
        for secret_data in secrets_data:
            # Build a lightweight Secret-like object for pattern matching
            probe = Secret(
                scan_id=scan.id,
                rule_id=secret_data["rule_id"],
                category=secret_data["category"],
                title=secret_data["title"],
                severity=secret_data["severity"],
                match=secret_data["match"],
                file_path=secret_data.get("file_path"),
                start_line=secret_data.get("start_line"),
            )
            fp_pattern_match = await fp_repo.matches_pattern(probe, container.name)

            initial_status = "to_review"
            if fp_pattern_match:
                initial_status = "false_positive"
                await fp_repo.record_match(fp_pattern_match.id)

            secret = Secret(
                scan_id=scan.id,
                rule_id=secret_data["rule_id"],
                category=secret_data["category"],
                title=secret_data["title"],
                severity=secret_data["severity"],
                match=secret_data["match"],
                start_line=secret_data.get("start_line"),
                end_line=secret_data.get("end_line"),
                code_snippet=secret_data.get("code_snippet"),
                layer_digest=secret_data.get("layer_digest"),
                file_path=secret_data.get("file_path"),
                status=initial_status,
            )
            self.db.add(secret)

            if initial_status != "false_positive":
                non_fp_secrets.append(secret_data)

        return non_fp_secrets

    async def notify_secrets_detected(
        self,
        container: Container,
        scan: Scan,
        secrets_list: list[dict],
    ) -> None:
        """Send notifications and log activity for detected secrets."""
        from app.services.notifications import NotificationDispatcher

        secret_critical = sum(1 for s in secrets_list if s["severity"] == "CRITICAL")
        secret_high = sum(1 for s in secrets_list if s["severity"] == "HIGH")
        secret_categories = list(set(s["category"] for s in secrets_list))

        dispatcher = NotificationDispatcher(self.db)
        await dispatcher.notify_secrets_detected(
            container_name=container.name,
            total_secrets=len(secrets_list),
            critical_count=secret_critical,
            high_count=secret_high,
            categories=secret_categories,
        )

        try:
            activity_logger = ActivityLogger(self.db)
            await activity_logger.log_secret_detected(
                container_name=container.name,
                container_id=container.id,
                scan_id=scan.id,
                total_secrets=len(secrets_list),
                critical_count=secret_critical,
                high_count=secret_high,
                categories=secret_categories,
            )
        except Exception as e:
            logger.error("Failed to log secret detection activity: %s", e, exc_info=True)
