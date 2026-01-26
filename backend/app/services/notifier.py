"""Notification service for sending alerts via ntfy."""

import logging

import httpx

from app.config import settings as app_settings
from app.database import db_session
from app.services.settings_manager import SettingsManager
from app.utils.log_redaction import redact_sensitive_data

logger = logging.getLogger(__name__)


class NotificationService:
    """Service for sending notifications via ntfy."""

    def __init__(self):
        """Initialize notification service."""
        # Settings will be loaded dynamically from database
        self.enabled = None
        self.url = None
        self.topic = None
        self.token = None

    async def _load_settings(self):
        """Load settings from database."""
        async with db_session() as db:
            settings_manager = SettingsManager(db)
            self.enabled = await settings_manager.get_bool(
                "ntfy_enabled", default=app_settings.ntfy_enabled
            )
            self.url = await settings_manager.get("ntfy_url", default=app_settings.ntfy_url)
            self.topic = await settings_manager.get("ntfy_topic", default=app_settings.ntfy_topic)
            self.token = await settings_manager.get("ntfy_token", default=app_settings.ntfy_token)

    async def send_notification(
        self,
        message: str,
        title: str | None = None,
        priority: int = 3,
        tags: list[str] | None = None,
    ) -> bool:
        """
        Send a notification via ntfy.

        Args:
            message: Notification message
            title: Optional title
            priority: Priority level (1-5, default 3)
            tags: Optional list of tags/emojis

        Returns:
            True if sent successfully
        """
        # Load settings from database
        await self._load_settings()

        if not self.enabled:
            logger.debug(f"Notification not sent (disabled): {redact_sensitive_data(message)}")
            return False

        try:
            endpoint = f"{self.url}/{self.topic}"

            headers = {}
            if title:
                headers["Title"] = title
            if tags:
                headers["Tags"] = ",".join(tags)
            headers["Priority"] = str(priority)

            # Add authentication token if configured
            if self.token:
                headers["Authorization"] = f"Bearer {self.token}"

            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post(
                    endpoint,
                    content=message,
                    headers=headers,
                )
                response.raise_for_status()
                logger.info(f"Notification sent: {redact_sensitive_data(message[:50])}")
                return True

        except httpx.HTTPError as e:
            logger.error(f"Failed to send notification: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error sending notification: {e}")
            return False

    async def notify_scan_complete(
        self,
        total_containers: int,
        critical: int,
        high: int,
        fixable_critical: int,
        fixable_high: int,
    ) -> bool:
        """
        Send notification when scan completes.

        Args:
            total_containers: Number of containers scanned
            critical: Total critical vulnerabilities
            high: Total high vulnerabilities
            fixable_critical: Fixable critical vulnerabilities
            fixable_high: Fixable high vulnerabilities

        Returns:
            True if sent successfully
        """
        # Load notification settings from database
        notify_on_scan_complete = False
        async with db_session() as db:
            settings_manager = SettingsManager(db)
            notify_on_scan_complete = await settings_manager.get_bool(
                "notify_on_scan_complete", default=app_settings.notify_on_scan_complete
            )

        if not notify_on_scan_complete:
            return False

        message = (
            f"Scanned {total_containers} containers: "
            f"{critical} critical ({fixable_critical} fixable), "
            f"{high} high ({fixable_high} fixable)"
        )

        # Determine priority based on critical count
        priority = 5 if critical > 0 else 3

        tags = ["shield", "VulnForge"]
        if critical > 0:
            tags.append("warning")

        return await self.send_notification(
            message=message,
            title="VulnForge: Scan Complete",
            priority=priority,
            tags=tags,
        )

    async def notify_critical_vulnerabilities(
        self, container_name: str, critical_count: int, fixable_count: int
    ) -> bool:
        """
        Send notification about critical vulnerabilities.

        Args:
            container_name: Name of affected container
            critical_count: Number of critical vulnerabilities
            fixable_count: Number of fixable critical vulnerabilities

        Returns:
            True if sent successfully
        """
        # Load notification settings from database
        async with db_session() as db:
            settings_manager = SettingsManager(db)
            notify_on_critical = await settings_manager.get_bool(
                "notify_on_critical", default=app_settings.notify_on_critical
            )
            notify_threshold_critical = await settings_manager.get_int(
                "notify_threshold_critical", default=app_settings.notify_threshold_critical
            )

        if not notify_on_critical:
            return False

        if critical_count < notify_threshold_critical:
            return False

        message = (
            f"{container_name}: {critical_count} critical vulnerabilities found "
            f"({fixable_count} fixable)"
        )

        return await self.send_notification(
            message=message,
            title="VulnForge: Critical Vulnerabilities",
            priority=5,
            tags=["warning", "rotating_light", "VulnForge"],
        )

    async def notify_scan_failed(self, container_name: str, error: str) -> bool:
        """
        Send notification when scan fails.

        Args:
            container_name: Name of container that failed
            error: Error message

        Returns:
            True if sent successfully
        """
        message = f"Failed to scan {container_name}: {error[:100]}"

        return await self.send_notification(
            message=message,
            title="VulnForge: Scan Failed",
            priority=4,
            tags=["x", "VulnForge"],
        )

    async def notify_secrets_detected(
        self,
        container_name: str,
        total_secrets: int,
        critical_count: int,
        high_count: int,
        categories: list[str],
    ) -> bool:
        """
        Send notification when secrets are detected in a container.

        Args:
            container_name: Name of container with secrets
            total_secrets: Total number of secrets detected
            critical_count: Number of critical severity secrets
            high_count: Number of high severity secrets
            categories: List of secret categories detected

        Returns:
            True if sent successfully
        """
        # Load settings to check if enabled
        await self._load_settings()

        # Only notify if critical secrets found (configurable threshold)
        if critical_count == 0 and high_count == 0:
            return False

        # Build message
        severity_parts = []
        if critical_count > 0:
            severity_parts.append(f"{critical_count} critical")
        if high_count > 0:
            severity_parts.append(f"{high_count} high")

        severity_text = " + ".join(severity_parts)

        # Include top 3 categories
        category_text = ", ".join(categories[:3])
        if len(categories) > 3:
            category_text += f" +{len(categories) - 3} more"

        message = (
            f"{container_name}: {total_secrets} secrets detected "
            f"({severity_text})\n"
            f"Categories: {category_text}"
        )

        # Critical secrets = max priority
        priority = 5 if critical_count > 0 else 4

        tags = ["key", "warning", "VulnForge"]
        if critical_count > 0:
            tags.append("rotating_light")

        return await self.send_notification(
            message=message,
            title="VulnForge: Secrets Detected",
            priority=priority,
            tags=tags,
        )

    async def notify_kev_detected(self, container_name: str, kev_count: int) -> bool:
        """
        Send notification when Known Exploited Vulnerabilities are detected.

        Args:
            container_name: Name of affected container
            kev_count: Number of KEV vulnerabilities found

        Returns:
            True if sent successfully
        """
        message = (
            f"{container_name}: {kev_count} actively exploited "
            f"CVE{'s' if kev_count != 1 else ''} found (CISA KEV)"
        )

        return await self.send_notification(
            message=message,
            title="VulnForge: Exploited CVEs Detected!",
            priority=5,  # Maximum priority - these are actively exploited
            tags=["warning", "rotating_light", "skull", "VulnForge"],
        )


# Legacy compatibility wrapper -------------------------------------------------


class LegacyNotifier(NotificationService):
    """Wrapper to maintain compatibility with legacy Notifier usage."""

    def __init__(self, legacy_settings: dict | None = None):
        super().__init__()
        self._legacy_settings = legacy_settings or {}

    @staticmethod
    def _as_bool(value, default=False):
        if value is None:
            return default
        if isinstance(value, bool):
            return value
        return str(value).lower() in {"true", "1", "yes", "on"}

    @staticmethod
    def _as_int(value, default=0):
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    async def _load_settings(self):
        if self._legacy_settings:
            self.enabled = self._as_bool(self._legacy_settings.get("ntfy_enabled"), True)
            self.url = self._legacy_settings.get("ntfy_url", app_settings.ntfy_url)
            self.topic = self._legacy_settings.get("ntfy_topic", app_settings.ntfy_topic)
            self.token = self._legacy_settings.get("ntfy_token", app_settings.ntfy_token)
        else:
            await super()._load_settings()

    async def notify_scan_complete(
        self, container_name: str, critical: int, high: int, medium: int, low: int
    ) -> bool:
        if self._legacy_settings:
            if not self._as_bool(
                self._legacy_settings.get("notify_on_scan_complete"),
                app_settings.notify_on_scan_complete,
            ):
                return False

            threshold = self._as_int(
                self._legacy_settings.get("notify_threshold_critical"),
                app_settings.notify_threshold_critical,
            )
            if critical < threshold:
                return False

            message = (
                f"Scanned 1 container: {critical} critical (0 fixable), {high} high (0 fixable)"
            )
            priority = 5 if critical > 0 else 3
            return await self.send_notification(
                message=message,
                title="VulnForge: Scan Complete",
                priority=priority,
                tags=["shield", "VulnForge"],
            )

        return await super().notify_scan_complete(1, critical, high, 0, 0)

    async def notify_critical_vulnerabilities(
        self, container_name: str, critical_count: int, fixable_count: int
    ) -> bool:
        if self._legacy_settings:
            notify_on_critical = self._as_bool(
                self._legacy_settings.get("notify_on_critical"), app_settings.notify_on_critical
            )
            if not notify_on_critical:
                return False

            threshold = self._as_int(
                self._legacy_settings.get("notify_threshold_critical"),
                app_settings.notify_threshold_critical,
            )
            if critical_count < threshold:
                return False

        return await super().notify_critical_vulnerabilities(
            container_name, critical_count, fixable_count
        )


# Backwards compatibility alias
Notifier = LegacyNotifier
