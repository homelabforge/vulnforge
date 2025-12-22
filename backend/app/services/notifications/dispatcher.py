"""Notification dispatcher for routing events to enabled services."""

import logging

from sqlalchemy.ext.asyncio import AsyncSession

from app.services.notifications.base import NotificationService
from app.services.settings_manager import SettingsManager

logger = logging.getLogger(__name__)


# VulnForge event type to settings key mapping
# Format: "event_type": ("category_enabled_key", "specific_event_key")
EVENT_SETTINGS_MAP = {
    # Security events
    "kev_detected": ("notify_security_enabled", "notify_security_kev"),
    "critical_vulnerabilities": ("notify_security_enabled", "notify_security_critical"),
    "secrets_detected": ("notify_security_enabled", "notify_security_secrets"),
    # Scan events
    "scan_complete": ("notify_scans_enabled", "notify_scans_complete"),
    "scan_failed": ("notify_scans_enabled", "notify_scans_failed"),
    "compliance_scan_complete": ("notify_scans_enabled", "notify_scans_compliance_complete"),
    "compliance_failures": ("notify_scans_enabled", "notify_scans_compliance_failures"),
    # System events
    "kev_catalog_refresh": ("notify_system_enabled", "notify_system_kev_refresh"),
    "backup_complete": ("notify_system_enabled", "notify_system_backup"),
}

# Priority mapping for different event types
EVENT_PRIORITY_MAP = {
    "kev_detected": "urgent",
    "critical_vulnerabilities": "urgent",
    "secrets_detected": "high",
    "scan_complete": "default",
    "scan_failed": "high",
    "compliance_scan_complete": "default",
    "compliance_failures": "high",
    "kev_catalog_refresh": "low",
    "backup_complete": "low",
}

# Tags mapping for different event types (emoji names for ntfy)
EVENT_TAGS_MAP = {
    "kev_detected": ["rotating_light", "skull", "warning"],
    "critical_vulnerabilities": ["rotating_light", "warning"],
    "secrets_detected": ["key", "warning"],
    "scan_complete": ["white_check_mark", "shield"],
    "scan_failed": ["x", "warning"],
    "compliance_scan_complete": ["clipboard", "white_check_mark"],
    "compliance_failures": ["clipboard", "warning"],
    "kev_catalog_refresh": ["arrows_counterclockwise"],
    "backup_complete": ["floppy_disk", "white_check_mark"],
}


class NotificationDispatcher:
    """Routes notifications to enabled services with priority-based retry."""

    # Service-specific retry delay multipliers
    # (some services like Discord are more sensitive to rapid retries)
    SERVICE_RETRY_MULTIPLIERS = {
        "discord": 1.5,  # Discord rate limits - slightly longer delay
        "slack": 1.2,  # Slack can be sensitive too
        "telegram": 1.0,  # Telegram is robust
        "ntfy": 1.0,  # Self-hosted, usually fast
        "gotify": 1.0,  # Self-hosted
        "pushover": 1.0,  # Cloud service, robust
        "email": 2.0,  # SMTP can be slow, longer delays
    }

    def __init__(self, db: AsyncSession):
        self.db = db
        self.settings = SettingsManager(db)

    async def _is_event_enabled(self, event_type: str) -> bool:
        """Check if an event type is enabled in settings."""
        if event_type not in EVENT_SETTINGS_MAP:
            # Unknown event types are enabled by default
            return True

        category_key, event_key = EVENT_SETTINGS_MAP[event_type]

        # Check category toggle first
        category_enabled = await self.settings.get_bool(category_key, default=True)
        if not category_enabled:
            return False

        # Check specific event toggle
        return await self.settings.get_bool(event_key, default=True)

    async def _get_enabled_services(self) -> list[NotificationService]:
        """Get list of enabled and configured notification services."""
        # Import here to avoid circular imports
        from app.services.notifications.discord import DiscordNotificationService
        from app.services.notifications.email import EmailNotificationService
        from app.services.notifications.gotify import GotifyNotificationService
        from app.services.notifications.ntfy import NtfyNotificationService
        from app.services.notifications.pushover import PushoverNotificationService
        from app.services.notifications.slack import SlackNotificationService
        from app.services.notifications.telegram import TelegramNotificationService

        services: list[NotificationService] = []

        # Check ntfy
        if await self.settings.get_bool("ntfy_enabled", default=False):
            server = await self.settings.get("ntfy_url")
            topic = await self.settings.get("ntfy_topic", default="vulnforge")
            api_key = await self.settings.get("ntfy_token")
            if server and topic:
                services.append(NtfyNotificationService(server, topic, api_key))

        # Check gotify
        if await self.settings.get_bool("gotify_enabled", default=False):
            server = await self.settings.get("gotify_server")
            token = await self.settings.get("gotify_token")
            if server and token:
                services.append(GotifyNotificationService(server, token))

        # Check pushover
        if await self.settings.get_bool("pushover_enabled", default=False):
            user_key = await self.settings.get("pushover_user_key")
            api_token = await self.settings.get("pushover_api_token")
            if user_key and api_token:
                services.append(PushoverNotificationService(user_key, api_token))

        # Check slack
        if await self.settings.get_bool("slack_enabled", default=False):
            webhook_url = await self.settings.get("slack_webhook_url")
            if webhook_url:
                services.append(SlackNotificationService(webhook_url))

        # Check discord
        if await self.settings.get_bool("discord_enabled", default=False):
            webhook_url = await self.settings.get("discord_webhook_url")
            if webhook_url:
                services.append(DiscordNotificationService(webhook_url))

        # Check telegram
        if await self.settings.get_bool("telegram_enabled", default=False):
            bot_token = await self.settings.get("telegram_bot_token")
            chat_id = await self.settings.get("telegram_chat_id")
            if bot_token and chat_id:
                services.append(TelegramNotificationService(bot_token, chat_id))

        # Check email
        if await self.settings.get_bool("email_enabled", default=False):
            smtp_host = await self.settings.get("email_smtp_host")
            smtp_port = await self.settings.get_int("email_smtp_port", default=587)
            smtp_user = await self.settings.get("email_smtp_user")
            smtp_password = await self.settings.get("email_smtp_password")
            from_address = await self.settings.get("email_from")
            to_address = await self.settings.get("email_to")
            use_tls = await self.settings.get_bool("email_smtp_tls", default=True)
            if smtp_host and smtp_user and smtp_password and from_address and to_address:
                services.append(
                    EmailNotificationService(
                        smtp_host,
                        smtp_port,
                        smtp_user,
                        smtp_password,
                        from_address,
                        to_address,
                        use_tls,
                    )
                )

        return services

    async def dispatch(
        self,
        event_type: str,
        title: str,
        message: str,
        priority: str | None = None,
        tags: list[str] | None = None,
        url: str | None = None,
    ) -> dict[str, bool]:
        """
        Dispatch a notification to all enabled services.

        Args:
            event_type: Type of event (e.g., "kev_detected", "scan_complete")
            title: Notification title
            message: Notification message body
            priority: Override priority (urgent, high, default, low, min)
            tags: Override tags/emojis
            url: Optional click URL

        Returns:
            Dictionary mapping service names to success status
        """
        results: dict[str, bool] = {}

        # Check if event enabled
        if not await self._is_event_enabled(event_type):
            logger.debug(f"Event type '{event_type}' is disabled")
            return results

        # Get enabled services
        services = await self._get_enabled_services()
        if not services:
            logger.debug("No notification services enabled")
            return results

        # Use default priority/tags if not provided
        final_priority = priority or EVENT_PRIORITY_MAP.get(event_type, "default")
        final_tags = tags or EVENT_TAGS_MAP.get(event_type, [])

        # Always add VulnForge tag
        if "VulnForge" not in final_tags:
            final_tags = list(final_tags) + ["VulnForge"]

        # Load global retry settings once
        max_attempts = await self.settings.get_int("notification_retry_attempts", default=3)
        base_delay = float(await self.settings.get("notification_retry_delay") or "2.0")

        # Send to all enabled services
        for service in services:
            try:
                # Adapt delay per service
                multiplier = self.SERVICE_RETRY_MULTIPLIERS.get(service.service_name, 1.0)
                service_delay = base_delay * multiplier

                # Use retry for high-priority events, direct send for low-priority
                if final_priority in ("urgent", "high"):
                    success = await service.send_with_retry(
                        title=title,
                        message=message,
                        priority=final_priority,
                        tags=final_tags,
                        url=url,
                        max_attempts=max_attempts,
                        retry_delay=service_delay,
                    )
                else:
                    success = await service.send(
                        title=title,
                        message=message,
                        priority=final_priority,
                        tags=final_tags,
                        url=url,
                    )

                results[service.service_name] = success
            except Exception as e:
                logger.error(f"Error sending to {service.service_name}: {e}")
                results[service.service_name] = False
            finally:
                await service.close()

        return results

    # =========================================================================
    # VulnForge-specific convenience methods
    # =========================================================================

    async def notify_kev_detected(
        self,
        container_name: str,
        kev_count: int,
        url: str | None = None,
    ) -> dict[str, bool]:
        """Send notification when Known Exploited Vulnerabilities are detected."""
        return await self.dispatch(
            event_type="kev_detected",
            title="VulnForge: Exploited CVEs Detected!",
            message=(
                f"{container_name}: {kev_count} actively exploited "
                f"CVE{'s' if kev_count != 1 else ''} found (CISA KEV)"
            ),
            url=url,
        )

    async def notify_critical_vulnerabilities(
        self,
        container_name: str,
        critical_count: int,
        fixable_count: int,
        url: str | None = None,
    ) -> dict[str, bool]:
        """Send notification about critical vulnerabilities."""
        return await self.dispatch(
            event_type="critical_vulnerabilities",
            title="VulnForge: Critical Vulnerabilities",
            message=(
                f"{container_name}: {critical_count} critical vulnerabilities found "
                f"({fixable_count} fixable)"
            ),
            url=url,
        )

    async def notify_secrets_detected(
        self,
        container_name: str,
        total_secrets: int,
        critical_count: int,
        high_count: int,
        categories: list[str],
        url: str | None = None,
    ) -> dict[str, bool]:
        """Send notification when secrets are detected in a container."""
        severity_parts = []
        if critical_count > 0:
            severity_parts.append(f"{critical_count} critical")
        if high_count > 0:
            severity_parts.append(f"{high_count} high")

        severity_text = " + ".join(severity_parts) if severity_parts else f"{total_secrets} total"

        # Include top 3 categories
        category_text = ", ".join(categories[:3])
        if len(categories) > 3:
            category_text += f" +{len(categories) - 3} more"

        return await self.dispatch(
            event_type="secrets_detected",
            title="VulnForge: Secrets Detected",
            message=(
                f"{container_name}: {total_secrets} secrets detected "
                f"({severity_text})\n"
                f"Categories: {category_text}"
            ),
            url=url,
        )

    async def notify_scan_complete(
        self,
        total_containers: int,
        critical: int,
        high: int,
        fixable_critical: int,
        fixable_high: int,
        url: str | None = None,
    ) -> dict[str, bool]:
        """Send notification when scan completes."""
        return await self.dispatch(
            event_type="scan_complete",
            title="VulnForge: Scan Complete",
            message=(
                f"Scanned {total_containers} containers: "
                f"{critical} critical ({fixable_critical} fixable), "
                f"{high} high ({fixable_high} fixable)"
            ),
            url=url,
        )

    async def notify_scan_failed(
        self,
        container_name: str,
        error: str,
        url: str | None = None,
    ) -> dict[str, bool]:
        """Send notification when scan fails."""
        return await self.dispatch(
            event_type="scan_failed",
            title="VulnForge: Scan Failed",
            message=f"Failed to scan {container_name}: {error[:100]}",
            url=url,
        )

    async def notify_compliance_scan_complete(
        self,
        total_checks: int,
        passed: int,
        failed: int,
        url: str | None = None,
    ) -> dict[str, bool]:
        """Send notification when compliance scan completes."""
        return await self.dispatch(
            event_type="compliance_scan_complete",
            title="VulnForge: Compliance Scan Complete",
            message=(
                f"Compliance scan finished: {passed}/{total_checks} checks passed, {failed} failed"
            ),
            url=url,
        )

    async def notify_compliance_failures(
        self,
        failed_count: int,
        categories: list[str],
        url: str | None = None,
    ) -> dict[str, bool]:
        """Send notification about compliance failures."""
        category_text = ", ".join(categories[:3])
        if len(categories) > 3:
            category_text += f" +{len(categories) - 3} more"

        return await self.dispatch(
            event_type="compliance_failures",
            title="VulnForge: Compliance Failures",
            message=f"{failed_count} compliance checks failed\nCategories: {category_text}",
            url=url,
        )
