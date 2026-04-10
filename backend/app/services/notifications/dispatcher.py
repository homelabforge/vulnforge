"""Notification dispatcher for routing events to enabled services."""

from __future__ import annotations

import hashlib
import logging
import time

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

    # --- Provider cache ---
    _provider_cache: dict[str, NotificationService] = {}
    _cache_settings_hash: str | None = None

    # --- Circuit breaker ---
    _failure_counts: dict[str, int] = {}
    _circuit_open_until: dict[str, float] = {}
    CIRCUIT_THRESHOLD = 5  # consecutive failures to trip
    CIRCUIT_RECOVERY_SECONDS = 300  # 5 minutes

    def __init__(self, db: AsyncSession):
        self.db = db
        self.settings = SettingsManager(db)

    def _is_circuit_open(self, service_name: str) -> bool:
        """Check if the circuit breaker is open for a service."""
        until = self._circuit_open_until.get(service_name)
        if until and time.time() < until:
            return True
        if until:
            del self._circuit_open_until[service_name]
            self._failure_counts[service_name] = 0
        return False

    def _record_failure(self, service_name: str) -> None:
        """Record a failure for a service and trip the circuit if threshold reached."""
        count = self._failure_counts.get(service_name, 0) + 1
        self._failure_counts[service_name] = count
        if count >= self.CIRCUIT_THRESHOLD:
            self._circuit_open_until[service_name] = time.time() + self.CIRCUIT_RECOVERY_SECONDS
            logger.warning(f"Circuit breaker tripped for {service_name} after {count} failures")

    def _record_success(self, service_name: str) -> None:
        """Reset failure tracking on success."""
        self._failure_counts.pop(service_name, None)
        self._circuit_open_until.pop(service_name, None)

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
        event_enabled = await self.settings.get_bool(event_key, default=True)
        return event_enabled if event_enabled is not None else True

    async def _get_enabled_services(self) -> list[NotificationService]:
        """Get list of enabled and configured notification services.

        Uses a class-level cache keyed by a hash of all provider settings.
        When settings change the hash changes, old providers are closed,
        and new ones are built.
        """
        # Import here to avoid circular imports
        from app.services.notifications.discord import DiscordNotificationService
        from app.services.notifications.email import EmailNotificationService
        from app.services.notifications.gotify import GotifyNotificationService
        from app.services.notifications.ntfy import NtfyNotificationService
        from app.services.notifications.pushover import PushoverNotificationService
        from app.services.notifications.slack import SlackNotificationService
        from app.services.notifications.telegram import TelegramNotificationService

        # Gather all provider-relevant settings in one batch
        provider_keys = [
            "ntfy_enabled",
            "ntfy_url",
            "ntfy_topic",
            "ntfy_token",
            "gotify_enabled",
            "gotify_server",
            "gotify_token",
            "pushover_enabled",
            "pushover_user_key",
            "pushover_api_token",
            "slack_enabled",
            "slack_webhook_url",
            "discord_enabled",
            "discord_webhook_url",
            "telegram_enabled",
            "telegram_bot_token",
            "telegram_chat_id",
            "email_enabled",
            "email_smtp_host",
            "email_smtp_port",
            "email_smtp_user",
            "email_smtp_password",
            "email_smtp_tls",
            "email_from",
            "email_to",
        ]
        raw = await self.settings.get_many(provider_keys)

        # Compute a hash of all provider settings
        hash_input = "|".join(f"{k}={raw.get(k, '')}" for k in sorted(provider_keys))
        settings_hash = hashlib.sha256(hash_input.encode()).hexdigest()

        # Return cached providers if settings haven't changed
        if settings_hash == self._cache_settings_hash and self._provider_cache:
            return list(self._provider_cache.values())

        # Settings changed — close old providers
        for old_svc in self._provider_cache.values():
            try:
                await old_svc.close()
            except Exception:  # noqa: BLE001
                pass

        cls = type(self)
        cls._provider_cache = {}
        cls._cache_settings_hash = settings_hash

        def _is_true(val: str | None) -> bool:
            return str(val).lower() in ("true", "1", "yes", "on") if val else False

        # Check ntfy
        if _is_true(raw.get("ntfy_enabled")):
            server = raw.get("ntfy_url")
            topic = raw.get("ntfy_topic") or "vulnforge"
            api_key = raw.get("ntfy_token")
            if server and topic:
                cls._provider_cache["ntfy"] = NtfyNotificationService(server, topic, api_key)

        # Check gotify
        if _is_true(raw.get("gotify_enabled")):
            server = raw.get("gotify_server")
            token = raw.get("gotify_token")
            if server and token:
                cls._provider_cache["gotify"] = GotifyNotificationService(server, token)

        # Check pushover
        if _is_true(raw.get("pushover_enabled")):
            user_key = raw.get("pushover_user_key")
            api_token = raw.get("pushover_api_token")
            if user_key and api_token:
                cls._provider_cache["pushover"] = PushoverNotificationService(user_key, api_token)

        # Check slack
        if _is_true(raw.get("slack_enabled")):
            webhook_url = raw.get("slack_webhook_url")
            if webhook_url:
                cls._provider_cache["slack"] = SlackNotificationService(webhook_url)

        # Check discord
        if _is_true(raw.get("discord_enabled")):
            webhook_url = raw.get("discord_webhook_url")
            if webhook_url:
                cls._provider_cache["discord"] = DiscordNotificationService(webhook_url)

        # Check telegram
        if _is_true(raw.get("telegram_enabled")):
            bot_token = raw.get("telegram_bot_token")
            chat_id = raw.get("telegram_chat_id")
            if bot_token and chat_id:
                cls._provider_cache["telegram"] = TelegramNotificationService(bot_token, chat_id)

        # Check email
        if _is_true(raw.get("email_enabled")):
            smtp_host = raw.get("email_smtp_host")
            try:
                smtp_port = int(raw.get("email_smtp_port") or "587")
            except ValueError, TypeError:
                smtp_port = 587
            smtp_user = raw.get("email_smtp_user")
            smtp_password = raw.get("email_smtp_password")
            from_address = raw.get("email_from")
            to_address = raw.get("email_to")
            use_tls = _is_true(raw.get("email_smtp_tls"))
            if smtp_host and smtp_user and smtp_password and from_address and to_address:
                cls._provider_cache["email"] = EmailNotificationService(
                    smtp_host,
                    smtp_port,
                    smtp_user,
                    smtp_password,
                    from_address,
                    to_address,
                    use_tls,
                )

        return list(cls._provider_cache.values())

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
        max_attempts = await self.settings.get_int("notification_retry_attempts", default=3) or 3
        base_delay = float(await self.settings.get("notification_retry_delay") or "2.0")

        # Send to all enabled services
        for service in services:
            # Skip services with open circuit breakers
            if self._is_circuit_open(service.service_name):
                logger.info(f"Skipping {service.service_name}: circuit breaker open")
                results[service.service_name] = False
                continue

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

                if success:
                    self._record_success(service.service_name)
                else:
                    self._record_failure(service.service_name)
            except Exception as e:
                logger.error(f"Error sending to {service.service_name}: {e}")
                results[service.service_name] = False
                self._record_failure(service.service_name)

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
