"""Settings manager service for handling application configuration."""

import json
import os
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Setting


def _env_or_default(key: str, default: str) -> str:
    """Retrieve setting override from environment variables."""
    env_keys = [
        key.upper(),
        f"VULNFORGE_{key.upper()}",
    ]
    for env_key in env_keys:
        value = os.getenv(env_key)
        if value:
            return value
    return default


class SettingsManager:
    """Manage application settings with typed access."""

    # Default settings values
    DEFAULTS = {
        # Application settings
        "log_level": "INFO",
        "timezone": "UTC",
        # Scan settings
        "scan_schedule": "0 2 * * *",  # 2 AM daily
        "scan_timeout": "300",  # 5 minutes
        "parallel_scans": "3",
        "enable_secret_scanning": "true",  # Enable Trivy secret detection
        # Compliance settings
        "compliance_scan_enabled": "true",  # Enable Docker Bench compliance scanning
        "compliance_scan_schedule": "0 3 * * 0",  # 3 AM every Sunday
        "compliance_notify_on_scan": "true",  # Send notification after compliance scan
        "compliance_notify_on_failures": "true",  # Send notification for failed checks
        # ============================================
        # Multi-Service Notification Settings
        # ============================================
        # Event category toggles
        "notify_security_enabled": "true",
        "notify_security_kev": "true",
        "notify_security_critical": "true",
        "notify_security_secrets": "true",
        "notify_scans_enabled": "true",
        "notify_scans_complete": "true",
        "notify_scans_failed": "true",
        "notify_scans_compliance_complete": "false",
        "notify_scans_compliance_failures": "true",
        "notify_system_enabled": "false",
        "notify_system_kev_refresh": "false",
        "notify_system_backup": "false",
        # Retry settings (global)
        "notification_retry_attempts": "3",
        "notification_retry_delay": "2.0",  # seconds
        # ntfy service (primary)
        "ntfy_enabled": "true",
        "ntfy_url": "https://ntfy:443",
        "ntfy_topic": "vulnforge",
        "ntfy_token": "",  # Access token for ntfy authentication
        # Gotify service
        "gotify_enabled": "false",
        "gotify_server": "",
        "gotify_token": "",
        # Pushover service
        "pushover_enabled": "false",
        "pushover_user_key": "",
        "pushover_api_token": "",
        # Slack service
        "slack_enabled": "false",
        "slack_webhook_url": "",
        # Discord service
        "discord_enabled": "false",
        "discord_webhook_url": "",
        # Telegram service
        "telegram_enabled": "false",
        "telegram_bot_token": "",
        "telegram_chat_id": "",
        # Email service
        "email_enabled": "false",
        "email_smtp_host": "",
        "email_smtp_port": "587",
        "email_smtp_user": "",
        "email_smtp_password": "",
        "email_smtp_tls": "true",
        "email_from": "",
        "email_to": "",
        # Legacy notification settings (for backwards compatibility)
        "notify_on_scan_complete": "true",
        "notify_on_critical": "true",
        "notify_threshold_critical": "1",
        "notify_threshold_high": "10",
        # Data retention
        "keep_scan_history_days": "90",
        # UI preferences
        "default_severity_filter": "all",
        "default_show_fixable_only": "false",
        "theme": "light",  # light or dark mode
        # KEV (Known Exploited Vulnerabilities) settings
        "kev_checking_enabled": "true",  # Enable CISA KEV checking
        "kev_cache_hours": "12",  # Cache KEV catalog for 12 hours
        "kev_last_refresh": "",  # Last KEV catalog refresh timestamp
        # Scanner offline resilience settings (scanner-agnostic)
        "scanner_db_max_age_hours": "24",  # Max age for scanner databases before requiring update
        "scanner_offline_mode": "auto",  # auto (use cached), strict (require fresh), fallback (use stale)
        "scanner_skip_db_update_when_fresh": "true",  # Skip DB updates if database is fresh
        "scanner_allow_stale_db": "true",  # Allow scans with stale databases when network unavailable
        "scanner_stale_db_warning_hours": "72",  # Warn when database is older than this
        # NOTE: Docker connection is now configured via DOCKER_HOST environment variable in compose
        # Authentication settings
        "auth_enabled": "false",  # Master auth toggle
        "auth_provider": "none",  # Options: none, authentik, custom_headers, api_key, basic_auth
        # Authentik provider settings
        "auth_authentik_header_username": "X-Authentik-Username",
        "auth_authentik_header_email": "X-Authentik-Email",
        "auth_authentik_header_groups": "X-Authentik-Groups",
        "auth_authentik_verify_secret": "",  # Shared secret for header verification (optional)
        "auth_authentik_secret_header": "X-Authentik-Secret",  # Header name for verification secret
        "auth_authentik_trusted_proxies": _env_or_default(
            "auth_authentik_trusted_proxies",
            '["127.0.0.1", "::1", "socket-proxy-ro", "host.docker.internal"]',
        ),
        # Custom headers provider settings
        "auth_custom_header_username": "X-Remote-User",
        "auth_custom_header_email": "X-Remote-Email",
        "auth_custom_header_groups": "X-Remote-Groups",
        "auth_custom_header_verify_secret": "",  # Shared secret for header verification (optional)
        "auth_custom_header_secret_header": "X-Auth-Secret",  # Header name for verification secret
        "auth_custom_header_trusted_proxies": _env_or_default(
            "auth_custom_header_trusted_proxies",
            '["127.0.0.1", "::1", "socket-proxy-ro", "host.docker.internal"]',
        ),
        # API key provider settings (JSON array)
        "auth_api_keys": "[]",  # [{"key": "abc123", "name": "my-script", "admin": true}]
        # Basic auth provider settings (JSON array with bcrypt hashes)
        "auth_basic_users": "[]",  # [{"username": "admin", "password_hash": "bcrypt...", "admin": true}]
        # Role/permission settings (provider-agnostic)
        "auth_require_admin": "false",  # Require admin for maintenance endpoints
        "auth_admin_group": "vulnforge-admins",  # Admin group name for header-based auth
        "auth_admin_usernames": "[]",  # JSON array of admin usernames (fallback)
        # CORS settings
        "cors_origins": '["https://vulnforge.starett.net", "http://localhost:5173"]',  # JSON array
    }

    DEFAULT_CATEGORIES = {
        "log_level": "general",
        "timezone": "system",
        "scan_schedule": "scanning",
        "scan_timeout": "scanning",
        "parallel_scans": "scanning",
        "enable_secret_scanning": "scanning",
        "compliance_scan_enabled": "compliance",
        "compliance_scan_schedule": "compliance",
        "compliance_notify_on_scan": "compliance",
        "compliance_notify_on_failures": "compliance",
        # Event toggles
        "notify_security_enabled": "notifications",
        "notify_security_kev": "notifications",
        "notify_security_critical": "notifications",
        "notify_security_secrets": "notifications",
        "notify_scans_enabled": "notifications",
        "notify_scans_complete": "notifications",
        "notify_scans_failed": "notifications",
        "notify_scans_compliance_complete": "notifications",
        "notify_scans_compliance_failures": "notifications",
        "notify_system_enabled": "notifications",
        "notify_system_kev_refresh": "notifications",
        "notify_system_backup": "notifications",
        # Retry settings
        "notification_retry_attempts": "notifications",
        "notification_retry_delay": "notifications",
        # ntfy service
        "ntfy_enabled": "notifications",
        "ntfy_url": "notifications",
        "ntfy_topic": "notifications",
        "ntfy_token": "notifications",
        # Gotify service
        "gotify_enabled": "notifications",
        "gotify_server": "notifications",
        "gotify_token": "notifications",
        # Pushover service
        "pushover_enabled": "notifications",
        "pushover_user_key": "notifications",
        "pushover_api_token": "notifications",
        # Slack service
        "slack_enabled": "notifications",
        "slack_webhook_url": "notifications",
        # Discord service
        "discord_enabled": "notifications",
        "discord_webhook_url": "notifications",
        # Telegram service
        "telegram_enabled": "notifications",
        "telegram_bot_token": "notifications",
        "telegram_chat_id": "notifications",
        # Email service
        "email_enabled": "notifications",
        "email_smtp_host": "notifications",
        "email_smtp_port": "notifications",
        "email_smtp_user": "notifications",
        "email_smtp_password": "notifications",
        "email_smtp_tls": "notifications",
        "email_from": "notifications",
        "email_to": "notifications",
        # Legacy notification settings
        "notify_on_scan_complete": "notifications",
        "notify_on_critical": "notifications",
        "notify_threshold_critical": "notifications",
        "notify_threshold_high": "notifications",
        "keep_scan_history_days": "retention",
        "default_severity_filter": "ui",
        "default_show_fixable_only": "ui",
        "kev_checking_enabled": "kev",
        "kev_cache_hours": "kev",
        "kev_last_refresh": "kev",
        "scanner_db_max_age_hours": "scanner",
        "scanner_offline_mode": "scanner",
        "scanner_skip_db_update_when_fresh": "scanner",
        "scanner_allow_stale_db": "scanner",
        "scanner_stale_db_warning_hours": "scanner",
        "auth_enabled": "auth",
        "auth_provider": "auth",
        "auth_authentik_header_username": "auth",
        "auth_authentik_header_email": "auth",
        "auth_authentik_header_groups": "auth",
        "auth_authentik_verify_secret": "auth",
        "auth_authentik_secret_header": "auth",
        "auth_authentik_trusted_proxies": "auth",
        "auth_custom_header_username": "auth",
        "auth_custom_header_email": "auth",
        "auth_custom_header_groups": "auth",
        "auth_custom_header_verify_secret": "auth",
        "auth_custom_header_secret_header": "auth",
        "auth_custom_header_trusted_proxies": "auth",
        "auth_api_keys": "auth",
        "auth_basic_users": "auth",
        "auth_require_admin": "auth",
        "auth_admin_group": "auth",
        "auth_admin_usernames": "auth",
        "cors_origins": "security",
    }

    def __init__(self, db: AsyncSession):
        """Initialize settings manager."""
        self.db = db

    async def get(self, key: str, default: str | None = None) -> str | None:
        """Get a setting value by key."""
        result = await self.db.execute(select(Setting).where(Setting.key == key))
        setting = result.scalar_one_or_none()

        if setting:
            return setting.value

        # Return default from DEFAULTS or provided default
        return default or self.DEFAULTS.get(key)

    async def get_int(self, key: str, default: int | None = None) -> int | None:
        """Get a setting as integer."""
        value = await self.get(key)
        if value is None:
            return default
        try:
            return int(value)
        except (ValueError, TypeError):
            return default

    async def get_bool(self, key: str, default: bool | None = None) -> bool | None:
        """Get a setting as boolean."""
        value = await self.get(key)
        if value is None:
            return default
        return value.lower() in ("true", "1", "yes", "on")

    async def get_json(self, key: str, default: Any = None) -> Any:
        """Get a setting as JSON."""
        value = await self.get(key)
        if value is None:
            return default
        try:
            return json.loads(value)
        except (ValueError, TypeError):
            return default

    async def get_many(self, keys: list[str]) -> dict[str, str | None]:
        """
        Get multiple setting values in a single query.

        Args:
            keys: List of setting keys to retrieve

        Returns:
            Dictionary mapping keys to string values (defaults applied when missing)
        """
        if not keys:
            return {}

        result = await self.db.execute(select(Setting).where(Setting.key.in_(keys)))
        rows = {setting.key: setting.value for setting in result.scalars()}

        values: dict[str, str | None] = {}
        for key in keys:
            if key in rows:
                values[key] = rows[key]
            else:
                values[key] = self.DEFAULTS.get(key)

        return values

    async def set(
        self,
        key: str,
        value: str,
        description: str | None = None,
        is_sensitive: bool | None = None,
    ) -> Setting:
        """Set a setting value with validation."""
        from app.validators import (
            validate_cron_expression,
            validate_log_level,
            validate_positive_integer,
            validate_topic_name,
            validate_url,
        )

        # Validate values based on setting key
        validated_value = value
        if key in ("scan_schedule", "compliance_scan_schedule"):
            validated_value = validate_cron_expression(value)
        elif key == "log_level":
            validated_value = validate_log_level(value)
        elif key in ("ntfy_url",):
            validated_value = validate_url(value, allowed_schemes=["http", "https"])
        elif key == "ntfy_topic":
            validated_value = validate_topic_name(value)
        elif key in (
            "scan_timeout",
            "parallel_scans",
            "keep_scan_history_days",
            "notify_threshold_critical",
            "notify_threshold_high",
            "notify_threshold_medium",
        ):
            validated_value = str(
                validate_positive_integer(
                    value, key, min_value=1, max_value=3600 if "timeout" in key else None
                )
            )

        result = await self.db.execute(select(Setting).where(Setting.key == key))
        setting = result.scalar_one_or_none()

        category = self._get_category(key)

        if setting:
            setting.value = validated_value
            if description is not None:
                setting.description = description
            if not getattr(setting, "category", None):
                setting.category = category
            # Auto-detect sensitive keys if not explicitly set
            if is_sensitive is not None:
                setting.is_sensitive = is_sensitive
            elif setting.is_sensitive is False:  # Only auto-detect if not already marked sensitive
                setting.is_sensitive = self._is_sensitive_key(key)
        else:
            # Determine if sensitive based on key name if not explicitly set
            if is_sensitive is None:
                is_sensitive = self._is_sensitive_key(key)
            setting = Setting(
                key=key,
                value=validated_value,
                description=description,
                category=category,
                is_sensitive=is_sensitive,
            )
            self.db.add(setting)

        await self.db.commit()
        await self.db.refresh(setting)
        return setting

    @staticmethod
    def _is_sensitive_key(key: str) -> bool:
        """Determine if a key should be marked as sensitive."""
        sensitive_keywords = ["token", "password", "secret", "key", "apikey", "api_key"]
        key_lower = key.lower()
        return any(keyword in key_lower for keyword in sensitive_keywords)

    async def get_all(self) -> dict[str, str]:
        """Get all settings as a dictionary."""
        result = await self.db.execute(select(Setting))
        settings = result.scalars().all()

        # Start with defaults
        all_settings = dict(self.DEFAULTS)

        # Override with database values
        for setting in settings:
            all_settings[setting.key] = setting.value

        return all_settings

    async def initialize_defaults(self) -> None:
        """Initialize default settings if they don't exist."""
        for key, value in self.DEFAULTS.items():
            result = await self.db.execute(select(Setting).where(Setting.key == key))
            existing = result.scalar_one_or_none()

            if not existing:
                setting = Setting(
                    key=key,
                    value=value,
                    description=self._get_description(key),
                    category=self._get_category(key),
                )
                self.db.add(setting)
            elif not getattr(existing, "category", None):
                existing.category = self._get_category(key)

        await self.db.commit()

    @staticmethod
    def _get_description(key: str) -> str:
        """Get human-readable description for a setting key."""
        descriptions = {
            "log_level": "Application logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)",
            "timezone": "System timezone for schedules and timestamps (IANA name, e.g., 'UTC', 'America/New_York')",
            "scan_schedule": "Cron schedule for automatic scans (e.g., '0 2 * * *' for 2 AM daily)",
            "scan_timeout": "Maximum time (seconds) allowed for a single container scan",
            "parallel_scans": "Maximum number of containers to scan in parallel",
            "ntfy_enabled": "Enable ntfy notifications",
            "ntfy_url": "Base URL for ntfy server",
            "ntfy_topic": "Topic name for ntfy notifications",
            "ntfy_token": "Access token for ntfy authentication (leave empty if not required)",
            "notify_on_scan_complete": "Send notification when scan completes",
            "notify_on_critical": "Send notification when critical vulnerabilities found",
            "notify_threshold_critical": "Minimum number of critical vulnerabilities to trigger notification",
            "notify_threshold_high": "Minimum number of high vulnerabilities to trigger notification",
            "keep_scan_history_days": "Number of days to keep scan history",
            "default_severity_filter": "Default severity filter for vulnerabilities page",
            "default_show_fixable_only": "Default state for 'show fixable only' filter",
            "kev_checking_enabled": "Enable checking CVEs against CISA's Known Exploited Vulnerabilities catalog",
            "kev_cache_hours": "Number of hours to cache KEV catalog before refreshing",
            "kev_last_refresh": "Last time the KEV catalog was refreshed (read-only)",
        }
        return descriptions.get(key, "")

    def _get_category(self, key: str) -> str:
        """Resolve category for a given setting key."""
        return self.DEFAULT_CATEGORIES.get(key, "general")
