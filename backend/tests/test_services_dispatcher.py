"""Tests for the notification dispatcher service.

This module tests the NotificationDispatcher which routes notifications
to enabled services based on event type settings, priority-based retry,
and VulnForge-specific convenience methods.
"""

from unittest.mock import AsyncMock, patch

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.services.notifications.base import NotificationService
from app.services.notifications.dispatcher import (
    EVENT_PRIORITY_MAP,
    NotificationDispatcher,
)
from app.services.settings_manager import SettingsManager


def _make_mock_service(name: str = "test") -> AsyncMock:
    """Create a mock notification service with the NotificationService spec."""
    mock_service = AsyncMock(spec=NotificationService)
    mock_service.service_name = name
    mock_service.send = AsyncMock(return_value=True)
    mock_service.send_with_retry = AsyncMock(return_value=True)
    mock_service.close = AsyncMock()
    return mock_service


class TestEventSettings:
    """Test event enable/disable logic."""

    @pytest.mark.asyncio
    async def test_unknown_event_type_enabled_by_default(self, db_session: AsyncSession):
        """_is_event_enabled returns True for event types not in EVENT_SETTINGS_MAP."""
        dispatcher = NotificationDispatcher(db_session)
        result = await dispatcher._is_event_enabled("totally_unknown_event_xyz")
        assert result is True

    @pytest.mark.asyncio
    async def test_event_enabled_when_both_toggles_on(self, db_session: AsyncSession):
        """Returns True when both category and event-specific toggles are enabled."""
        settings = SettingsManager(db_session)
        # Ensure both toggles are on (they default to True, but be explicit)
        await settings.set("notify_security_enabled", "true")
        await settings.set("notify_security_kev", "true")

        dispatcher = NotificationDispatcher(db_session)
        result = await dispatcher._is_event_enabled("kev_detected")
        assert result is True

    @pytest.mark.asyncio
    async def test_event_disabled_when_category_off(self, db_session: AsyncSession):
        """Returns False when the category-level toggle is disabled."""
        settings = SettingsManager(db_session)
        await settings.set("notify_security_enabled", "false")

        dispatcher = NotificationDispatcher(db_session)
        result = await dispatcher._is_event_enabled("kev_detected")
        assert result is False

    @pytest.mark.asyncio
    async def test_event_disabled_when_specific_toggle_off(self, db_session: AsyncSession):
        """Returns False when the event-specific toggle is disabled."""
        settings = SettingsManager(db_session)
        await settings.set("notify_security_enabled", "true")
        await settings.set("notify_security_kev", "false")

        dispatcher = NotificationDispatcher(db_session)
        result = await dispatcher._is_event_enabled("kev_detected")
        assert result is False


class TestGetEnabledServices:
    """Test service discovery from settings."""

    @pytest.mark.asyncio
    async def test_no_services_when_none_enabled(self, db_session: AsyncSession):
        """Returns empty list when all services are disabled."""
        settings = SettingsManager(db_session)
        # Disable the ntfy service that's enabled by default
        await settings.set("ntfy_enabled", "false")

        dispatcher = NotificationDispatcher(db_session)
        services = await dispatcher._get_enabled_services()
        assert services == []

    @pytest.mark.asyncio
    async def test_ntfy_service_enabled(self, db_session: AsyncSession):
        """Returns ntfy service when ntfy settings are configured."""
        settings = SettingsManager(db_session)
        await settings.set("ntfy_enabled", "true")
        await settings.set("ntfy_url", "https://ntfy.example.com")
        await settings.set("ntfy_topic", "vulnforge-test")

        dispatcher = NotificationDispatcher(db_session)
        services = await dispatcher._get_enabled_services()

        assert len(services) >= 1
        ntfy_services = [s for s in services if s.service_name == "ntfy"]
        assert len(ntfy_services) == 1

    @pytest.mark.asyncio
    async def test_slack_service_enabled(self, db_session: AsyncSession):
        """Returns slack service when slack settings are configured."""
        settings = SettingsManager(db_session)
        # Disable ntfy default to isolate this test
        await settings.set("ntfy_enabled", "false")
        await settings.set("slack_enabled", "true")
        await settings.set("slack_webhook_url", "https://hooks.slack.com/services/T00/B00/xxx")

        dispatcher = NotificationDispatcher(db_session)
        services = await dispatcher._get_enabled_services()

        assert len(services) == 1
        assert services[0].service_name == "slack"

    @pytest.mark.asyncio
    async def test_multiple_services_enabled(self, db_session: AsyncSession):
        """Returns all enabled services when multiple are configured."""
        settings = SettingsManager(db_session)
        await settings.set("ntfy_enabled", "true")
        await settings.set("ntfy_url", "https://ntfy.example.com")
        await settings.set("ntfy_topic", "vulnforge-test")
        await settings.set("slack_enabled", "true")
        await settings.set("slack_webhook_url", "https://hooks.slack.com/services/T00/B00/xxx")
        await settings.set("discord_enabled", "true")
        await settings.set("discord_webhook_url", "https://discord.com/api/webhooks/123/abc")

        dispatcher = NotificationDispatcher(db_session)
        services = await dispatcher._get_enabled_services()

        service_names = {s.service_name for s in services}
        assert "ntfy" in service_names
        assert "slack" in service_names
        assert "discord" in service_names
        assert len(services) >= 3

    @pytest.mark.asyncio
    async def test_service_not_returned_when_missing_config(self, db_session: AsyncSession):
        """Service not returned when enabled but missing required config (URL/token)."""
        settings = SettingsManager(db_session)
        await settings.set("ntfy_enabled", "false")
        # Enable gotify but leave server/token empty
        await settings.set("gotify_enabled", "true")
        await settings.set("gotify_server", "")
        await settings.set("gotify_token", "")

        dispatcher = NotificationDispatcher(db_session)
        services = await dispatcher._get_enabled_services()

        gotify_services = [s for s in services if s.service_name == "gotify"]
        assert len(gotify_services) == 0


class TestDispatch:
    """Test notification dispatch flow."""

    @pytest.mark.asyncio
    async def test_dispatch_skips_disabled_event(self, db_session: AsyncSession):
        """Returns empty dict when the event type is disabled."""
        settings = SettingsManager(db_session)
        await settings.set("notify_scans_enabled", "false")

        dispatcher = NotificationDispatcher(db_session)
        result = await dispatcher.dispatch(
            event_type="scan_complete",
            title="Scan Done",
            message="All containers scanned",
        )
        assert result == {}

    @pytest.mark.asyncio
    async def test_dispatch_no_services(self, db_session: AsyncSession):
        """Returns empty dict when no notification services are enabled."""
        settings = SettingsManager(db_session)
        await settings.set("ntfy_enabled", "false")

        dispatcher = NotificationDispatcher(db_session)
        result = await dispatcher.dispatch(
            event_type="scan_complete",
            title="Scan Done",
            message="All containers scanned",
        )
        assert result == {}

    @pytest.mark.asyncio
    async def test_dispatch_sends_to_enabled_services(self, db_session: AsyncSession):
        """Mock service has send called when dispatch is triggered."""
        mock_service = _make_mock_service("mock-ntfy")

        dispatcher = NotificationDispatcher(db_session)
        with patch.object(dispatcher, "_get_enabled_services", return_value=[mock_service]):
            result = await dispatcher.dispatch(
                event_type="scan_complete",
                title="Scan Done",
                message="All containers scanned",
            )

        assert result == {"mock-ntfy": True}
        mock_service.send.assert_called_once()
        mock_service.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_dispatch_uses_retry_for_urgent(self, db_session: AsyncSession):
        """Verify send_with_retry is called for urgent priority events."""
        mock_service = _make_mock_service("mock-urgent")

        dispatcher = NotificationDispatcher(db_session)
        with patch.object(dispatcher, "_get_enabled_services", return_value=[mock_service]):
            result = await dispatcher.dispatch(
                event_type="kev_detected",
                title="KEV Alert",
                message="Exploited CVE found",
            )

        assert result == {"mock-urgent": True}
        mock_service.send_with_retry.assert_called_once()
        mock_service.send.assert_not_called()

    @pytest.mark.asyncio
    async def test_dispatch_uses_direct_send_for_low(self, db_session: AsyncSession):
        """Verify send (not retry) is called for low priority events."""
        # Enable system notifications so the event passes the enabled check
        settings = SettingsManager(db_session)
        await settings.set("notify_system_enabled", "true")
        await settings.set("notify_system_kev_refresh", "true")

        mock_service = _make_mock_service("mock-low")

        dispatcher = NotificationDispatcher(db_session)
        with patch.object(dispatcher, "_get_enabled_services", return_value=[mock_service]):
            result = await dispatcher.dispatch(
                event_type="kev_catalog_refresh",
                title="KEV Refresh",
                message="Catalog updated",
            )

        # kev_catalog_refresh has priority "low"
        assert EVENT_PRIORITY_MAP["kev_catalog_refresh"] == "low"
        assert result == {"mock-low": True}
        mock_service.send.assert_called_once()
        mock_service.send_with_retry.assert_not_called()

    @pytest.mark.asyncio
    async def test_dispatch_adds_vulnforge_tag(self, db_session: AsyncSession):
        """Verify 'VulnForge' is always added to the tags list."""
        # Enable system notifications so the event passes the enabled check
        settings = SettingsManager(db_session)
        await settings.set("notify_system_enabled", "true")
        await settings.set("notify_system_backup", "true")

        mock_service = _make_mock_service("mock-tags")

        dispatcher = NotificationDispatcher(db_session)
        with patch.object(dispatcher, "_get_enabled_services", return_value=[mock_service]):
            await dispatcher.dispatch(
                event_type="backup_complete",
                title="Backup Done",
                message="Backup finished",
            )

        # backup_complete has priority "low" -> send() is called
        call_kwargs = mock_service.send.call_args
        assert call_kwargs is not None, "send() was not called"
        tags = call_kwargs.kwargs.get("tags") or call_kwargs[1].get("tags")
        assert "VulnForge" in tags


class TestConvenienceMethods:
    """Test VulnForge-specific convenience methods."""

    @pytest.mark.asyncio
    async def test_notify_kev_detected(self, db_session: AsyncSession):
        """Verify correct event_type and message format for KEV notifications."""
        dispatcher = NotificationDispatcher(db_session)
        with patch.object(dispatcher, "dispatch", new_callable=AsyncMock) as mock_dispatch:
            mock_dispatch.return_value = {"ntfy": True}
            await dispatcher.notify_kev_detected(
                container_name="nginx-prod",
                kev_count=3,
                url="https://vulnforge.example.com/scan/1",
            )

            mock_dispatch.assert_called_once()
            call_kwargs = mock_dispatch.call_args.kwargs
            assert call_kwargs["event_type"] == "kev_detected"
            assert "nginx-prod" in call_kwargs["message"]
            assert "3" in call_kwargs["message"]
            assert "CVEs" in call_kwargs["message"]
            assert "VulnForge" in call_kwargs["title"]

    @pytest.mark.asyncio
    async def test_notify_scan_complete(self, db_session: AsyncSession):
        """Verify correct message format for scan complete notifications."""
        dispatcher = NotificationDispatcher(db_session)
        with patch.object(dispatcher, "dispatch", new_callable=AsyncMock) as mock_dispatch:
            mock_dispatch.return_value = {"ntfy": True}
            await dispatcher.notify_scan_complete(
                total_containers=10,
                critical=2,
                high=5,
                fixable_critical=1,
                fixable_high=3,
                url="https://vulnforge.example.com",
            )

            mock_dispatch.assert_called_once()
            call_kwargs = mock_dispatch.call_args.kwargs
            assert call_kwargs["event_type"] == "scan_complete"
            assert "10" in call_kwargs["message"]
            assert "2 critical" in call_kwargs["message"]
            assert "1 fixable" in call_kwargs["message"]

    @pytest.mark.asyncio
    async def test_notify_scan_failed(self, db_session: AsyncSession):
        """Verify error truncation in scan failed notifications."""
        dispatcher = NotificationDispatcher(db_session)
        long_error = "x" * 200  # Exceeds the 100-char truncation

        with patch.object(dispatcher, "dispatch", new_callable=AsyncMock) as mock_dispatch:
            mock_dispatch.return_value = {"ntfy": True}
            await dispatcher.notify_scan_failed(
                container_name="broken-container",
                error=long_error,
            )

            mock_dispatch.assert_called_once()
            call_kwargs = mock_dispatch.call_args.kwargs
            assert call_kwargs["event_type"] == "scan_failed"
            assert "broken-container" in call_kwargs["message"]
            # The error should be truncated to 100 chars in the message
            assert len(call_kwargs["message"]) < 200
