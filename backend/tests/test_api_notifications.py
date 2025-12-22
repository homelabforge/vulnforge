"""Tests for notification API endpoints.

This module tests the notification API which provides:
- Notification history and logging
- Notification rules (CRUD operations)
- Service-specific notification testing (ntfy, gotify, pushover, etc.)
"""

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import NotificationLog, NotificationRule

# ============================================
# Notification History Tests
# ============================================


class TestNotificationHistory:
    """Test GET /api/v1/notifications/history endpoint."""

    @pytest.mark.asyncio
    async def test_get_notification_history_empty(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test getting notification history with no records."""
        # Act
        response = await authenticated_client.get("/api/v1/notifications/history")

        # Assert
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) == 0

    @pytest.mark.asyncio
    async def test_get_notification_history_with_logs(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test getting notification history with records."""
        # Arrange
        log = NotificationLog(
            notification_type="scan_completed",
            channel="ntfy",
            title="Scan Complete",
            message="Scan finished successfully",
            status="sent",
            priority=3,
        )
        db_session.add(log)
        await db_session.commit()

        # Act
        response = await authenticated_client.get("/api/v1/notifications/history")

        # Assert
        assert response.status_code == 200
        data = response.json()
        assert len(data) >= 1

        notification = data[0]
        assert notification["notification_type"] == "scan_completed"
        assert notification["channel"] == "ntfy"
        assert notification["status"] == "sent"

    @pytest.mark.asyncio
    async def test_get_notification_history_filter_by_type(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test filtering notification history by type."""
        # Arrange
        log1 = NotificationLog(
            notification_type="scan_completed",
            channel="ntfy",
            message="Scan complete",
            status="sent",
        )
        log2 = NotificationLog(
            notification_type="critical_vulnerability",
            channel="ntfy",
            message="Critical vuln found",
            status="sent",
        )
        db_session.add_all([log1, log2])
        await db_session.commit()

        # Act
        response = await authenticated_client.get(
            "/api/v1/notifications/history",
            params={"notification_type": "scan_completed"},
        )

        # Assert
        assert response.status_code == 200
        data = response.json()
        assert all(log["notification_type"] == "scan_completed" for log in data)

    @pytest.mark.asyncio
    async def test_get_notification_history_filter_by_status(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test filtering notification history by status."""
        # Arrange
        log1 = NotificationLog(
            notification_type="scan_completed",
            channel="ntfy",
            message="Scan complete",
            status="sent",
        )
        log2 = NotificationLog(
            notification_type="scan_completed",
            channel="ntfy",
            message="Scan complete",
            status="failed",
            error_message="Connection failed",
        )
        db_session.add_all([log1, log2])
        await db_session.commit()

        # Act
        response = await authenticated_client.get(
            "/api/v1/notifications/history",
            params={"status": "failed"},
        )

        # Assert
        assert response.status_code == 200
        data = response.json()
        assert all(log["status"] == "failed" for log in data)

    @pytest.mark.asyncio
    async def test_get_notification_history_with_pagination(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test notification history pagination."""
        # Arrange - Create multiple logs
        for i in range(10):
            log = NotificationLog(
                notification_type="scan_completed",
                channel="ntfy",
                message=f"Scan {i} complete",
                status="sent",
            )
            db_session.add(log)
        await db_session.commit()

        # Act
        response = await authenticated_client.get(
            "/api/v1/notifications/history",
            params={"skip": 3, "limit": 5},
        )

        # Assert
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 5


class TestGetNotificationById:
    """Test GET /api/v1/notifications/history/{notification_id} endpoint."""

    @pytest.mark.asyncio
    async def test_get_notification_by_id_success(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test getting a specific notification by ID."""
        # Arrange
        log = NotificationLog(
            notification_type="scan_completed",
            channel="ntfy",
            title="Test Notification",
            message="Test message",
            status="sent",
            priority=3,
        )
        db_session.add(log)
        await db_session.commit()
        await db_session.refresh(log)

        # Act
        response = await authenticated_client.get(f"/api/v1/notifications/history/{log.id}")

        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == log.id
        assert data["notification_type"] == "scan_completed"
        assert data["channel"] == "ntfy"

    @pytest.mark.asyncio
    async def test_get_notification_by_id_not_found(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test getting non-existent notification."""
        # Act
        response = await authenticated_client.get("/api/v1/notifications/history/99999")

        # Assert
        assert response.status_code == 404
        data = response.json()
        assert "not found" in data["detail"].lower()


class TestGetNotificationsForScan:
    """Test GET /api/v1/notifications/history/scan/{scan_id} endpoint."""

    @pytest.mark.asyncio
    async def test_get_notifications_for_scan_success(
        self, authenticated_client: AsyncClient, db_session: AsyncSession, make_scan
    ):
        """Test getting notifications for a specific scan."""
        # Arrange
        scan = make_scan(container_id=1, scan_status="completed")
        db_session.add(scan)
        await db_session.commit()
        await db_session.refresh(scan)

        log1 = NotificationLog(
            scan_id=scan.id,
            notification_type="scan_completed",
            channel="ntfy",
            message="Scan complete",
            status="sent",
        )
        log2 = NotificationLog(
            scan_id=scan.id,
            notification_type="scan_completed",
            channel="email",
            message="Scan complete email",
            status="sent",
        )
        db_session.add_all([log1, log2])
        await db_session.commit()

        # Act
        response = await authenticated_client.get(f"/api/v1/notifications/history/scan/{scan.id}")

        # Assert
        assert response.status_code == 200
        data = response.json()
        assert len(data) >= 2
        assert all(log["scan_id"] == scan.id for log in data)

    @pytest.mark.asyncio
    async def test_get_notifications_for_scan_no_notifications(
        self, authenticated_client: AsyncClient, db_session: AsyncSession, make_scan
    ):
        """Test getting notifications for scan with no notifications."""
        # Arrange
        scan = make_scan(container_id=1, scan_status="completed")
        db_session.add(scan)
        await db_session.commit()
        await db_session.refresh(scan)

        # Act
        response = await authenticated_client.get(f"/api/v1/notifications/history/scan/{scan.id}")

        # Assert
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) == 0


class TestGetNotificationStats:
    """Test GET /api/v1/notifications/stats endpoint."""

    @pytest.mark.asyncio
    async def test_get_notification_stats_empty(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test getting stats with no notifications."""
        # Act
        response = await authenticated_client.get("/api/v1/notifications/stats")

        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["total_notifications"] == 0
        assert data["sent"] == 0
        assert data["failed"] == 0
        assert data["success_rate"] == 0
        assert isinstance(data["by_type"], dict)

    @pytest.mark.asyncio
    async def test_get_notification_stats_with_data(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test getting notification statistics."""
        # Arrange
        log1 = NotificationLog(
            notification_type="scan_completed",
            channel="ntfy",
            message="Success",
            status="sent",
        )
        log2 = NotificationLog(
            notification_type="scan_completed",
            channel="ntfy",
            message="Success",
            status="sent",
        )
        log3 = NotificationLog(
            notification_type="critical_vulnerability",
            channel="email",
            message="Failed",
            status="failed",
        )
        db_session.add_all([log1, log2, log3])
        await db_session.commit()

        # Act
        response = await authenticated_client.get("/api/v1/notifications/stats")

        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["total_notifications"] >= 3
        assert data["sent"] >= 2
        assert data["failed"] >= 1
        assert data["success_rate"] > 0
        assert "scan_completed" in data["by_type"]
        assert "critical_vulnerability" in data["by_type"]


# ============================================
# Notification Rules Tests
# ============================================


class TestGetNotificationRules:
    """Test GET /api/v1/notifications/rules endpoint."""

    @pytest.mark.asyncio
    async def test_get_notification_rules_empty(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test getting rules with no records."""
        # Act
        response = await authenticated_client.get("/api/v1/notifications/rules")

        # Assert
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) == 0

    @pytest.mark.asyncio
    async def test_get_notification_rules_with_data(
        self, authenticated_client: AsyncClient, db_session: AsyncSession, make_notification_rule
    ):
        """Test getting notification rules."""
        # Arrange
        rule1 = make_notification_rule(name="critical_alert", enabled=True)
        rule2 = make_notification_rule(name="scan_complete", enabled=True)
        db_session.add_all([rule1, rule2])
        await db_session.commit()

        # Act
        response = await authenticated_client.get("/api/v1/notifications/rules")

        # Assert
        assert response.status_code == 200
        data = response.json()
        assert len(data) >= 2

    @pytest.mark.asyncio
    async def test_get_notification_rules_enabled_only(
        self, authenticated_client: AsyncClient, db_session: AsyncSession, make_notification_rule
    ):
        """Test filtering for enabled rules only."""
        # Arrange
        rule1 = make_notification_rule(name="enabled_rule", enabled=True)
        rule2 = make_notification_rule(name="disabled_rule", enabled=False)
        db_session.add_all([rule1, rule2])
        await db_session.commit()

        # Act
        response = await authenticated_client.get(
            "/api/v1/notifications/rules",
            params={"enabled_only": True},
        )

        # Assert
        assert response.status_code == 200
        data = response.json()
        assert all(rule["enabled"] is True for rule in data)


class TestGetNotificationRule:
    """Test GET /api/v1/notifications/rules/{rule_id} endpoint."""

    @pytest.mark.asyncio
    async def test_get_notification_rule_success(
        self, authenticated_client: AsyncClient, db_session: AsyncSession, make_notification_rule
    ):
        """Test getting a specific notification rule."""
        # Arrange
        rule = make_notification_rule(
            name="test_rule",
            event_type="scan_completed",
            min_critical=5,
        )
        db_session.add(rule)
        await db_session.commit()
        await db_session.refresh(rule)

        # Act
        response = await authenticated_client.get(f"/api/v1/notifications/rules/{rule.id}")

        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == rule.id
        assert data["name"] == "test_rule"
        assert data["event_type"] == "scan_completed"

    @pytest.mark.asyncio
    async def test_get_notification_rule_not_found(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test getting non-existent rule."""
        # Act
        response = await authenticated_client.get("/api/v1/notifications/rules/99999")

        # Assert
        assert response.status_code == 404
        data = response.json()
        assert "not found" in data["detail"].lower()


class TestCreateNotificationRule:
    """Test POST /api/v1/notifications/rules endpoint."""

    @pytest.mark.asyncio
    async def test_create_notification_rule_success(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test creating a new notification rule."""
        # Arrange
        rule_data = {
            "name": "critical_vulns_alert",
            "description": "Alert on critical vulnerabilities",
            "event_type": "new_vulnerabilities",
            "enabled": True,
            "min_critical": 1,
            "message_template": "Found {critical_count} critical vulnerabilities!",
            "priority": 5,
        }

        # Act
        response = await authenticated_client.post("/api/v1/notifications/rules", json=rule_data)

        # Assert
        assert response.status_code == 201
        data = response.json()
        assert data["name"] == "critical_vulns_alert"
        assert data["min_critical"] == 1

        # Verify in database
        result = await db_session.execute(
            select(NotificationRule).where(NotificationRule.name == "critical_vulns_alert")
        )
        rule = result.scalar_one_or_none()
        assert rule is not None
        assert rule.min_critical == 1

    @pytest.mark.asyncio
    async def test_create_notification_rule_duplicate_name(
        self, authenticated_client: AsyncClient, db_session: AsyncSession, make_notification_rule
    ):
        """Test creating rule with duplicate name."""
        # Arrange
        existing_rule = make_notification_rule(name="duplicate_test")
        db_session.add(existing_rule)
        await db_session.commit()

        rule_data = {
            "name": "duplicate_test",
            "event_type": "scan_completed",
            "message_template": "Test message",
        }

        # Act
        response = await authenticated_client.post("/api/v1/notifications/rules", json=rule_data)

        # Assert
        assert response.status_code == 400
        data = response.json()
        assert "already exists" in data["detail"].lower()

    @pytest.mark.asyncio
    async def test_create_notification_rule_validation_error(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test creating rule with missing required fields."""
        # Arrange - Missing required field 'message_template'
        rule_data = {
            "name": "incomplete_rule",
            "event_type": "scan_completed",
        }

        # Act
        response = await authenticated_client.post("/api/v1/notifications/rules", json=rule_data)

        # Assert
        assert response.status_code == 422  # Pydantic validation error

    @pytest.mark.skip(reason="Auth disabled in tests - all requests pass through")
    async def test_create_notification_rule_requires_admin(self, authenticated_client: AsyncClient):
        """Test create rule endpoint requires admin authentication."""
        pass


class TestUpdateNotificationRule:
    """Test PATCH /api/v1/notifications/rules/{rule_id} endpoint."""

    @pytest.mark.asyncio
    async def test_update_notification_rule_success(
        self, authenticated_client: AsyncClient, db_session: AsyncSession, make_notification_rule
    ):
        """Test updating an existing notification rule."""
        # Arrange
        rule = make_notification_rule(
            name="original_rule",
            min_critical=5,
            enabled=True,
        )
        db_session.add(rule)
        await db_session.commit()
        await db_session.refresh(rule)

        update_data = {
            "min_critical": 10,
            "enabled": False,
        }

        # Act
        response = await authenticated_client.patch(
            f"/api/v1/notifications/rules/{rule.id}",
            json=update_data,
        )

        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["min_critical"] == 10
        assert data["enabled"] is False

        # Verify in database
        await db_session.refresh(rule)
        assert rule.min_critical == 10
        assert rule.enabled is False

    @pytest.mark.asyncio
    async def test_update_notification_rule_not_found(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test updating non-existent rule."""
        # Arrange
        update_data = {"min_critical": 10}

        # Act
        response = await authenticated_client.patch(
            "/api/v1/notifications/rules/99999",
            json=update_data,
        )

        # Assert
        assert response.status_code == 404
        data = response.json()
        assert "not found" in data["detail"].lower()

    @pytest.mark.skip(reason="Auth disabled in tests - all requests pass through")
    async def test_update_notification_rule_requires_admin(self, authenticated_client: AsyncClient):
        """Test update rule endpoint requires admin authentication."""
        pass


class TestDeleteNotificationRule:
    """Test DELETE /api/v1/notifications/rules/{rule_id} endpoint."""

    @pytest.mark.asyncio
    async def test_delete_notification_rule_success(
        self, authenticated_client: AsyncClient, db_session: AsyncSession, make_notification_rule
    ):
        """Test deleting a notification rule."""
        # Arrange
        rule = make_notification_rule(name="to_delete")
        db_session.add(rule)
        await db_session.commit()
        await db_session.refresh(rule)
        rule_id = rule.id

        # Act
        response = await authenticated_client.delete(f"/api/v1/notifications/rules/{rule_id}")

        # Assert
        assert response.status_code == 204

        # Verify deletion
        result = await db_session.execute(
            select(NotificationRule).where(NotificationRule.id == rule_id)
        )
        deleted_rule = result.scalar_one_or_none()
        assert deleted_rule is None

    @pytest.mark.asyncio
    async def test_delete_notification_rule_not_found(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test deleting non-existent rule."""
        # Act
        response = await authenticated_client.delete("/api/v1/notifications/rules/99999")

        # Assert
        assert response.status_code == 404
        data = response.json()
        assert "not found" in data["detail"].lower()

    @pytest.mark.skip(reason="Auth disabled in tests - all requests pass through")
    async def test_delete_notification_rule_requires_admin(self, authenticated_client: AsyncClient):
        """Test delete rule endpoint requires admin authentication."""
        pass


class TestToggleNotificationRule:
    """Test POST /api/v1/notifications/rules/{rule_id}/toggle endpoint."""

    @pytest.mark.asyncio
    async def test_toggle_notification_rule_enable(
        self, authenticated_client: AsyncClient, db_session: AsyncSession, make_notification_rule
    ):
        """Test enabling a disabled rule."""
        # Arrange
        rule = make_notification_rule(name="toggle_test", enabled=False)
        db_session.add(rule)
        await db_session.commit()
        await db_session.refresh(rule)

        # Act
        response = await authenticated_client.post(f"/api/v1/notifications/rules/{rule.id}/toggle")

        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["enabled"] is True

        # Verify in database
        await db_session.refresh(rule)
        assert rule.enabled is True

    @pytest.mark.asyncio
    async def test_toggle_notification_rule_disable(
        self, authenticated_client: AsyncClient, db_session: AsyncSession, make_notification_rule
    ):
        """Test disabling an enabled rule."""
        # Arrange
        rule = make_notification_rule(name="toggle_test", enabled=True)
        db_session.add(rule)
        await db_session.commit()
        await db_session.refresh(rule)

        # Act
        response = await authenticated_client.post(f"/api/v1/notifications/rules/{rule.id}/toggle")

        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["enabled"] is False

        # Verify in database
        await db_session.refresh(rule)
        assert rule.enabled is False

    @pytest.mark.asyncio
    async def test_toggle_notification_rule_not_found(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test toggling non-existent rule."""
        # Act
        response = await authenticated_client.post("/api/v1/notifications/rules/99999/toggle")

        # Assert
        assert response.status_code == 404
        data = response.json()
        assert "not found" in data["detail"].lower()

    @pytest.mark.skip(reason="Auth disabled in tests - all requests pass through")
    async def test_toggle_notification_rule_requires_admin(self, authenticated_client: AsyncClient):
        """Test toggle endpoint requires admin authentication."""
        pass


# ============================================
# Notification Service Tests
# ============================================


class TestSendTestNotification:
    """Test POST /api/v1/notifications/test endpoint (legacy)."""

    @pytest.mark.asyncio
    async def test_send_test_notification_success(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test sending a test notification."""
        # Arrange
        with patch("app.services.notifier.NotificationService") as mock_service:
            mock_instance = MagicMock()
            mock_instance.send_notification = AsyncMock()
            mock_service.return_value = mock_instance

            # Act
            response = await authenticated_client.post("/api/v1/notifications/test")

            # Assert
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "success"
            assert "sent" in data["message"].lower()

    @pytest.mark.asyncio
    async def test_send_test_notification_timeout(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test notification timeout handling."""
        # Arrange
        with patch("app.services.notifier.NotificationService") as mock_service:
            mock_instance = MagicMock()
            mock_instance.send_notification = AsyncMock(
                side_effect=httpx.TimeoutException("Timeout")
            )
            mock_service.return_value = mock_instance

            # Act
            response = await authenticated_client.post("/api/v1/notifications/test")

            # Assert
            assert response.status_code == 504

    @pytest.mark.asyncio
    async def test_send_test_notification_connection_error(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test notification connection error handling."""
        # Arrange
        with patch("app.services.notifier.NotificationService") as mock_service:
            mock_instance = MagicMock()
            mock_instance.send_notification = AsyncMock(
                side_effect=httpx.ConnectError("Connection failed")
            )
            mock_service.return_value = mock_instance

            # Act
            response = await authenticated_client.post("/api/v1/notifications/test")

            # Assert
            assert response.status_code == 503


class TestNtfyConnection:
    """Test POST /api/v1/notifications/test/ntfy endpoint."""

    @pytest.mark.asyncio
    async def test_ntfy_connection_success(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test successful ntfy connection."""
        # Arrange - Configure ntfy settings
        from app.services.settings_manager import SettingsManager

        settings = SettingsManager(db_session)
        await settings.set("ntfy_enabled", "true")
        await settings.set("ntfy_url", "https://ntfy.sh")
        await settings.set("ntfy_topic", "test-topic")
        await db_session.commit()

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.raise_for_status = MagicMock()
            mock_instance.post = AsyncMock(return_value=mock_response)
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=None)
            mock_client.return_value = mock_instance

            # Act
            response = await authenticated_client.post("/api/v1/notifications/test/ntfy")

            # Assert
            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True

    @pytest.mark.asyncio
    async def test_ntfy_connection_disabled(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test ntfy when disabled."""
        # Arrange
        from app.services.settings_manager import SettingsManager

        settings = SettingsManager(db_session)
        await settings.set("ntfy_enabled", "false")
        await db_session.commit()

        # Act
        response = await authenticated_client.post("/api/v1/notifications/test/ntfy")

        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is False
        assert "disabled" in data["message"].lower()

    @pytest.mark.asyncio
    async def test_ntfy_connection_not_configured(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test ntfy when not configured."""
        # Arrange
        from app.services.settings_manager import SettingsManager

        settings = SettingsManager(db_session)
        await settings.set("ntfy_enabled", "false")
        await db_session.commit()

        # Act
        response = await authenticated_client.post("/api/v1/notifications/test/ntfy")

        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is False
        assert "not configured" in data["message"].lower() or "disabled" in data["message"].lower()


class TestGotifyConnection:
    """Test POST /api/v1/notifications/test/gotify endpoint."""

    @pytest.mark.asyncio
    async def test_gotify_connection_success(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test successful Gotify connection."""
        # Arrange
        from app.services.settings_manager import SettingsManager

        settings = SettingsManager(db_session)
        await settings.set("gotify_enabled", "true")
        await settings.set("gotify_server", "https://gotify.example.com")
        await settings.set("gotify_token", "test-token")
        await db_session.commit()

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.raise_for_status = MagicMock()
            mock_instance.post = AsyncMock(return_value=mock_response)
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=None)
            mock_client.return_value = mock_instance

            # Act
            response = await authenticated_client.post("/api/v1/notifications/test/gotify")

            # Assert
            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True

    @pytest.mark.asyncio
    async def test_gotify_connection_disabled(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test Gotify when disabled."""
        # Arrange
        from app.services.settings_manager import SettingsManager

        settings = SettingsManager(db_session)
        await settings.set("gotify_enabled", "false")
        await db_session.commit()

        # Act
        response = await authenticated_client.post("/api/v1/notifications/test/gotify")

        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is False


class TestPushoverConnection:
    """Test POST /api/v1/notifications/test/pushover endpoint."""

    @pytest.mark.asyncio
    async def test_pushover_connection_success(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test successful Pushover connection."""
        # Arrange
        from app.services.settings_manager import SettingsManager

        settings = SettingsManager(db_session)
        await settings.set("pushover_enabled", "true")
        await settings.set("pushover_user_key", "test-user-key")
        await settings.set("pushover_api_token", "test-api-token")
        await db_session.commit()

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()

            # Mock validation response
            validate_response = MagicMock()
            validate_response.status_code = 200
            validate_response.json.return_value = {"status": 1}

            # Mock message response
            message_response = MagicMock()
            message_response.status_code = 200
            message_response.raise_for_status = MagicMock()

            mock_instance.post = AsyncMock(side_effect=[validate_response, message_response])
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=None)
            mock_client.return_value = mock_instance

            # Act
            response = await authenticated_client.post("/api/v1/notifications/test/pushover")

            # Assert
            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True


class TestSlackConnection:
    """Test POST /api/v1/notifications/test/slack endpoint."""

    @pytest.mark.asyncio
    async def test_slack_connection_success(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test successful Slack connection."""
        # Arrange
        from app.services.settings_manager import SettingsManager

        settings = SettingsManager(db_session)
        await settings.set("slack_enabled", "true")
        await settings.set("slack_webhook_url", "https://hooks.slack.com/test")
        await db_session.commit()

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.text = "ok"
            mock_instance.post = AsyncMock(return_value=mock_response)
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=None)
            mock_client.return_value = mock_instance

            # Act
            response = await authenticated_client.post("/api/v1/notifications/test/slack")

            # Assert
            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True


class TestDiscordConnection:
    """Test POST /api/v1/notifications/test/discord endpoint."""

    @pytest.mark.asyncio
    async def test_discord_connection_success(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test successful Discord connection."""
        # Arrange
        from app.services.settings_manager import SettingsManager

        settings = SettingsManager(db_session)
        await settings.set("discord_enabled", "true")
        await settings.set("discord_webhook_url", "https://discord.com/api/webhooks/test")
        await db_session.commit()

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_response = MagicMock()
            mock_response.status_code = 204
            mock_instance.post = AsyncMock(return_value=mock_response)
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=None)
            mock_client.return_value = mock_instance

            # Act
            response = await authenticated_client.post("/api/v1/notifications/test/discord")

            # Assert
            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True


class TestTelegramConnection:
    """Test POST /api/v1/notifications/test/telegram endpoint."""

    @pytest.mark.asyncio
    async def test_telegram_connection_success(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test successful Telegram connection."""
        # Arrange
        from app.services.settings_manager import SettingsManager

        settings = SettingsManager(db_session)
        await settings.set("telegram_enabled", "true")
        await settings.set("telegram_bot_token", "test-bot-token")
        await settings.set("telegram_chat_id", "test-chat-id")
        await db_session.commit()

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()

            # Mock getMe response
            me_response = MagicMock()
            me_response.status_code = 200
            me_response.json.return_value = {
                "ok": True,
                "result": {"username": "TestBot"},
            }

            # Mock sendMessage response
            send_response = MagicMock()
            send_response.json.return_value = {"ok": True}

            mock_instance.get = AsyncMock(return_value=me_response)
            mock_instance.post = AsyncMock(return_value=send_response)
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=None)
            mock_client.return_value = mock_instance

            # Act
            response = await authenticated_client.post("/api/v1/notifications/test/telegram")

            # Assert
            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True


class TestEmailConnection:
    """Test POST /api/v1/notifications/test/email endpoint."""

    @pytest.mark.asyncio
    async def test_email_connection_success(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test successful email connection."""
        # Arrange
        from app.services.settings_manager import SettingsManager

        settings = SettingsManager(db_session)
        await settings.set("email_enabled", "true")
        await settings.set("email_smtp_host", "smtp.example.com")
        await settings.set("email_smtp_port", "587")
        await settings.set("email_smtp_user", "user@example.com")
        await settings.set("email_smtp_password", "password")
        await settings.set("email_from", "vulnforge@example.com")
        await settings.set("email_to", "admin@example.com")
        await db_session.commit()

        with patch(
            "app.services.notifications.email.EmailNotificationService"
        ) as mock_email_service:
            mock_instance = MagicMock()
            mock_instance.test_connection = AsyncMock(return_value=(True, "Connection successful"))
            mock_email_service.return_value = mock_instance

            # Act
            response = await authenticated_client.post("/api/v1/notifications/test/email")

            # Assert
            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True

    @pytest.mark.asyncio
    async def test_email_connection_disabled(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test email when disabled."""
        # Arrange
        from app.services.settings_manager import SettingsManager

        settings = SettingsManager(db_session)
        await settings.set("email_enabled", "false")
        await db_session.commit()

        # Act
        response = await authenticated_client.post("/api/v1/notifications/test/email")

        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is False
        assert "disabled" in data["message"].lower()

    @pytest.mark.asyncio
    async def test_email_connection_incomplete_config(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test email with incomplete configuration."""
        # Arrange
        from app.services.settings_manager import SettingsManager

        settings = SettingsManager(db_session)
        await settings.set("email_enabled", "true")
        await settings.set("email_smtp_host", "smtp.example.com")
        # Missing other required fields
        await db_session.commit()

        # Act
        response = await authenticated_client.post("/api/v1/notifications/test/email")

        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is False
        assert "incomplete" in data["message"].lower()
