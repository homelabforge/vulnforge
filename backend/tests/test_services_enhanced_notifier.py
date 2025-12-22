"""Tests for Enhanced Notification Service."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest


class TestEnhancedNotifierInit:
    """Test EnhancedNotificationService initialization."""

    def test_init_success(self):
        """Test successful initialization."""
        from app.services.enhanced_notifier import EnhancedNotificationService

        service = EnhancedNotificationService()

        # Initialization should complete without error
        assert service is not None


class TestSendNotificationWithLogging:
    """Test send_notification_with_logging method."""

    @pytest.mark.asyncio
    async def test_send_notification_logs_to_database(self):
        """Test notification is logged to database."""
        from app.services.enhanced_notifier import EnhancedNotificationService

        service = EnhancedNotificationService()

        # Mock the dispatcher
        with patch(
            "app.services.enhanced_notifier.NotificationDispatcher"
        ) as mock_dispatcher_class:
            mock_dispatcher = AsyncMock()
            mock_dispatcher.dispatch = AsyncMock(return_value={"ntfy": True})
            mock_dispatcher_class.return_value = mock_dispatcher

            # Mock db_session context
            with patch("app.services.enhanced_notifier.db_session") as mock_db_context:
                mock_db = AsyncMock()
                mock_db.add = MagicMock()
                mock_db.commit = AsyncMock()
                mock_db.__aenter__.return_value = mock_db
                mock_db.__aexit__.return_value = AsyncMock()
                mock_db_context.return_value = mock_db

                # Act
                result = await service.send_notification_with_logging(
                    notification_type="scan_completed",
                    message="Test message",
                    title="Test Title",
                    priority=3,
                )

                # Assert
                assert result is True
                mock_db.add.assert_called_once()
                mock_db.commit.assert_called_once()


class TestEvaluateRule:
    """Test evaluate_rule method."""

    @pytest.mark.asyncio
    async def test_evaluate_rule_passes_when_conditions_met(self):
        """Test that rule passes when conditions are met."""
        from app.services.enhanced_notifier import EnhancedNotificationService

        service = EnhancedNotificationService()

        # Create mock rule
        mock_rule = MagicMock()
        mock_rule.enabled = True
        mock_rule.min_critical = 1
        mock_rule.min_high = None
        mock_rule.min_medium = None
        mock_rule.min_total = None

        # Act
        result = await service.evaluate_rule(mock_rule, {"critical_count": 5})

        # Assert
        assert result is True

    @pytest.mark.asyncio
    async def test_evaluate_rule_fails_when_threshold_not_met(self):
        """Test that rule fails when threshold not met."""
        from app.services.enhanced_notifier import EnhancedNotificationService

        service = EnhancedNotificationService()

        # Create mock rule
        mock_rule = MagicMock()
        mock_rule.enabled = True
        mock_rule.min_critical = 10
        mock_rule.min_high = None
        mock_rule.min_medium = None
        mock_rule.min_total = None

        # Act
        result = await service.evaluate_rule(mock_rule, {"critical_count": 5})

        # Assert
        assert result is False


class TestTemplateRendering:
    """Test template rendering."""

    def test_render_template_simple(self):
        """Test simple template rendering."""
        from app.services.enhanced_notifier import EnhancedNotificationService

        service = EnhancedNotificationService()

        # Act
        result = service.render_template("Hello $name!", {"name": "World"})

        # Assert
        assert result == "Hello World!"

    def test_render_template_missing_variable(self):
        """Test template with missing variable."""
        from app.services.enhanced_notifier import EnhancedNotificationService

        service = EnhancedNotificationService()

        # Act - safe_substitute leaves $name as-is when variable missing
        result = service.render_template("Hello $name!", {})

        # Assert - Template should leave $name unchanged
        assert result == "Hello $name!"
