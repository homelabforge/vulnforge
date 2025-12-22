"""Tests for notification service providers.

This module tests all notification providers with their actual API:
- ntfy (self-hosted)
- Discord (webhook)
- Slack (webhook)
- Telegram (bot API)
- Gotify (self-hosted)
- Pushover (commercial service)
- Email (SMTP)

All providers use the same interface from base.NotificationService:
    async def send(title, message, priority="default", tags=None, url=None) -> bool
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest


class TestNtfyNotificationService:
    """Test ntfy notification provider."""

    @pytest.mark.asyncio
    async def test_send_ntfy_notification_success(self):
        """Test sending ntfy notification successfully."""
        from app.services.notifications.ntfy import NtfyNotificationService

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_client.return_value = mock_instance
            mock_instance.aclose = AsyncMock()
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.raise_for_status = MagicMock()
            mock_instance.post = AsyncMock(return_value=mock_response)

            service = NtfyNotificationService("http://ntfy.example.com", "test-topic")

            success = await service.send(
                title="Test Alert",
                message="Test notification",
                priority="default",
            )

            assert success is True
            mock_instance.post.assert_called_once()
            await service.close()

    @pytest.mark.asyncio
    async def test_ntfy_with_auth_token(self):
        """Test sending ntfy notification with auth token."""
        from app.services.notifications.ntfy import NtfyNotificationService

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_client.return_value = mock_instance
            mock_instance.aclose = AsyncMock()
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.raise_for_status = MagicMock()
            mock_instance.post = AsyncMock(return_value=mock_response)

            service = NtfyNotificationService(
                "http://ntfy.example.com", "test-topic", api_key="secret-token"
            )

            await service.send("Test", "Message")

            # Verify Authorization header was set in init
            assert "Authorization" in service.headers
            assert "Bearer secret-token" == service.headers["Authorization"]
            await service.close()

    @pytest.mark.asyncio
    async def test_ntfy_connection_timeout(self):
        """Test ntfy connection timeout handling."""
        import httpx

        from app.services.notifications.ntfy import NtfyNotificationService

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_client.return_value = mock_instance
            mock_instance.aclose = AsyncMock()
            mock_instance.post = AsyncMock(side_effect=httpx.TimeoutException("Timeout"))

            service = NtfyNotificationService("http://ntfy.example.com", "test-topic")

            success = await service.send("Test", "Message")

            assert success is False
            await service.close()


class TestDiscordNotificationService:
    """Test Discord webhook notification provider."""

    @pytest.mark.asyncio
    async def test_send_discord_notification(self):
        """Test sending Discord webhook notification."""
        from app.services.notifications.discord import DiscordNotificationService

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_client.return_value = mock_instance
            mock_instance.aclose = AsyncMock()
            mock_response = MagicMock()
            mock_response.status_code = 204
            mock_instance.post = AsyncMock(return_value=mock_response)

            service = DiscordNotificationService("https://discord.com/api/webhooks/test")

            success = await service.send(
                title="Test Alert",
                message="Critical vulnerability detected",
                priority="high",
            )

            assert success is True
            await service.close()


class TestSlackNotificationService:
    """Test Slack webhook notification provider."""

    @pytest.mark.asyncio
    async def test_send_slack_notification(self):
        """Test sending Slack webhook notification."""
        from app.services.notifications.slack import SlackNotificationService

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_client.return_value = mock_instance
            mock_instance.aclose = AsyncMock()
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.text = "ok"  # Slack expects text == "ok"
            mock_instance.post = AsyncMock(return_value=mock_response)

            service = SlackNotificationService("https://hooks.slack.com/services/test")

            success = await service.send(
                title="Test Alert",
                message="Scan completed",
                priority="default",
            )

            assert success is True
            await service.close()


class TestTelegramNotificationService:
    """Test Telegram bot notification provider."""

    @pytest.mark.asyncio
    async def test_send_telegram_notification(self):
        """Test sending Telegram notification."""
        from app.services.notifications.telegram import TelegramNotificationService

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_client.return_value = mock_instance
            mock_instance.aclose = AsyncMock()
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"ok": True}
            mock_instance.post = AsyncMock(return_value=mock_response)

            service = TelegramNotificationService("bot_token", "chat_id")

            success = await service.send(
                title="Test Alert",
                message="Vulnerability detected",
                priority="high",
            )

            assert success is True
            await service.close()


class TestGotifyNotificationService:
    """Test Gotify notification provider."""

    @pytest.mark.asyncio
    async def test_send_gotify_notification(self):
        """Test sending Gotify notification."""
        from app.services.notifications.gotify import GotifyNotificationService

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_client.return_value = mock_instance
            mock_instance.aclose = AsyncMock()
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_instance.post = AsyncMock(return_value=mock_response)

            service = GotifyNotificationService("http://gotify.example.com", "app_token")

            success = await service.send(
                title="Test Alert",
                message="Test message",
                priority="default",
            )

            assert success is True
            await service.close()


class TestPushoverNotificationService:
    """Test Pushover notification provider."""

    @pytest.mark.asyncio
    async def test_send_pushover_notification(self):
        """Test sending Pushover notification."""
        from app.services.notifications.pushover import PushoverNotificationService

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_client.return_value = mock_instance
            mock_instance.aclose = AsyncMock()
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"status": 1}
            mock_instance.post = AsyncMock(return_value=mock_response)

            service = PushoverNotificationService("user_key", "api_token")

            success = await service.send(
                title="Test Alert",
                message="Critical issue detected",
                priority="high",
            )

            assert success is True
            await service.close()


class TestEmailNotificationService:
    """Test SMTP email notification provider."""

    @pytest.mark.asyncio
    async def test_send_email_via_smtp(self):
        """Test sending email via SMTP."""
        from app.services.notifications.email import EmailNotificationService

        with patch("app.services.notifications.email.aiosmtplib.send") as mock_send:
            mock_send.return_value = AsyncMock()

            service = EmailNotificationService(
                smtp_host="smtp.gmail.com",
                smtp_port=587,
                smtp_user="test@example.com",
                smtp_password="password",
                from_address="vulnforge@example.com",
                to_address="admin@example.com",
                use_tls=True,
            )

            success = await service.send(
                title="Test Alert",
                message="Critical vulnerability detected in nginx",
            )

            assert success is True
            mock_send.assert_called_once()
            await service.close()
