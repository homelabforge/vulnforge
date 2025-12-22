"""Telegram notification service."""

import logging

import httpx

from app.services.notifications.base import NotificationService

logger = logging.getLogger(__name__)

TELEGRAM_API_BASE = "https://api.telegram.org"


class TelegramNotificationService(NotificationService):
    """Telegram bot notification service implementation."""

    service_name = "telegram"

    def __init__(
        self,
        bot_token: str,
        chat_id: str,
    ) -> None:
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.client = httpx.AsyncClient(timeout=10.0)

    async def close(self) -> None:
        """Close HTTP client."""
        await self.client.aclose()

    async def send(
        self,
        title: str,
        message: str,
        priority: str = "default",
        tags: list[str] | None = None,
        url: str | None = None,
    ) -> bool:
        try:
            endpoint = f"{TELEGRAM_API_BASE}/bot{self.bot_token}/sendMessage"

            # Build HTML formatted message
            # Priority emoji
            priority_emoji = {
                "urgent": "\u26a0\ufe0f",  # Warning sign
                "high": "\u2757",  # Exclamation mark
                "default": "\u2139\ufe0f",  # Info
                "low": "\u2705",  # Check mark
                "min": "\u25aa\ufe0f",  # Small square
            }.get(priority, "\u2139\ufe0f")

            # Format message with HTML
            html_message = f"{priority_emoji} <b>{title}</b>\n\n{message}"

            # Add tags
            if tags:
                tag_text = " ".join(f"#{tag}" for tag in tags)
                html_message += f"\n\n{tag_text}"

            payload = {
                "chat_id": self.chat_id,
                "text": html_message,
                "parse_mode": "HTML",
                "disable_web_page_preview": True,
            }

            # Add inline button for URL
            if url:
                payload["reply_markup"] = {
                    "inline_keyboard": [[{"text": "View Details", "url": url}]]
                }

            response = await self.client.post(endpoint, json=payload)
            response.raise_for_status()

            result = response.json()
            if result.get("ok"):
                logger.info(f"[telegram] Sent notification: {title}")
                return True

            logger.error(f"[telegram] API error: {result.get('description', 'Unknown error')}")
            return False

        except httpx.HTTPStatusError as e:
            logger.error(f"[telegram] HTTP error: {e}")
            return False
        except (httpx.ConnectError, httpx.TimeoutException) as e:
            logger.error(f"[telegram] Connection error: {e}")
            return False
        except (ValueError, KeyError) as e:
            logger.error(f"[telegram] Invalid data: {e}")
            return False

    async def test_connection(self) -> tuple[bool, str]:
        try:
            # First verify the bot token is valid
            me_endpoint = f"{TELEGRAM_API_BASE}/bot{self.bot_token}/getMe"
            response = await self.client.get(me_endpoint)

            if response.status_code != 200:
                return False, "Invalid bot token"

            result = response.json()
            if not result.get("ok"):
                return False, f"Bot validation failed: {result.get('description', 'Unknown')}"

            bot_name = result.get("result", {}).get("username", "Unknown")

            # Send test message
            success = await self.send(
                title="Test Notification",
                message=f"This is a test notification from VulnForge.\nBot: @{bot_name}",
                priority="low",
                tags=["VulnForge", "test"],
            )

            if success:
                return True, f"Test notification sent via @{bot_name}"
            return False, "Bot is valid but failed to send test notification"

        except Exception as e:
            return False, f"Connection test failed: {str(e)}"
