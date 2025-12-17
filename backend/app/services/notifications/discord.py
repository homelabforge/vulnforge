"""Discord notification service."""

import logging
from typing import Optional

import httpx

from app.services.notifications.base import NotificationService

logger = logging.getLogger(__name__)

# Color mapping for Discord embeds (decimal format)
COLOR_MAP = {
    "urgent": 0xDC2626,   # Red
    "high": 0xF97316,     # Orange
    "default": 0x3B82F6,  # Blue
    "low": 0x10B981,      # Green
    "min": 0x6B7280,      # Gray
}


class DiscordNotificationService(NotificationService):
    """Discord webhook notification service implementation."""

    service_name = "discord"

    def __init__(self, webhook_url: str) -> None:
        self.webhook_url = webhook_url
        self.client = httpx.AsyncClient(timeout=10.0)

    async def close(self) -> None:
        """Close HTTP client."""
        await self.client.aclose()

    async def send(
        self,
        title: str,
        message: str,
        priority: str = "default",
        tags: Optional[list[str]] = None,
        url: Optional[str] = None,
    ) -> bool:
        try:
            # Build Discord embed
            color = COLOR_MAP.get(priority, COLOR_MAP["default"])

            embed = {
                "title": title,
                "description": message,
                "color": color,
                "footer": {"text": "VulnForge"},
            }

            if url:
                embed["url"] = url

            # Add tags as a field
            if tags:
                tag_text = " ".join(f"`{tag}`" for tag in tags)
                embed["fields"] = [
                    {"name": "Tags", "value": tag_text, "inline": True}
                ]

            payload = {
                "embeds": [embed],
            }

            response = await self.client.post(
                self.webhook_url,
                json=payload,
            )

            # Discord returns 204 No Content on success
            if response.status_code == 204:
                logger.info(f"[discord] Sent notification: {title}")
                return True

            # Also accept 200 with empty or valid response
            if response.status_code == 200:
                logger.info(f"[discord] Sent notification: {title}")
                return True

            logger.error(f"[discord] Unexpected response: {response.status_code} - {response.text}")
            return False

        except httpx.HTTPStatusError as e:
            logger.error(f"[discord] HTTP error: {e}")
            return False
        except (httpx.ConnectError, httpx.TimeoutException) as e:
            logger.error(f"[discord] Connection error: {e}")
            return False
        except (ValueError, KeyError) as e:
            logger.error(f"[discord] Invalid data: {e}")
            return False

    async def test_connection(self) -> tuple[bool, str]:
        try:
            success = await self.send(
                title="Test Notification",
                message="This is a test notification from VulnForge.",
                priority="low",
                tags=["VulnForge", "test"],
            )

            if success:
                return True, "Test notification sent successfully"
            return False, "Failed to send test notification"

        except Exception as e:
            return False, f"Connection test failed: {str(e)}"
