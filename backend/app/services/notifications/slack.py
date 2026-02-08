"""Slack notification service."""

import logging
from typing import Any

import httpx

from app.services.notifications.base import NotificationService

logger = logging.getLogger(__name__)

# Color mapping for Slack attachments
COLOR_MAP = {
    "urgent": "#dc2626",  # Red
    "high": "#f97316",  # Orange
    "default": "#3b82f6",  # Blue
    "low": "#10b981",  # Green
    "min": "#6b7280",  # Gray
}


class SlackNotificationService(NotificationService):
    """Slack webhook notification service implementation."""

    service_name = "slack"

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
        tags: list[str] | None = None,
        url: str | None = None,
    ) -> bool:
        try:
            # Build Slack message with attachment for color
            color = COLOR_MAP.get(priority, COLOR_MAP["default"])

            # Build tag text
            tag_text = ""
            if tags:
                tag_text = " ".join(f"`{tag}`" for tag in tags)

            # Build attachment
            attachment: dict[str, Any] = {
                "color": color,
                "title": title,
                "text": message,
                "footer": "VulnForge",
            }

            if tag_text:
                attachment["fields"] = [{"title": "Tags", "value": tag_text, "short": True}]

            if url:
                attachment["title_link"] = url

            payload = {
                "attachments": [attachment],
            }

            response = await self.client.post(
                self.webhook_url,
                json=payload,
            )

            # Slack returns "ok" as text on success
            if response.status_code == 200 and response.text == "ok":
                logger.info(f"[slack] Sent notification: {title}")
                return True

            logger.error(f"[slack] Unexpected response: {response.status_code} - {response.text}")
            return False

        except httpx.HTTPStatusError as e:
            logger.error(f"[slack] HTTP error: {e}")
            return False
        except (httpx.ConnectError, httpx.TimeoutException) as e:
            logger.error(f"[slack] Connection error: {e}")
            return False
        except (ValueError, KeyError) as e:
            logger.error(f"[slack] Invalid data: {e}")
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
