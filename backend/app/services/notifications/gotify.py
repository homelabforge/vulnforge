"""Gotify notification service."""

import logging

import httpx

from app.services.notifications.base import NotificationService

logger = logging.getLogger(__name__)

# Priority mapping from standard names to Gotify values (0-10)
PRIORITY_MAP = {
    "urgent": 10,
    "high": 8,
    "default": 5,
    "low": 3,
    "min": 1,
}


class GotifyNotificationService(NotificationService):
    """Gotify push notification service implementation."""

    service_name = "gotify"

    def __init__(
        self,
        server_url: str,
        app_token: str,
    ) -> None:
        self.server_url = server_url.rstrip("/")
        self.app_token = app_token
        self.client = httpx.AsyncClient(
            timeout=10.0,
            headers={"X-Gotify-Key": app_token},
        )

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
            endpoint = f"{self.server_url}/message"

            # Build message with tags in body if present
            full_message = message
            if tags:
                tag_text = " ".join(f"#{tag}" for tag in tags)
                full_message = f"{message}\n\n{tag_text}"

            payload = {
                "title": title,
                "message": full_message,
                "priority": PRIORITY_MAP.get(priority, 5),
            }

            # Add click URL via extras if provided
            if url:
                payload["extras"] = {"client::notification": {"click": {"url": url}}}

            response = await self.client.post(endpoint, json=payload)
            response.raise_for_status()

            logger.info(f"[gotify] Sent notification: {title}")
            return True

        except httpx.HTTPStatusError as e:
            logger.error(f"[gotify] HTTP error: {e}")
            return False
        except (httpx.ConnectError, httpx.TimeoutException) as e:
            logger.error(f"[gotify] Connection error: {e}")
            return False
        except (ValueError, KeyError) as e:
            logger.error(f"[gotify] Invalid data: {e}")
            return False

    async def test_connection(self) -> tuple[bool, str]:
        try:
            success = await self.send(
                title="Test Notification",
                message="This is a test notification from VulnForge.",
                priority="low",
                tags=["VulnForge"],
            )

            if success:
                return True, "Test notification sent successfully"
            return False, "Failed to send test notification"

        except Exception as e:
            return False, f"Connection test failed: {str(e)}"
