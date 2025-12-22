"""Pushover notification service."""

import logging

import httpx

from app.services.notifications.base import NotificationService

logger = logging.getLogger(__name__)

# Priority mapping from standard names to Pushover values (-2 to 2)
# Note: 2 (emergency) requires retry/expire params
PRIORITY_MAP = {
    "urgent": 1,  # High priority (bypass quiet hours)
    "high": 1,
    "default": 0,  # Normal priority
    "low": -1,  # Low priority (no sound/vibration)
    "min": -2,  # Lowest priority (no notification)
}

PUSHOVER_API_URL = "https://api.pushover.net/1/messages.json"


class PushoverNotificationService(NotificationService):
    """Pushover push notification service implementation."""

    service_name = "pushover"

    def __init__(
        self,
        user_key: str,
        api_token: str,
    ) -> None:
        self.user_key = user_key
        self.api_token = api_token
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
            # Build message with tags if present
            full_message = message
            if tags:
                tag_text = " ".join(f"#{tag}" for tag in tags)
                full_message = f"{message}\n\n{tag_text}"

            payload = {
                "token": self.api_token,
                "user": self.user_key,
                "title": title,
                "message": full_message,
                "priority": PRIORITY_MAP.get(priority, 0),
            }

            if url:
                payload["url"] = url
                payload["url_title"] = "View Details"

            response = await self.client.post(PUSHOVER_API_URL, data=payload)
            response.raise_for_status()

            result = response.json()
            if result.get("status") == 1:
                logger.info(f"[pushover] Sent notification: {title}")
                return True
            else:
                logger.error(f"[pushover] API error: {result.get('errors', 'Unknown error')}")
                return False

        except httpx.HTTPStatusError as e:
            logger.error(f"[pushover] HTTP error: {e}")
            return False
        except (httpx.ConnectError, httpx.TimeoutException) as e:
            logger.error(f"[pushover] Connection error: {e}")
            return False
        except (ValueError, KeyError) as e:
            logger.error(f"[pushover] Invalid data: {e}")
            return False

    async def test_connection(self) -> tuple[bool, str]:
        try:
            # Use Pushover's validate endpoint first
            validate_url = "https://api.pushover.net/1/users/validate.json"
            response = await self.client.post(
                validate_url,
                data={"token": self.api_token, "user": self.user_key},
            )

            if response.status_code == 200:
                result = response.json()
                if result.get("status") == 1:
                    # Credentials valid, send test notification
                    success = await self.send(
                        title="Test Notification",
                        message="This is a test notification from VulnForge.",
                        priority="low",
                        tags=["VulnForge"],
                    )
                    if success:
                        return True, "Test notification sent successfully"
                    return False, "Credentials valid but failed to send test notification"
                else:
                    return False, f"Invalid credentials: {result.get('errors', ['Unknown'])}"

            return False, f"Validation failed with status {response.status_code}"

        except Exception as e:
            return False, f"Connection test failed: {str(e)}"
