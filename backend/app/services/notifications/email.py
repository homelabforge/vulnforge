"""Email notification service."""

import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional

import aiosmtplib

from app.services.notifications.base import NotificationService

logger = logging.getLogger(__name__)


class EmailNotificationService(NotificationService):
    """SMTP email notification service implementation."""

    service_name = "email"

    def __init__(
        self,
        smtp_host: str,
        smtp_port: int,
        smtp_user: str,
        smtp_password: str,
        from_address: str,
        to_address: str,
        use_tls: bool = True,
    ) -> None:
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.smtp_user = smtp_user
        self.smtp_password = smtp_password
        self.from_address = from_address
        self.to_address = to_address
        self.use_tls = use_tls

    async def close(self) -> None:
        """No persistent connection to close."""
        pass

    async def send(
        self,
        title: str,
        message: str,
        priority: str = "default",
        tags: Optional[list[str]] = None,
        url: Optional[str] = None,
    ) -> bool:
        try:
            # Create message
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"[VulnForge] {title}"
            msg["From"] = self.from_address
            msg["To"] = self.to_address

            # Set priority header
            if priority in ("urgent", "high"):
                msg["X-Priority"] = "1"
                msg["Importance"] = "high"
            elif priority == "low":
                msg["X-Priority"] = "5"
                msg["Importance"] = "low"

            # Build plain text version
            plain_text = f"{title}\n\n{message}"
            if tags:
                plain_text += f"\n\nTags: {', '.join(tags)}"
            if url:
                plain_text += f"\n\nView Details: {url}"

            # Build HTML version
            priority_color = {
                "urgent": "#dc2626",
                "high": "#f97316",
                "default": "#3b82f6",
                "low": "#10b981",
                "min": "#6b7280",
            }.get(priority, "#3b82f6")

            tag_html = ""
            if tags:
                tag_badges = " ".join(
                    f'<span style="background-color:#e5e7eb;padding:2px 8px;'
                    f'border-radius:4px;font-size:12px;margin-right:4px;">{tag}</span>'
                    for tag in tags
                )
                tag_html = f'<p style="margin-top:16px;">{tag_badges}</p>'

            url_html = ""
            if url:
                url_html = (
                    f'<p style="margin-top:16px;">'
                    f'<a href="{url}" style="color:{priority_color};">View Details</a>'
                    f'</p>'
                )

            html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
</head>
<body style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;padding:20px;">
    <div style="border-left:4px solid {priority_color};padding-left:16px;">
        <h2 style="color:{priority_color};margin:0 0 16px 0;">{title}</h2>
        <p style="color:#374151;line-height:1.6;white-space:pre-wrap;">{message}</p>
        {tag_html}
        {url_html}
    </div>
    <hr style="border:none;border-top:1px solid #e5e7eb;margin:24px 0;">
    <p style="color:#9ca3af;font-size:12px;">
        Sent by VulnForge Notification System
    </p>
</body>
</html>
"""

            # Attach both versions
            msg.attach(MIMEText(plain_text, "plain"))
            msg.attach(MIMEText(html_content, "html"))

            # Send email
            if self.use_tls:
                await aiosmtplib.send(
                    msg,
                    hostname=self.smtp_host,
                    port=self.smtp_port,
                    username=self.smtp_user,
                    password=self.smtp_password,
                    start_tls=True,
                )
            else:
                await aiosmtplib.send(
                    msg,
                    hostname=self.smtp_host,
                    port=self.smtp_port,
                    username=self.smtp_user,
                    password=self.smtp_password,
                )

            logger.info(f"[email] Sent notification: {title}")
            return True

        except aiosmtplib.SMTPException as e:
            logger.error(f"[email] SMTP error: {e}")
            return False
        except (ConnectionError, TimeoutError, OSError) as e:
            logger.error(f"[email] Connection error: {e}")
            return False
        except Exception as e:
            logger.error(f"[email] Unexpected error: {e}")
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
                return True, f"Test email sent to {self.to_address}"
            return False, "Failed to send test email"

        except Exception as e:
            return False, f"Connection test failed: {str(e)}"
