"""Notification API endpoints."""

import httpx
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_db
from app.dependencies.auth import require_admin
from app.models import NotificationLog as NotificationLogModel
from app.models import NotificationRule as NotificationRuleModel
from app.models.user import User
from app.schemas.notification import (
    NotificationLog,
    NotificationRule,
    NotificationRuleCreate,
    NotificationRuleUpdate,
)

router = APIRouter()


# Notification History Endpoints


@router.get("/history", response_model=list[NotificationLog])
async def get_notification_history(
    skip: int = 0,
    limit: int = 100,
    notification_type: str | None = None,
    status: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    """
    Get notification history with optional filtering.

    Args:
        skip: Number of records to skip
        limit: Maximum number of records to return
        notification_type: Filter by notification type
        status: Filter by status (sent, failed, pending)
    """
    query = select(NotificationLogModel).order_by(desc(NotificationLogModel.created_at))

    if notification_type:
        query = query.where(NotificationLogModel.notification_type == notification_type)

    if status:
        query = query.where(NotificationLogModel.status == status)

    query = query.offset(skip).limit(limit)

    result = await db.execute(query)
    logs = result.scalars().all()

    return [NotificationLog.model_validate(log) for log in logs]


@router.get("/history/{notification_id}", response_model=NotificationLog)
async def get_notification_by_id(
    notification_id: int,
    db: AsyncSession = Depends(get_db),
):
    """Get a specific notification by ID."""
    result = await db.execute(
        select(NotificationLogModel).where(NotificationLogModel.id == notification_id)
    )
    log = result.scalar_one_or_none()

    if not log:
        raise HTTPException(status_code=404, detail="Notification not found")

    return NotificationLog.model_validate(log)


@router.get("/history/scan/{scan_id}", response_model=list[NotificationLog])
async def get_notifications_for_scan(
    scan_id: int,
    db: AsyncSession = Depends(get_db),
):
    """Get all notifications for a specific scan."""
    result = await db.execute(
        select(NotificationLogModel)
        .where(NotificationLogModel.scan_id == scan_id)
        .order_by(desc(NotificationLogModel.created_at))
    )
    logs = result.scalars().all()

    return [NotificationLog.model_validate(log) for log in logs]


@router.get("/stats")
async def get_notification_stats(db: AsyncSession = Depends(get_db)):
    """Get notification statistics."""
    # Total notifications
    total_result = await db.execute(select(NotificationLogModel))
    total = len(total_result.scalars().all())

    # Sent notifications
    sent_result = await db.execute(
        select(NotificationLogModel).where(NotificationLogModel.status == "sent")
    )
    sent = len(sent_result.scalars().all())

    # Failed notifications
    failed_result = await db.execute(
        select(NotificationLogModel).where(NotificationLogModel.status == "failed")
    )
    failed = len(failed_result.scalars().all())

    # By type
    type_result = await db.execute(select(NotificationLogModel))
    all_logs = type_result.scalars().all()
    by_type = {}
    for log in all_logs:
        by_type[log.notification_type] = by_type.get(log.notification_type, 0) + 1

    return {
        "total_notifications": total,
        "sent": sent,
        "failed": failed,
        "success_rate": (sent / total * 100) if total > 0 else 0,
        "by_type": by_type,
    }


# Notification Rules Endpoints


@router.get("/rules", response_model=list[NotificationRule])
async def get_notification_rules(
    enabled_only: bool = False,
    db: AsyncSession = Depends(get_db),
):
    """Get all notification rules."""
    query = select(NotificationRuleModel)

    if enabled_only:
        query = query.where(NotificationRuleModel.enabled)

    result = await db.execute(query)
    rules = result.scalars().all()

    return [NotificationRule.model_validate(rule) for rule in rules]


@router.get("/rules/{rule_id}", response_model=NotificationRule)
async def get_notification_rule(
    rule_id: int,
    db: AsyncSession = Depends(get_db),
):
    """Get a specific notification rule by ID."""
    result = await db.execute(
        select(NotificationRuleModel).where(NotificationRuleModel.id == rule_id)
    )
    rule = result.scalar_one_or_none()

    if not rule:
        raise HTTPException(status_code=404, detail="Notification rule not found")

    return NotificationRule.model_validate(rule)


@router.post("/rules", response_model=NotificationRule, status_code=201)
async def create_notification_rule(
    rule: NotificationRuleCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_admin),
):
    """Create a new notification rule. Admin only."""
    # Check if rule with same name exists
    existing = await db.execute(
        select(NotificationRuleModel).where(NotificationRuleModel.name == rule.name)
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=400, detail=f"Rule with name '{rule.name}' already exists")

    new_rule = NotificationRuleModel(**rule.model_dump())
    db.add(new_rule)
    await db.commit()
    await db.refresh(new_rule)

    return NotificationRule.model_validate(new_rule)


@router.patch("/rules/{rule_id}", response_model=NotificationRule)
async def update_notification_rule(
    rule_id: int,
    rule_update: NotificationRuleUpdate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_admin),
):
    """Update an existing notification rule. Admin only."""
    result = await db.execute(
        select(NotificationRuleModel).where(NotificationRuleModel.id == rule_id)
    )
    rule = result.scalar_one_or_none()

    if not rule:
        raise HTTPException(status_code=404, detail="Notification rule not found")

    # Update fields
    update_data = rule_update.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(rule, key, value)

    await db.commit()
    await db.refresh(rule)

    return NotificationRule.model_validate(rule)


@router.delete("/rules/{rule_id}", status_code=204)
async def delete_notification_rule(
    rule_id: int,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_admin),
):
    """Delete a notification rule. Admin only."""
    result = await db.execute(
        select(NotificationRuleModel).where(NotificationRuleModel.id == rule_id)
    )
    rule = result.scalar_one_or_none()

    if not rule:
        raise HTTPException(status_code=404, detail="Notification rule not found")

    await db.delete(rule)
    await db.commit()


@router.post("/rules/{rule_id}/toggle", response_model=NotificationRule)
async def toggle_notification_rule(
    rule_id: int,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_admin),
):
    """Toggle a notification rule's enabled status. Admin only."""
    result = await db.execute(
        select(NotificationRuleModel).where(NotificationRuleModel.id == rule_id)
    )
    rule = result.scalar_one_or_none()

    if not rule:
        raise HTTPException(status_code=404, detail="Notification rule not found")

    rule.enabled = not rule.enabled
    await db.commit()
    await db.refresh(rule)

    return NotificationRule.model_validate(rule)


# ============================================
# Service Test Endpoints
# ============================================


@router.post("/test")
async def send_test_notification():
    """Send a test notification to verify ntfy configuration (legacy endpoint)."""
    from app.services.notifier import NotificationService

    notifier = NotificationService()

    try:
        await notifier.send_notification(
            message="This is a test notification from VulnForge Settings. If you received this, your notification configuration is working correctly!",
            title="VulnForge Test Notification",
            priority=3,
            tags="test,VulnForge",
        )
        return {"status": "success", "message": "Test notification sent successfully"}
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="Notification server timed out")
    except httpx.ConnectError:
        raise HTTPException(
            status_code=503, detail="Cannot connect to notification server - check ntfy URL"
        )
    except httpx.HTTPStatusError as e:
        raise HTTPException(
            status_code=e.response.status_code, detail=f"Notification server error: {e}"
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid notification configuration: {e}")


@router.post("/test/ntfy")
async def test_ntfy_connection(db: AsyncSession = Depends(get_db)):
    """Test ntfy server connection."""
    from app.services.settings_manager import SettingsManager

    settings = SettingsManager(db)
    try:
        ntfy_enabled = await settings.get_bool("ntfy_enabled")
        ntfy_server = await settings.get("ntfy_url")
        ntfy_topic = await settings.get("ntfy_topic")
        ntfy_token = await settings.get("ntfy_token")

        if not ntfy_enabled:
            return {"success": False, "message": "ntfy notifications are disabled"}

        if not ntfy_server or not ntfy_topic:
            return {"success": False, "message": "ntfy server or topic not configured"}

        # Send test notification
        server_url = ntfy_server.rstrip("/")
        headers = {}
        if ntfy_token:
            headers["Authorization"] = f"Bearer {ntfy_token}"
        headers["Title"] = "Test Notification"
        headers["Priority"] = "2"
        headers["Tags"] = "white_check_mark,VulnForge"

        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                f"{server_url}/{ntfy_topic}",
                content="This is a test notification from VulnForge.",
                headers=headers,
            )
            response.raise_for_status()
            return {"success": True, "message": "Test notification sent"}
    except Exception:
        return {"success": False, "message": "Connection test failed. Check logs for details."}


@router.post("/test/gotify")
async def test_gotify_connection(db: AsyncSession = Depends(get_db)):
    """Test Gotify server connection."""
    from app.services.settings_manager import SettingsManager

    settings = SettingsManager(db)
    try:
        gotify_enabled = await settings.get_bool("gotify_enabled")
        gotify_server = await settings.get("gotify_server")
        gotify_token = await settings.get("gotify_token")

        if not gotify_enabled:
            return {"success": False, "message": "Gotify notifications are disabled"}

        if not gotify_server or not gotify_token:
            return {"success": False, "message": "Gotify server or token not configured"}

        server_url = gotify_server.rstrip("/")
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                f"{server_url}/message",
                headers={"X-Gotify-Key": gotify_token},
                json={
                    "title": "Test Notification",
                    "message": "This is a test notification from VulnForge.",
                    "priority": 5,
                },
            )
            response.raise_for_status()
            return {"success": True, "message": "Test notification sent"}
    except Exception:
        return {"success": False, "message": "Connection test failed. Check logs for details."}


@router.post("/test/pushover")
async def test_pushover_connection(db: AsyncSession = Depends(get_db)):
    """Test Pushover connection."""
    from app.services.settings_manager import SettingsManager

    settings = SettingsManager(db)
    try:
        pushover_enabled = await settings.get_bool("pushover_enabled")
        pushover_user_key = await settings.get("pushover_user_key")
        pushover_api_token = await settings.get("pushover_api_token")

        if not pushover_enabled:
            return {"success": False, "message": "Pushover notifications are disabled"}

        if not pushover_user_key or not pushover_api_token:
            return {"success": False, "message": "Pushover user key or API token not configured"}

        # Validate credentials first
        async with httpx.AsyncClient(timeout=10.0) as client:
            validate_response = await client.post(
                "https://api.pushover.net/1/users/validate.json",
                data={"token": pushover_api_token, "user": pushover_user_key},
            )

            if validate_response.status_code == 200:
                result = validate_response.json()
                if result.get("status") == 1:
                    # Send test message
                    response = await client.post(
                        "https://api.pushover.net/1/messages.json",
                        data={
                            "token": pushover_api_token,
                            "user": pushover_user_key,
                            "title": "Test Notification",
                            "message": "This is a test notification from VulnForge.",
                            "priority": -1,
                        },
                    )
                    response.raise_for_status()
                    return {"success": True, "message": "Test notification sent"}
                else:
                    return {
                        "success": False,
                        "message": f"Invalid credentials: {result.get('errors', ['Unknown'])}",
                    }

            return {
                "success": False,
                "message": f"Validation failed with status {validate_response.status_code}",
            }
    except Exception:
        return {"success": False, "message": "Connection test failed. Check logs for details."}


@router.post("/test/slack")
async def test_slack_connection(db: AsyncSession = Depends(get_db)):
    """Test Slack webhook connection."""
    from app.services.settings_manager import SettingsManager

    settings = SettingsManager(db)
    try:
        slack_enabled = await settings.get_bool("slack_enabled")
        slack_webhook_url = await settings.get("slack_webhook_url")

        if not slack_enabled:
            return {"success": False, "message": "Slack notifications are disabled"}

        if not slack_webhook_url:
            return {"success": False, "message": "Slack webhook URL not configured"}

        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                slack_webhook_url,
                json={
                    "attachments": [
                        {
                            "color": "#10b981",
                            "title": "Test Notification",
                            "text": "This is a test notification from VulnForge.",
                            "footer": "VulnForge",
                        }
                    ]
                },
            )

            if response.status_code == 200 and response.text == "ok":
                return {"success": True, "message": "Test notification sent"}
            else:
                return {"success": False, "message": f"Unexpected response: {response.text}"}
    except Exception:
        return {"success": False, "message": "Connection test failed. Check logs for details."}


@router.post("/test/discord")
async def test_discord_connection(db: AsyncSession = Depends(get_db)):
    """Test Discord webhook connection."""
    from app.services.settings_manager import SettingsManager

    settings = SettingsManager(db)
    try:
        discord_enabled = await settings.get_bool("discord_enabled")
        discord_webhook_url = await settings.get("discord_webhook_url")

        if not discord_enabled:
            return {"success": False, "message": "Discord notifications are disabled"}

        if not discord_webhook_url:
            return {"success": False, "message": "Discord webhook URL not configured"}

        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                discord_webhook_url,
                json={
                    "embeds": [
                        {
                            "title": "Test Notification",
                            "description": "This is a test notification from VulnForge.",
                            "color": 0x10B981,
                            "footer": {"text": "VulnForge"},
                        }
                    ]
                },
            )

            if response.status_code in (200, 204):
                return {"success": True, "message": "Test notification sent"}
            else:
                return {"success": False, "message": f"Unexpected response: {response.status_code}"}
    except Exception:
        return {"success": False, "message": "Connection test failed. Check logs for details."}


@router.post("/test/telegram")
async def test_telegram_connection(db: AsyncSession = Depends(get_db)):
    """Test Telegram bot connection."""
    from app.services.settings_manager import SettingsManager

    settings = SettingsManager(db)
    try:
        telegram_enabled = await settings.get_bool("telegram_enabled")
        telegram_bot_token = await settings.get("telegram_bot_token")
        telegram_chat_id = await settings.get("telegram_chat_id")

        if not telegram_enabled:
            return {"success": False, "message": "Telegram notifications are disabled"}

        if not telegram_bot_token or not telegram_chat_id:
            return {"success": False, "message": "Telegram bot token or chat ID not configured"}

        async with httpx.AsyncClient(timeout=10.0) as client:
            # Verify bot token first
            me_response = await client.get(
                f"https://api.telegram.org/bot{telegram_bot_token}/getMe"
            )

            if me_response.status_code != 200:
                return {"success": False, "message": "Invalid bot token"}

            me_result = me_response.json()
            if not me_result.get("ok"):
                return {
                    "success": False,
                    "message": f"Bot validation failed: {me_result.get('description', 'Unknown')}",
                }

            bot_name = me_result.get("result", {}).get("username", "Unknown")

            # Send test message
            response = await client.post(
                f"https://api.telegram.org/bot{telegram_bot_token}/sendMessage",
                json={
                    "chat_id": telegram_chat_id,
                    "text": f"\u2705 <b>Test Notification</b>\n\nThis is a test notification from VulnForge.\nBot: @{bot_name}",
                    "parse_mode": "HTML",
                },
            )

            result = response.json()
            if result.get("ok"):
                return {"success": True, "message": f"Test notification sent via @{bot_name}"}
            else:
                return {
                    "success": False,
                    "message": f"Failed: {result.get('description', 'Unknown error')}",
                }
    except Exception:
        return {"success": False, "message": "Connection test failed. Check logs for details."}


@router.post("/test/email")
async def test_email_connection(db: AsyncSession = Depends(get_db)):
    """Test SMTP email connection."""
    from app.services.settings_manager import SettingsManager

    settings = SettingsManager(db)
    try:
        email_enabled = await settings.get_bool("email_enabled")

        if not email_enabled:
            return {"success": False, "message": "Email notifications are disabled"}

        smtp_host = await settings.get("email_smtp_host")
        smtp_port = await settings.get_int("email_smtp_port", default=587)
        smtp_user = await settings.get("email_smtp_user")
        smtp_password = await settings.get("email_smtp_password")
        from_address = await settings.get("email_from")
        to_address = await settings.get("email_to")
        use_tls = await settings.get_bool("email_smtp_tls", default=True)

        if not all([smtp_host, smtp_user, smtp_password, from_address, to_address]):
            return {"success": False, "message": "Email configuration incomplete"}

        from app.services.notifications.email import EmailNotificationService

        email_service = EmailNotificationService(
            smtp_host=smtp_host,
            smtp_port=smtp_port,
            smtp_user=smtp_user,
            smtp_password=smtp_password,
            from_address=from_address,
            to_address=to_address,
            use_tls=use_tls,
        )

        success, message = await email_service.test_connection()
        return {"success": success, "message": message}
    except Exception:
        return {"success": False, "message": "Connection test failed. Check logs for details."}
