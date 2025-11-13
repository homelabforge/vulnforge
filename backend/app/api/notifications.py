"""Notification API endpoints."""

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
        query = query.where(NotificationRuleModel.enabled == True)

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
        raise HTTPException(
            status_code=400, detail=f"Rule with name '{rule.name}' already exists"
        )

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


@router.post("/test")
async def send_test_notification():
    """Send a test notification to verify ntfy configuration."""
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
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to send test notification: {str(e)}")
