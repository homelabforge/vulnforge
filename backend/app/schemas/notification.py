"""Notification schemas."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class NotificationLogBase(BaseModel):
    """Base notification log schema."""

    notification_type: str
    channel: str
    title: str | None = None
    message: str
    status: str
    error_message: str | None = None
    priority: int | None = None
    tags: str | None = None


class NotificationLogCreate(NotificationLogBase):
    """Schema for creating notification log."""

    scan_id: int | None = None


class NotificationLog(NotificationLogBase):
    """Notification log schema with all fields."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    scan_id: int | None
    created_at: datetime
    sent_at: datetime | None


class NotificationRuleBase(BaseModel):
    """Base notification rule schema."""

    name: str
    description: str | None = None
    enabled: bool = True
    event_type: str
    min_critical: int | None = None
    min_high: int | None = None
    min_medium: int | None = None
    min_total: int | None = None
    title_template: str | None = None
    message_template: str
    priority: int = 3
    tags: str | None = None
    send_to_ntfy: bool = True


class NotificationRuleCreate(NotificationRuleBase):
    """Schema for creating notification rule."""

    pass


class NotificationRuleUpdate(BaseModel):
    """Schema for updating notification rule."""

    description: str | None = None
    enabled: bool | None = None
    event_type: str | None = None
    min_critical: int | None = None
    min_high: int | None = None
    min_medium: int | None = None
    min_total: int | None = None
    title_template: str | None = None
    message_template: str | None = None
    priority: int | None = None
    tags: str | None = None
    send_to_ntfy: bool | None = None


class NotificationRule(NotificationRuleBase):
    """Notification rule schema with all fields."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    created_at: datetime
    updated_at: datetime
