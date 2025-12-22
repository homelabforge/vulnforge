"""Notification rule database model."""

from datetime import datetime

from sqlalchemy import Boolean, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base
from app.utils.timezone import get_now


class NotificationRule(Base):
    """Model for customizable notification rules."""

    __tablename__ = "notification_rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # Rule identification
    name: Mapped[str] = mapped_column(String(100), unique=True)  # e.g., "critical_new_vulns"
    description: Mapped[str | None] = mapped_column(String(200), nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)

    # Trigger conditions
    event_type: Mapped[str] = mapped_column(
        String(50)
    )  # e.g., "scan_complete", "new_vulnerabilities"

    # Condition thresholds
    min_critical: Mapped[int | None] = mapped_column(Integer, nullable=True)
    min_high: Mapped[int | None] = mapped_column(Integer, nullable=True)
    min_medium: Mapped[int | None] = mapped_column(Integer, nullable=True)
    min_total: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Notification settings
    title_template: Mapped[str | None] = mapped_column(String(200), nullable=True)
    message_template: Mapped[str] = mapped_column(Text)
    priority: Mapped[int] = mapped_column(Integer, default=3)  # 1-5
    tags: Mapped[str | None] = mapped_column(String(200), nullable=True)  # Comma-separated

    # Channel settings
    send_to_ntfy: Mapped[bool] = mapped_column(Boolean, default=True)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(default=get_now)
    updated_at: Mapped[datetime] = mapped_column(default=get_now, onupdate=get_now)
