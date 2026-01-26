"""Notification log database model."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.utils.timezone import get_now

if TYPE_CHECKING:
    from app.models.scan import Scan


class NotificationLog(Base):
    """Model for tracking notification delivery history."""

    __tablename__ = "notification_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # Associated scan (optional - some notifications may not be scan-specific)
    scan_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("scans.id"), nullable=True)

    # Notification details
    notification_type: Mapped[str] = mapped_column(
        String(50)
    )  # e.g., "scan_complete", "critical_vulns", "scan_failed"
    channel: Mapped[str] = mapped_column(String(20))  # e.g., "ntfy", "email", "slack"
    title: Mapped[str | None] = mapped_column(String(200), nullable=True)
    message: Mapped[str] = mapped_column(Text)

    # Delivery tracking
    status: Mapped[str] = mapped_column(String(20))  # "sent", "failed", "pending"
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Notification metadata
    priority: Mapped[int | None] = mapped_column(Integer, nullable=True)
    tags: Mapped[str | None] = mapped_column(String(200), nullable=True)  # Comma-separated

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(default=get_now)
    sent_at: Mapped[datetime | None] = mapped_column(nullable=True)

    # Relationships
    scan: Mapped[Scan] = relationship("Scan", back_populates="notification_logs")
