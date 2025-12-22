"""Activity log model for tracking system events."""

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, DateTime, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base
from app.utils.timezone import get_now


class ActivityLog(Base):
    """Activity log for tracking system events."""

    __tablename__ = "activity_logs"
    __table_args__ = (
        # Composite indexes for common query patterns
        Index("ix_activity_timestamp", "timestamp"),
        Index("ix_activity_event_type", "event_type"),
        Index("ix_activity_container_id", "container_id"),
        Index("ix_activity_severity", "severity"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # Event classification
    event_type: Mapped[str] = mapped_column(
        String, nullable=False, index=True
    )  # scan_completed, scan_failed, secret_detected, high_severity_found, container_discovered, etc.
    severity: Mapped[str] = mapped_column(
        String, nullable=False, default="info"
    )  # info, warning, critical

    # Container reference (nullable - some events may not be container-specific)
    container_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    container_name: Mapped[str | None] = mapped_column(
        String, nullable=True
    )  # Denormalized for quick display

    # Event details
    title: Mapped[str] = mapped_column(String, nullable=False)  # Brief summary
    description: Mapped[str | None] = mapped_column(Text, nullable=True)  # Detailed description

    # Flexible metadata storage for event-specific data
    # Examples: {"scan_id": 123, "duration": 45.2, "total_vulns": 87, "critical_count": 3}
    event_metadata: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)

    # Timestamps (timezone-aware based on config.timezone)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime, default=get_now, nullable=False, index=True
    )  # When event occurred
    created_at: Mapped[datetime] = mapped_column(DateTime, default=get_now, nullable=False)
