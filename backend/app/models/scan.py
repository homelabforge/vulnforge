"""Scan model."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship, synonym

from app.db import Base
from app.utils.timezone import get_now

if TYPE_CHECKING:
    from app.models.container import Container
    from app.models.notification_log import NotificationLog
    from app.models.secret import Secret
    from app.models.vulnerability import Vulnerability


class Scan(Base):
    """Individual scan of a container."""

    __tablename__ = "scans"
    __table_args__ = (
        # Composite indexes for common query patterns
        Index("ix_scan_container_date", "container_id", "scan_date"),
        Index("ix_scan_container_status", "container_id", "scan_status"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    container_id: Mapped[int] = mapped_column(Integer, ForeignKey("containers.id"), nullable=False)

    # Scan metadata
    scan_date: Mapped[datetime] = mapped_column(DateTime, default=get_now, index=True)
    scan_status: Mapped[str] = mapped_column(
        String, default="in_progress"
    )  # in_progress, completed, failed
    scan_type: Mapped[str | None] = mapped_column(String, default="vulnerability", nullable=True)
    scan_duration_seconds: Mapped[float | None] = mapped_column(Float, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Image scanned
    image_scanned: Mapped[str] = mapped_column(String, nullable=False)

    # Vulnerability summary
    total_vulns: Mapped[int] = mapped_column(Integer, default=0)
    fixable_vulns: Mapped[int] = mapped_column(Integer, default=0)
    critical_count: Mapped[int] = mapped_column(Integer, default=0)
    high_count: Mapped[int] = mapped_column(Integer, default=0)
    medium_count: Mapped[int] = mapped_column(Integer, default=0)
    low_count: Mapped[int] = mapped_column(Integer, default=0)

    # CVE Delta Tracking - stores JSON arrays of CVE IDs compared to previous scan
    # cves_fixed: CVEs that were present in the previous scan but not in this one
    # cves_introduced: CVEs that are new in this scan compared to the previous scan
    cves_fixed: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON array
    cves_introduced: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON array

    # Relationships
    container: Mapped[Container] = relationship("Container", back_populates="scans")
    vulnerabilities: Mapped[list[Vulnerability]] = relationship(
        "Vulnerability", back_populates="scan", cascade="all, delete-orphan"
    )
    secrets: Mapped[list[Secret]] = relationship(
        "Secret", back_populates="scan", cascade="all, delete-orphan"
    )
    notification_logs: Mapped[list[NotificationLog]] = relationship(
        "NotificationLog", back_populates="scan", cascade="all, delete-orphan"
    )

    # Compatibility aliases for legacy tests
    image_name = synonym("image_scanned")
    status = synonym("scan_status")
    created_at = synonym("scan_date")
