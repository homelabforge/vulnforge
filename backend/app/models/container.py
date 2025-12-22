"""Container model."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, Float, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base
from app.utils.timezone import get_now

if TYPE_CHECKING:
    from app.models.scan import Scan


class Container(Base):
    """Docker container information and scan history."""

    __tablename__ = "containers"
    __table_args__ = (
        # Composite indexes for common query patterns
        Index("ix_container_running_vulns", "is_running", "total_vulns"),
        Index("ix_container_critical_count", "critical_count"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    container_id: Mapped[str | None] = mapped_column(String, unique=True, nullable=True, index=True)
    name: Mapped[str] = mapped_column(String, unique=True, nullable=False, index=True)
    image: Mapped[str] = mapped_column(String, nullable=False)
    image_tag: Mapped[str] = mapped_column(String, nullable=False)
    image_id: Mapped[str] = mapped_column(String, nullable=False)

    # Status
    is_running: Mapped[bool] = mapped_column(Boolean, default=True)
    is_my_project: Mapped[bool] = mapped_column(Boolean, default=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=get_now)

    # Scan summary (updated after each scan)
    last_scan_date: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_scan_status: Mapped[str | None] = mapped_column(
        String, nullable=True
    )  # completed, failed, in_progress

    # Vulnerability counts (denormalized for quick access)
    total_vulns: Mapped[int] = mapped_column(Integer, default=0)
    fixable_vulns: Mapped[int] = mapped_column(Integer, default=0)
    critical_count: Mapped[int] = mapped_column(Integer, default=0)
    high_count: Mapped[int] = mapped_column(Integer, default=0)
    medium_count: Mapped[int] = mapped_column(Integer, default=0)
    low_count: Mapped[int] = mapped_column(Integer, default=0)

    # Scanner coverage: number of scanners that found vulnerabilities (1 or 2)
    scanner_coverage: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Dive image efficiency metrics
    dive_efficiency_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    dive_inefficient_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dive_image_size_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dive_layer_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dive_analyzed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime, default=get_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=get_now, onupdate=get_now)

    # Relationships
    scans: Mapped[list[Scan]] = relationship(
        "Scan", back_populates="container", cascade="all, delete-orphan"
    )
