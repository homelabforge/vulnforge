"""ScanJob model for tracking scan correlation."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.utils.timezone import get_now

if TYPE_CHECKING:
    from app.models.container import Container
    from app.models.scan import Scan


class ScanJob(Base):
    """Tracks scan jobs for API correlation.

    Created at enqueue time with a stable job_id. The queue worker
    links the ScanJob to its Scan row once processing starts.
    External consumers poll by job_id to retrieve the scan_id.
    """

    __tablename__ = "scan_jobs"
    __table_args__ = (
        Index("ix_scan_jobs_status", "status"),
        Index("ix_scan_jobs_container_id", "container_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    container_id: Mapped[int] = mapped_column(Integer, ForeignKey("containers.id"), nullable=False)
    container_name: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(
        String(50), default="queued", nullable=False
    )  # queued, processing, completed, failed
    scan_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("scans.id"), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=get_now, nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    # Relationships
    container: Mapped[Container] = relationship("Container")
    scan: Mapped[Scan | None] = relationship("Scan")
