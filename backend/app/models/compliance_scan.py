"""Compliance scan model for tracking compliance scan runs."""

from datetime import datetime

from sqlalchemy import DateTime, Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base
from app.utils.timezone import get_now


class ComplianceScan(Base):
    """Model for tracking compliance scan executions."""

    __tablename__ = "compliance_scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True, autoincrement=True)

    # Scan metadata
    scan_date: Mapped[datetime] = mapped_column(DateTime, default=get_now, index=True)
    scan_duration_seconds: Mapped[float | None] = mapped_column(Float, nullable=True)
    scan_status: Mapped[str] = mapped_column(
        String(50), default="in_progress"
    )  # in_progress, completed, failed
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Scan trigger
    trigger_type: Mapped[str] = mapped_column(String(20), default="manual")  # manual, scheduled

    # Overall results
    total_checks: Mapped[int] = mapped_column(Integer, default=0)
    passed_checks: Mapped[int] = mapped_column(Integer, default=0)
    warned_checks: Mapped[int] = mapped_column(Integer, default=0)
    failed_checks: Mapped[int] = mapped_column(Integer, default=0)
    info_checks: Mapped[int] = mapped_column(Integer, default=0)
    note_checks: Mapped[int] = mapped_column(Integer, default=0)

    # Compliance score (percentage of passed checks)
    compliance_score: Mapped[float | None] = mapped_column(Float, nullable=True)

    # Category breakdown (stored as JSON-like string for simplicity)
    category_scores: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )  # JSON: {"Host": 85.5, "Daemon": 90.0, ...}

    def __repr__(self) -> str:
        """String representation."""
        return f"<ComplianceScan(id={self.id}, date={self.scan_date}, score={self.compliance_score}, status={self.scan_status})>"
