"""Image compliance scan model for tracking Dockle scan runs."""

from datetime import datetime

from sqlalchemy import DateTime, Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base
from app.utils.timezone import get_now


class ImageComplianceScan(Base):
    """Model for tracking Dockle image compliance scan executions."""

    __tablename__ = "image_compliance_scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True, autoincrement=True)

    # Scan metadata
    scan_date: Mapped[datetime] = mapped_column(DateTime, default=get_now, index=True)
    scan_duration_seconds: Mapped[float | None] = mapped_column(Float, nullable=True)
    scan_status: Mapped[str] = mapped_column(
        String(50), default="in_progress"
    )  # in_progress, completed, failed
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Image information
    image_name: Mapped[str] = mapped_column(String(500), index=True)
    image_id: Mapped[str | None] = mapped_column(String(100), nullable=True, index=True)

    # Scan trigger
    trigger_type: Mapped[str] = mapped_column(
        String(20), default="manual"
    )  # manual, scheduled, post-vulnerability-scan

    # Overall results
    total_checks: Mapped[int] = mapped_column(Integer, default=0)
    passed_checks: Mapped[int] = mapped_column(Integer, default=0)
    failed_checks: Mapped[int] = mapped_column(Integer, default=0)
    info_checks: Mapped[int] = mapped_column(Integer, default=0)
    skip_checks: Mapped[int] = mapped_column(Integer, default=0)

    # Compliance score (0-100, calculated from pass/fail ratio)
    compliance_score: Mapped[float | None] = mapped_column(Float, nullable=True)

    # Category breakdown (stored as JSON string for simplicity)
    category_scores: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )  # JSON: {"CIS Benchmarks": 85.5, ...}

    # Severity breakdown
    fatal_count: Mapped[int] = mapped_column(Integer, default=0)
    warn_count: Mapped[int] = mapped_column(Integer, default=0)

    # Affected containers (JSON array of container names using this image)
    affected_containers: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )  # JSON: ["container1", "container2"]

    def __repr__(self) -> str:
        """String representation."""
        return f"<ImageComplianceScan(id={self.id}, image={self.image_name}, score={self.compliance_score}, status={self.scan_status})>"
