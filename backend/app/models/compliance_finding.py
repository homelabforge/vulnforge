"""Compliance finding model for security compliance checks."""

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base
from app.utils.timezone import get_now


class ComplianceFinding(Base):
    """Model for security compliance findings."""

    __tablename__ = "compliance_findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True, autoincrement=True)

    # Check identification
    check_id: Mapped[str] = mapped_column(String(20), index=True)  # e.g., "VF-D-001", "VF-C-003"
    check_number: Mapped[str | None] = mapped_column(
        String(20), nullable=True
    )  # Alternative ID format (legacy)
    title: Mapped[str] = mapped_column(String(500))
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Target (container/image name for per-target checks)
    target: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)

    # Status and severity
    status: Mapped[str] = mapped_column(String(20), index=True)  # PASS, WARN, FAIL, INFO, NOTE
    severity: Mapped[str] = mapped_column(String(20), index=True)  # HIGH, MEDIUM, LOW, INFO
    category: Mapped[str] = mapped_column(
        String(100), index=True
    )  # Host, Daemon, Files, Images, Runtime, Operations

    # Remediation
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Additional details
    actual_value: Mapped[str | None] = mapped_column(Text, nullable=True)  # Current configuration
    expected_value: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )  # Recommended configuration

    # False positive / ignore support
    is_ignored: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    ignored_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    ignored_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ignored_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    # Tracking
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=get_now)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=get_now, onupdate=get_now)
    scan_date: Mapped[datetime] = mapped_column(DateTime, default=get_now, index=True)

    # Indexes for performance
    __table_args__ = (
        Index("ix_compliance_check_id_status", "check_id", "status"),
        Index("ix_compliance_category_status", "category", "status"),
        Index("ix_compliance_severity_status", "severity", "status"),
    )

    def __repr__(self) -> str:
        """String representation."""
        return f"<ComplianceFinding(check_id={self.check_id}, status={self.status}, severity={self.severity})>"
