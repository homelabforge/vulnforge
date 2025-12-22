"""Image compliance finding model for Dockle image linting checks."""

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base
from app.utils.timezone import get_now


class ImageComplianceFinding(Base):
    """Model for Dockle image compliance findings."""

    __tablename__ = "image_compliance_findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True, autoincrement=True)

    # Check identification
    check_id: Mapped[str] = mapped_column(
        String(50), index=True
    )  # e.g., "CIS-DI-0001", "DKL-DI-0002"
    check_number: Mapped[str | None] = mapped_column(String(50), nullable=True)
    title: Mapped[str] = mapped_column(String(500))
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Image information
    image_name: Mapped[str] = mapped_column(String(500), index=True)  # Image name or ID
    image_id: Mapped[str | None] = mapped_column(
        String(100), nullable=True, index=True
    )  # Docker image ID

    # Status and severity
    status: Mapped[str] = mapped_column(String(20), index=True)  # PASS, FAIL, INFO, SKIP
    severity: Mapped[str] = mapped_column(
        String(20), index=True
    )  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category: Mapped[str] = mapped_column(
        String(100), index=True
    )  # "CIS Benchmarks", "Dockle Best Practices"

    # Remediation
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Alert details (multiple alerts can exist for one check)
    alerts: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON array of alert messages

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
        Index("ix_image_compliance_check_id_image", "check_id", "image_name"),
        Index("ix_image_compliance_image_status", "image_name", "status"),
        Index("ix_image_compliance_severity_status", "severity", "status"),
    )

    def __repr__(self) -> str:
        """String representation."""
        return f"<ImageComplianceFinding(check_id={self.check_id}, image={self.image_name}, status={self.status})>"
