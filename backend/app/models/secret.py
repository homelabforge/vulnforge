"""Secret model for storing detected secrets from Trivy scans."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship, synonym

from app.database import Base
from app.utils.timezone import get_now

if TYPE_CHECKING:
    from app.models.scan import Scan


class Secret(Base):
    """Model for secrets detected during container scans."""

    __tablename__ = "secrets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(Integer, ForeignKey("scans.id", ondelete="CASCADE"))
    scan_result_id = synonym("scan_id")

    # Secret identification
    rule_id: Mapped[str] = mapped_column(String(100))  # Trivy rule ID
    category: Mapped[str] = mapped_column(String(50))  # AWS, GitHub, Generic, etc.
    title: Mapped[str] = mapped_column(String(200))  # Human-readable title
    severity: Mapped[str] = mapped_column(String(20))  # CRITICAL, HIGH, MEDIUM, LOW

    # Location information
    file_path: Mapped[str | None] = mapped_column(String(500), nullable=True)
    start_line: Mapped[int | None] = mapped_column(Integer, nullable=True)
    end_line: Mapped[int | None] = mapped_column(Integer, nullable=True)
    layer_digest: Mapped[str | None] = mapped_column(String(100), nullable=True)

    # Secret details (always redacted)
    match: Mapped[str] = mapped_column(Text)  # Redacted match from Trivy
    code_snippet: Mapped[str | None] = mapped_column(Text, nullable=True)  # Code context (redacted)

    # False positive management
    status: Mapped[str] = mapped_column(
        String(20), default="to_review"
    )  # to_review, false_positive, confirmed, accepted_risk
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)  # User notes

    # Metadata
    created_at: Mapped[datetime] = mapped_column(DateTime, default=get_now)
    updated_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, onupdate=get_now)

    # Relationships
    scan: Mapped[Scan] = relationship("Scan", back_populates="secrets")
