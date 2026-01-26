"""False positive pattern model for persistent secret exclusions."""

from datetime import datetime

from sqlalchemy import DateTime, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base
from app.utils.timezone import get_now


class FalsePositivePattern(Base):
    """
    Persistent false positive patterns for automatic secret exclusion.

    When a secret is marked as false positive, a pattern is created based on
    its fingerprint (container + file path + rule ID). Future scans that find
    the same pattern will automatically mark those secrets as false positives.
    """

    __tablename__ = "false_positive_patterns"
    __table_args__ = (
        UniqueConstraint("container_name", "file_path", "rule_id", name="uix_fp_pattern"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # Pattern matching criteria
    container_name: Mapped[str] = mapped_column(String(255))  # Container name pattern
    file_path: Mapped[str] = mapped_column(String(500))  # Exact file path
    rule_id: Mapped[str] = mapped_column(String(100))  # Trivy rule ID

    # Metadata
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)  # Why it's a FP
    created_by: Mapped[str] = mapped_column(String(50), default="user")  # user or auto
    created_at: Mapped[datetime] = mapped_column(DateTime, default=get_now)

    # Statistics
    match_count: Mapped[int] = mapped_column(Integer, default=0)  # Times pattern matched
    last_matched: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
