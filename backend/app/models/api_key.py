"""API Key model for secure API authentication."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class APIKey(Base):
    """API Key for external service authentication."""

    __tablename__ = "api_keys"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(String(512))
    key_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)  # SHA256 hash
    key_prefix: Mapped[str] = mapped_column(String(8), nullable=False)  # First 8 chars (vf_abc12)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_by: Mapped[str | None] = mapped_column(String(255), default="admin")

    __table_args__ = (Index("idx_api_keys_key_hash", "key_hash"),)

    def is_active(self) -> bool:
        """Check if API key is active (not revoked)."""
        return self.revoked_at is None

    def to_dict(self) -> dict:
        """Convert to dictionary for API responses."""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "key_prefix": self.key_prefix,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_used_at": self.last_used_at.isoformat() if self.last_used_at else None,
            "revoked_at": self.revoked_at.isoformat() if self.revoked_at else None,
            "is_active": self.is_active(),
            "created_by": self.created_by,
        }
