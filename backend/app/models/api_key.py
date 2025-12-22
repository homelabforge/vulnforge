"""API Key model for secure API authentication."""

from sqlalchemy import Column, DateTime, Integer, String

from app.db import Base


class APIKey(Base):
    """API Key for external service authentication."""

    __tablename__ = "api_keys"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False)
    description = Column(String(512))
    key_hash = Column(String(64), nullable=False, unique=True)  # SHA256 hash
    key_prefix = Column(String(8), nullable=False)  # First 8 chars for display (vf_abc12)
    created_at = Column(DateTime(timezone=True), nullable=False)
    last_used_at = Column(DateTime(timezone=True))
    revoked_at = Column(DateTime(timezone=True))
    created_by = Column(String(255), default="admin")

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
