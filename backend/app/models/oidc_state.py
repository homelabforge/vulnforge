"""OIDC state model for OAuth2/OIDC authentication flows."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import DateTime, Index, String
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class OIDCState(Base):
    """OIDC state model for tracking OAuth2/OIDC authentication flows.

    Stores CSRF protection state tokens and nonces for OIDC login flows.
    State tokens are one-time use and expire after 10 minutes.
    """

    __tablename__ = "oidc_states"

    state: Mapped[str] = mapped_column(String(128), primary_key=True, index=True, nullable=False)
    nonce: Mapped[str] = mapped_column(String(128), nullable=False)
    redirect_uri: Mapped[str] = mapped_column(String(512), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (Index("idx_oidc_states_expires_at", "expires_at"),)

    def is_expired(self) -> bool:
        """Check if state has expired (10-minute TTL)."""
        now = datetime.now(UTC)
        expires = self.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=UTC)
        return now > expires

    @classmethod
    def get_expiry_time(cls, minutes: int = 10) -> datetime:
        """Get expiry timestamp for new state (default 10 minutes)."""
        return datetime.now(UTC) + timedelta(minutes=minutes)
