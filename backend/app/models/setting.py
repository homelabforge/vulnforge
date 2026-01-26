"""Settings model for app configuration."""

from datetime import datetime

from sqlalchemy import Boolean, DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base
from app.utils.timezone import get_now


class Setting(Base):
    """Key-value store for application settings."""

    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(String, primary_key=True)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    category: Mapped[str] = mapped_column(String(50), nullable=False, default="general")
    is_sensitive: Mapped[bool] = mapped_column(Boolean, default=False)  # For tokens/passwords

    updated_at: Mapped[datetime] = mapped_column(DateTime, default=get_now, onupdate=get_now)
