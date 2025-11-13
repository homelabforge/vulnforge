"""Setting schemas."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class SettingBase(BaseModel):
    """Base setting schema."""

    key: str
    value: str
    description: str | None = None
    category: str = "general"
    is_sensitive: bool = False


class SettingUpdate(BaseModel):
    """Schema for updating a setting."""

    value: str


class Setting(SettingBase):
    """Full setting schema."""

    model_config = ConfigDict(from_attributes=True)

    updated_at: datetime
