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


class SettingUpdateResponse(BaseModel):
    """Response wrapper for setting write operations.

    Includes the updated setting plus a flag indicating whether the
    application must be restarted for the change to take effect.
    Read endpoints (GET) continue returning plain Setting schemas.
    """

    setting: Setting
    restart_required: bool = False
