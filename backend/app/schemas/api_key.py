"""Pydantic schemas for API key management."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class APIKeyCreate(BaseModel):
    """Request schema for creating a new API key."""

    name: str = Field(..., min_length=1, max_length=255, description="Human-readable key name")
    description: str | None = Field(None, max_length=512, description="Optional key description")


class APIKeyResponse(BaseModel):
    """Response schema for API key (without the actual key)."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    description: str | None
    key_prefix: str  # e.g., "vf_abc12..."
    created_at: datetime
    last_used_at: datetime | None
    revoked_at: datetime | None
    is_active: bool
    created_by: str


class APIKeyCreated(BaseModel):
    """Response schema when a key is first created (includes the actual key)."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    description: str | None
    key: str  # Full API key - shown only once!
    key_prefix: str
    created_at: datetime
    created_by: str

    warning: str = "⚠️ Save this key now - it won't be shown again!"


class APIKeyList(BaseModel):
    """Response schema for listing API keys."""

    keys: list[APIKeyResponse]
    total: int
