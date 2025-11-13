"""Pydantic schemas for Activity API."""

from datetime import datetime
from typing import Any, Dict, List

from pydantic import BaseModel, ConfigDict


class ActivityLog(BaseModel):
    """Activity log schema for API responses."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    event_type: str
    severity: str
    container_id: int | None
    container_name: str | None
    title: str
    description: str | None
    event_metadata: Dict[str, Any] | None
    timestamp: datetime
    created_at: datetime


class ActivityList(BaseModel):
    """Paginated activity list response."""

    activities: List[ActivityLog]
    total: int
    event_type_counts: Dict[str, int]


class ActivityTypeCount(BaseModel):
    """Event type with count."""

    type: str
    count: int
    label: str


class ActivityTypesResponse(BaseModel):
    """Response for activity types endpoint."""

    types: List[ActivityTypeCount]
