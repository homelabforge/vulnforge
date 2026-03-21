"""Common response schemas used across multiple route modules."""

from pydantic import BaseModel


class MessageResponse(BaseModel):
    """Generic success/failure response with a message."""

    success: bool
    message: str


class StatusMessageResponse(BaseModel):
    """Response with status and message fields."""

    status: str
    message: str


class ActionResponse(BaseModel):
    """Response for simple action endpoints (delete, clear, etc.)."""

    message: str
    detail: str | None = None


class FPPatternDeleteResponse(BaseModel):
    """Response from deleting a false-positive pattern."""

    message: str
    unsuppressed_secrets: int


class TrivyDbInfoResponse(BaseModel):
    """Trivy vulnerability database information."""

    db_version: str | None
    updated_at: str | None
    next_update: str | None
    downloaded_at: str | None
