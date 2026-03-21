"""Common response schemas used across multiple route modules."""

from pydantic import BaseModel


class MessageResponse(BaseModel):
    """Generic success/failure response with a message."""

    success: bool
    message: str


class ActionResponse(BaseModel):
    """Response for simple action endpoints (delete, clear, etc.)."""

    message: str
    detail: str | None = None
