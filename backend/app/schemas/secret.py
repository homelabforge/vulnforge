"""Secret schemas for API responses."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from app.validators import VALID_SECRET_STATUSES

REDACTED = "***REDACTED***"


class Secret(BaseModel):
    """Secret detection result."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    scan_id: int
    rule_id: str
    category: str
    title: str
    severity: str
    match: str
    file_path: str | None = None
    start_line: int | None = None
    end_line: int | None = None
    code_snippet: str | None = None
    layer_digest: str | None = None
    status: str = "to_review"
    notes: str | None = None
    created_at: datetime
    updated_at: datetime | None = None

    @model_validator(mode="after")
    def ensure_redaction(self) -> "Secret":
        """Defensive redaction — ensure secret content is never exposed via API."""
        if self.match and self.match != REDACTED:
            self.match = REDACTED
        if self.code_snippet and REDACTED not in self.code_snippet:
            self.code_snippet = REDACTED
        return self


class SecretUpdate(BaseModel):
    """Schema for updating secret status."""

    status: str | None = None
    notes: str | None = None

    @field_validator("status")
    @classmethod
    def validate_status(cls, v: str | None) -> str | None:
        """Validate status against allowed values."""
        if v is None:
            return v
        v_lower = v.lower()
        if v_lower not in VALID_SECRET_STATUSES:
            raise ValueError(f"Invalid status. Must be one of: {', '.join(VALID_SECRET_STATUSES)}")
        return v_lower


class SecretSummary(BaseModel):
    """Summary statistics for detected secrets."""

    total_secrets: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    affected_containers: int
    top_categories: dict[str, int]
