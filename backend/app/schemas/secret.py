"""Secret schemas for API responses."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict


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


class SecretUpdate(BaseModel):
    """Schema for updating secret status."""

    status: str | None = None
    notes: str | None = None


class SecretSummary(BaseModel):
    """Summary statistics for detected secrets."""

    total_secrets: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    affected_containers: int
    top_categories: dict[str, int]
