"""Scan schemas."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class ScanBase(BaseModel):
    """Base scan schema."""

    container_id: int
    image_scanned: str


class ScanCreate(ScanBase):
    """Schema for creating a scan."""

    pass


class ScanRequest(BaseModel):
    """Schema for requesting a scan."""

    container_ids: list[int] | None = None  # None means scan all


class Scan(ScanBase):
    """Full scan schema."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    scan_date: datetime
    scan_status: str
    scan_duration_seconds: float | None
    error_message: str | None
    total_vulns: int
    fixable_vulns: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int


class ScanProgress(BaseModel):
    """Real-time scan progress."""

    scan_id: int | None
    container_id: int
    container_name: str
    status: str  # queued, scanning, completed, failed
    progress_percent: int
    message: str | None
    started_at: datetime | None
    completed_at: datetime | None


class ScanSummary(BaseModel):
    """Summary of scan results."""

    total_containers: int
    containers_scanned: int
    containers_failed: int
    total_vulnerabilities: int
    fixable_vulnerabilities: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    scan_duration_seconds: float
