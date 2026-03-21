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
    # CVE delta tracking - JSON encoded arrays of CVE IDs
    cves_fixed: str | None = None
    cves_introduced: str | None = None


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


class ScanJobSchema(BaseModel):
    """Schema for scan job status responses."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    container_id: int
    container_name: str
    status: str  # queued, processing, completed, failed
    scan_id: int | None = None
    error_message: str | None = None
    created_at: datetime
    completed_at: datetime | None = None


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


class ScanTriggerResponse(BaseModel):
    """Response from POST /scan — scan enqueue result."""

    message: str
    queued: int
    skipped: int
    total_requested: int
    job_ids: list[int]


class ScanAbortResponse(BaseModel):
    """Response from POST /{scan_id}/abort."""

    message: str
    scan_id: int


class ScanRetryResponse(BaseModel):
    """Response from POST /{scan_id}/retry."""

    message: str
    scan_id: int
    container: str


class CveDeltaScanEntry(BaseModel):
    """Individual scan entry in a CVE delta response."""

    scan_id: int
    scan_date: str
    container_name: str
    image: str
    total_vulns: int
    cves_fixed: list[str]
    cves_fixed_count: int
    cves_introduced: list[str]
    cves_introduced_count: int


class CveDeltaSummary(BaseModel):
    """Summary totals for CVE delta response."""

    total_cves_fixed: int
    total_cves_introduced: int
    net_change: int


class CveDeltaResponse(BaseModel):
    """Response from GET /cve-delta — used by TideWatch integration."""

    since_hours: int
    cutoff_time: str
    total_scans: int
    summary: CveDeltaSummary
    scans: list[CveDeltaScanEntry]


class ScanQueueStatus(BaseModel):
    """Current scan queue status."""

    queue_size: int = 0
    active_scans: int = 0
    current_scan: str | None = None
    workers_active: int = 0
    batch_total: int = 0
    batch_completed: int = 0
    scanner_stats: dict | None = None


class ScanProgressSnapshot(BaseModel):
    """Combined scan and queue status for polling clients."""

    status: str  # idle, scanning
    current_container: str | None = None
    progress_current: int | None = None
    progress_total: int | None = None
    scan: dict | None = None
    queue: ScanQueueStatus | None = None
