"""Pydantic schemas for image compliance API endpoints."""

from datetime import datetime

from pydantic import BaseModel


class ImageScanTriggerResponse(BaseModel):
    """Response from triggering a single image scan."""

    message: str
    image_name: str


class ImageScanAllTriggerResponse(BaseModel):
    """Response from triggering a batch image scan."""

    message: str
    image_count: int


class ImageComplianceAlert(BaseModel):
    """Alert detail from Trivy image misconfiguration check."""

    code: str
    line: int | None = None


class ImageScanLastResult(BaseModel):
    """Result of the most recently completed image scan."""

    image_name: str
    success: bool
    error: str | None = None
    finished_at: str | None = None


class ImageScanCurrentStatus(BaseModel):
    """Union of idle/scanning/completed states — all fields optional except status."""

    status: str  # idle, scanning, completed
    # Completed state (set by route handler)
    last_scan_id: int | None = None
    # Scanning state (from image_misconfig_state.get_status())
    mode: str | None = None
    current_image: str | None = None
    progress_current: int | None = None
    progress_total: int | None = None
    started_at: str | None = None
    targets: list[str] | None = None
    # Both idle and scanning
    last_result: ImageScanLastResult | None = None


class ImageComplianceSummaryResponse(BaseModel):
    """Aggregated compliance summary across all scanned images."""

    total_images_scanned: int
    compliance_score: float | None
    total_checks: int
    passed_checks: int
    failed_checks: int
    fatal_count: int
    warn_count: int
    last_scan_date: datetime | None
    last_scan_status: str | None
    image_name: str | None
    category_breakdown: dict[str, float] | None


class ImageComplianceImageEntry(BaseModel):
    """A scanned image with its latest compliance data."""

    image_name: str
    compliance_score: float | None
    total_checks: int | None = None
    passed_checks: int | None = None
    failed_checks: int | None = None
    active_failures: int
    fatal_count: int | None = None
    warn_count: int | None = None
    last_scan_date: datetime | None
    affected_containers: list[str]


class ImageComplianceFindingResponse(BaseModel):
    """A single image compliance finding."""

    id: int
    check_id: str
    title: str
    description: str | None = None
    status: str
    severity: str
    category: str
    remediation: str | None = None
    alerts: list[ImageComplianceAlert]
    is_ignored: bool
    ignored_reason: str | None = None
    ignored_by: str | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None


class ImageFindingIgnoreResponse(BaseModel):
    """Response after marking a finding as ignored."""

    id: int
    check_id: str
    is_ignored: bool
    ignored_by: str | None
    ignored_at: datetime | None


class ImageFindingUnignoreResponse(BaseModel):
    """Response after unmarking a finding as ignored."""

    id: int
    check_id: str
    is_ignored: bool


class ImageComplianceScanHistoryEntry(BaseModel):
    """A single entry in scan history."""

    id: int
    scan_date: datetime | None
    scan_status: str
    image_name: str
    compliance_score: float | None = None
    total_checks: int | None = None
    passed_checks: int | None = None
    failed_checks: int | None = None
    scan_duration_seconds: float | None = None
    error_message: str | None = None
