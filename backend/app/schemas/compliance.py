"""Pydantic schemas for compliance API."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class ComplianceFindingBase(BaseModel):
    """Base schema for compliance findings."""

    check_id: str
    check_number: str | None = None
    title: str
    description: str | None = None
    status: str  # PASS, WARN, FAIL, INFO, NOTE, SKIP
    severity: str  # HIGH, MEDIUM, LOW, INFO
    category: str
    target: str | None = None  # Container/image name for per-target checks
    remediation: str | None = None
    actual_value: str | None = None
    expected_value: str | None = None


class ComplianceFinding(ComplianceFindingBase):
    """Full compliance finding schema with tracking."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    is_ignored: bool = False
    ignored_reason: str | None = None
    ignored_by: str | None = None
    ignored_at: datetime | None = None
    first_seen: datetime
    last_seen: datetime
    scan_date: datetime


class ComplianceFindingIgnoreRequest(BaseModel):
    """Request to mark a finding as ignored/false positive."""

    finding_id: int
    reason: str = Field(..., min_length=1, max_length=1000)


class ComplianceFindingUnignoreRequest(BaseModel):
    """Request to unmark a finding as ignored."""

    finding_id: int


class ComplianceScanBase(BaseModel):
    """Base schema for compliance scans."""

    scan_date: datetime
    scan_duration_seconds: float | None = None
    scan_status: str
    error_message: str | None = None
    trigger_type: str  # manual, scheduled
    total_checks: int = 0
    passed_checks: int = 0
    warned_checks: int = 0
    failed_checks: int = 0
    info_checks: int = 0
    note_checks: int = 0
    compliance_score: float | None = None
    category_scores: str | None = None


class ComplianceScan(ComplianceScanBase):
    """Full compliance scan schema."""

    model_config = ConfigDict(from_attributes=True)

    id: int


class ComplianceSummary(BaseModel):
    """Summary of current compliance status."""

    last_scan_date: datetime | None = None
    last_scan_status: str | None = None
    compliance_score: float | None = None
    total_checks: int = 0
    passed_checks: int = 0
    warned_checks: int = 0
    failed_checks: int = 0
    info_checks: int = 0
    note_checks: int = 0
    high_severity_failures: int = 0
    medium_severity_failures: int = 0
    low_severity_failures: int = 0
    ignored_findings_count: int = 0
    category_breakdown: dict[str, float] | None = None  # Category name -> compliance score %


class ComplianceTriggerRequest(BaseModel):
    """Request to trigger a compliance scan."""

    trigger_type: str = Field(default="manual", pattern="^(manual|scheduled)$")


class ComplianceCurrentScan(BaseModel):
    """Current compliance scan status."""

    status: str  # idle, scanning, completed
    scan_id: int | None = None
    started_at: datetime | None = None
    progress: str | None = None

    # Real-time progress fields
    current_check: str | None = None
    current_check_id: str | None = None
    progress_current: int | None = None
    progress_total: int | None = None
