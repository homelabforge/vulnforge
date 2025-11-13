"""Container schemas."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class ContainerBase(BaseModel):
    """Base container schema."""

    name: str
    image: str
    image_tag: str
    image_id: str


class ContainerCreate(ContainerBase):
    """Schema for creating a container."""

    is_running: bool = True


class ContainerUpdate(BaseModel):
    """Schema for updating a container."""

    is_running: bool | None = None
    last_seen: datetime | None = None


class Container(ContainerBase):
    """Full container schema."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    is_running: bool
    last_seen: datetime
    last_scan_date: datetime | None
    last_scan_status: str | None
    total_vulns: int
    fixable_vulns: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    scanner_coverage: int | None
    dive_efficiency_score: float | None
    dive_inefficient_bytes: int | None
    dive_image_size_bytes: int | None
    dive_layer_count: int | None
    dive_analyzed_at: datetime | None
    created_at: datetime
    updated_at: datetime
    vulnerability_summary: ContainerVulnerabilitySummary | None = None
    last_scan: ContainerLastScan | None = None


class ContainerSummary(BaseModel):
    """Summary container schema for lists."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    image: str
    image_tag: str
    is_running: bool
    last_scan_date: datetime | None
    last_scan_status: str | None
    total_vulns: int
    fixable_vulns: int
    critical_count: int
    high_count: int
    scanner_coverage: int | None
    dive_efficiency_score: float | None
    dive_analyzed_at: datetime | None
    vulnerability_summary: ContainerVulnerabilitySummary | None = None
    last_scan: ContainerLastScan | None = None


class ContainerList(BaseModel):
    """List of containers with metadata."""

    containers: list[ContainerSummary]
    total: int
    scanned: int
    never_scanned: int


class ContainerVulnerabilitySummary(BaseModel):
    """Aggregated vulnerability figures for a container."""

    total: int
    fixable: int
    critical: int
    high: int
    medium: int
    low: int


class ContainerScanVulnerability(BaseModel):
    """Lightweight vulnerability representation for list views."""

    cve_id: str | None
    severity: str | None
    package_name: str | None
    installed_version: str | None
    fixed_version: str | None
    is_fixable: bool | None
    cvss_score: float | None
    title: str | None


class ContainerLastScan(BaseModel):
    """Summary of the most recent scan and notable findings."""

    id: int
    status: str | None
    started_at: datetime | None
    finished_at: datetime | None
    total_vulns: int
    critical: int
    high: int
    medium: int
    low: int
    vulnerabilities: list[ContainerScanVulnerability]
    cves: list[str]
