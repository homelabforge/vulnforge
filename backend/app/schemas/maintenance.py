"""Pydantic schemas for maintenance API endpoints."""

from pydantic import BaseModel


class CleanupResponse(BaseModel):
    """Response from cleanup operation."""

    status: str
    deleted_scans: int = 0
    deleted_vulnerabilities: int = 0
    deleted_secrets: int = 0
    deleted_notifications: int = 0
    deleted_activity_logs: int = 0
    scan_jobs: int = 0


class CleanupStatsResponse(BaseModel):
    """Statistics about cleanable data."""

    total_scans: int
    old_scans: int
    retention_days: int
    cutoff_date: str
    can_clean: bool


class CacheStatsResponse(BaseModel):
    """Cache statistics."""

    total_keys: int = 0
    total_size_bytes: int = 0
    hit_rate: float = 0.0
    hits: int = 0
    misses: int = 0


class BackupCreateResponse(BaseModel):
    """Response from creating a backup."""

    status: str
    filename: str
    path: str
    size_bytes: int
    size_mb: float
    created_at: str


class BackupListResponse(BaseModel):
    """Response listing available backups."""

    backups: list[dict]
    total: int


class BackupRestoreResponse(BaseModel):
    """Response from restoring a backup."""

    status: str
    message: str
    safety_backup: str
    note: str


class KevRefreshResponse(BaseModel):
    """Response from refreshing the KEV catalog."""

    status: str
    message: str
    kev_catalog_size: int
    last_refresh: str | None
    vulnerabilities_checked: int
    vulnerabilities_updated: int
    newly_flagged_as_kev: int
    newly_unflagged_as_kev: int


class KevStatusResponse(BaseModel):
    """KEV catalog status."""

    kev_enabled: bool
    catalog_size: int
    last_refresh: str | None
    needs_refresh: bool
    kev_vulnerabilities_in_db: int
    cache_hours: int
