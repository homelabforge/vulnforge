"""Pydantic schemas for API requests and responses."""

from app.schemas.activity import (
    ActivityList,
    ActivityLog,
    ActivityTypeCount,
    ActivityTypesResponse,
)
from app.schemas.container import (
    Container,
    ContainerCreate,
    ContainerLastScan,
    ContainerList,
    ContainerScanVulnerability,
    ContainerSummary,
    ContainerUpdate,
    ContainerVulnerabilitySummary,
)
from app.schemas.scan import Scan, ScanCreate, ScanProgress, ScanRequest, ScanSummary
from app.schemas.setting import Setting, SettingUpdate
from app.schemas.vulnerability import (
    PaginatedVulnerabilities,
    RemediationGroup,
    Vulnerability,
    VulnerabilityStats,
    VulnerabilitySummary,
    VulnerabilityUpdate,
)
from app.schemas.widget import (
    ContainerVulnCount,
    RemediationItem,
    WidgetCritical,
    WidgetRemediation,
    WidgetSummary,
    WidgetTopContainers,
)

__all__ = [
    "ActivityList",
    "ActivityLog",
    "ActivityTypeCount",
    "ActivityTypesResponse",
    "Container",
    "ContainerCreate",
    "ContainerUpdate",
    "ContainerLastScan",
    "ContainerList",
    "ContainerSummary",
    "ContainerScanVulnerability",
    "ContainerVulnerabilitySummary",
    "ContainerVulnCount",
    "PaginatedVulnerabilities",
    "RemediationGroup",
    "RemediationItem",
    "Scan",
    "ScanCreate",
    "ScanRequest",
    "ScanProgress",
    "ScanSummary",
    "Vulnerability",
    "VulnerabilityUpdate",
    "VulnerabilitySummary",
    "VulnerabilityStats",
    "Setting",
    "SettingUpdate",
    "WidgetSummary",
    "WidgetCritical",
    "WidgetTopContainers",
    "WidgetRemediation",
]
