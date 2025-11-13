"""Homepage widget schemas."""

from datetime import datetime

from pydantic import BaseModel


class WidgetSummary(BaseModel):
    """Overall summary for Homepage widget."""

    total_containers: int
    scanned_containers: int
    last_scan: datetime | None
    total_vulnerabilities: int
    fixable_vulnerabilities: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    total_secrets: int = 0


class WidgetCritical(BaseModel):
    """Critical vulnerabilities focus."""

    critical_total: int
    critical_fixable: int
    high_total: int
    high_fixable: int
    most_vulnerable_container: str | None
    most_vulnerable_count: int


class ContainerVulnCount(BaseModel):
    """Container with vulnerability count."""

    name: str
    total_vulns: int
    fixable_vulns: int
    critical_count: int
    high_count: int


class WidgetTopContainers(BaseModel):
    """Top vulnerable containers."""

    containers: list[ContainerVulnCount]


class RemediationItem(BaseModel):
    """Single remediation action."""

    package: str
    current_version: str
    fixed_version: str
    fixes_count: int
    fixes_critical: int
    fixes_high: int


class WidgetRemediation(BaseModel):
    """Actionable remediation information."""

    total_packages_to_update: int
    total_cves_fixable: int
    critical_cves_fixable: int
    high_cves_fixable: int
    impact_message: str  # "Update X packages to fix Y CVEs"
    top_remediations: list[RemediationItem]
