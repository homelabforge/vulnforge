"""Schema builders for container API responses.

Extracted from routes/containers.py to provide consistent container schema
assembly across routes without duplicating business logic.
"""

from datetime import timedelta

from app.schemas import (
    ContainerLastScan,
    ContainerScanVulnerability,
    ContainerVulnerabilitySummary,
)

_SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
_MAX_VULNS = 200


def build_last_scan(scan, vulnerabilities) -> ContainerLastScan:
    """Build a ContainerLastScan from a scan and its vulnerabilities.

    Uses immutable scan-row counts (historical snapshots) for the summary,
    and sorts/deduplicates vulnerabilities for the detail list.
    """
    finished_at = None
    if scan.scan_date:
        finished_at = scan.scan_date
        if scan.scan_duration_seconds is not None:
            finished_at = scan.scan_date + timedelta(seconds=scan.scan_duration_seconds)

    sorted_vulns = sorted(
        vulnerabilities,
        key=lambda v: (
            _SEVERITY_RANK.get((v.severity or "").upper(), 9),
            v.cve_id or "",
        ),
    )

    seen_cves: set[str] = set()
    cves: list[str] = []
    vuln_summaries: list[ContainerScanVulnerability] = []

    for vuln in sorted_vulns[:_MAX_VULNS]:
        vuln_summaries.append(
            ContainerScanVulnerability(
                cve_id=vuln.cve_id,
                severity=vuln.severity,
                package_name=vuln.package_name,
                installed_version=vuln.installed_version,
                fixed_version=vuln.fixed_version,
                is_fixable=vuln.is_fixable,
                cvss_score=vuln.cvss_score,
                title=vuln.title,
            )
        )
        if vuln.cve_id and vuln.cve_id not in seen_cves:
            cves.append(vuln.cve_id)
            seen_cves.add(vuln.cve_id)

    return ContainerLastScan(
        id=scan.id,
        status=scan.scan_status,
        started_at=scan.scan_date,
        finished_at=finished_at,
        total_vulns=scan.total_vulns,
        critical=scan.critical_count,
        high=scan.high_count,
        medium=scan.medium_count,
        low=scan.low_count,
        vulnerabilities=vuln_summaries,
        cves=cves,
    )


def build_vuln_summary(container) -> ContainerVulnerabilitySummary:
    """Build a vulnerability summary from a container's denormalized counts.

    These are actionable counts (excluding false_positive/accepted) — see
    resync_container_counts() in container_repository.py.
    """
    return ContainerVulnerabilitySummary(
        total=container.total_vulns,
        fixable=container.fixable_vulns,
        critical=container.critical_count,
        high=container.high_count,
        medium=container.medium_count,
        low=container.low_count,
    )
