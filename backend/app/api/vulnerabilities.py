"""Vulnerability API endpoints."""

import csv
import io
import json

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse

from app.db import db_session
from app.dependencies.auth import require_admin
from app.models.user import User
from app.repositories.dependencies import get_activity_logger, get_vulnerability_repository
from app.repositories.vulnerability_repository import VulnerabilityRepository
from app.schemas import (
    PaginatedVulnerabilities,
    RemediationGroup,
    Vulnerability as VulnSchema,
    VulnerabilitySummary,
    VulnerabilityUpdate,
)
from app.services.activity_logger import ActivityLogger

router = APIRouter()


@router.get("/", response_model=PaginatedVulnerabilities)
async def list_vulnerabilities(
    severity: str | None = None,
    fixable_only: bool = False,
    kev_only: bool = False,
    status: str | None = None,
    limit: int = 100,
    offset: int = 0,
    vuln_repo: VulnerabilityRepository = Depends(get_vulnerability_repository),
):
    """List all vulnerabilities with filters and pagination."""
    vulnerabilities, total = await vuln_repo.get_all(
        severity=severity,
        fixable_only=fixable_only,
        kev_only=kev_only,
        status=status,
        limit=limit,
        offset=offset,
    )

    vuln_summaries = [VulnerabilitySummary(**v) for v in vulnerabilities]

    return PaginatedVulnerabilities(
        vulnerabilities=vuln_summaries,
        total=total,
        limit=limit,
        offset=offset,
        has_more=(offset + limit) < total,
    )


# IMPORTANT: Specific routes must come BEFORE path parameter routes
# Otherwise FastAPI will interpret "remediation-groups" as a vuln_id


@router.post("/bulk-update")
async def bulk_update_vulnerabilities(
    vuln_ids: list[int],
    update: VulnerabilityUpdate,
    vuln_repo: VulnerabilityRepository = Depends(get_vulnerability_repository),
    activity_logger: ActivityLogger = Depends(get_activity_logger),
    user: User = Depends(require_admin),
):
    """Bulk update multiple vulnerabilities status/notes. Admin only."""
    if not vuln_ids:
        raise HTTPException(status_code=400, detail="No vulnerability IDs provided")

    updated_count = await vuln_repo.bulk_update_status(
        vuln_ids=vuln_ids, status=update.status, notes=update.notes
    )

    if updated_count == 0:
        raise HTTPException(status_code=404, detail="No vulnerabilities found")

    # Log bulk vulnerability status change for audit trail
    await activity_logger.log_bulk_vulnerability_status_changed(
        vuln_count=updated_count,
        old_status="to_fix",  # Assume default
        new_status=update.status,
        username=user.username,
        notes=update.notes,
    )

    return {"updated": updated_count, "message": f"Updated {updated_count} vulnerabilities"}


@router.get("/remediation-groups", response_model=list[RemediationGroup])
async def get_remediation_groups(
    container_id: int | None = None,
    vuln_repo: VulnerabilityRepository = Depends(get_vulnerability_repository),
):
    """
    Get remediation groups - packages that can be updated to fix multiple CVEs.
    Groups vulnerabilities by package and fixed version.
    """
    groups = await vuln_repo.get_remediation_groups(container_id=container_id)

    return [RemediationGroup(**g) for g in groups]


@router.get("/export")
async def export_vulnerabilities(
    format: str = "csv",  # csv or json
    severity: str | None = None,
    fixable_only: bool = False,
    status: str | None = None,
    include_false_positives: bool = False,
    vuln_repo: VulnerabilityRepository = Depends(get_vulnerability_repository),
):
    """Export vulnerabilities to CSV or JSON."""
    rows = await vuln_repo.get_for_export(
        severity=severity,
        fixable_only=fixable_only,
        status=status,
        exclude_false_positives=not include_false_positives,
    )

    if format == "csv":
        # Create CSV
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(
            [
                "CVE ID",
                "Container",
                "Package",
                "Severity",
                "CVSS",
                "Installed Version",
                "Fixed Version",
                "Fixable",
                "Status",
                "Title",
            ]
        )
        for row in rows:
            writer.writerow(
                [
                    row["cve_id"],
                    row["container"],
                    row["package"],
                    row["severity"],
                    row["cvss_score"] or "",
                    row["installed_version"],
                    row["fixed_version"] or "",
                    "Yes" if row["is_fixable"] else "No",
                    row["status"],
                    row["title"] or "",
                ]
            )

        return StreamingResponse(
            io.BytesIO(output.getvalue().encode()),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=vulnerabilities.csv"},
        )
    else:  # json
        return StreamingResponse(
            io.BytesIO(json.dumps(rows, indent=2).encode()),
            media_type="application/json",
            headers={"Content-Disposition": "attachment; filename=vulnerabilities.json"},
        )


@router.get("/scanner/comparison")
async def get_scanner_comparison(
    vuln_repo: VulnerabilityRepository = Depends(get_vulnerability_repository),
):
    """Get scanner statistics (Trivy only)."""
    from sqlalchemy import func, select
    from app.models import Vulnerability

    async with db_session() as db:
        # Get total vulnerability count
        result = await db.execute(
            select(func.count(Vulnerability.id))
        )
        total_vulns = result.scalar() or 0

        # Get Trivy vulnerabilities breakdown by severity
        severity_result = await db.execute(
            select(
                Vulnerability.severity,
                func.count(Vulnerability.id).label("count")
            )
            .group_by(Vulnerability.severity)
        )
        trivy_by_severity = {row[0]: row[1] for row in severity_result.fetchall()}

        return {
            "total_trivy": total_vulns,
            "trivy_by_severity": trivy_by_severity,
        }


# Path parameter routes MUST come last
@router.get("/{vuln_id}", response_model=VulnSchema)
async def get_vulnerability(
    vuln_id: int, vuln_repo: VulnerabilityRepository = Depends(get_vulnerability_repository)
):
    """Get vulnerability by ID."""
    vuln = await vuln_repo.get_by_id(vuln_id)

    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    return VulnSchema.model_validate(vuln)


@router.patch("/{vuln_id}", response_model=VulnSchema)
async def update_vulnerability(
    vuln_id: int,
    update: VulnerabilityUpdate,
    vuln_repo: VulnerabilityRepository = Depends(get_vulnerability_repository),
    activity_logger: ActivityLogger = Depends(get_activity_logger),
    user: User = Depends(require_admin),
):
    """Update vulnerability status/notes. Admin only."""
    vuln = await vuln_repo.update_status(vuln_id=vuln_id, status=update.status, notes=update.notes)

    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    # Log single vulnerability status change for audit trail
    await activity_logger.log_vulnerability_status_changed(
        vuln_id=vuln.id,
        cve_id=vuln.cve_id,
        old_status="to_fix",  # Assume default
        new_status=update.status,
        username=user.username,
        notes=update.notes,
    )

    return VulnSchema.model_validate(vuln)
