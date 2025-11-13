"""Secret API endpoints."""

import csv
import io
import json

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse

from app.dependencies.auth import require_admin
from app.models.user import User
from app.repositories.dependencies import get_activity_logger, get_fp_pattern_repository, get_secret_repository
from app.repositories.false_positive_pattern_repository import FalsePositivePatternRepository
from app.repositories.secret_repository import SecretRepository
from app.schemas.secret import Secret as SecretSchema, SecretSummary, SecretUpdate
from app.services.activity_logger import ActivityLogger

router = APIRouter()


@router.get("/containers/{container_id}/secrets", response_model=list[SecretSchema])
async def get_container_secrets(
    container_id: int,
    limit: int = 100,
    secret_repo: SecretRepository = Depends(get_secret_repository),
    user: User = Depends(require_admin),
):
    """
    Get all secrets detected in the latest scan of a container. Admin only.

    Args:
        container_id: Container ID
        limit: Maximum number of secrets to return

    Returns:
        List of detected secrets from the most recent scan (excluding false positives)
    """
    secrets = await secret_repo.get_by_container(container_id, limit=limit)
    return [SecretSchema.model_validate(s) for s in secrets]


@router.get("/scans/{scan_id}/secrets", response_model=list[SecretSchema])
async def get_scan_secrets(
    scan_id: int,
    limit: int = 100,
    secret_repo: SecretRepository = Depends(get_secret_repository),
    user: User = Depends(require_admin),
):
    """
    Get all secrets detected in a specific scan. Admin only.

    Args:
        scan_id: Scan ID
        limit: Maximum number of secrets to return

    Returns:
        List of detected secrets (excluding false positives)
    """
    secrets = await secret_repo.get_by_scan(scan_id, limit=limit)
    return [SecretSchema.model_validate(s) for s in secrets]


@router.get("/secrets/summary", response_model=SecretSummary)
async def get_secrets_summary(
    secret_repo: SecretRepository = Depends(get_secret_repository),
    user: User = Depends(require_admin),
):
    """
    Get summary of all detected secrets across all containers. Admin only.

    Returns:
        Summary statistics for detected secrets (excluding false positives)
    """
    summary = await secret_repo.get_summary()
    return SecretSummary(**summary)


@router.get("/secrets/export")
async def export_secrets(
    format: str = "csv",
    severity: str | None = None,
    category: str | None = None,
    include_false_positives: bool = False,
    secret_repo: SecretRepository = Depends(get_secret_repository),
    user: User = Depends(require_admin),
):
    """
    Export secrets to CSV or JSON format. Admin only.

    Args:
        format: Export format (csv or json)
        severity: Filter by severity
        category: Filter by category
        include_false_positives: Whether to include false positives in export

    Returns:
        StreamingResponse with CSV or JSON file
    """
    # Get secrets with container names
    secrets_with_containers = await secret_repo.get_for_export(
        severity=severity,
        category=category,
        include_false_positives=include_false_positives,
    )

    if format == "json":
        # Export as JSON
        data = [
            {
                "id": s.id,
                "container": container_name,
                "rule_id": s.rule_id,
                "category": s.category,
                "title": s.title,
                "severity": s.severity,
                "file_path": s.file_path,
                "start_line": s.start_line,
                "end_line": s.end_line,
                "match": s.match,
                "layer_digest": s.layer_digest,
                "status": s.status,
                "created_at": s.created_at.isoformat() if s.created_at else None,
            }
            for s, container_name in secrets_with_containers
        ]
        content = json.dumps(data, indent=2)
        media_type = "application/json"
        filename = "secrets.json"
    else:
        # Export as CSV
        output = io.StringIO()
        writer = csv.DictWriter(
            output,
            fieldnames=[
                "ID",
                "Container",
                "Rule ID",
                "Category",
                "Title",
                "Severity",
                "File Path",
                "Start Line",
                "End Line",
                "Match",
                "Layer Digest",
                "Status",
                "Created At",
            ],
        )
        writer.writeheader()
        for s, container_name in secrets_with_containers:
            writer.writerow(
                {
                    "ID": s.id,
                    "Container": container_name,
                    "Rule ID": s.rule_id,
                    "Category": s.category,
                    "Title": s.title,
                    "Severity": s.severity,
                    "File Path": s.file_path or "",
                    "Start Line": s.start_line or "",
                    "End Line": s.end_line or "",
                    "Match": s.match,
                    "Layer Digest": s.layer_digest or "",
                    "Status": s.status,
                    "Created At": s.created_at.isoformat() if s.created_at else "",
                }
            )
        content = output.getvalue()
        media_type = "text/csv"
        filename = "secrets.csv"

    return StreamingResponse(
        iter([content]),
        media_type=media_type,
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.get("/secrets/", response_model=list[SecretSchema])
async def list_all_secrets(
    severity: str | None = None,
    category: str | None = None,
    limit: int = 100,
    offset: int = 0,
    secret_repo: SecretRepository = Depends(get_secret_repository),
    user: User = Depends(require_admin),
):
    """
    List all detected secrets with optional filtering. Admin only.

    Args:
        severity: Filter by severity (CRITICAL, HIGH, MEDIUM, LOW)
        category: Filter by category (AWS, GitHub, Generic, etc.)
        limit: Maximum number of results
        offset: Pagination offset

    Returns:
        List of secrets matching filters (excluding false positives)
    """
    secrets = await secret_repo.get_all_active(
        severity=severity, category=category, limit=limit, offset=offset
    )
    return [SecretSchema.model_validate(s) for s in secrets]


@router.get("/secrets/{secret_id}", response_model=SecretSchema)
async def get_secret(
    secret_id: int,
    secret_repo: SecretRepository = Depends(get_secret_repository),
    user: User = Depends(require_admin),
):
    """
    Get a specific secret by ID. Admin only.

    Args:
        secret_id: Secret ID

    Returns:
        Secret details (includes false positives for detail view)
    """
    secret = await secret_repo.get_by_id(secret_id)

    if not secret:
        raise HTTPException(status_code=404, detail="Secret not found")

    return SecretSchema.model_validate(secret)


@router.patch("/secrets/{secret_id}", response_model=SecretSchema)
async def update_secret(
    secret_id: int,
    update: SecretUpdate,
    secret_repo: SecretRepository = Depends(get_secret_repository),
    fp_repo: FalsePositivePatternRepository = Depends(get_fp_pattern_repository),
    activity_logger: ActivityLogger = Depends(get_activity_logger),
    user: User = Depends(require_admin),
):
    """
    Update a secret's status and notes (for false positive management). Admin only.

    When marking a secret as false_positive, automatically creates a persistent
    pattern so future scans will auto-mark similar secrets.

    Args:
        secret_id: Secret ID
        update: Fields to update (status, notes)

    Returns:
        Updated secret
    """
    if update.status is None:
        raise HTTPException(status_code=400, detail="Status is required")

    secret = await secret_repo.update_status(
        secret_id=secret_id, status=update.status, notes=update.notes
    )

    if not secret:
        raise HTTPException(status_code=404, detail="Secret not found")

    # Log the status change for audit trail
    # Get container name from secret's scan
    from app.repositories.secret_repository import SecretRepository
    container_name = "unknown"
    if secret.scan_id:
        try:
            # Get scan to find container
            from sqlalchemy import select
            from app.models import Scan
            result = await secret_repo.db.execute(
                select(Scan).where(Scan.id == secret.scan_id)
            )
            scan = result.scalar_one_or_none()
            if scan:
                from app.models import Container
                result = await secret_repo.db.execute(
                    select(Container).where(Container.id == scan.container_id)
                )
                container = result.scalar_one_or_none()
                if container:
                    container_name = container.name
        except Exception:
            pass

    await activity_logger.log_secret_status_changed(
        secret_id=secret.id,
        container_name=container_name,
        old_status="active",  # Assume active before update
        new_status=update.status,
        username=user.username,
        notes=update.notes,
    )

    # If marking as false positive, create a persistent pattern (with username)
    if update.status == "false_positive":
        await fp_repo.create_from_secret(secret_id, update.notes, created_by=user.username)

    return SecretSchema.model_validate(secret)


@router.post("/secrets/bulk-update")
async def bulk_update_secrets(
    secret_ids: list[int],
    update: SecretUpdate,
    secret_repo: SecretRepository = Depends(get_secret_repository),
    fp_repo: FalsePositivePatternRepository = Depends(get_fp_pattern_repository),
    activity_logger: ActivityLogger = Depends(get_activity_logger),
    user: User = Depends(require_admin),
):
    """
    Bulk update multiple secrets' status and notes. Admin only.

    When marking secrets as false_positive, automatically creates persistent
    patterns for each one.

    Args:
        secret_ids: List of secret IDs
        update: Fields to update (status, notes)

    Returns:
        Number of secrets updated
    """
    if update.status is None:
        raise HTTPException(status_code=400, detail="Status is required")

    updated_count = await secret_repo.bulk_update_status(
        secret_ids=secret_ids, status=update.status, notes=update.notes
    )

    # Log bulk status change for audit trail
    await activity_logger.log_secret_status_changed(
        secret_id=0,  # Bulk operation
        container_name=f"bulk_{len(secret_ids)}_secrets",
        old_status="active",
        new_status=update.status,
        username=user.username,
        notes=f"Bulk update of {updated_count} secrets: {update.notes or 'No reason provided'}",
    )

    # If marking as false positive, create patterns for all (with username)
    if update.status == "false_positive":
        for secret_id in secret_ids:
            await fp_repo.create_from_secret(secret_id, update.notes, created_by=user.username)

    return {"updated": updated_count, "total": len(secret_ids)}
