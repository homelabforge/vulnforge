"""False Positive Pattern API endpoints."""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.dependencies.auth import require_admin
from app.models.user import User
from app.repositories.dependencies import get_activity_logger, get_fp_pattern_repository
from app.repositories.false_positive_pattern_repository import FalsePositivePatternRepository
from app.services.activity_logger import ActivityLogger

router = APIRouter()


class FPPatternSchema(BaseModel):
    """False positive pattern schema."""

    id: int
    container_name: str
    file_path: str
    rule_id: str
    reason: str | None
    created_by: str
    created_at: str
    match_count: int
    last_matched: str | None

    class Config:
        from_attributes = True


class CreateFPPatternRequest(BaseModel):
    """Request to create FP pattern from secret."""

    secret_id: int
    reason: str | None = None


@router.get("/", response_model=list[FPPatternSchema])
async def list_fp_patterns(
    fp_repo: FalsePositivePatternRepository = Depends(get_fp_pattern_repository),
):
    """
    List all false positive patterns.

    Returns:
        List of FP patterns
    """
    patterns = await fp_repo.get_all()
    return [
        FPPatternSchema(
            id=p.id,
            container_name=p.container_name,
            file_path=p.file_path,
            rule_id=p.rule_id,
            reason=p.reason,
            created_by=p.created_by,
            created_at=p.created_at.isoformat(),
            match_count=p.match_count,
            last_matched=p.last_matched.isoformat() if p.last_matched else None,
        )
        for p in patterns
    ]


@router.get("/container/{container_name}", response_model=list[FPPatternSchema])
async def list_container_fp_patterns(
    container_name: str,
    fp_repo: FalsePositivePatternRepository = Depends(get_fp_pattern_repository),
):
    """
    List FP patterns for a specific container.

    Args:
        container_name: Container name

    Returns:
        List of FP patterns
    """
    patterns = await fp_repo.get_by_container(container_name)
    return [
        FPPatternSchema(
            id=p.id,
            container_name=p.container_name,
            file_path=p.file_path,
            rule_id=p.rule_id,
            reason=p.reason,
            created_by=p.created_by,
            created_at=p.created_at.isoformat(),
            match_count=p.match_count,
            last_matched=p.last_matched.isoformat() if p.last_matched else None,
        )
        for p in patterns
    ]


@router.post("/", response_model=FPPatternSchema)
async def create_fp_pattern(
    request: CreateFPPatternRequest,
    fp_repo: FalsePositivePatternRepository = Depends(get_fp_pattern_repository),
    activity_logger: ActivityLogger = Depends(get_activity_logger),
    user: User = Depends(require_admin),
):
    """
    Create a false positive pattern from a secret. Admin only.

    Args:
        request: Secret ID and optional reason

    Returns:
        Created pattern
    """
    # Pass authenticated username to repository
    pattern = await fp_repo.create_from_secret(
        request.secret_id, request.reason, created_by=user.username
    )

    if not pattern:
        raise HTTPException(
            status_code=404, detail="Secret not found or pattern already exists"
        )

    # Log the admin action for audit trail
    await activity_logger.log_false_positive_created(
        pattern_id=pattern.id,
        container_name=pattern.container_name,
        file_path=pattern.file_path,
        rule_id=pattern.rule_id,
        username=user.username,
        reason=request.reason,
    )

    return FPPatternSchema(
        id=pattern.id,
        container_name=pattern.container_name,
        file_path=pattern.file_path,
        rule_id=pattern.rule_id,
        reason=pattern.reason,
        created_by=pattern.created_by,
        created_at=pattern.created_at.isoformat(),
        match_count=pattern.match_count,
        last_matched=pattern.last_matched.isoformat() if pattern.last_matched else None,
    )


@router.delete("/{pattern_id}")
async def delete_fp_pattern(
    pattern_id: int,
    fp_repo: FalsePositivePatternRepository = Depends(get_fp_pattern_repository),
    user: User = Depends(require_admin),
):
    """
    Delete a false positive pattern. Admin only.

    Args:
        pattern_id: Pattern ID

    Returns:
        Success message
    """
    deleted = await fp_repo.delete(pattern_id)

    if not deleted:
        raise HTTPException(status_code=404, detail="Pattern not found")

    return {"message": "Pattern deleted successfully"}
