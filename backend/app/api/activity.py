"""Activity API endpoints."""

from typing import Dict

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_db
from app.repositories.activity_log_repository import ActivityLogRepository
from app.schemas import ActivityList, ActivityLog, ActivityTypeCount, ActivityTypesResponse

router = APIRouter()

# Event type labels for frontend display
EVENT_TYPE_LABELS: Dict[str, str] = {
    "scan_completed": "Scan Completed",
    "scan_failed": "Scan Failed",
    "secret_detected": "Secret Detected",
    "high_severity_found": "High Severity Found",
    "container_discovered": "Container Discovered",
    "container_status_changed": "Status Changed",
    "batch_scan_completed": "Batch Scan Completed",
}


@router.get("/", response_model=ActivityList)
async def get_activities(
    limit: int = Query(50, ge=1, le=200, description="Maximum number of activities to return"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    event_type: str | None = Query(None, description="Filter by event type"),
    severity: str | None = Query(None, description="Filter by severity (info, warning, critical)"),
    container_id: int | None = Query(None, description="Filter by container ID"),
    db: AsyncSession = Depends(get_db),
):
    """
    Get recent activity logs with pagination and filtering.

    Args:
        limit: Maximum number of activities to return (1-200, default 50)
        offset: Pagination offset
        event_type: Filter by event type (optional)
        severity: Filter by severity (optional)
        container_id: Filter by container ID (optional)
        db: Database session

    Returns:
        ActivityList with activities, total count, and event type counts
    """
    repository = ActivityLogRepository(db)

    # Get filtered activities
    activities, total = await repository.get_recent(
        limit=limit,
        offset=offset,
        event_type_filter=event_type,
        severity_filter=severity,
        container_id_filter=container_id,
    )

    # Get event type counts (for filter chips)
    event_type_counts = await repository.count_by_type()

    return ActivityList(
        activities=activities, total=total, event_type_counts=event_type_counts
    )


@router.get("/types", response_model=ActivityTypesResponse)
async def get_activity_types(db: AsyncSession = Depends(get_db)):
    """
    Get available activity event types with counts.

    Args:
        db: Database session

    Returns:
        List of activity types with counts and labels
    """
    repository = ActivityLogRepository(db)
    counts = await repository.count_by_type()

    types = [
        ActivityTypeCount(type=event_type, count=count, label=EVENT_TYPE_LABELS.get(event_type, event_type))
        for event_type, count in counts.items()
    ]

    # Sort by count descending
    types.sort(key=lambda x: x.count, reverse=True)

    return ActivityTypesResponse(types=types)


@router.get("/container/{container_id}", response_model=list[ActivityLog])
async def get_container_activities(
    container_id: int,
    limit: int = Query(50, ge=1, le=200, description="Maximum number of activities to return"),
    db: AsyncSession = Depends(get_db),
):
    """
    Get activities for a specific container.

    Args:
        container_id: Container ID
        limit: Maximum number of activities to return
        db: Database session

    Returns:
        List of ActivityLog instances for the container
    """
    repository = ActivityLogRepository(db)
    activities = await repository.get_by_container(container_id, limit=limit)
    return activities
