"""Activity log repository for centralized activity queries."""

from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import ActivityLog
from app.utils.timezone import get_now


class ActivityLogRepository:
    """Repository for ActivityLog model."""

    def __init__(self, db: AsyncSession):
        """
        Initialize the repository.

        Args:
            db: AsyncSession database session
        """
        self.db = db

    async def create(
        self,
        event_type: str,
        severity: str,
        title: str,
        description: str | None = None,
        container_id: int | None = None,
        container_name: str | None = None,
        metadata: dict[str, Any] | None = None,
        timestamp: datetime | None = None,
    ) -> ActivityLog:
        """
        Create a new activity log entry.

        Args:
            event_type: Type of event (scan_completed, scan_failed, etc.)
            severity: Severity level (info, warning, critical)
            title: Brief event summary
            description: Detailed description (optional)
            container_id: Container ID if applicable
            container_name: Container name if applicable
            metadata: Event-specific data dictionary
            timestamp: Event timestamp (defaults to now)

        Returns:
            Created ActivityLog instance
        """
        if timestamp is None:
            timestamp = get_now()

        activity = ActivityLog(
            event_type=event_type,
            severity=severity,
            title=title,
            description=description,
            container_id=container_id,
            container_name=container_name,
            event_metadata=metadata or {},
            timestamp=timestamp,
        )

        self.db.add(activity)
        await self.db.commit()
        await self.db.refresh(activity)
        return activity

    async def get_recent(
        self,
        limit: int = 50,
        offset: int = 0,
        event_type_filter: str | None = None,
        severity_filter: str | None = None,
        container_id_filter: int | None = None,
    ) -> tuple[list[ActivityLog], int]:
        """
        Get recent activity logs with pagination and filtering.

        Args:
            limit: Maximum number of activities to return
            offset: Pagination offset
            event_type_filter: Filter by event type (optional)
            severity_filter: Filter by severity (optional)
            container_id_filter: Filter by container ID (optional)

        Returns:
            Tuple of (activities list, total count)
        """
        # Build query
        query = select(ActivityLog)

        # Apply filters
        if event_type_filter:
            query = query.where(ActivityLog.event_type == event_type_filter)
        if severity_filter:
            query = query.where(ActivityLog.severity == severity_filter)
        if container_id_filter:
            query = query.where(ActivityLog.container_id == container_id_filter)

        # Order by timestamp descending (most recent first)
        query = query.order_by(ActivityLog.timestamp.desc())

        # Get total count
        count_query = select(func.count(ActivityLog.id))
        if event_type_filter:
            count_query = count_query.where(ActivityLog.event_type == event_type_filter)
        if severity_filter:
            count_query = count_query.where(ActivityLog.severity == severity_filter)
        if container_id_filter:
            count_query = count_query.where(ActivityLog.container_id == container_id_filter)

        total_result = await self.db.execute(count_query)
        total = total_result.scalar() or 0

        # Apply pagination
        query = query.limit(limit).offset(offset)

        # Execute query
        result = await self.db.execute(query)
        activities = list(result.scalars().all())

        return activities, total

    async def get_by_container(self, container_id: int, limit: int = 50) -> list[ActivityLog]:
        """
        Get activities for a specific container.

        Args:
            container_id: Container ID
            limit: Maximum number of activities to return

        Returns:
            List of ActivityLog instances
        """
        query = (
            select(ActivityLog)
            .where(ActivityLog.container_id == container_id)
            .order_by(ActivityLog.timestamp.desc())
            .limit(limit)
        )

        result = await self.db.execute(query)
        return list(result.scalars().all())

    async def count_total(self) -> int:
        """
        Count total activity logs.

        Returns:
            Total count of activity logs
        """
        result = await self.db.execute(select(func.count(ActivityLog.id)))
        return result.scalar() or 0

    async def count_by_type(self) -> dict[str, int]:
        """
        Count activities grouped by event type.

        Returns:
            Dictionary mapping event_type to count
        """
        query = select(ActivityLog.event_type, func.count(ActivityLog.id)).group_by(
            ActivityLog.event_type
        )

        result = await self.db.execute(query)
        counts = {row[0]: row[1] for row in result.fetchall()}
        return counts

    async def delete_older_than(self, days: int) -> int:
        """
        Delete activity logs older than specified days.

        Args:
            days: Number of days to retain

        Returns:
            Number of deleted records
        """
        cutoff_date = get_now() - timedelta(days=days)

        stmt = delete(ActivityLog).where(ActivityLog.timestamp < cutoff_date)
        result = await self.db.execute(stmt)
        await self.db.commit()

        return result.rowcount  # type: ignore[union-attr]
