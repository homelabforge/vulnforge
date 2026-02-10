"""Cleanup service for automatic data retention management."""

import logging
from datetime import timedelta

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import db_session
from app.models import Scan, ScanJob, Vulnerability
from app.services.settings_manager import SettingsManager
from app.utils.timezone import get_now

logger = logging.getLogger(__name__)


class CleanupService:
    """Service for cleaning up old scan data based on retention settings."""

    @staticmethod
    async def cleanup_old_scans(db: AsyncSession | None = None):
        """Delete scan history older than the configured retention period.

        Args:
            db: Optional database session. If provided, uses this session (for testing/API calls).
                If None, creates its own session (for background tasks).
        """
        if db is not None:
            # Use provided session (for testing/API calls)
            return await CleanupService._cleanup_with_session(db)
        else:
            # Create own session (for background tasks)
            async with db_session() as session:
                return await CleanupService._cleanup_with_session(session)

    @staticmethod
    async def _cleanup_with_session(db: AsyncSession):
        """Internal method that performs cleanup with a given session."""
        try:
            settings_manager = SettingsManager(db)
            retention_days = (
                await settings_manager.get_int("keep_scan_history_days", default=90) or 90
            )

            # Calculate cutoff date
            cutoff_date = get_now() - timedelta(days=retention_days)

            logger.info(f"Starting scan history cleanup (retention: {retention_days} days)")

            # Find scans older than retention period
            old_scans_result = await db.execute(select(Scan.id).where(Scan.scan_date < cutoff_date))
            old_scan_ids = [row[0] for row in old_scans_result.fetchall()]

            if not old_scan_ids:
                logger.info("No old scans to clean up")
                return {
                    "scans_deleted": 0,
                    "vulnerabilities_deleted": 0,
                    "retention_days": retention_days,
                }

            # Count vulnerabilities that will be deleted
            vuln_count_result = await db.execute(
                select(Vulnerability).where(Vulnerability.scan_id.in_(old_scan_ids))
            )
            vuln_count = len(vuln_count_result.scalars().all())

            # Delete vulnerabilities first (foreign key dependency)
            await db.execute(delete(Vulnerability).where(Vulnerability.scan_id.in_(old_scan_ids)))

            # Delete old scans
            await db.execute(delete(Scan).where(Scan.id.in_(old_scan_ids)))

            await db.commit()

            logger.info(
                f"Cleanup complete: Deleted {len(old_scan_ids)} scans and "
                f"{vuln_count} associated vulnerabilities older than {retention_days} days"
            )

            return {
                "scans_deleted": len(old_scan_ids),
                "vulnerabilities_deleted": vuln_count,
                "retention_days": retention_days,
                "cutoff_date": cutoff_date.isoformat(),
            }

        except Exception as e:
            logger.error(f"Error during cleanup: {e}")
            await db.rollback()
            raise

    @staticmethod
    async def cleanup_old_scan_jobs(db: AsyncSession | None = None, retention_days: int = 30):
        """Delete completed/failed ScanJob rows older than retention period.

        Also marks orphaned 'queued' ScanJob rows (older than 1 hour) as failed.

        Args:
            db: Optional database session. If None, creates its own.
            retention_days: Days to retain completed/failed jobs (default 30).
        """
        if db is not None:
            return await CleanupService._cleanup_scan_jobs_with_session(db, retention_days)
        else:
            async with db_session() as session:
                return await CleanupService._cleanup_scan_jobs_with_session(session, retention_days)

    @staticmethod
    async def _cleanup_scan_jobs_with_session(db: AsyncSession, retention_days: int):
        """Internal method to clean up ScanJob rows."""
        try:
            cutoff = get_now() - timedelta(days=retention_days)
            orphan_cutoff = get_now() - timedelta(hours=1)

            # Delete terminal ScanJob rows older than retention period
            old_jobs = await db.execute(
                delete(ScanJob)
                .where(
                    ScanJob.status.in_(["completed", "failed"]),
                    ScanJob.completed_at < cutoff,
                )
                .returning(ScanJob.id)
            )
            deleted_count = len(old_jobs.fetchall())

            # Mark orphaned "queued" jobs (stuck > 1 hour) as failed
            orphan_result = await db.execute(
                select(ScanJob).where(
                    ScanJob.status == "queued",
                    ScanJob.created_at < orphan_cutoff,
                )
            )
            orphans = orphan_result.scalars().all()
            for orphan in orphans:
                orphan.status = "failed"
                orphan.error_message = "Orphaned: stuck in queued state for over 1 hour"
                orphan.completed_at = get_now()

            await db.commit()

            if deleted_count or orphans:
                logger.info(
                    f"ScanJob cleanup: deleted {deleted_count} old jobs, "
                    f"marked {len(orphans)} orphans as failed"
                )

            return {
                "deleted": deleted_count,
                "orphans_failed": len(orphans),
                "retention_days": retention_days,
            }
        except Exception as e:
            logger.error(f"Error during ScanJob cleanup: {e}")
            await db.rollback()
            raise

    @staticmethod
    async def get_cleanup_stats(db: AsyncSession | None = None) -> dict:
        """Get statistics about data that could be cleaned up.

        Args:
            db: Optional database session. If provided, uses this session (for testing/API calls).
                If None, creates its own session (for background tasks).
        """
        if db is not None:
            # Use provided session (for testing/API calls)
            return await CleanupService._get_stats_with_session(db)
        else:
            # Create own session (for background tasks)
            async with db_session() as session:
                return await CleanupService._get_stats_with_session(session)

    @staticmethod
    async def _get_stats_with_session(db: AsyncSession) -> dict:
        """Internal method that gets cleanup stats with a given session."""
        settings_manager = SettingsManager(db)
        retention_days = await settings_manager.get_int("keep_scan_history_days", default=90) or 90

        cutoff_date = get_now() - timedelta(days=retention_days)

        # Count old scans
        old_scans_result = await db.execute(select(Scan).where(Scan.scan_date < cutoff_date))
        old_scans_count = len(old_scans_result.scalars().all())

        # Count total scans
        total_scans_result = await db.execute(select(Scan))
        total_scans = len(total_scans_result.scalars().all())

        return {
            "total_scans": total_scans,
            "old_scans": old_scans_count,
            "retention_days": retention_days,
            "cutoff_date": cutoff_date.isoformat(),
            "can_clean": old_scans_count > 0,
        }
