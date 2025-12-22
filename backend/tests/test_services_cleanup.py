"""Tests for cleanup service.

This module tests the cleanup service which provides:
- Old scan data purging based on retention settings
- Database cleanup statistics
"""

from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import pytest


class TestCleanupService:
    """Test cleanup service basic operations."""

    @pytest.mark.asyncio
    async def test_cleanup_old_scans_with_explicit_db(self, db_session, make_container, make_scan):
        """Test cleaning up old scans with explicit db session."""
        from sqlalchemy import select

        from app.models import Scan
        from app.services.cleanup_service import CleanupService

        # Arrange
        container = make_container()
        db_session.add(container)
        await db_session.commit()
        await db_session.refresh(container)

        # Create old scan (90 days old)
        old_scan = make_scan(
            container_id=container.id,
            scan_date=datetime.now(UTC) - timedelta(days=90),
        )
        # Create recent scan
        recent_scan = make_scan(container_id=container.id, scan_date=datetime.now(UTC))
        db_session.add_all([old_scan, recent_scan])
        await db_session.commit()

        # Mock retention setting (60 days)
        with patch(
            "app.services.cleanup_service.SettingsManager.get_int",
            return_value=60,
        ):
            # Act
            result = await CleanupService.cleanup_old_scans(db_session)

        # Assert
        assert isinstance(result, dict)
        assert "scans_deleted" in result
        assert "vulnerabilities_deleted" in result
        assert "retention_days" in result
        assert "cutoff_date" in result
        assert result["retention_days"] == 60
        assert result["scans_deleted"] >= 1

        # Verify old scan was deleted
        scan_result = await db_session.execute(select(Scan).where(Scan.id == old_scan.id))
        assert scan_result.scalar_one_or_none() is None

        # Verify recent scan still exists
        scan_result = await db_session.execute(select(Scan).where(Scan.id == recent_scan.id))
        assert scan_result.scalar_one_or_none() is not None

    @pytest.mark.asyncio
    async def test_cleanup_old_scans_with_auto_session(self, db_session, make_container, make_scan):
        """Test cleanup creates own session when db=None."""
        from app.services.cleanup_service import CleanupService

        # Arrange
        container = make_container()
        db_session.add(container)
        await db_session.commit()
        await db_session.refresh(container)

        # Create old scan
        old_scan = make_scan(
            container_id=container.id,
            scan_date=datetime.now(UTC) - timedelta(days=100),
        )
        db_session.add(old_scan)
        await db_session.commit()

        # Mock retention setting (60 days)
        with patch(
            "app.services.cleanup_service.SettingsManager.get_int",
            return_value=60,
        ):
            # Act - call with None to trigger auto-session creation
            result = await CleanupService.cleanup_old_scans(None)

        # Assert
        assert isinstance(result, dict)
        assert "scans_deleted" in result

    @pytest.mark.asyncio
    async def test_cleanup_preserves_recent_scans(self, db_session, make_container, make_scan):
        """Test cleanup preserves scans within retention period."""
        from sqlalchemy import select

        from app.models import Scan
        from app.services.cleanup_service import CleanupService

        # Arrange
        container = make_container()
        db_session.add(container)
        await db_session.commit()
        await db_session.refresh(container)

        # Create only recent scans
        recent_scans = []
        for days_ago in [1, 5, 10, 20]:
            scan = make_scan(
                container_id=container.id,
                scan_date=datetime.now(UTC) - timedelta(days=days_ago),
            )
            db_session.add(scan)
            recent_scans.append(scan)
        await db_session.commit()

        # Mock retention setting (60 days)
        with patch(
            "app.services.cleanup_service.SettingsManager.get_int",
            return_value=60,
        ):
            # Act
            result = await CleanupService.cleanup_old_scans(db_session)

        # Assert
        assert result["scans_deleted"] == 0

        # Verify all scans still exist
        for scan in recent_scans:
            scan_result = await db_session.execute(select(Scan).where(Scan.id == scan.id))
            assert scan_result.scalar_one_or_none() is not None

    @pytest.mark.asyncio
    async def test_get_cleanup_stats(self, db_session, make_container, make_scan):
        """Test getting cleanup statistics."""
        from app.services.cleanup_service import CleanupService

        # Arrange
        container = make_container()
        db_session.add(container)
        await db_session.commit()
        await db_session.refresh(container)

        # Create mix of old and recent scans
        for days_ago in [5, 10, 70, 80, 100]:
            scan = make_scan(
                container_id=container.id,
                scan_date=datetime.now(UTC) - timedelta(days=days_ago),
            )
            db_session.add(scan)
        await db_session.commit()

        # Mock retention setting (60 days)
        with patch(
            "app.services.cleanup_service.SettingsManager.get_int",
            return_value=60,
        ):
            # Act
            stats = await CleanupService.get_cleanup_stats(db_session)

        # Assert
        assert isinstance(stats, dict)
        assert "total_scans" in stats
        assert "old_scans" in stats
        assert "retention_days" in stats
        assert "cutoff_date" in stats
        assert "can_clean" in stats
        assert stats["retention_days"] == 60
        assert stats["total_scans"] == 5
        assert stats["old_scans"] == 3  # 70, 80, 100 days old
        assert stats["can_clean"] is True

    @pytest.mark.asyncio
    async def test_get_cleanup_stats_no_old_scans(self, db_session, make_container, make_scan):
        """Test cleanup stats when no old scans exist."""
        from app.services.cleanup_service import CleanupService

        # Arrange
        container = make_container()
        db_session.add(container)
        await db_session.commit()
        await db_session.refresh(container)

        # Create only recent scans
        for days_ago in [1, 5, 10]:
            scan = make_scan(
                container_id=container.id,
                scan_date=datetime.now(UTC) - timedelta(days=days_ago),
            )
            db_session.add(scan)
        await db_session.commit()

        # Mock retention setting (60 days)
        with patch(
            "app.services.cleanup_service.SettingsManager.get_int",
            return_value=60,
        ):
            # Act
            stats = await CleanupService.get_cleanup_stats(db_session)

        # Assert
        assert stats["total_scans"] == 3
        assert stats["old_scans"] == 0
        assert stats["can_clean"] is False
