"""Regression tests for issues identified in Codex review (2025-02-09).

Tests cover:
- scan_id bypasses time filter in cve-delta endpoint
- Orphan ScanJob rows marked failed on enqueue miss
- ScanJob retention cleanup
- run_scans_sequentially removal (dead code)
"""

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy import select

from app.models import ScanJob


class TestCveDeltaScanIdFilter:
    """Verify scan_id lookup ignores the since_hours time window."""

    @pytest.mark.asyncio
    async def test_cve_delta_with_scan_id_ignores_time_window(
        self, authenticated_client, db_session, make_container, make_scan
    ):
        """When scan_id is provided, since_hours should not filter it out."""
        container = make_container()
        db_session.add(container)
        await db_session.commit()
        await db_session.refresh(container)

        # Create a scan from 48 hours ago (outside default 24h window)
        old_scan = make_scan(
            container_id=container.id,
            scan_status="completed",
            scan_date=datetime.now(UTC) - timedelta(hours=48),
            cves_fixed="[]",
            cves_introduced="[]",
        )
        db_session.add(old_scan)
        await db_session.commit()
        await db_session.refresh(old_scan)

        # Query with scan_id — should return even though outside 24h window
        response = await authenticated_client.get(
            f"/api/v1/scans/cve-delta?scan_id={old_scan.id}&since_hours=24"
        )
        assert response.status_code == 200
        data = response.json()
        assert data["total_scans"] == 1

    @pytest.mark.asyncio
    async def test_cve_delta_without_scan_id_respects_time_window(
        self, authenticated_client, db_session, make_container, make_scan
    ):
        """Without scan_id, since_hours should filter normally."""
        container = make_container()
        db_session.add(container)
        await db_session.commit()
        await db_session.refresh(container)

        # Create a scan from 48 hours ago
        old_scan = make_scan(
            container_id=container.id,
            scan_status="completed",
            scan_date=datetime.now(UTC) - timedelta(hours=48),
            cves_fixed="[]",
            cves_introduced="[]",
        )
        db_session.add(old_scan)
        await db_session.commit()

        # Query without scan_id — should NOT return the old scan
        response = await authenticated_client.get("/api/v1/scans/cve-delta?since_hours=24")
        assert response.status_code == 200
        data = response.json()
        assert data["total_scans"] == 0


class TestOrphanScanJobHandling:
    """Verify ScanJob rows are marked failed when enqueue fails."""

    @pytest.mark.asyncio
    async def test_orphan_scan_job_marked_failed_on_enqueue_miss(
        self, authenticated_client, db_session, make_container
    ):
        """If enqueue() returns False, the ScanJob should be marked failed."""
        container = make_container()
        db_session.add(container)
        await db_session.commit()
        await db_session.refresh(container)

        # Mock enqueue to always return False (race condition)
        mock_queue = MagicMock()
        mock_queue.active_scans = set()
        mock_queue.queued_scans = set()
        mock_queue.enqueue = AsyncMock(return_value=False)
        mock_queue.register_batch = MagicMock()

        with patch("app.services.scan_orchestrator.get_scan_queue", return_value=mock_queue):
            response = await authenticated_client.post(
                "/api/v1/scans/scan",
                json={"container_ids": [container.id]},
            )

        assert response.status_code == 200
        data = response.json()

        # Should report 0 queued, 1 skipped
        assert data["queued"] == 0
        assert data["skipped"] == 1
        # job_ids should be empty (only queued jobs returned)
        assert data["job_ids"] == []

        # Verify the ScanJob row was marked failed
        result = await db_session.execute(
            select(ScanJob).where(ScanJob.container_id == container.id)
        )
        scan_job = result.scalar_one_or_none()
        assert scan_job is not None
        assert scan_job.status == "failed"
        assert "Enqueue failed" in scan_job.error_message
        assert scan_job.completed_at is not None


class TestScanJobCleanup:
    """Verify ScanJob retention cleanup works correctly."""

    @pytest.mark.asyncio
    async def test_cleanup_deletes_old_completed_jobs(self, db_session, make_container):
        """Completed ScanJobs older than retention period should be deleted."""
        from app.services.cleanup_service import CleanupService

        container = make_container()
        db_session.add(container)
        await db_session.commit()
        await db_session.refresh(container)

        # Create old completed job (60 days ago)
        old_job = ScanJob(
            container_id=container.id,
            container_name=container.name,
            status="completed",
            created_at=datetime.now(UTC) - timedelta(days=60),
            completed_at=datetime.now(UTC) - timedelta(days=60),
        )
        # Create recent completed job
        recent_job = ScanJob(
            container_id=container.id,
            container_name=container.name,
            status="completed",
            created_at=datetime.now(UTC) - timedelta(hours=1),
            completed_at=datetime.now(UTC) - timedelta(hours=1),
        )
        db_session.add_all([old_job, recent_job])
        await db_session.commit()

        result = await CleanupService.cleanup_old_scan_jobs(db_session, retention_days=30)

        assert result["deleted"] >= 1

        # Old job should be gone
        check = await db_session.execute(select(ScanJob).where(ScanJob.id == old_job.id))
        assert check.scalar_one_or_none() is None

        # Recent job should still exist
        check = await db_session.execute(select(ScanJob).where(ScanJob.id == recent_job.id))
        assert check.scalar_one_or_none() is not None

    @pytest.mark.asyncio
    async def test_cleanup_marks_orphaned_queued_jobs_failed(self, db_session, make_container):
        """Queued ScanJobs stuck for over 1 hour should be marked failed."""
        from app.services.cleanup_service import CleanupService

        container = make_container()
        db_session.add(container)
        await db_session.commit()
        await db_session.refresh(container)

        # Create orphan job (stuck in queued for 2 hours)
        orphan = ScanJob(
            container_id=container.id,
            container_name=container.name,
            status="queued",
            created_at=datetime.now(UTC) - timedelta(hours=2),
        )
        # Create fresh queued job (just created)
        fresh = ScanJob(
            container_id=container.id,
            container_name=container.name,
            status="queued",
            created_at=datetime.now(UTC),
        )
        db_session.add_all([orphan, fresh])
        await db_session.commit()

        result = await CleanupService.cleanup_old_scan_jobs(db_session, retention_days=30)

        assert result["orphans_failed"] >= 1

        # Refresh to see updates
        await db_session.refresh(orphan)
        assert orphan.status == "failed"
        assert orphan.error_message is not None
        assert "Orphaned" in orphan.error_message

        # Fresh job should still be queued
        await db_session.refresh(fresh)
        assert fresh.status == "queued"

    @pytest.mark.asyncio
    async def test_cleanup_preserves_active_jobs(self, db_session, make_container):
        """Processing ScanJobs should not be touched by cleanup."""
        from app.services.cleanup_service import CleanupService

        container = make_container()
        db_session.add(container)
        await db_session.commit()
        await db_session.refresh(container)

        processing_job = ScanJob(
            container_id=container.id,
            container_name=container.name,
            status="processing",
            created_at=datetime.now(UTC) - timedelta(hours=2),
        )
        db_session.add(processing_job)
        await db_session.commit()

        result = await CleanupService.cleanup_old_scan_jobs(db_session, retention_days=30)

        assert result["deleted"] == 0
        assert result["orphans_failed"] == 0

        await db_session.refresh(processing_job)
        assert processing_job.status == "processing"


class TestDeadCodeRemoval:
    """Verify dead code has been properly removed."""

    def test_run_scans_sequentially_removed(self):
        """run_scans_sequentially should no longer exist in scans module."""
        from app.routes import scans

        assert not hasattr(scans, "run_scans_sequentially")

    def test_scan_state_import_removed(self):
        """scan_state should no longer be imported in scans module."""
        import app.routes.scans as scans_module

        # Check the module doesn't reference scan_state
        assert not hasattr(scans_module, "scan_state")
