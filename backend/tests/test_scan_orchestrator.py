"""Tests for ScanOrchestrator — shared enqueue service for API and scheduler."""

from unittest.mock import AsyncMock, MagicMock

import pytest
from sqlalchemy import select

from app.models import Container, ScanJob
from app.services.scan_orchestrator import ScanOrchestrator
from app.services.scan_queue import ScanPriority, ScanQueue


@pytest.fixture(autouse=True)
def _mock_scan_events(monkeypatch):
    """Stub schedule_broadcast so _emit_status_update never touches asyncio tasks."""
    monkeypatch.setattr(
        "app.services.scan_queue.scan_events.schedule_broadcast",
        lambda _: None,
    )


@pytest.fixture
def mock_scan_queue():
    """Create a mock ScanQueue with sensible defaults."""
    q = MagicMock(spec=ScanQueue)
    q.active_scans = set()
    q.queued_scans = set()
    q.enqueue = AsyncMock(return_value=True)
    q.register_batch = MagicMock()
    return q


@pytest.fixture
async def containers(db_session):
    """Create 3 test containers."""
    result = []
    for i in range(3):
        c = Container(
            name=f"test-container-{i}",
            image=f"test-image-{i}",
            image_tag="latest",
            image_id=f"test-image-{i}:latest",
        )
        db_session.add(c)
        result.append(c)
    await db_session.commit()
    for c in result:
        await db_session.refresh(c)
    return result


class TestEnqueueContainers:
    """Test ScanOrchestrator.enqueue_containers()."""

    @pytest.mark.asyncio
    async def test_enqueue_all_containers(self, db_session, containers, mock_scan_queue):
        """container_ids=None resolves all containers and creates ScanJob per container."""
        orchestrator = ScanOrchestrator(db_session, mock_scan_queue)
        result = await orchestrator.enqueue_containers(container_ids=None, source="test")

        assert result.total_requested == 3
        assert result.queued == 3
        assert result.skipped == 0
        assert len(result.job_ids) == 3

        # Verify ScanJob rows created
        scan_jobs = await db_session.execute(select(ScanJob))
        jobs = scan_jobs.scalars().all()
        assert len(jobs) == 3
        assert all(j.status == "queued" for j in jobs)

    @pytest.mark.asyncio
    async def test_enqueue_specific_containers(self, db_session, containers, mock_scan_queue):
        """Only specified container IDs are enqueued."""
        orchestrator = ScanOrchestrator(db_session, mock_scan_queue)
        result = await orchestrator.enqueue_containers(
            container_ids=[containers[0].id], source="api"
        )

        assert result.total_requested == 1
        assert result.queued == 1
        assert len(result.job_ids) == 1

    @pytest.mark.asyncio
    async def test_enqueue_skips_active_scans(self, db_session, containers, mock_scan_queue):
        """Containers already in active_scans are skipped."""
        mock_scan_queue.active_scans = {containers[0].id}

        orchestrator = ScanOrchestrator(db_session, mock_scan_queue)
        result = await orchestrator.enqueue_containers(container_ids=None, source="api")

        assert result.queued == 2
        assert result.skipped == 1

    @pytest.mark.asyncio
    async def test_enqueue_skips_queued_scans(self, db_session, containers, mock_scan_queue):
        """Containers already in queued_scans are skipped."""
        mock_scan_queue.queued_scans = {containers[1].id}

        orchestrator = ScanOrchestrator(db_session, mock_scan_queue)
        result = await orchestrator.enqueue_containers(container_ids=None, source="api")

        assert result.queued == 2
        assert result.skipped == 1

    @pytest.mark.asyncio
    async def test_enqueue_handles_race_condition(self, db_session, containers, mock_scan_queue):
        """Enqueue failure marks orphan ScanJob as failed."""
        mock_scan_queue.enqueue = AsyncMock(return_value=False)

        orchestrator = ScanOrchestrator(db_session, mock_scan_queue)
        result = await orchestrator.enqueue_containers(container_ids=None, source="api")

        assert result.queued == 0
        assert result.skipped == 3
        assert result.job_ids == []  # No queued jobs

        # Verify all ScanJobs marked failed
        scan_jobs = await db_session.execute(select(ScanJob))
        jobs = scan_jobs.scalars().all()
        assert len(jobs) == 3
        assert all(j.status == "failed" for j in jobs)
        assert all("Enqueue failed" in j.error_message for j in jobs)
        assert all(j.completed_at is not None for j in jobs)

    @pytest.mark.asyncio
    async def test_enqueue_auto_priority(self, db_session, containers, mock_scan_queue):
        """<=3 containers = HIGH, >3 = NORMAL (when priority not specified)."""
        # 3 containers → HIGH
        orchestrator = ScanOrchestrator(db_session, mock_scan_queue)
        await orchestrator.enqueue_containers(
            container_ids=[containers[0].id, containers[1].id, containers[2].id],
            source="api",
        )
        # enqueue was called with HIGH priority
        _, kwargs = mock_scan_queue.enqueue.call_args
        assert kwargs.get("priority") is None  # positional arg
        args = mock_scan_queue.enqueue.call_args_list[0]
        assert args[0][2] == ScanPriority.HIGH

    @pytest.mark.asyncio
    async def test_enqueue_empty_returns_zero(self, db_session, mock_scan_queue):
        """No containers found returns zero-result."""
        orchestrator = ScanOrchestrator(db_session, mock_scan_queue)
        result = await orchestrator.enqueue_containers(container_ids=[99999], source="api")

        assert result.total_requested == 0
        assert result.queued == 0

    @pytest.mark.asyncio
    async def test_register_batch_called(self, db_session, containers, mock_scan_queue):
        """Orchestrator calls register_batch with container count and source."""
        orchestrator = ScanOrchestrator(db_session, mock_scan_queue)
        await orchestrator.enqueue_containers(container_ids=None, source="scheduler")

        mock_scan_queue.register_batch.assert_called_once_with(3, source="scheduler")


class TestBatchNotification:
    """Test additive batch counter behavior."""

    def test_register_batch_additive_during_active_scans(self):
        """Two register_batch calls accumulate when scans are in-flight."""
        q = ScanQueue()
        q.register_batch(5, source="api")
        assert q._batch_total == 5

        # Simulate an active scan so the second batch adds to the first
        q.active_scans.add(1)
        q.register_batch(10, source="scheduler")
        assert q._batch_total == 15

    def test_register_batch_resets_when_idle(self):
        """register_batch resets stale counters when no scans are active."""
        q = ScanQueue()
        q._batch_completed = 44
        q._batch_total = 44
        q._batch_results = [{"total_vulns": 1}] * 44

        # No active scans, empty queue — new batch should reset first
        q.register_batch(44, source="api")

        assert q._batch_total == 44
        assert q._batch_completed == 0
        assert len(q._batch_results) == 0

    def test_register_batch_preserves_during_active_scans(self):
        """register_batch preserves counters when scans are still running."""
        q = ScanQueue()
        q._batch_completed = 3
        q._batch_results = [{"total_vulns": 1}, {"total_vulns": 2}]
        q.active_scans.add(42)

        q.register_batch(5, source="api")

        assert q._batch_completed == 3
        assert len(q._batch_results) == 2
        assert q._batch_total == 5
