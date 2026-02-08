"""Tests for scan queue service — data structures, enqueue/dequeue, status, helpers."""

from datetime import UTC, datetime

import pytest

from app.services.scan_queue import ScanJob, ScanPriority, ScanQueue

# ---------------------------------------------------------------------------
# Autouse: prevent SSE broadcast attempts during queue operations
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _mock_scan_events(monkeypatch):
    """Stub schedule_broadcast so _emit_status_update never touches asyncio tasks."""
    monkeypatch.setattr(
        "app.services.scan_queue.scan_events.schedule_broadcast",
        lambda _: None,
    )


# ---------------------------------------------------------------------------
# Override the conftest autouse fixture that replaces ScanQueue with a dummy.
# We need the *real* ScanQueue for these tests.
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _restore_real_scan_queue(monkeypatch):
    """Undo the conftest _mock_background_services patch for get_scan_queue."""
    from app.services import scan_queue as sq_module

    # Reset the global singleton so each test gets a fresh queue.
    monkeypatch.setattr(sq_module, "_scan_queue", None)


# ============================================================
# ScanPriority
# ============================================================


class TestScanPriority:
    """Test ScanPriority enum."""

    def test_priority_ordering(self):
        """HIGH < NORMAL < LOW by numeric value."""
        assert ScanPriority.HIGH.value < ScanPriority.NORMAL.value
        assert ScanPriority.NORMAL.value < ScanPriority.LOW.value

    def test_priority_values(self):
        """Verify the concrete numeric values."""
        assert ScanPriority.HIGH.value == 1
        assert ScanPriority.NORMAL.value == 2
        assert ScanPriority.LOW.value == 3


# ============================================================
# ScanJob
# ============================================================


class TestScanJob:
    """Test ScanJob dataclass."""

    def test_scan_job_creation(self):
        """Basic creation with defaults populates correctly."""
        job = ScanJob(container_id=1, container_name="nginx", priority=ScanPriority.NORMAL)
        assert job.container_id == 1
        assert job.container_name == "nginx"
        assert job.priority == ScanPriority.NORMAL
        assert job.retry_count == 0
        assert job.max_retries == 3

    def test_scan_job_auto_created_at(self):
        """created_at is populated automatically when not provided."""
        job = ScanJob(container_id=1, container_name="nginx", priority=ScanPriority.NORMAL)
        assert job.created_at is not None
        assert isinstance(job.created_at, datetime)

    def test_scan_job_ordering_by_priority(self):
        """HIGH priority job sorts before LOW priority job."""
        high = ScanJob(container_id=1, container_name="a", priority=ScanPriority.HIGH)
        low = ScanJob(container_id=2, container_name="b", priority=ScanPriority.LOW)
        assert high < low

    def test_scan_job_ordering_same_priority_by_time(self):
        """For same priority, earlier created_at sorts first."""
        earlier = datetime(2025, 1, 1, tzinfo=UTC)
        later = datetime(2025, 1, 2, tzinfo=UTC)
        job1 = ScanJob(
            container_id=1, container_name="a", priority=ScanPriority.NORMAL, created_at=earlier
        )
        job2 = ScanJob(
            container_id=2, container_name="b", priority=ScanPriority.NORMAL, created_at=later
        )
        assert job1 < job2

    def test_scan_job_equality(self):
        """Same container_id, priority, and created_at are equal."""
        ts = datetime(2025, 6, 1, tzinfo=UTC)
        job1 = ScanJob(
            container_id=5, container_name="x", priority=ScanPriority.HIGH, created_at=ts
        )
        job2 = ScanJob(
            container_id=5, container_name="y", priority=ScanPriority.HIGH, created_at=ts
        )
        assert job1 == job2


# ============================================================
# ScanQueue unit tests (no workers)
# ============================================================


class TestScanQueueUnit:
    """Test ScanQueue methods that don't require workers."""

    def test_init_defaults(self):
        """Verify initial state after construction."""
        q = ScanQueue()
        assert q.queue.qsize() == 0
        assert len(q.active_scans) == 0
        assert len(q.queued_scans) == 0
        assert q.running is False
        assert q._current_scan is None
        assert q._batch_total == 0
        assert q._batch_completed == 0

    async def test_enqueue_success(self):
        """Enqueue returns True and updates queued_scans."""
        q = ScanQueue()
        result = await q.enqueue(1, "nginx", ScanPriority.NORMAL)
        assert result is True
        assert 1 in q.queued_scans
        assert q.queue.qsize() == 1

    async def test_enqueue_duplicate_queued(self):
        """Second enqueue for the same container returns False."""
        q = ScanQueue()
        await q.enqueue(1, "nginx", ScanPriority.NORMAL)
        result = await q.enqueue(1, "nginx", ScanPriority.NORMAL)
        assert result is False
        assert q.queue.qsize() == 1

    async def test_enqueue_duplicate_active(self):
        """Enqueue returns False if container_id is in active_scans."""
        q = ScanQueue()
        q.active_scans.add(1)
        result = await q.enqueue(1, "nginx")
        assert result is False
        assert q.queue.qsize() == 0

    def test_start_batch(self):
        """start_batch sets batch tracking state correctly."""
        q = ScanQueue()
        q.start_batch(10)
        assert q._batch_total == 10
        assert q._batch_completed == 0
        assert q._batch_results == []

    def test_get_status(self):
        """get_status returns dict with expected keys and values."""
        q = ScanQueue()
        q._batch_total = 5
        q._batch_completed = 2
        status = q.get_status()
        assert status["queue_size"] == 0
        assert status["active_scans"] == 0
        assert status["current_scan"] is None
        assert status["workers_active"] == 0
        assert status["batch_total"] == 5
        assert status["batch_completed"] == 2

    def test_get_progress_snapshot_idle(self):
        """Idle state returns status='idle' and scan=None."""
        q = ScanQueue()
        snapshot = q.get_progress_snapshot()
        assert snapshot["status"] == "idle"
        assert snapshot["scan"] is None
        assert "queue" in snapshot

    async def test_abort_scan_not_found(self):
        """abort_scan returns False when no matching scan exists."""
        q = ScanQueue()
        result = await q.abort_scan(999)
        assert result is False

    async def test_retry_scan(self):
        """retry_scan enqueues with HIGH priority by default."""
        q = ScanQueue()
        result = await q.retry_scan(1, "nginx")
        assert result is True
        assert 1 in q.queued_scans
        # Verify the queued item has HIGH priority
        priority_val, _, job = await q.queue.get()
        assert priority_val == ScanPriority.HIGH.value
        assert job.container_name == "nginx"

    def test_clear_abort_flags(self):
        """clear_abort_flags empties the abort set."""
        q = ScanQueue()
        q._abort_requested.add(1)
        q._abort_requested.add(2)
        q.clear_abort_flags()
        assert len(q._abort_requested) == 0


# ============================================================
# Helper methods (_as_int, _as_bool, _record_metrics)
# ============================================================


class TestHelperMethods:
    """Test static helper methods on ScanQueue."""

    def test_as_int_valid(self):
        """String '42' converts to int 42."""
        assert ScanQueue._as_int("42", 0) == 42

    def test_as_int_none(self):
        """None returns the default."""
        assert ScanQueue._as_int(None, 99) == 99

    def test_as_int_invalid(self):
        """Non-numeric string returns the default."""
        assert ScanQueue._as_int("abc", 7) == 7

    def test_as_bool_true_values(self):
        """Various truthy string values convert to True."""
        for val in ("true", "1", "yes", "on", "True", "YES", "ON"):
            assert ScanQueue._as_bool(val, False) is True, f"Expected True for {val!r}"

    def test_as_bool_false_values(self):
        """Non-truthy string values convert to False."""
        for val in ("false", "0", "no", "off", "anything", ""):
            assert ScanQueue._as_bool(val, True) is False, f"Expected False for {val!r}"

    def test_as_bool_none(self):
        """None returns the default."""
        assert ScanQueue._as_bool(None, True) is True
        assert ScanQueue._as_bool(None, False) is False

    def test_record_metrics(self):
        """_record_metrics populates the deques and increments counter."""
        q = ScanQueue()
        q._record_metrics(duration=12.5, queue_wait=1.2)
        assert len(q._recent_durations) == 1
        assert len(q._recent_queue_waits) == 1
        assert q._processed_count == 1
        assert q._recent_durations[0] == 12.5
        assert q._recent_queue_waits[0] == 1.2
