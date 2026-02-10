"""Scan orchestrator — shared service for enqueuing scans with ScanJob tracking.

Extracts the two-phase commit pattern from the /scan route into a reusable
service. Both the API route and the scheduler call through this single class,
ensuring ScanJob rows are always created and batch notifications are tracked.
"""

import logging
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Container, ScanJob
from app.services.scan_queue import ScanPriority, ScanQueue, get_scan_queue
from app.utils.timezone import get_now

logger = logging.getLogger(__name__)


@dataclass
class EnqueueResult:
    """Result of a batch enqueue operation."""

    queued: int = 0
    skipped: int = 0
    total_requested: int = 0
    job_ids: list[int] = field(default_factory=list)


class ScanOrchestrator:
    """Orchestrates scan enqueuing with ScanJob tracking and batch management.

    This is the ONLY entry point for creating ScanJob rows and enqueuing to the
    priority queue. Used by both the API route and the scheduler.
    """

    def __init__(self, db: AsyncSession, scan_queue: ScanQueue | None = None) -> None:
        self.db = db
        self.scan_queue = scan_queue or get_scan_queue()

    async def enqueue_containers(
        self,
        container_ids: list[int] | None = None,
        priority: ScanPriority | None = None,
        source: str = "api",
    ) -> EnqueueResult:
        """Enqueue containers for scanning with ScanJob creation.

        Two-phase commit:
          Phase 1: Create ScanJob rows (status="queued") and commit so
                   IDs are populated and visible to workers.
          Phase 2: Enqueue each to the in-memory priority queue. If an enqueue
                   fails (race condition), mark the orphan ScanJob as failed.

        Args:
            container_ids: Specific container IDs, or None for all.
            priority: Priority level. If None, auto-selects based on count
                      (<=3 = HIGH, >3 = NORMAL).
            source: Origin of the request ("api" or "scheduler") for logging.

        Returns:
            EnqueueResult with queue counts and job IDs.
        """
        # Resolve containers
        if container_ids:
            result = await self.db.execute(
                select(Container.id, Container.name).where(Container.id.in_(container_ids))
            )
        else:
            result = await self.db.execute(select(Container.id, Container.name))
        containers = result.fetchall()

        if not containers:
            return EnqueueResult(total_requested=0)

        # Auto-select priority if not specified
        if priority is None:
            priority = ScanPriority.HIGH if len(containers) <= 3 else ScanPriority.NORMAL

        # Register batch for notification tracking (additive, safe for overlapping)
        self.scan_queue.register_batch(len(containers), source=source)

        # Phase 1: Create ScanJob rows for eligible containers
        queued_count = 0
        skipped_count = 0
        scan_jobs: list[ScanJob] = []
        eligible: list[tuple[int, str]] = []

        for container_id, container_name in containers:
            if (
                container_id in self.scan_queue.active_scans
                or container_id in self.scan_queue.queued_scans
            ):
                skipped_count += 1
                continue

            scan_job = ScanJob(
                container_id=container_id,
                container_name=container_name,
                status="queued",
                created_at=get_now(),
            )
            self.db.add(scan_job)
            scan_jobs.append(scan_job)
            eligible.append((container_id, container_name))

        # Commit ScanJob rows first — IDs populated (expire_on_commit=False)
        if scan_jobs:
            await self.db.commit()

        # Phase 2: Enqueue to in-memory priority queue
        # Workers can now find the committed DB rows via _link_scan_job()
        job_by_container: dict[int, ScanJob] = {
            cid: sj for (cid, _), sj in zip(eligible, scan_jobs)
        }
        failed_jobs: list[ScanJob] = []

        for container_id, container_name in eligible:
            if await self.scan_queue.enqueue(container_id, container_name, priority):
                queued_count += 1
            else:
                # Race: another request enqueued between eligibility check and now
                skipped_count += 1
                orphan_job = job_by_container.get(container_id)
                if orphan_job:
                    orphan_job.status = "failed"
                    orphan_job.error_message = (
                        "Enqueue failed: container already queued by another request"
                    )
                    orphan_job.completed_at = get_now()
                    failed_jobs.append(orphan_job)

        if failed_jobs:
            await self.db.commit()

        logger.info(
            f"ScanOrchestrator ({source}): queued={queued_count}, "
            f"skipped={skipped_count}, total={len(containers)}"
        )

        return EnqueueResult(
            queued=queued_count,
            skipped=skipped_count,
            total_requested=len(containers),
            job_ids=[j.id for j in scan_jobs if j.status == "queued"],
        )
