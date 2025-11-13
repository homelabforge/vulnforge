"""Scan queue service for managing async scan operations."""

import asyncio
import logging
from collections import deque
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Optional

from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import db_session
from app.models import Container, FalsePositivePattern, Scan, Secret, Vulnerability
from app.services.activity_logger import ActivityLogger
from app.services.cache_manager import get_cache
from app.services.dive_service import DiveError, DiveService
from app.services.docker_client import DockerService
from app.services.enhanced_notifier import get_enhanced_notifier
from app.services.settings_manager import SettingsManager
from app.services.trivy_scanner import TrivyScanner
from app.services.trivy_health import TrivyHealthMonitor
from app.services.network_check import get_connectivity_checker, ConnectivityStatus
from app.services.scan_errors import get_error_classifier
from app.services.scan_events import scan_events
from app.utils.timezone import get_now

logger = logging.getLogger(__name__)


class ScanPriority(Enum):
    """Scan priority levels."""

    HIGH = 1  # Individual container scans
    NORMAL = 2  # Scheduled scans
    LOW = 3  # Bulk scans


@dataclass
class ScanJob:
    """Represents a scan job in the queue."""

    container_id: int
    container_name: str
    priority: ScanPriority
    retry_count: int = 0
    max_retries: int = 3
    created_at: datetime = None

    def __post_init__(self):
        """Initialize created_at if not provided."""
        if self.created_at is None:
            self.created_at = get_now()

    def __lt__(self, other):
        """Compare jobs by priority for priority queue."""
        if self.priority.value != other.priority.value:
            return self.priority.value < other.priority.value
        return self.created_at < other.created_at


class ScanQueue:
    """Manages async scan queue with worker pool."""

    def __init__(self):
        """Initialize scan queue."""
        self.queue: asyncio.PriorityQueue = asyncio.PriorityQueue()
        self.active_scans: set[int] = set()  # Container IDs currently scanning
        self.queued_scans: set[int] = set()  # Container IDs queued but not yet scanning
        self.workers: list[asyncio.Task] = []
        self.running = False
        self._current_scan: Optional[str] = None
        self._batch_total = 0  # Total containers in current batch
        self._batch_completed = 0  # Completed scans in current batch
        self._batch_results: list[dict] = []  # Store results for batch summary
        self._abort_requested: set[int] = set()  # Container IDs requested for abort
        self._current_scan_tasks: dict[int, asyncio.Task] = {}  # Active scan tasks for abort
        self._recent_durations: deque[float] = deque(maxlen=50)
        self._recent_queue_waits: deque[float] = deque(maxlen=50)
        self._processed_count = 0
        self.trivy_scanner: Optional[TrivyScanner] = None  # Shared scanner instance

    async def start(self, num_workers: int = 3, trivy_scanner: Optional[TrivyScanner] = None):
        """Start queue workers."""
        if self.running:
            logger.warning("Scan queue already running")
            return

        self.running = True
        self.trivy_scanner = trivy_scanner
        logger.info(f"Starting scan queue with {num_workers} workers")

        # Start worker tasks
        for i in range(num_workers):
            worker = asyncio.create_task(self._worker(i))
            self.workers.append(worker)

    async def stop(self):
        """Stop queue workers gracefully."""
        logger.info("Stopping scan queue...")
        self.running = False

        # Wait for workers to finish
        for worker in self.workers:
            worker.cancel()

        await asyncio.gather(*self.workers, return_exceptions=True)
        self.workers.clear()
        logger.info("Scan queue stopped")

    async def enqueue(
        self,
        container_id: int,
        container_name: str,
        priority: ScanPriority = ScanPriority.NORMAL,
    ) -> bool:
        """
        Add a scan job to the queue.

        Returns True if job was added, False if already scanning or queued.
        """
        # Check if container is already being scanned or queued
        if container_id in self.active_scans:
            logger.info(f"Container {container_name} already scanning")
            return False

        if container_id in self.queued_scans:
            logger.info(f"Container {container_name} already queued")
            return False

        job = ScanJob(
            container_id=container_id,
            container_name=container_name,
            priority=priority,
        )

        # Mark as queued
        self.queued_scans.add(container_id)

        await self.queue.put((job.priority.value, job.created_at, job))
        logger.info(
            f"Enqueued scan for {container_name} (priority={priority.name}, queue_size={self.queue.qsize()})"
        )
        self._emit_status_update()
        return True


    async def _worker(self, worker_id: int):
        """Worker task that processes scan jobs."""
        logger.info(f"Worker {worker_id} started")

        try:
            docker_service = DockerService()
        except Exception as e:
            logger.error(f"Worker {worker_id} failed to initialize Docker client: {e}")
            return

        try:
            while self.running:
                try:
                    # Get job from queue with timeout
                    _, _, job = await asyncio.wait_for(
                        self.queue.get(), timeout=1.0
                    )
                except asyncio.TimeoutError:
                    continue
                except asyncio.CancelledError:
                    logger.info(f"Worker {worker_id} cancelled")
                    break
                except Exception as e:
                    logger.error(f"Worker {worker_id} queue get error: {e}")
                    continue

                # Check if abort was requested
                if job.container_id in self._abort_requested:
                    logger.info(f"Worker {worker_id} skipping aborted scan: {job.container_name}")
                    self._abort_requested.discard(job.container_id)
                    self.queued_scans.discard(job.container_id)
                    self.queue.task_done()
                    self._emit_status_update()
                    continue

                # Move from queued to active
                self.queued_scans.discard(job.container_id)
                self.active_scans.add(job.container_id)
                self._current_scan = job.container_name
                self._emit_status_update()

                # Create and track the scan task for abort functionality
                scan_task = asyncio.create_task(self._process_scan(job, docker_service))
                self._current_scan_tasks[job.container_id] = scan_task

                try:
                    logger.info(
                        f"Worker {worker_id} processing: {job.container_name} "
                        f"(attempt {job.retry_count + 1}/{job.max_retries + 1})"
                    )

                    scan_result = await scan_task
                    logger.info(f"Worker {worker_id} completed: {job.container_name}")

                    await self.increment_completed()

                    if isinstance(scan_result, dict):
                        duration = scan_result.get("duration")
                        if duration is not None:
                            queue_wait = (get_now() - job.created_at).total_seconds()
                            self._record_metrics(duration=duration, queue_wait=queue_wait)

                except Exception as e:
                    logger.error(f"Worker {worker_id} scan error for {job.container_name}: {e}")

                    if job.retry_count < job.max_retries:
                        job.retry_count += 1
                        self.queued_scans.add(job.container_id)
                        await self.queue.put((
                            ScanPriority.LOW.value,
                            get_now(),
                            job
                        ))
                        logger.info(f"Re-queued {job.container_name} (retry {job.retry_count})")
                    else:
                        logger.error(
                            f"Max retries exceeded for {job.container_name}, giving up"
                        )

                finally:
                    self.active_scans.discard(job.container_id)
                    self._current_scan_tasks.pop(job.container_id, None)
                    if not self.active_scans:
                        self._current_scan = None
                    self.queue.task_done()
                    self._emit_status_update()
        finally:
            docker_service.close()
            logger.info(f"Worker {worker_id} stopped")

    async def _process_scan(self, job: ScanJob, docker_service: DockerService):
        """Process a single scan job."""
    
        result_payload: dict | None = None
    
        def _as_int(value: str | None, default: int) -> int:
            try:
                return int(value) if value is not None else default
            except (TypeError, ValueError):
                return default
    
        def _as_bool(value: str | None, default: bool) -> bool:
            if value is None:
                return default
            return str(value).lower() in ("true", "1", "yes", "on")
    
        try:
            # Get settings for timeout
            async with db_session() as db:
                try:
                    settings_manager = SettingsManager(db)
                    settings_values = await settings_manager.get_many([
                        "scan_timeout",
                        "enable_secret_scanning",
                        "scanner_db_max_age_hours",
                        "scanner_skip_db_update_when_fresh",
                        "scanner_stale_db_warning_hours",
                    ])
    
                    timeout = _as_int(settings_values.get("scan_timeout"), 300)
                    enable_secret_scanning = _as_bool(settings_values.get("enable_secret_scanning"), True)
    
                    # Get container from DB
                    result = await db.execute(
                        select(Container).where(Container.id == job.container_id)
                    )
                    container = result.scalar_one_or_none()
    
                    if not container:
                        logger.error(f"Container {job.container_id} not found in database")
                        return
    
                    # Create scan record
                    scan = Scan(
                        container_id=container.id,
                        scan_status="in_progress",
                        image_scanned=f"{container.image}:{container.image_tag}",
                    )
                    db.add(scan)
                    await db.commit()
                    await db.refresh(scan)
    
                    # Update container status
                    container.last_scan_status = "in_progress"
                    await db.commit()

                    # Use shared Trivy scanner (fallback to creating if not provided)
                    trivy_scanner = self.trivy_scanner or TrivyScanner(docker_service)

                    # Get offline resilience settings
                    max_db_age_hours = _as_int(settings_values.get("scanner_db_max_age_hours"), 24)
                    skip_db_when_fresh = _as_bool(settings_values.get("scanner_skip_db_update_when_fresh"), True)
                    stale_warning_hours = _as_int(settings_values.get("scanner_stale_db_warning_hours"), 72)
    
                    # Check Trivy DB freshness using health monitor
                    trivy_health = TrivyHealthMonitor(trivy_scanner)
                    trivy_db_health = await trivy_health.check_database_health(
                        max_age_hours=max_db_age_hours,
                        stale_warning_hours=stale_warning_hours
                    )
    
                    # Determine if we should skip DB update based on settings
                    skip_trivy_db_update = skip_db_when_fresh and trivy_db_health.can_skip_update
    
                    # Pre-flight network connectivity check
                    connectivity_checker = get_connectivity_checker()
                    network_status = await connectivity_checker.check_connectivity()
    
                    logger.info(
                        f"Network pre-flight check: {network_status.status.value} - "
                        f"{len(network_status.reachable_hosts)}/{len(connectivity_checker.test_hosts)} hosts reachable"
                    )
    
                    # Warn if offline but not skipping DB updates
                    if network_status.is_offline and not skip_trivy_db_update:
                        logger.warning(
                            f"System is OFFLINE but scanner DB updates are required. "
                            f"Scan may fail. Consider enabling 'Skip DB update when fresh' in settings."
                        )
    
                    # Track scanner status
                    scanner_status = {
                        "trivy": {
                            "attempted": False,
                            "success": False,
                            "error": None,
                            "classified_error": None,
                            "db_age_hours": trivy_db_health.age_hours,
                            "db_status": trivy_db_health.status.value,
                            "db_freshness": trivy_db_health.freshness.value,
                            "warnings": trivy_db_health.warnings,
                        },
                        "network": {
                            "status": network_status.status.value,
                            "reachable_hosts": network_status.reachable_hosts,
                            "unreachable_hosts": network_status.unreachable_hosts,
                        },
                    }
    
                    try:
                        start_time = get_now()
                        # Build image reference
                        image_ref = f"{container.image}:{container.image_tag}"

                        # Run Trivy scanner
                        logger.info(f"Running Trivy scanner for {container.name}")
                        scanner_status["trivy"]["attempted"] = True

                        try:
                            trivy_result = await asyncio.wait_for(
                                trivy_scanner.scan_image(
                                    image_ref,
                                    scan_secrets=enable_secret_scanning,
                                    skip_db_update=skip_trivy_db_update
                                ),
                                timeout=timeout,
                            )
                            scanner_status["trivy"]["success"] = True
                        except Exception as e:
                            error_msg = str(e)
                            logger.error(f"Trivy scan failed: {error_msg}")

                            # Classify the error with actionable suggestions
                            error_classifier = get_error_classifier()
                            classified_error = error_classifier.classify_error(
                                scanner_name="Trivy",
                                error_message=error_msg,
                                db_age_hours=trivy_db_health.age_hours
                            )

                            scanner_status["trivy"]["error"] = error_msg
                            scanner_status["trivy"]["classified_error"] = classified_error.to_dict()

                            # Log actionable suggestions
                            logger.warning(
                                f"Trivy error classified as {classified_error.error_type.value}: "
                                f"{classified_error.user_message}"
                            )
                            for suggestion in classified_error.suggestions:
                                logger.info(f"  → {suggestion}")

                            trivy_result = None

                        # Process Trivy results - add scanner metadata
                        vulnerabilities = []
                        if trivy_result:
                            import json
                            for vuln in trivy_result.get("vulnerabilities", []):
                                vuln["scanner"] = "trivy"
                                vuln["confidence"] = "MEDIUM"
                                vuln["found_by_scanners"] = json.dumps(["trivy"])
                                vulnerabilities.append(vuln)

                        secrets = trivy_result.get("secrets", []) if trivy_result else []
    
                        duration = (get_now() - start_time).total_seconds()

                        # Process results
                        if vulnerabilities or secrets:
                            # Calculate summary statistics from vulnerabilities
                            severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
                            fixable_count = 0
                            for vuln in vulnerabilities:
                                severity = vuln.get("severity", "UNKNOWN")
                                severity_counts[severity] = severity_counts.get(severity, 0) + 1
                                if vuln.get("is_fixable", False):
                                    fixable_count += 1
    
                            # Update scan with results
                            scan.scan_status = "completed"
                            scan.scan_duration_seconds = duration
                            scan.total_vulns = len(vulnerabilities)
                            scan.fixable_vulns = fixable_count
                            scan.critical_count = severity_counts["CRITICAL"]
                            scan.high_count = severity_counts["HIGH"]
                            scan.medium_count = severity_counts["MEDIUM"]
                            scan.low_count = severity_counts["LOW"]
    
                            # Log scanner status for monitoring
                            logger.info(
                                f"Trivy scan {'successful' if scanner_status['trivy']['success'] else 'failed'} - "
                                f"DB age: {trivy_db_health.age_hours}h (skip_update={skip_trivy_db_update})"
                            )

                            # Store vulnerabilities with scanner metadata
                            for vuln_data in vulnerabilities:
                                vuln = Vulnerability(
                                    scan_id=scan.id,
                                    cve_id=vuln_data["cve_id"],
                                    package_name=vuln_data["package_name"],
                                    severity=vuln_data["severity"],
                                    cvss_score=vuln_data.get("cvss_score"),
                                    title=vuln_data.get("title"),
                                    description=vuln_data.get("description"),
                                    installed_version=vuln_data["installed_version"],
                                    fixed_version=vuln_data.get("fixed_version"),
                                    is_fixable=vuln_data["is_fixable"],
                                    primary_url=vuln_data.get("primary_url"),
                                    references=vuln_data.get("references"),
                                    scanner=vuln_data.get("scanner", "trivy"),
                                    confidence=vuln_data.get("confidence"),
                                    found_by_scanners=vuln_data.get("found_by_scanners"),
                                )
                                db.add(vuln)
    
                            # Store secrets (with automatic FP pattern matching)
                            secrets_list = []
                            for secret_data in secrets:
                                # Check if this matches a false positive pattern
                                fp_pattern_match = None
                                fp_patterns_query = await db.execute(
                                    select(FalsePositivePattern).where(
                                        FalsePositivePattern.container_name == container.name,
                                        FalsePositivePattern.file_path
                                        == secret_data.get("file_path", ""),
                                        FalsePositivePattern.rule_id == secret_data["rule_id"],
                                    )
                                )
                                fp_pattern_match = fp_patterns_query.scalar_one_or_none()
    
                                # Determine initial status based on FP pattern
                                initial_status = "to_review"
                                if fp_pattern_match:
                                    initial_status = "false_positive"
                                    # Update pattern statistics
                                    fp_pattern_match.match_count += 1
                                    fp_pattern_match.last_matched = get_now()
    
                                secret = Secret(
                                    scan_id=scan.id,
                                    rule_id=secret_data["rule_id"],
                                    category=secret_data["category"],
                                    title=secret_data["title"],
                                    severity=secret_data["severity"],
                                    match=secret_data["match"],
                                    start_line=secret_data.get("start_line"),
                                    end_line=secret_data.get("end_line"),
                                    code_snippet=secret_data.get("code_snippet"),
                                    layer_digest=secret_data.get("layer_digest"),
                                    file_path=secret_data.get("file_path"),
                                    status=initial_status,
                                )
                                db.add(secret)
    
                                # Only add to notification list if NOT a false positive
                                if initial_status != "false_positive":
                                    secrets_list.append(secret_data)
    
                            # Send notification if secrets detected
                            if secrets_list:
                                from app.services.notifier import NotificationService
    
                                # Count secrets by severity
                                secret_critical = sum(1 for s in secrets_list if s["severity"] == "CRITICAL")
                                secret_high = sum(1 for s in secrets_list if s["severity"] == "HIGH")
    
                                # Get unique categories
                                secret_categories = list(set(s["category"] for s in secrets_list))
    
                                notifier = NotificationService()
                                await notifier.notify_secrets_detected(
                                    container_name=container.name,
                                    total_secrets=len(secrets_list),
                                    critical_count=secret_critical,
                                    high_count=secret_high,
                                    categories=secret_categories,
                                )
    
                                # Log activity: secrets detected (non-invasive)
                                try:
                                    activity_logger = ActivityLogger(db)
                                    await activity_logger.log_secret_detected(
                                        container_name=container.name,
                                        container_id=container.id,
                                        scan_id=scan.id,
                                        total_secrets=len(secrets_list),
                                        critical_count=secret_critical,
                                        high_count=secret_high,
                                        categories=secret_categories,
                                    )
                                except Exception as e:
                                    logger.error(f"Failed to log secret detection activity: {e}", exc_info=True)
    
                            # Update container summary
                            container.total_vulns = scan.total_vulns
                            container.fixable_vulns = scan.fixable_vulns
                            container.critical_count = scan.critical_count
                            container.high_count = scan.high_count
                            container.medium_count = scan.medium_count
                            container.low_count = scan.low_count
                            container.last_scan_status = "completed"
    
                            # Set scanner coverage (always 1 for Trivy-only)
                            container.scanner_coverage = 1
    
                            logger.info(
                                f"Scan completed for {container.name}: "
                                f"{scan.total_vulns} vulnerabilities in {duration:.1f}s"
                            )
    
                            # Run Dive image efficiency analysis (non-blocking - errors logged but don't fail scan)
                            try:
                                dive_service = DiveService(docker_service)
                                dive_results = await dive_service.analyze_image(image_ref)
    
                                # Update container with Dive metrics
                                container.dive_efficiency_score = dive_results["efficiency_score"]
                                container.dive_inefficient_bytes = dive_results["inefficient_bytes"]
                                container.dive_image_size_bytes = dive_results["image_size_bytes"]
                                container.dive_layer_count = dive_results["layer_count"]
                                container.dive_analyzed_at = get_now()
    
                                logger.info(
                                    f"Dive analysis for {container.name}: "
                                    f"{dive_results['efficiency_score']:.1%} efficient, "
                                    f"{dive_results['layer_count']} layers"
                                )
    
                            except DiveError as e:
                                # Dive failed, but Trivy succeeded - log warning and continue
                                logger.warning(
                                    f"Dive analysis failed for {container.name}: {e}. "
                                    f"Scan completed successfully without efficiency data."
                                )
                                # Clear Dive data if analysis failed
                                container.dive_efficiency_score = None
                                container.dive_inefficient_bytes = None
                                container.dive_image_size_bytes = None
                                container.dive_layer_count = None
                                container.dive_analyzed_at = None
    
                            # Invalidate widget caches after successful scan
                            cache = get_cache()
                            await cache.invalidate_pattern("widget:*")
    
                            # Store result for batch summary (instead of sending per-container notification)
                            self._batch_results.append({
                                "container_name": container.name,
                                "total_vulns": scan.total_vulns,
                                "fixable_count": scan.fixable_vulns,
                                "critical_count": scan.critical_count,
                                "high_count": scan.high_count,
                                "medium_count": scan.medium_count,
                                "low_count": scan.low_count,
                                "scan_id": scan.id,
                            })
    
                            # Log activity: successful scan completion (non-invasive)
                            try:
                                activity_logger = ActivityLogger(db)
                                await activity_logger.log_scan_completed(
                                    container_name=container.name,
                                    container_id=container.id,
                                    scan_id=scan.id,
                                    duration=duration,
                                    total_vulns=scan.total_vulns,
                                    fixable_vulns=scan.fixable_vulns,
                                    critical_count=scan.critical_count,
                                    high_count=scan.high_count,
                                    medium_count=scan.medium_count,
                                    low_count=scan.low_count,
                                )
    
                                # Log high-severity event if threshold exceeded
                                if scan.critical_count > 0 or scan.high_count >= 10:
                                    await activity_logger.log_high_severity_found(
                                        container_name=container.name,
                                        container_id=container.id,
                                        scan_id=scan.id,
                                        critical_count=scan.critical_count,
                                        high_count=scan.high_count,
                                    )
                            except Exception as e:
                                logger.error(f"Failed to log scan activity: {e}", exc_info=True)
    
                        else:
                            scan.scan_status = "failed"
                            scan.error_message = "Scan returned no results"
                            container.last_scan_status = "failed"
    
                            # Log activity: scan failure (non-invasive)
                            try:
                                activity_logger = ActivityLogger(db)
                                await activity_logger.log_scan_failed(
                                    container_name=container.name,
                                    container_id=container.id,
                                    error_message="Scan returned no results",
                                    scan_id=scan.id,
                                )
                            except Exception as e:
                                logger.error(f"Failed to log scan failure activity: {e}", exc_info=True)
    
                    except asyncio.TimeoutError:
                        scan.scan_status = "failed"
                        scan.error_message = f"Scan timeout after {timeout}s"
                        container.last_scan_status = "failed"
                        logger.error(f"Scan timeout for {container.name}")
    
                        # Log activity: scan timeout (non-invasive)
                        try:
                            activity_logger = ActivityLogger(db)
                            await activity_logger.log_scan_failed(
                                container_name=container.name,
                                container_id=container.id,
                                error_message=f"Scan timeout after {timeout}s",
                                scan_id=scan.id,
                            )
                        except Exception as e:
                            logger.error(f"Failed to log scan timeout activity: {e}", exc_info=True)
    
                        raise
    
                    # Update container scan date
                    container.last_scan_date = get_now()
                    await db.commit()
                    result_payload = {
                        "duration": duration,
                        "status": scan.scan_status,
                    }
                except asyncio.TimeoutError:
                    raise

        except asyncio.TimeoutError:
            raise

        except Exception as e:
            logger.error(f"Scan processing error for {job.container_name}: {e}", exc_info=True)
            raise

        return result_payload
    
    def start_batch(self, total: int):
        """Start a new scan batch."""
        self._batch_total = total
        self._batch_completed = 0
        self._batch_results = []  # Clear previous results
        self._emit_status_update()

    async def increment_completed(self):
        """Increment completed scan count and send batch notification when done."""
        self._batch_completed += 1
        self._emit_status_update()

        # Check if batch is complete
        if (self._batch_completed >= self._batch_total and
            self.queue.qsize() == 0 and
            len(self.active_scans) == 0 and
            self._batch_total > 0):

            # Send single batch summary notification
            await self._send_batch_notification()

            # Reset batch tracking
            self._batch_total = 0
            self._batch_completed = 0
            self._batch_results = []
            self._emit_status_update()

    async def _send_batch_notification(self):
        """Send a single summary notification for the completed batch."""
        if not self._batch_results:
            return

        # Calculate batch totals
        total_containers = len(self._batch_results)
        total_vulns = sum(r["total_vulns"] for r in self._batch_results)
        total_critical = sum(r["critical_count"] for r in self._batch_results)
        total_high = sum(r["high_count"] for r in self._batch_results)
        total_fixable = sum(r["fixable_count"] for r in self._batch_results)

        # Send single notification with batch summary
        notifier = get_enhanced_notifier()
        context = {
            "total_containers": total_containers,
            "total_vulns": total_vulns,
            "critical_count": total_critical,
            "high_count": total_high,
            "fixable_count": total_fixable,
            "batch_results": self._batch_results,
        }

        await notifier.process_rules(
            event_type="scan_batch_complete",
            context=context,
            scan_id=None,
        )

        logger.info(
            f"Batch scan complete: {total_containers} containers, "
            f"{total_vulns} vulnerabilities ({total_critical} critical, {total_high} high)"
        )

        # Log activity: batch scan completion (non-invasive)
        async with db_session() as db:
            activity_logger = ActivityLogger(db)
            # Calculate duration (estimate from batch start to now)
            # Note: We don't track batch start time, so using 0 as placeholder
            await activity_logger.log_batch_scan_completed(
                containers_count=total_containers,
                total_vulns=total_vulns,
                duration=0.0,  # Batch duration tracking could be added as enhancement
                failed_count=0,  # Could track failures if needed
            )
        return result_payload

    def _record_metrics(self, duration: float, queue_wait: float) -> None:
        """Update rolling performance metrics for scan processing."""
        self._recent_durations.append(duration)
        self._recent_queue_waits.append(queue_wait)
        self._processed_count += 1

        # Emit aggregated metrics occasionally to avoid log noise
        if self._processed_count % 10 == 0:
            avg_duration = sum(self._recent_durations) / len(self._recent_durations)
            avg_wait = sum(self._recent_queue_waits) / len(self._recent_queue_waits)
            logger.info(
                "Scan queue metrics: avg_duration=%.2fs avg_queue_wait=%.2fs (window=%d)",
                avg_duration,
                avg_wait,
                len(self._recent_durations),
            )

    def get_status(self) -> dict:
        """Get current queue status."""
        return {
            "queue_size": self.queue.qsize(),
            "active_scans": len(self.active_scans),
            "current_scan": self._current_scan,
            "workers_active": len([w for w in self.workers if not w.done()]),
            "batch_total": self._batch_total,
            "batch_completed": self._batch_completed,
        }

    def get_progress_snapshot(self) -> dict:
        """Return combined scan and queue status suitable for clients."""
        queue_status = self.get_status()
        is_scanning = queue_status["active_scans"] > 0 or queue_status["queue_size"] > 0

        if is_scanning:
            status = {
                "status": "scanning",
                "current_container": queue_status["current_scan"],
                "progress_current": queue_status["batch_completed"],
                "progress_total": queue_status["batch_total"],
            }
        else:
            status = {"status": "idle", "scan": None}

        status["queue"] = queue_status
        return status

    def _emit_status_update(self) -> None:
        """Schedule an async broadcast of the current status."""
        scan_events.schedule_broadcast(self.get_progress_snapshot())

    async def abort_scan(self, container_id: int) -> bool:
        """
        Request abort of a running or queued scan.

        Args:
            container_id: ID of container whose scan should be aborted

        Returns:
            True if abort was successful, False if scan not found
        """
        # Mark for abort
        self._abort_requested.add(container_id)

        # Cancel running scan if active
        if container_id in self._current_scan_tasks:
            task = self._current_scan_tasks[container_id]
            if not task.done():
                task.cancel()
                logger.info(f"Cancelled active scan for container {container_id}")
                self._emit_status_update()
                return True

        # Remove from queue if pending (complex - would need queue rebuild)
        # For now, just mark it and worker will skip it
        if container_id in self.active_scans or self.queue.qsize() > 0:
            logger.info(f"Marked scan for container {container_id} for abort")
            self._emit_status_update()
            return True

        logger.warning(f"No active or queued scan found for container {container_id}")
        self._emit_status_update()
        return False

    async def retry_scan(
        self,
        container_id: int,
        container_name: str,
        priority: ScanPriority = ScanPriority.HIGH,
    ) -> bool:
        """
        Retry a failed scan with high priority.

        Args:
            container_id: ID of container to retry
            container_name: Name of container
            priority: Priority for retry (default: HIGH)

        Returns:
            True if scan was queued for retry
        """
        # Remove abort flag if present
        self._abort_requested.discard(container_id)

        # Enqueue with specified priority
        result = await self.enqueue(container_id, container_name, priority)
        if result:
            logger.info(f"Queued retry scan for {container_name} with priority {priority.name}")
        else:
            logger.warning(f"Could not queue retry for {container_name} - already scanning")
        return result

    def clear_abort_flags(self):
        """Clear all abort flags."""
        cleared = len(self._abort_requested)
        self._abort_requested.clear()
        if cleared > 0:
            logger.info(f"Cleared {cleared} abort flags")

    async def get_scanner_health(self, max_age_hours: int = 24, stale_warning_hours: int = 72) -> dict:
        """
        Get health status of Trivy scanner using health monitor.

        Args:
            max_age_hours: Maximum age for database freshness (default: 24)
            stale_warning_hours: Age threshold for stale DB warning (default: 72)

        Returns:
            Dict with scanner health information
        """
        docker_service = DockerService()
        try:
            # Get settings for thresholds
            async with db_session() as db:
                settings_manager = SettingsManager(db)
                max_age_hours = await settings_manager.get_int("scanner_db_max_age_hours", default=24)
                stale_warning_hours = await settings_manager.get_int("scanner_stale_db_warning_hours", default=72)

            # Check Trivy health using health monitor
            trivy_scanner = TrivyScanner(docker_service)
            trivy_health = TrivyHealthMonitor(trivy_scanner)
            trivy_status = await trivy_health.get_status_summary(max_age_hours)

            return {
                "trivy": trivy_status,
                "settings": {
                    "max_db_age_hours": max_age_hours,
                    "stale_warning_hours": stale_warning_hours,
                },
            }
        finally:
            docker_service.close()


# Global scan queue instance
_scan_queue: Optional[ScanQueue] = None


def get_scan_queue() -> ScanQueue:
    """Get or create the global scan queue instance."""
    global _scan_queue
    if _scan_queue is None:
        _scan_queue = ScanQueue()
    return _scan_queue
