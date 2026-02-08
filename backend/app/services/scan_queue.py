"""Scan queue service for managing async scan operations."""

import asyncio
import logging
from collections import deque
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from functools import total_ordering

from sqlalchemy import select

from app.database import db_session
from app.models import Container, FalsePositivePattern, Scan, Secret, Vulnerability
from app.services.activity_logger import ActivityLogger
from app.services.cache_manager import get_cache
from app.services.dive_service import DiveError, DiveService
from app.services.docker_client import DockerService
from app.services.network_check import get_connectivity_checker
from app.services.scan_errors import get_error_classifier
from app.services.scan_events import scan_events
from app.services.settings_manager import SettingsManager
from app.services.trivy_health import TrivyHealthMonitor
from app.services.trivy_scanner import TrivyScanner
from app.utils.timezone import get_now

logger = logging.getLogger(__name__)


class ScanPriority(Enum):
    """Scan priority levels."""

    HIGH = 1  # Individual container scans
    NORMAL = 2  # Scheduled scans
    LOW = 3  # Bulk scans


@total_ordering
@dataclass
class ScanJob:
    """Represents a scan job in the queue."""

    container_id: int
    container_name: str
    priority: ScanPriority
    retry_count: int = 0
    max_retries: int = 3
    created_at: datetime | None = None

    def __post_init__(self):
        """Initialize created_at if not provided."""
        if self.created_at is None:
            self.created_at = get_now()

    def __lt__(self, other):
        """Compare jobs by priority for priority queue."""
        if self.priority.value != other.priority.value:
            return self.priority.value < other.priority.value
        return self.created_at < other.created_at

    def __eq__(self, other):
        """Check equality for priority queue."""
        return (
            self.priority.value == other.priority.value
            and self.created_at == other.created_at
            and self.container_id == other.container_id
        )


class ScanQueue:
    """Manages async scan queue with worker pool."""

    def __init__(self):
        """Initialize scan queue."""
        self.queue: asyncio.PriorityQueue = asyncio.PriorityQueue()
        self.active_scans: set[int] = set()  # Container IDs currently scanning
        self.queued_scans: set[int] = set()  # Container IDs queued but not yet scanning
        self.workers: list[asyncio.Task] = []
        self.running = False
        self._current_scan: str | None = None
        self._batch_total = 0  # Total containers in current batch
        self._batch_completed = 0  # Completed scans in current batch
        self._batch_results: list[dict] = []  # Store results for batch summary
        self._abort_requested: set[int] = set()  # Container IDs requested for abort
        self._current_scan_tasks: dict[int, asyncio.Task] = {}  # Active scan tasks for abort
        self._recent_durations: deque[float] = deque(maxlen=50)
        self._recent_queue_waits: deque[float] = deque(maxlen=50)
        self._processed_count = 0
        self.trivy_scanner: TrivyScanner | None = None  # Shared scanner instance

    async def start(self, num_workers: int = 3, trivy_scanner: TrivyScanner | None = None):
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

        # Clean up any pending broadcast tasks
        await scan_events.cleanup_tasks()

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
            while self.running:
                try:
                    # Get job from queue with timeout
                    _, _, job = await asyncio.wait_for(self.queue.get(), timeout=1.0)
                except TimeoutError:
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

                # Create a DockerService per job so we always respect the latest
                # docker_socket_proxy setting and can refresh connections as needed.
                try:
                    job_docker_service = DockerService()
                except Exception as e:
                    logger.error(
                        f"Worker {worker_id} failed to initialize Docker client for job {job.container_name}: {e}"
                    )
                    self.active_scans.discard(job.container_id)
                    self._current_scan = None
                    self.queue.task_done()
                    self._emit_status_update()
                    continue

                # Create and track the scan task for abort functionality
                scan_task = asyncio.create_task(self._process_scan(job, job_docker_service))
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
                        await self.queue.put((ScanPriority.LOW.value, get_now(), job))
                        logger.info(f"Re-queued {job.container_name} (retry {job.retry_count})")
                    else:
                        logger.error(f"Max retries exceeded for {job.container_name}, giving up")

                finally:
                    self.active_scans.discard(job.container_id)
                    self._current_scan_tasks.pop(job.container_id, None)
                    if not self.active_scans:
                        self._current_scan = None
                    self.queue.task_done()
                    self._emit_status_update()
                    job_docker_service.close()
        finally:
            logger.info(f"Worker {worker_id} stopped")

    @staticmethod
    def _as_int(value: str | None, default: int) -> int:
        """Convert a string setting value to int with fallback."""
        try:
            return int(value) if value is not None else default
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _as_bool(value: str | None, default: bool) -> bool:
        """Convert a string setting value to bool with fallback."""
        if value is None:
            return default
        return str(value).lower() in ("true", "1", "yes", "on")

    async def _store_vulnerabilities_with_kev(
        self,
        db,
        scan: Scan,
        vulnerabilities: list[dict],
    ) -> int:
        """Store vulnerabilities with KEV enrichment. Returns KEV match count."""
        settings_manager = SettingsManager(db)
        kev_enabled = await settings_manager.get_bool("kev_checking_enabled", default=True)

        from app.services.kev import get_kev_service

        kev_service = get_kev_service()
        if kev_enabled:
            await kev_service.ensure_catalog_loaded()

        kev_count = 0
        for vuln_data in vulnerabilities:
            is_kev = False
            kev_added_date = None
            kev_due_date = None

            if kev_enabled:
                kev_info = kev_service.get_kev_info(vuln_data["cve_id"])
                if kev_info:
                    is_kev = True
                    kev_added_date = kev_info.get("date_added")
                    kev_due_date = kev_info.get("due_date")
                    kev_count += 1

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
                is_kev=is_kev,
                kev_added_date=kev_added_date,
                kev_due_date=kev_due_date,
            )
            db.add(vuln)

        return kev_count

    async def _store_secrets_with_fp_matching(
        self,
        db,
        scan: Scan,
        container: Container,
        secrets_data: list[dict],
    ) -> list[dict]:
        """Store secrets with false-positive pattern matching. Returns non-FP secrets."""
        non_fp_secrets: list[dict] = []
        for secret_data in secrets_data:
            fp_patterns_query = await db.execute(
                select(FalsePositivePattern).where(
                    FalsePositivePattern.container_name == container.name,
                    FalsePositivePattern.file_path == secret_data.get("file_path", ""),
                    FalsePositivePattern.rule_id == secret_data["rule_id"],
                )
            )
            fp_pattern_match = fp_patterns_query.scalar_one_or_none()

            initial_status = "to_review"
            if fp_pattern_match:
                initial_status = "false_positive"
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

            if initial_status != "false_positive":
                non_fp_secrets.append(secret_data)

        return non_fp_secrets

    async def _notify_secrets_detected(
        self,
        db,
        container: Container,
        scan: Scan,
        secrets_list: list[dict],
    ) -> None:
        """Send notifications and log activity for detected secrets."""
        from app.services.notifications import NotificationDispatcher

        secret_critical = sum(1 for s in secrets_list if s["severity"] == "CRITICAL")
        secret_high = sum(1 for s in secrets_list if s["severity"] == "HIGH")
        secret_categories = list(set(s["category"] for s in secrets_list))

        dispatcher = NotificationDispatcher(db)
        await dispatcher.notify_secrets_detected(
            container_name=container.name,
            total_secrets=len(secrets_list),
            critical_count=secret_critical,
            high_count=secret_high,
            categories=secret_categories,
        )

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

    async def _run_dive_analysis(
        self,
        docker_service: DockerService,
        container: Container,
        image_ref: str,
    ) -> None:
        """Run Dive image efficiency analysis. Errors are logged but don't fail the scan."""
        try:
            dive_service = DiveService(docker_service)
            dive_results = await dive_service.analyze_image(image_ref)

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
            logger.warning(
                f"Dive analysis failed for {container.name}: {e}. "
                f"Scan completed successfully without efficiency data."
            )
            container.dive_efficiency_score = None
            container.dive_inefficient_bytes = None
            container.dive_image_size_bytes = None
            container.dive_layer_count = None
            container.dive_analyzed_at = None

    async def _log_scan_activity(
        self,
        db,
        container: Container,
        scan: Scan,
        duration: float,
    ) -> None:
        """Log activity events for a successful scan."""
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

    @staticmethod
    async def _log_scan_failure(db, container: Container, scan_id: int, error_message: str) -> None:
        """Log activity event for a failed scan."""
        try:
            activity_logger = ActivityLogger(db)
            await activity_logger.log_scan_failed(
                container_name=container.name,
                container_id=container.id,
                error_message=error_message,
                scan_id=scan_id,
            )
        except Exception as e:
            logger.error(f"Failed to log scan failure activity: {e}", exc_info=True)

    async def _process_scan(self, job: ScanJob, docker_service: DockerService):
        """Process a single scan job — orchestrator for scan lifecycle."""

        result_payload: dict | None = None

        try:
            async with db_session() as db:
                try:
                    # --- Fetch settings ---
                    settings_manager = SettingsManager(db)
                    settings_values = await settings_manager.get_many(
                        [
                            "scan_timeout",
                            "enable_secret_scanning",
                            "scanner_db_max_age_hours",
                            "scanner_skip_db_update_when_fresh",
                            "scanner_stale_db_warning_hours",
                        ]
                    )

                    timeout = self._as_int(settings_values.get("scan_timeout"), 300)
                    enable_secret_scanning = self._as_bool(
                        settings_values.get("enable_secret_scanning"), True
                    )

                    # --- Load container ---
                    result = await db.execute(
                        select(Container).where(Container.id == job.container_id)
                    )
                    container = result.scalar_one_or_none()
                    if not container:
                        logger.error(f"Container {job.container_id} not found in database")
                        return

                    # Refresh image tag from Docker before scanning
                    live_container = docker_service.get_container(container.name)
                    if live_container:
                        old_tag = container.image_tag
                        new_tag = live_container.get("image_tag", container.image_tag)
                        if old_tag != new_tag:
                            logger.info(
                                f"Container {container.name} image tag changed: "
                                f"{old_tag} → {new_tag} (refreshing before scan)"
                            )
                            container.image = live_container.get("image", container.image)
                            container.image_tag = new_tag
                            container.image_id = live_container.get("image_id", container.image_id)
                            await db.commit()
                            await db.refresh(container)

                    # --- Create scan record ---
                    scan = Scan(
                        container_id=container.id,
                        scan_status="in_progress",
                        image_scanned=f"{container.image}:{container.image_tag}",
                    )
                    db.add(scan)
                    await db.commit()
                    await db.refresh(scan)

                    container.last_scan_status = "in_progress"
                    await db.commit()

                    # --- Prepare scanner + health checks ---
                    trivy_scanner = self.trivy_scanner or TrivyScanner(docker_service)

                    max_db_age_hours = self._as_int(
                        settings_values.get("scanner_db_max_age_hours"), 24
                    )
                    skip_db_when_fresh = self._as_bool(
                        settings_values.get("scanner_skip_db_update_when_fresh"), True
                    )
                    stale_warning_hours = self._as_int(
                        settings_values.get("scanner_stale_db_warning_hours"), 72
                    )

                    trivy_health = TrivyHealthMonitor(trivy_scanner)
                    trivy_db_health = await trivy_health.check_database_health(
                        max_age_hours=max_db_age_hours, stale_warning_hours=stale_warning_hours
                    )
                    skip_trivy_db_update = skip_db_when_fresh and trivy_db_health.can_skip_update

                    connectivity_checker = get_connectivity_checker()
                    network_status = await connectivity_checker.check_connectivity()

                    logger.info(
                        f"Network pre-flight check: {network_status.status.value} - "
                        f"{len(network_status.reachable_hosts)}/{len(connectivity_checker.test_hosts)} hosts reachable"
                    )

                    if network_status.is_offline and not skip_trivy_db_update:
                        logger.warning(
                            "System is OFFLINE but scanner DB updates are required. "
                            "Scan may fail. Consider enabling 'Skip DB update when fresh' in settings."
                        )

                    try:
                        start_time = get_now()
                        image_ref = f"{container.image}:{container.image_tag}"

                        # --- Run Trivy scanner ---
                        logger.info(f"Running Trivy scanner for {container.name}")
                        try:
                            trivy_result = await asyncio.wait_for(
                                trivy_scanner.scan_image(
                                    image_ref,
                                    scan_secrets=enable_secret_scanning,
                                    skip_db_update=skip_trivy_db_update,
                                ),
                                timeout=timeout,
                            )
                        except Exception as e:
                            error_msg = str(e)
                            logger.error(f"Trivy scan failed: {error_msg}")

                            error_classifier = get_error_classifier()
                            classified_error = error_classifier.classify_error(
                                scanner_name="Trivy",
                                error_message=error_msg,
                                db_age_hours=trivy_db_health.age_hours,
                            )
                            logger.warning(
                                f"Trivy error classified as {classified_error.error_type.value}: "
                                f"{classified_error.user_message}"
                            )
                            for suggestion in classified_error.suggestions:
                                logger.info(f"  → {suggestion}")

                            trivy_result = None

                        # --- Process results ---
                        import json

                        vulnerabilities = []
                        if trivy_result:
                            for vuln in trivy_result.get("vulnerabilities", []):
                                vuln["scanner"] = "trivy"
                                vuln["confidence"] = "MEDIUM"
                                vuln["found_by_scanners"] = json.dumps(["trivy"])
                                vulnerabilities.append(vuln)

                        secrets_raw = trivy_result.get("secrets", []) if trivy_result else []
                        duration = (get_now() - start_time).total_seconds()

                        if trivy_result is not None:
                            # Compute severity counts
                            severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
                            fixable_count = 0
                            for vuln in vulnerabilities:
                                sev = vuln.get("severity", "UNKNOWN")
                                severity_counts[sev] = severity_counts.get(sev, 0) + 1
                                if vuln.get("is_fixable", False):
                                    fixable_count += 1

                            # CVE delta
                            current_cves = {v["cve_id"] for v in vulnerabilities}
                            previous_cves: set[str] = set()
                            prev_scan_result = await db.execute(
                                select(Scan)
                                .where(
                                    Scan.container_id == container.id,
                                    Scan.scan_status == "completed",
                                    Scan.id != scan.id,
                                )
                                .order_by(Scan.scan_date.desc())
                                .limit(1)
                            )
                            prev_scan = prev_scan_result.scalar_one_or_none()
                            if prev_scan:
                                prev_vulns_result = await db.execute(
                                    select(Vulnerability.cve_id).where(
                                        Vulnerability.scan_id == prev_scan.id
                                    )
                                )
                                previous_cves = {row[0] for row in prev_vulns_result.fetchall()}

                            cves_fixed = list(previous_cves - current_cves)
                            cves_introduced = list(current_cves - previous_cves)
                            if cves_fixed or cves_introduced:
                                logger.info(
                                    f"CVE delta for {container.name}: "
                                    f"{len(cves_fixed)} fixed, {len(cves_introduced)} introduced"
                                )

                            # Update scan record
                            scan.scan_status = "completed"
                            scan.cves_fixed = json.dumps(cves_fixed) if cves_fixed else None
                            scan.cves_introduced = (
                                json.dumps(cves_introduced) if cves_introduced else None
                            )
                            scan.scan_duration_seconds = duration
                            scan.total_vulns = len(vulnerabilities)
                            scan.fixable_vulns = fixable_count
                            scan.critical_count = severity_counts["CRITICAL"]
                            scan.high_count = severity_counts["HIGH"]
                            scan.medium_count = severity_counts["MEDIUM"]
                            scan.low_count = severity_counts["LOW"]

                            logger.info(
                                f"Trivy scan successful - "
                                f"DB age: {trivy_db_health.age_hours}h (skip_update={skip_trivy_db_update})"
                            )

                            # Store vulnerabilities + KEV enrichment
                            kev_count = await self._store_vulnerabilities_with_kev(
                                db, scan, vulnerabilities
                            )

                            # Store secrets + FP matching
                            secrets_list = await self._store_secrets_with_fp_matching(
                                db, scan, container, secrets_raw
                            )
                            if secrets_list:
                                await self._notify_secrets_detected(
                                    db, container, scan, secrets_list
                                )

                            # Update container summary
                            container.total_vulns = scan.total_vulns
                            container.fixable_vulns = scan.fixable_vulns
                            container.critical_count = scan.critical_count
                            container.high_count = scan.high_count
                            container.medium_count = scan.medium_count
                            container.low_count = scan.low_count
                            container.last_scan_status = "completed"
                            container.scanner_coverage = 1

                            logger.info(
                                f"Scan completed for {container.name}: "
                                f"{scan.total_vulns} vulnerabilities in {duration:.1f}s"
                            )

                            # Dive analysis (non-blocking)
                            await self._run_dive_analysis(docker_service, container, image_ref)

                            # Invalidate widget caches
                            cache = get_cache()
                            await cache.invalidate_pattern("widget:*")

                            # Store batch result
                            self._batch_results.append(
                                {
                                    "container_name": container.name,
                                    "total_vulns": scan.total_vulns,
                                    "fixable_count": scan.fixable_vulns,
                                    "critical_count": scan.critical_count,
                                    "high_count": scan.high_count,
                                    "medium_count": scan.medium_count,
                                    "low_count": scan.low_count,
                                    "kev_count": kev_count,
                                    "scan_id": scan.id,
                                }
                            )

                            # Log activity
                            await self._log_scan_activity(db, container, scan, duration)

                        else:
                            # Scanner returned no data
                            scan.scan_status = "failed"
                            scan.error_message = "Scanner returned no data"
                            container.last_scan_status = "failed"
                            await self._log_scan_failure(
                                db, container, scan.id, "Scanner returned no data"
                            )

                    except TimeoutError:
                        scan.scan_status = "failed"
                        scan.error_message = f"Scan timeout after {timeout}s"
                        container.last_scan_status = "failed"
                        logger.error(f"Scan timeout for {container.name}")
                        await self._log_scan_failure(
                            db, container, scan.id, f"Scan timeout after {timeout}s"
                        )
                        raise

                    # Finalize
                    container.last_scan_date = get_now()
                    await db.commit()
                    result_payload = {
                        "duration": duration,
                        "status": scan.scan_status,
                    }
                except TimeoutError:
                    raise

        except TimeoutError:
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
        if (
            self._batch_completed >= self._batch_total
            and self.queue.qsize() == 0
            and len(self.active_scans) == 0
            and self._batch_total > 0
        ):
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
        total_kev = sum(r.get("kev_count", 0) for r in self._batch_results)

        # Calculate fixable critical and high for scan_complete notification
        fixable_critical = sum(r.get("fixable_critical", 0) for r in self._batch_results)
        fixable_high = sum(r.get("fixable_high", 0) for r in self._batch_results)

        # Get containers with KEV vulnerabilities for batched notification
        kev_containers = [
            r["container_name"] for r in self._batch_results if r.get("kev_count", 0) > 0
        ]

        # Send notification via multi-service dispatcher
        from app.services.notifications import NotificationDispatcher

        async with db_session() as db:
            dispatcher = NotificationDispatcher(db)

            # Send batched KEV notification if any KEV vulns found
            if total_kev > 0 and kev_containers:
                await dispatcher.dispatch(
                    event_type="kev_detected",
                    title="VulnForge: Exploited CVEs Detected!",
                    message=(
                        f"Batch scan found {total_kev} actively exploited CVE{'s' if total_kev != 1 else ''} "
                        f"(CISA KEV) across {len(kev_containers)} container{'s' if len(kev_containers) != 1 else ''}: "
                        f"{', '.join(kev_containers[:5])}"
                        + (
                            f" and {len(kev_containers) - 5} more"
                            if len(kev_containers) > 5
                            else ""
                        )
                    ),
                    priority="urgent",
                    tags=["kev", "exploited", "batch"],
                )

            await dispatcher.notify_scan_complete(
                total_containers=total_containers,
                critical=total_critical,
                high=total_high,
                fixable_critical=fixable_critical,
                fixable_high=fixable_high,
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

    async def get_scanner_health(
        self, max_age_hours: int = 24, stale_warning_hours: int = 72
    ) -> dict:
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
                max_age_hours = (
                    await settings_manager.get_int("scanner_db_max_age_hours", default=24) or 24
                )
                stale_warning_hours = (
                    await settings_manager.get_int("scanner_stale_db_warning_hours", default=72)
                    or 72
                )

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
_scan_queue: ScanQueue | None = None


def get_scan_queue() -> ScanQueue:
    """Get or create the global scan queue instance."""
    global _scan_queue
    if _scan_queue is None:
        _scan_queue = ScanQueue()
    return _scan_queue
