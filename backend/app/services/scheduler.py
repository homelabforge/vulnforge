"""Scan scheduler service for automated scanning."""

import logging

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from sqlalchemy import select

from app.config import settings

logger = logging.getLogger(__name__)


async def scheduled_scan_task():
    """Execute scheduled scan of all containers."""
    from app.db import async_session_maker
    from app.models import Container
    from app.services.docker_client import DockerService

    logger.info("Starting scheduled scan...")

    # First, auto-discover containers before scanning
    try:
        docker_service = DockerService()
        async with async_session_maker() as db:
            docker_containers = docker_service.list_containers(all_containers=True)
            discovered = []

            for dc in docker_containers:
                result = await db.execute(select(Container).where(Container.name == dc["name"]))
                container = result.scalar_one_or_none()

                if container:
                    container.is_running = dc["is_running"]
                    container.image = dc["image"]
                    container.image_tag = dc["image_tag"]
                    container.image_id = dc["image_id"]
                else:
                    container = Container(
                        name=dc["name"],
                        image=dc["image"],
                        image_tag=dc["image_tag"],
                        image_id=dc["image_id"],
                        is_running=dc["is_running"],
                    )
                    db.add(container)
                    discovered.append(dc["name"])

            await db.commit()
            logger.info(
                f"Pre-scan discovery: {len(docker_containers)} total, {len(discovered)} new"
            )

        docker_service.close()
    except Exception as e:
        # INTENTIONAL: Pre-scan discovery failures should not stop the scan.
        # Log and continue to the actual scan.
        logger.error(f"Error during pre-scan discovery: {e}")

    # Now trigger the scan
    try:
        from app.api.scans import perform_scan

        async with async_session_maker() as db:
            # Get all container IDs
            result = await db.execute(select(Container.id))
            container_ids = [row[0] for row in result.fetchall()]

            docker_service = DockerService()

            # Queue scans for all containers
            for cid in container_ids:
                try:
                    await perform_scan(cid, db, docker_service)
                except Exception as e:
                    # INTENTIONAL: One container failure should not stop other scans.
                    logger.error(f"Error scanning container {cid}: {e}")

            docker_service.close()
            logger.info(f"Scheduled scan complete: {len(container_ids)} containers scanned")

    except Exception as e:
        # INTENTIONAL: Scheduled scan errors should be logged but not crash the scheduler.
        logger.error(f"Error during scheduled scan: {e}")


async def scheduled_compliance_scan_task():
    """Execute scheduled Docker Bench compliance scan."""
    from app.api.compliance import perform_compliance_scan
    from app.services.docker_client import DockerService

    logger.info("Starting scheduled compliance scan...")

    try:
        docker_service = DockerService()
        await perform_compliance_scan(docker_service, trigger_type="scheduled")
        docker_service.close()
        logger.info("Scheduled compliance scan complete")
    except Exception as e:
        # INTENTIONAL: Scheduled compliance scan errors should not crash the scheduler.
        logger.error(f"Error during scheduled compliance scan: {e}")


async def scheduled_kev_refresh_task():
    """Execute scheduled KEV catalog refresh."""
    from app.db import async_session_maker
    from app.models import Vulnerability
    from app.services.kev import get_kev_service
    from app.services.settings_manager import SettingsManager

    logger.info("Starting scheduled KEV catalog refresh...")

    try:
        kev_service = get_kev_service()

        # Fetch latest KEV catalog
        success = await kev_service.fetch_kev_catalog()
        if not success:
            logger.error("Failed to refresh KEV catalog")
            return

        # Update last refresh timestamp in settings
        async with async_session_maker() as db:
            settings_manager = SettingsManager(db)
            await settings_manager.set(
                "kev_last_refresh",
                kev_service.get_last_refresh().isoformat()
                if kev_service.get_last_refresh()
                else "",
            )

        # Re-check all existing vulnerabilities against updated KEV catalog
        logger.info("Re-checking all vulnerabilities against KEV catalog...")
        async with async_session_maker() as db:
            result = await db.execute(select(Vulnerability))
            vulnerabilities = result.scalars().all()

            updated_count = 0
            for vuln in vulnerabilities:
                kev_info = kev_service.get_kev_info(vuln.cve_id)

                if kev_info:
                    # CVE is in KEV catalog
                    if not vuln.is_kev:
                        vuln.is_kev = True
                        vuln.kev_added_date = kev_info.get("date_added")
                        vuln.kev_due_date = kev_info.get("due_date")
                        updated_count += 1
                else:
                    # CVE is not in KEV catalog (or was removed)
                    if vuln.is_kev:
                        vuln.is_kev = False
                        vuln.kev_added_date = None
                        vuln.kev_due_date = None
                        updated_count += 1

            await db.commit()
            logger.info(f"KEV refresh complete: {updated_count} vulnerabilities updated")

    except Exception as e:
        # INTENTIONAL: Scheduled KEV refresh errors should not crash the scheduler.
        logger.error(f"Error during KEV refresh: {e}")


class ScanScheduler:
    """Service for scheduling automated scans."""

    def __init__(self):
        """Initialize scheduler."""
        self.scheduler = AsyncIOScheduler()
        self.scan_job_id = "automated_scan"
        self.compliance_job_id = "automated_compliance_scan"
        self.kev_refresh_job_id = "automated_kev_refresh"

    def start(
        self,
        scan_schedule: str | None = None,
        compliance_schedule: str | None = None,
        kev_enabled: bool = True,
    ):
        """
        Start the scheduler.

        Args:
            scan_schedule: Vulnerability scan schedule (cron expression, defaults to settings)
            compliance_schedule: Compliance scan schedule (cron expression)
            kev_enabled: Enable KEV catalog refresh (default: True)
        """
        try:
            # Use provided scan schedule or fall back to settings
            schedule = scan_schedule if scan_schedule is not None else settings.scan_schedule

            # Parse vulnerability scan schedule
            trigger = CronTrigger.from_crontab(schedule)

            # Add vulnerability scan job
            self.scheduler.add_job(
                scheduled_scan_task,
                trigger=trigger,
                id=self.scan_job_id,
                name="Automated vulnerability scan",
                replace_existing=True,
            )

            # Add compliance scan job if schedule provided
            if compliance_schedule:
                compliance_trigger = CronTrigger.from_crontab(compliance_schedule)
                self.scheduler.add_job(
                    scheduled_compliance_scan_task,
                    trigger=compliance_trigger,
                    id=self.compliance_job_id,
                    name="Automated compliance scan",
                    replace_existing=True,
                )
                logger.info(f"Compliance scan scheduled: {compliance_schedule}")

            # Add KEV refresh job (daily at 1 AM)
            if kev_enabled:
                kev_trigger = CronTrigger.from_crontab("0 1 * * *")
                self.scheduler.add_job(
                    scheduled_kev_refresh_task,
                    trigger=kev_trigger,
                    id=self.kev_refresh_job_id,
                    name="Automated KEV catalog refresh",
                    replace_existing=True,
                )
                logger.info("KEV catalog refresh scheduled: 0 1 * * * (daily at 1 AM)")

            self.scheduler.start()
            logger.info(f"Scheduler started with vulnerability scan schedule: {schedule}")

        except Exception as e:
            logger.error(f"Failed to start scheduler: {e}")
            raise

    def stop(self):
        """Stop the scheduler."""
        if self.scheduler.running:
            self.scheduler.shutdown(wait=False)
            logger.info("Scheduler stopped")

    def get_next_run_time(self):
        """
        Get next scheduled run time.

        Returns:
            Next run time or None
        """
        job = self.scheduler.get_job(self.scan_job_id)
        if job:
            return job.next_run_time
        return None

    def update_schedule(self, cron_expression: str):
        """
        Update vulnerability scan schedule.

        Args:
            cron_expression: New cron expression
        """
        try:
            trigger = CronTrigger.from_crontab(cron_expression)

            # Remove existing job
            self.scheduler.remove_job(self.scan_job_id)

            # Add new job
            self.scheduler.add_job(
                scheduled_scan_task,
                trigger=trigger,
                id=self.scan_job_id,
                name="Automated vulnerability scan",
                replace_existing=True,
            )

            logger.info(f"Vulnerability scan schedule updated to: {cron_expression}")

        except Exception as e:
            logger.error(f"Failed to update schedule: {e}")
            raise

    def update_compliance_schedule(self, cron_expression: str, enabled: bool = True):
        """
        Update compliance scan schedule.

        Args:
            cron_expression: New cron expression
            enabled: Whether compliance scanning is enabled
        """
        try:
            # Remove existing job if it exists
            try:
                self.scheduler.remove_job(self.compliance_job_id)
            except Exception:
                pass  # Job might not exist yet

            # Add new job if enabled
            if enabled:
                trigger = CronTrigger.from_crontab(cron_expression)
                self.scheduler.add_job(
                    scheduled_compliance_scan_task,
                    trigger=trigger,
                    id=self.compliance_job_id,
                    name="Automated compliance scan",
                    replace_existing=True,
                )
                logger.info(f"Compliance scan schedule updated to: {cron_expression}")
            else:
                logger.info("Compliance scanning disabled")

        except Exception as e:
            logger.error(f"Failed to update compliance schedule: {e}")
            raise

    def get_compliance_next_run_time(self):
        """
        Get next compliance scan run time.

        Returns:
            Next run time or None
        """
        job = self.scheduler.get_job(self.compliance_job_id)
        if job:
            return job.next_run_time
        return None
