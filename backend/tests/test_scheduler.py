"""Tests for scheduler service."""

from unittest.mock import MagicMock, patch

import pytest

import app.services.scheduler as scheduler_module


@pytest.fixture(autouse=True)
def _mock_background_services():
    """Override global fixture that swaps out ScanScheduler."""
    yield


class TestSchedulerStartup:
    """Tests for scheduler startup and shutdown behavior."""

    @patch("app.services.scheduler.AsyncIOScheduler")
    def test_scheduler_starts_successfully(self, mock_scheduler_class):
        """Scheduler should configure vulnerability scan job and start."""
        mock_scheduler = MagicMock()
        mock_scheduler.running = False
        mock_scheduler_class.return_value = mock_scheduler

        scheduler = scheduler_module.ScanScheduler()
        scheduler.start(scan_schedule="0 2 * * *", kev_enabled=False)

        mock_scheduler.start.assert_called_once()
        add_job_calls = mock_scheduler.add_job.call_args_list
        assert len(add_job_calls) == 1
        assert add_job_calls[0].args[0] is scheduler_module.scheduled_scan_task

    @patch("app.services.scheduler.AsyncIOScheduler")
    def test_scheduler_stops_gracefully(self, mock_scheduler_class):
        """Scheduler shutdown should stop underlying APScheduler instance."""
        mock_scheduler = MagicMock()
        mock_scheduler.running = False
        mock_scheduler_class.return_value = mock_scheduler

        scheduler = scheduler_module.ScanScheduler()
        scheduler.start(scan_schedule="0 2 * * *", kev_enabled=False)

        mock_scheduler.running = True
        scheduler.stop()

        mock_scheduler.shutdown.assert_called_once_with(wait=False)


class TestScheduledScans:
    """Tests for configured scheduled jobs."""

    @patch("app.services.scheduler.AsyncIOScheduler")
    def test_vulnerability_scan_scheduled(self, mock_scheduler_class):
        """Vulnerability scan job should always be scheduled."""
        mock_scheduler = MagicMock()
        mock_scheduler_class.return_value = mock_scheduler

        scheduler = scheduler_module.ScanScheduler()
        scheduler.start(scan_schedule="0 2 * * *", kev_enabled=False)

        scheduled = [call.args[0] for call in mock_scheduler.add_job.call_args_list]
        assert scheduler_module.scheduled_scan_task in scheduled

    @patch("app.services.scheduler.AsyncIOScheduler")
    def test_compliance_scan_scheduled(self, mock_scheduler_class):
        """Providing a compliance schedule should register the job."""
        mock_scheduler = MagicMock()
        mock_scheduler_class.return_value = mock_scheduler

        scheduler = scheduler_module.ScanScheduler()
        scheduler.start(
            scan_schedule="0 2 * * *",
            compliance_schedule="0 3 * * 0",
            kev_enabled=False,
        )

        scheduled = [call.args[0] for call in mock_scheduler.add_job.call_args_list]
        assert scheduler_module.scheduled_compliance_scan_task in scheduled

    @patch("app.services.scheduler.AsyncIOScheduler")
    def test_kev_refresh_scheduled(self, mock_scheduler_class):
        """KEV refresh should be added when enabled."""
        mock_scheduler = MagicMock()
        mock_scheduler_class.return_value = mock_scheduler

        scheduler = scheduler_module.ScanScheduler()
        scheduler.start(scan_schedule="0 2 * * *", kev_enabled=True)

        scheduled = [call.args[0] for call in mock_scheduler.add_job.call_args_list]
        assert scheduler_module.scheduled_kev_refresh_task in scheduled


class TestCronParsing:
    """Tests for cron expression validation helpers."""

    def test_valid_cron_expressions_accepted(self):
        """Valid cron expressions should pass croniter validation."""
        from croniter import croniter

        valid_crons = [
            "0 2 * * *",
            "*/15 * * * *",
            "0 0 * * 0",
        ]

        for cron in valid_crons:
            assert croniter.is_valid(cron)

    def test_invalid_cron_expressions_rejected(self):
        """Invalid cron expressions should be rejected."""
        from croniter import croniter

        invalid_crons = [
            "invalid",
            "60 * * * *",
            "* 25 * * *",
        ]

        for cron in invalid_crons:
            assert not croniter.is_valid(cron)


class TestScheduleUpdates:
    """Tests for updating schedules at runtime."""

    @patch("app.services.scheduler.AsyncIOScheduler")
    def test_update_scan_schedule(self, mock_scheduler_class):
        """Updating scan schedule should replace existing job."""
        mock_scheduler = MagicMock()
        mock_scheduler_class.return_value = mock_scheduler

        scheduler = scheduler_module.ScanScheduler()
        scheduler.start(scan_schedule="0 2 * * *", kev_enabled=False)

        mock_scheduler.add_job.reset_mock()
        scheduler.update_schedule("0 3 * * *")

        mock_scheduler.remove_job.assert_called_once_with("automated_scan")
        add_job_call = mock_scheduler.add_job.call_args
        assert add_job_call.args[0] is scheduler_module.scheduled_scan_task


class TestTimezoneHandling:
    """Tests for scheduler instantiation details."""

    @patch("app.services.scheduler.AsyncIOScheduler")
    def test_scheduler_uses_default_timezone(self, mock_scheduler_class):
        """Scheduler should use APScheduler instance constructed by service."""
        mock_scheduler = MagicMock()
        mock_scheduler_class.return_value = mock_scheduler

        scheduler = scheduler_module.ScanScheduler()
        assert scheduler.scheduler is mock_scheduler


class TestSchedulerErrors:
    """Tests for scheduler error handling."""

    @patch("app.services.scheduler.AsyncIOScheduler")
    def test_job_failure_surfaces_exception(self, mock_scheduler_class):
        """Failure to schedule a job should raise to caller."""
        mock_scheduler = MagicMock()
        mock_scheduler.add_job.side_effect = Exception("failed to schedule")
        mock_scheduler_class.return_value = mock_scheduler

        scheduler = scheduler_module.ScanScheduler()

        with pytest.raises(Exception):
            scheduler.start(scan_schedule="0 2 * * *", kev_enabled=False)

    @patch("app.services.scheduler.AsyncIOScheduler")
    def test_scheduler_startup_failure(self, mock_scheduler_class):
        """Failure during scheduler start should raise to caller."""
        mock_scheduler = MagicMock()
        mock_scheduler.start.side_effect = Exception("Scheduler start failed")
        mock_scheduler_class.return_value = mock_scheduler

        scheduler = scheduler_module.ScanScheduler()

        with pytest.raises(Exception):
            scheduler.start(scan_schedule="0 2 * * *", kev_enabled=False)
