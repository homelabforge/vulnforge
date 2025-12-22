"""Tests for activity logger service.

This module tests the activity logger service which provides:
- Scan event logging (completed, failed, secrets, high severity)
- Container event logging (discovered, status changed)
- False positive and compliance event logging
- Vulnerability and secret status change logging
"""

import pytest


class TestActivityLogger:
    """Test activity logger basic operations."""

    @pytest.mark.asyncio
    async def test_create_activity_logger(self, db_session):
        """Test creating activity logger instance."""
        from app.services.activity_logger import ActivityLogger

        logger = ActivityLogger(db_session)
        assert logger is not None
        assert logger.db == db_session

    @pytest.mark.asyncio
    async def test_log_scan_completed(self, db_session):
        """Test logging scan completed event."""
        from sqlalchemy import select

        from app.models import ActivityLog
        from app.services.activity_logger import ActivityLogger

        logger = ActivityLogger(db_session)

        # Act
        await logger.log_scan_completed(
            container_name="nginx-prod",
            container_id="abc123",
            scan_id=1,
            duration=5.2,
            total_vulns=15,
            fixable_vulns=10,
            critical_count=2,
            high_count=5,
            medium_count=6,
            low_count=2,
        )

        # Assert
        result = await db_session.execute(
            select(ActivityLog)
            .where(ActivityLog.event_type == "scan_completed")
            .order_by(ActivityLog.created_at.desc())
            .limit(1)
        )
        log = result.scalar_one_or_none()
        assert log is not None
        assert "nginx-prod" in log.title
        assert "15" in log.description

    @pytest.mark.asyncio
    async def test_log_scan_failed(self, db_session):
        """Test logging scan failed event."""
        from sqlalchemy import select

        from app.models import ActivityLog
        from app.services.activity_logger import ActivityLogger

        logger = ActivityLogger(db_session)

        # Act
        await logger.log_scan_failed(
            container_name="nginx-prod",
            container_id="abc123",
            error_message="Trivy returned exit code 1",
            scan_id=1,
        )

        # Assert
        result = await db_session.execute(
            select(ActivityLog)
            .where(ActivityLog.event_type == "scan_failed")
            .order_by(ActivityLog.created_at.desc())
            .limit(1)
        )
        log = result.scalar_one_or_none()
        assert log is not None
        assert "nginx-prod" in log.title
        assert "exit code 1" in log.description

    @pytest.mark.asyncio
    async def test_log_secret_detected(self, db_session):
        """Test logging secret detection event."""
        from sqlalchemy import select

        from app.models import ActivityLog
        from app.services.activity_logger import ActivityLogger

        logger = ActivityLogger(db_session)

        # Act
        await logger.log_secret_detected(
            container_name="app-backend",
            container_id="def456",
            scan_id=2,
            total_secrets=5,
            critical_count=2,
            high_count=3,
            categories=["api-key", "password"],
        )

        # Assert
        result = await db_session.execute(
            select(ActivityLog)
            .where(ActivityLog.event_type == "secret_detected")
            .order_by(ActivityLog.created_at.desc())
            .limit(1)
        )
        log = result.scalar_one_or_none()
        assert log is not None
        assert "app-backend" in log.title
        assert "5" in log.description

    @pytest.mark.asyncio
    async def test_log_high_severity_found(self, db_session):
        """Test logging high severity vulnerability detection."""
        from sqlalchemy import select

        from app.models import ActivityLog
        from app.services.activity_logger import ActivityLogger

        logger = ActivityLogger(db_session)

        # Act
        await logger.log_high_severity_found(
            container_name="web-server",
            container_id="ghi789",
            scan_id=3,
            critical_count=3,
            high_count=7,
        )

        # Assert
        result = await db_session.execute(
            select(ActivityLog)
            .where(ActivityLog.event_type == "high_severity_found")
            .order_by(ActivityLog.created_at.desc())
            .limit(1)
        )
        log = result.scalar_one_or_none()
        assert log is not None
        assert "web-server" in log.title
        assert "3" in log.description or "critical" in log.description.lower()

    @pytest.mark.asyncio
    async def test_log_container_discovered(self, db_session):
        """Test logging container discovery event."""
        from sqlalchemy import select

        from app.models import ActivityLog
        from app.services.activity_logger import ActivityLogger

        logger = ActivityLogger(db_session)

        # Act
        await logger.log_container_discovered(
            container_name="redis-cache",
            container_id="jkl012",
            image="redis",
            image_tag="7.2-alpine",
            is_running=True,
        )

        # Assert
        result = await db_session.execute(
            select(ActivityLog)
            .where(ActivityLog.event_type == "container_discovered")
            .order_by(ActivityLog.created_at.desc())
            .limit(1)
        )
        log = result.scalar_one_or_none()
        assert log is not None
        assert "redis-cache" in log.title
        assert "redis:7.2-alpine" in log.description

    @pytest.mark.asyncio
    async def test_log_batch_scan_completed(self, db_session):
        """Test logging batch scan completion."""
        from sqlalchemy import select

        from app.models import ActivityLog
        from app.services.activity_logger import ActivityLogger

        logger = ActivityLogger(db_session)

        # Act
        await logger.log_batch_scan_completed(
            containers_count=10,
            total_vulns=45,
            duration=120.5,
            failed_count=2,
        )

        # Assert
        result = await db_session.execute(
            select(ActivityLog)
            .where(ActivityLog.event_type == "batch_scan_completed")
            .order_by(ActivityLog.created_at.desc())
            .limit(1)
        )
        log = result.scalar_one_or_none()
        assert log is not None
        assert "10" in log.description
        assert "45" in log.description

    @pytest.mark.asyncio
    async def test_log_container_status_changed(self, db_session):
        """Test logging container status change."""
        from sqlalchemy import select

        from app.models import ActivityLog
        from app.services.activity_logger import ActivityLogger

        logger = ActivityLogger(db_session)

        # Act
        await logger.log_container_status_changed(
            container_name="database",
            container_id="mno345",
            old_status="running",
            new_status="stopped",
        )

        # Assert
        result = await db_session.execute(
            select(ActivityLog)
            .where(ActivityLog.event_type == "container_status_changed")
            .order_by(ActivityLog.created_at.desc())
            .limit(1)
        )
        log = result.scalar_one_or_none()
        assert log is not None
        assert "database" in log.title
        assert "running" in log.description
        assert "stopped" in log.description

    @pytest.mark.asyncio
    async def test_log_false_positive_created(self, db_session):
        """Test logging false positive creation."""
        from sqlalchemy import select

        from app.models import ActivityLog
        from app.services.activity_logger import ActivityLogger

        logger = ActivityLogger(db_session)

        # Act
        await logger.log_false_positive_created(
            pattern_id=1,
            container_name="api-server",
            file_path="/app/config.yaml",
            rule_id="generic-api-key",
            username="admin",
            reason="Development API key, not production",
        )

        # Assert
        result = await db_session.execute(
            select(ActivityLog)
            .where(ActivityLog.event_type == "admin_action")
            .order_by(ActivityLog.created_at.desc())
            .limit(1)
        )
        log = result.scalar_one_or_none()
        assert log is not None
        assert "admin" in log.title
        assert "api-server" in log.description
        assert "generic-api-key" in log.description

    @pytest.mark.asyncio
    async def test_log_compliance_finding_ignored(self, db_session):
        """Test logging compliance finding ignore."""
        from sqlalchemy import select

        from app.models import ActivityLog
        from app.services.activity_logger import ActivityLogger

        logger = ActivityLogger(db_session)

        # Act
        await logger.log_compliance_finding_ignored(
            finding_id=10,
            check_id="5.1",
            check_title="AppArmor profile not enabled",
            username="admin",
            reason="Using SELinux instead",
        )

        # Assert
        result = await db_session.execute(
            select(ActivityLog)
            .where(ActivityLog.event_type == "admin_action")
            .order_by(ActivityLog.created_at.desc())
            .limit(1)
        )
        log = result.scalar_one_or_none()
        assert log is not None
        assert "admin" in log.title
        assert "5.1" in log.description or "AppArmor" in log.description

    @pytest.mark.asyncio
    async def test_log_compliance_finding_unignored(self, db_session):
        """Test logging compliance finding unignore."""
        from sqlalchemy import select

        from app.models import ActivityLog
        from app.services.activity_logger import ActivityLogger

        logger = ActivityLogger(db_session)

        # Act
        await logger.log_compliance_finding_unignored(
            finding_id=10,
            check_id="5.1",
            check_title="AppArmor profile not enabled",
            username="admin",
        )

        # Assert
        result = await db_session.execute(
            select(ActivityLog)
            .where(ActivityLog.event_type == "admin_action")
            .order_by(ActivityLog.created_at.desc())
            .limit(1)
        )
        log = result.scalar_one_or_none()
        assert log is not None
        assert "admin" in log.title
        assert "5.1" in log.description or "AppArmor" in log.description

    @pytest.mark.asyncio
    async def test_log_secret_status_changed(self, db_session):
        """Test logging secret status change."""
        from sqlalchemy import select

        from app.models import ActivityLog
        from app.services.activity_logger import ActivityLogger

        logger = ActivityLogger(db_session)

        # Act
        await logger.log_secret_status_changed(
            secret_id=5,
            container_name="backend-api",
            old_status="active",
            new_status="resolved",
            username="security_team",
            notes="Rotated API key",
        )

        # Assert
        result = await db_session.execute(
            select(ActivityLog)
            .where(ActivityLog.event_type == "admin_action")
            .order_by(ActivityLog.created_at.desc())
            .limit(1)
        )
        log = result.scalar_one_or_none()
        assert log is not None
        assert "security_team" in log.title
        assert "backend-api" in log.description
        assert "active" in log.description or "resolved" in log.description

    @pytest.mark.asyncio
    async def test_log_vulnerability_status_changed(self, db_session):
        """Test logging single vulnerability status change."""
        from sqlalchemy import select

        from app.models import ActivityLog
        from app.services.activity_logger import ActivityLogger

        logger = ActivityLogger(db_session)

        # Act
        await logger.log_vulnerability_status_changed(
            vuln_id=100,
            cve_id="CVE-2024-1234",
            container_name="web-app",
            old_status="open",
            new_status="fixed",
            username="devops",
            notes="Upgraded package to 2.3.4",
        )

        # Assert
        result = await db_session.execute(
            select(ActivityLog)
            .where(ActivityLog.event_type == "admin_action")
            .order_by(ActivityLog.created_at.desc())
            .limit(1)
        )
        log = result.scalar_one_or_none()
        assert log is not None
        assert "devops" in log.title
        assert "CVE-2024-1234" in log.description
        assert "web-app" in log.description

    @pytest.mark.asyncio
    async def test_log_bulk_vulnerability_status_changed(self, db_session):
        """Test logging bulk vulnerability status change."""
        from sqlalchemy import select

        from app.models import ActivityLog
        from app.services.activity_logger import ActivityLogger

        logger = ActivityLogger(db_session)

        # Act
        await logger.log_bulk_vulnerability_status_changed(
            vuln_ids=[101, 102, 103, 104, 105],
            new_status="acknowledged",
            username="security_admin",
            notes="False positives - using internal version",
        )

        # Assert
        result = await db_session.execute(
            select(ActivityLog)
            .where(ActivityLog.event_type == "admin_action")
            .order_by(ActivityLog.created_at.desc())
            .limit(1)
        )
        log = result.scalar_one_or_none()
        assert log is not None
        assert "security_admin" in log.title
        assert "5" in log.description  # 5 vulnerabilities
        assert "acknowledged" in log.description


class TestActivityLoggerErrorHandling:
    """Test error handling in activity logger."""

    @pytest.mark.asyncio
    async def test_logging_does_not_raise_on_db_error(self, db_session):
        """Test that logging methods handle database errors gracefully."""
        from app.services.activity_logger import ActivityLogger

        logger = ActivityLogger(db_session)

        # Close the session to force a database error
        await db_session.close()

        # Act - should not raise even though session is closed
        try:
            await logger.log_scan_completed(
                container_name="test",
                container_id="test123",
                scan_id=1,
                duration=1.0,
                total_vulns=0,
                fixable_vulns=0,
                critical_count=0,
                high_count=0,
                medium_count=0,
                low_count=0,
            )
            # If we get here without exception, the test passes
            assert True
        except Exception as e:
            pytest.fail(f"Activity logger should not raise exceptions, but raised: {e}")
