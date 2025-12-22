"""Tests for activity log API endpoints.

This module tests the activity logging API which provides:
- Activity log retrieval with pagination
- Activity filtering by event type, severity, container
- Activity types listing with counts
- Container-specific activity logs

NOTE: The activity API does NOT require authentication currently.
NOTE: Search, export, user audit, and statistics endpoints DO NOT exist.
"""

from datetime import datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession


class TestGetActivityLogs:
    """Test GET /api/v1/activity endpoint."""

    @pytest.mark.asyncio
    async def test_get_all_activity_logs(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test getting all activity logs."""
        from app.models import ActivityLog

        # Arrange - Create test activity logs
        logs = [
            ActivityLog(
                event_type="scan_started",
                title="Scan Started",
                description="Started scan for nginx",
                severity="info",
                event_metadata={"container": "nginx"},
            ),
            ActivityLog(
                event_type="scan_completed",
                title="Scan Completed",
                description="Completed scan for nginx",
                severity="info",
            ),
            ActivityLog(
                event_type="container_discovered",
                title="Container Discovered",
                description="Found new container",
                severity="info",
            ),
        ]
        for log in logs:
            db_session.add(log)
        await db_session.commit()

        # Act
        response = await authenticated_client.get("/api/v1/activity/")

        # Assert
        assert response.status_code == 200
        data = response.json()
        assert "activities" in data
        assert "total" in data
        assert "event_type_counts" in data
        assert isinstance(data["activities"], list)
        assert len(data["activities"]) >= 3

    @pytest.mark.asyncio
    async def test_get_activity_logs_with_pagination(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test activity logs pagination."""
        from app.models import ActivityLog

        # Arrange - Create 20 activity logs
        for i in range(20):
            log = ActivityLog(
                event_type="test_activity",
                title="Test Activity",
                description=f"Test activity {i}",
                severity="info",
            )
            db_session.add(log)
        await db_session.commit()

        # Act - Get first page
        response = await authenticated_client.get("/api/v1/activity/?limit=10&offset=0")

        # Assert
        assert response.status_code == 200
        data = response.json()
        assert len(data["activities"]) == 10

        # Act - Get second page
        response2 = await authenticated_client.get("/api/v1/activity/?limit=10&offset=10")

        # Assert
        assert response2.status_code == 200
        data2 = response2.json()
        assert len(data2["activities"]) == 10
        # Should be different records
        assert data["activities"][0]["id"] != data2["activities"][0]["id"]

    @pytest.mark.asyncio
    async def test_activity_logs_ordered_by_timestamp(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test activity logs are ordered by timestamp descending."""
        from app.models import ActivityLog
        from app.utils.timezone import get_now

        # Arrange
        now = get_now()
        log1 = ActivityLog(
            event_type="test",
            title="Old Activity",
            description="Old activity",
            severity="info",
            timestamp=now - timedelta(hours=2),
        )

        log2 = ActivityLog(
            event_type="test",
            title="Recent Activity",
            description="Recent activity",
            severity="info",
            timestamp=now,
        )
        db_session.add_all([log1, log2])
        await db_session.commit()

        # Act
        response = await authenticated_client.get("/api/v1/activity/?limit=2")

        # Assert
        assert response.status_code == 200
        data = response.json()
        activities = data["activities"]
        assert len(activities) >= 2
        # Most recent should be first
        timestamps = [
            datetime.fromisoformat(item["timestamp"].replace("Z", "+00:00"))
            for item in activities[:2]
        ]
        assert timestamps == sorted(timestamps, reverse=True)


class TestFilterActivityLogs:
    """Test activity log filtering."""

    @pytest.mark.asyncio
    async def test_filter_by_event_type(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test filtering activity logs by event type."""
        from app.models import ActivityLog

        # Arrange
        logs = [
            ActivityLog(
                event_type="scan_started",
                title="Scan Started 1",
                description="Scan 1",
                severity="info",
            ),
            ActivityLog(
                event_type="scan_started",
                title="Scan Started 2",
                description="Scan 2",
                severity="info",
            ),
            ActivityLog(
                event_type="container_discovered",
                title="Container Found",
                description="Found container",
                severity="info",
            ),
        ]
        for log in logs:
            db_session.add(log)
        await db_session.commit()

        # Act
        response = await authenticated_client.get("/api/v1/activity/?event_type=scan_started")

        # Assert
        assert response.status_code == 200
        data = response.json()
        assert len(data["activities"]) >= 2
        for item in data["activities"]:
            assert item["event_type"] == "scan_started"

    @pytest.mark.asyncio
    async def test_filter_by_severity(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test filtering activity logs by severity."""
        from app.models import ActivityLog

        # Arrange
        logs = [
            ActivityLog(
                event_type="scan_completed",
                title="Normal Scan",
                description="Normal scan completed",
                severity="info",
            ),
            ActivityLog(
                event_type="high_severity_found",
                title="Critical Vulnerability",
                description="Critical CVE found",
                severity="critical",
            ),
            ActivityLog(
                event_type="scan_failed",
                title="Scan Warning",
                description="Scan had warnings",
                severity="warning",
            ),
        ]
        for log in logs:
            db_session.add(log)
        await db_session.commit()

        # Act
        response = await authenticated_client.get("/api/v1/activity/?severity=critical")

        # Assert
        assert response.status_code == 200
        data = response.json()
        assert len(data["activities"]) >= 1
        for item in data["activities"]:
            assert item["severity"] == "critical"

    @pytest.mark.asyncio
    async def test_filter_by_container_id(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test filtering activity logs by container ID."""
        from app.models import ActivityLog

        # Arrange
        logs = [
            ActivityLog(
                event_type="scan_completed",
                title="Container 1 Scan",
                description="Scanned container 1",
                severity="info",
                container_id=1,
                container_name="nginx",
            ),
            ActivityLog(
                event_type="scan_completed",
                title="Container 2 Scan",
                description="Scanned container 2",
                severity="info",
                container_id=2,
                container_name="redis",
            ),
            ActivityLog(
                event_type="scan_completed",
                title="Container 1 Scan Again",
                description="Scanned container 1 again",
                severity="info",
                container_id=1,
                container_name="nginx",
            ),
        ]
        for log in logs:
            db_session.add(log)
        await db_session.commit()

        # Act
        response = await authenticated_client.get("/api/v1/activity/?container_id=1")

        # Assert
        assert response.status_code == 200
        data = response.json()
        assert len(data["activities"]) >= 2
        for item in data["activities"]:
            assert item["container_id"] == 1

    @pytest.mark.asyncio
    async def test_filter_multiple_criteria(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test filtering with multiple criteria."""
        from app.models import ActivityLog

        # Arrange
        logs = [
            ActivityLog(
                event_type="scan_started",
                title="Critical Scan Started",
                description="Started critical scan",
                severity="critical",
            ),
            ActivityLog(
                event_type="scan_started",
                title="Info Scan Started",
                description="Started info scan",
                severity="info",
            ),
            ActivityLog(
                event_type="scan_completed",
                title="Critical Scan Done",
                description="Completed critical scan",
                severity="critical",
            ),
        ]
        for log in logs:
            db_session.add(log)
        await db_session.commit()

        # Act
        response = await authenticated_client.get(
            "/api/v1/activity/?event_type=scan_started&severity=critical"
        )

        # Assert
        assert response.status_code == 200
        data = response.json()
        assert len(data["activities"]) >= 1
        for item in data["activities"]:
            assert item["event_type"] == "scan_started"
            assert item["severity"] == "critical"


class TestActivityTypes:
    """Test GET /api/v1/activity/types endpoint."""

    @pytest.mark.asyncio
    async def test_get_activity_types(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test getting activity types with counts."""
        from app.models import ActivityLog

        # Arrange
        logs = [
            ActivityLog(
                event_type="scan_started",
                title="Scan 1",
                description="Scan 1",
                severity="info",
            ),
            ActivityLog(
                event_type="scan_started",
                title="Scan 2",
                description="Scan 2",
                severity="info",
            ),
            ActivityLog(
                event_type="scan_completed",
                title="Scan Done",
                description="Scan completed",
                severity="info",
            ),
        ]
        for log in logs:
            db_session.add(log)
        await db_session.commit()

        # Act
        response = await authenticated_client.get("/api/v1/activity/types")

        # Assert
        assert response.status_code == 200
        data = response.json()
        assert "types" in data
        assert isinstance(data["types"], list)

        # Find scan_started type
        scan_started = next((t for t in data["types"] if t["type"] == "scan_started"), None)
        assert scan_started is not None
        assert scan_started["count"] >= 2
        assert "label" in scan_started

    @pytest.mark.asyncio
    async def test_activity_types_sorted_by_count(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test activity types are sorted by count descending."""
        from app.models import ActivityLog

        # Arrange - Create different counts for each type
        logs = []
        # 5 scan_started
        for i in range(5):
            logs.append(
                ActivityLog(
                    event_type="scan_started",
                    title=f"Scan {i}",
                    description="Scan",
                    severity="info",
                )
            )
        # 2 scan_completed
        for i in range(2):
            logs.append(
                ActivityLog(
                    event_type="scan_completed",
                    title=f"Done {i}",
                    description="Done",
                    severity="info",
                )
            )
        for log in logs:
            db_session.add(log)
        await db_session.commit()

        # Act
        response = await authenticated_client.get("/api/v1/activity/types")

        # Assert
        assert response.status_code == 200
        data = response.json()
        types = data["types"]
        # Should be sorted by count descending
        counts = [t["count"] for t in types]
        assert counts == sorted(counts, reverse=True)


class TestContainerActivities:
    """Test GET /api/v1/activity/container/{container_id} endpoint."""

    @pytest.mark.asyncio
    async def test_get_container_activities(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test getting activities for specific container."""
        from app.models import ActivityLog

        # Arrange
        logs = [
            ActivityLog(
                event_type="scan_completed",
                title="Nginx Scan",
                description="Scanned nginx",
                severity="info",
                container_id=1,
                container_name="nginx",
            ),
            ActivityLog(
                event_type="scan_failed",
                title="Nginx Scan Failed",
                description="Scan failed for nginx",
                severity="warning",
                container_id=1,
                container_name="nginx",
            ),
            ActivityLog(
                event_type="scan_completed",
                title="Redis Scan",
                description="Scanned redis",
                severity="info",
                container_id=2,
                container_name="redis",
            ),
        ]
        for log in logs:
            db_session.add(log)
        await db_session.commit()

        # Act
        response = await authenticated_client.get("/api/v1/activity/container/1")

        # Assert
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) >= 2
        for item in data:
            assert item["container_id"] == 1
            assert item["container_name"] == "nginx"

    @pytest.mark.asyncio
    async def test_get_container_activities_with_limit(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test container activities with limit."""
        from app.models import ActivityLog

        # Arrange - Create 15 logs for container 1
        for i in range(15):
            log = ActivityLog(
                event_type="test_event",
                title=f"Activity {i}",
                description=f"Test {i}",
                severity="info",
                container_id=1,
                container_name="test-container",
            )
            db_session.add(log)
        await db_session.commit()

        # Act
        response = await authenticated_client.get("/api/v1/activity/container/1?limit=10")

        # Assert
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 10

    @pytest.mark.asyncio
    async def test_get_container_activities_not_found(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test getting activities for non-existent container."""
        # Act
        response = await authenticated_client.get("/api/v1/activity/container/99999")

        # Assert
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) == 0


class TestActivityMetadata:
    """Test activity log metadata handling."""

    @pytest.mark.asyncio
    async def test_activity_with_metadata(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test creating and retrieving activity with metadata."""
        from app.models import ActivityLog

        # Arrange
        metadata = {
            "scan_id": 123,
            "duration": 45.2,
            "total_vulns": 87,
            "critical_count": 3,
        }
        log = ActivityLog(
            event_type="scan_completed",
            title="Complex Scan Completed",
            description="Completed scan with metadata",
            severity="info",
            event_metadata=metadata,
        )
        db_session.add(log)
        await db_session.commit()

        # Act
        response = await authenticated_client.get("/api/v1/activity/")

        # Assert
        assert response.status_code == 200
        data = response.json()
        # Find our log
        found = next(
            (a for a in data["activities"] if a["title"] == "Complex Scan Completed"),
            None,
        )
        assert found is not None
        assert found["event_metadata"] == metadata

    @pytest.mark.asyncio
    async def test_activity_without_metadata(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test activity log without metadata."""
        from app.models import ActivityLog

        # Arrange
        log = ActivityLog(
            event_type="simple_event",
            title="Simple Event",
            description="Event without metadata",
            severity="info",
            event_metadata=None,
        )
        db_session.add(log)
        await db_session.commit()

        # Act
        response = await authenticated_client.get("/api/v1/activity/")

        # Assert
        assert response.status_code == 200
        data = response.json()
        found = next((a for a in data["activities"] if a["title"] == "Simple Event"), None)
        assert found is not None
        assert found["event_metadata"] is None
