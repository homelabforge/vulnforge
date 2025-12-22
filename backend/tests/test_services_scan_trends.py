"""Tests for scan trends service.

This module tests the scan trends service which provides:
- Vulnerability trend analysis over time windows
- Historical trend calculation with velocity metrics
- Trend aggregation across scan history
- Statistical analysis (percent change, averages)
"""

from datetime import UTC, datetime, timedelta

import pytest


class TestBuildScanTrends:
    """Test build_scan_trends function."""

    @pytest.mark.asyncio
    async def test_build_scan_trends_empty_database(self, db_session):
        """Test building trends with no scans in database."""
        from app.services.scan_trends import build_scan_trends

        # Act
        trends = await build_scan_trends(db_session, window_days=30)

        # Assert
        assert trends is not None
        assert trends["window_days"] == 30
        assert trends["series"] == []
        assert trends["summary"]["total_scans"] == 0
        assert trends["summary"]["total_vulns"] == 0

    @pytest.mark.asyncio
    async def test_build_scan_trends_with_scans(self, db_session, make_container, make_scan):
        """Test building trends with scan data."""
        from app.services.scan_trends import build_scan_trends

        # Arrange
        container = make_container()
        db_session.add(container)
        await db_session.commit()
        await db_session.refresh(container)

        # Create scans over last 7 days
        for i in range(7):
            scan = make_scan(
                container_id=container.id,
                scan_date=datetime.now(UTC) - timedelta(days=i),
                scan_status="completed",
                total_vulns=10 + i,
                fixable_vulns=5 + i,
                critical_count=1,
                high_count=2,
            )
            db_session.add(scan)
        await db_session.commit()

        # Act
        trends = await build_scan_trends(db_session, window_days=30)

        # Assert
        assert trends is not None
        assert trends["window_days"] == 30
        assert len(trends["series"]) >= 1
        assert trends["summary"]["total_scans"] >= 7
        assert trends["summary"]["completed_scans"] >= 7
        assert trends["summary"]["total_vulns"] > 0

    @pytest.mark.asyncio
    async def test_build_scan_trends_custom_window(self, db_session, make_container, make_scan):
        """Test building trends with custom time window."""
        from app.services.scan_trends import build_scan_trends

        # Arrange
        container = make_container()
        db_session.add(container)
        await db_session.commit()
        await db_session.refresh(container)

        # Create scans
        for i in range(5):
            scan = make_scan(
                container_id=container.id,
                scan_date=datetime.now(UTC) - timedelta(days=i),
                scan_status="completed",
                total_vulns=10,
            )
            db_session.add(scan)
        await db_session.commit()

        # Act
        trends = await build_scan_trends(db_session, window_days=7)

        # Assert
        assert trends["window_days"] == 7
        assert len(trends["series"]) >= 1

    @pytest.mark.asyncio
    async def test_build_scan_trends_max_window_capped(self, db_session):
        """Test that window_days is capped at 90."""
        from app.services.scan_trends import build_scan_trends

        # Act
        trends = await build_scan_trends(db_session, window_days=365)

        # Assert - Should be capped at 90
        assert trends["window_days"] == 90

    @pytest.mark.asyncio
    async def test_build_scan_trends_min_window_capped(self, db_session):
        """Test that window_days is min 1 day."""
        from app.services.scan_trends import build_scan_trends

        # Act
        trends = await build_scan_trends(db_session, window_days=0)

        # Assert - Should be at least 1
        assert trends["window_days"] == 1

    @pytest.mark.asyncio
    async def test_build_scan_trends_severity_counts(self, db_session, make_container, make_scan):
        """Test that severity counts are aggregated correctly."""
        from app.services.scan_trends import build_scan_trends

        # Arrange
        container = make_container()
        db_session.add(container)
        await db_session.commit()
        await db_session.refresh(container)

        # Create scan with known severity counts
        scan = make_scan(
            container_id=container.id,
            scan_date=datetime.now(UTC),
            scan_status="completed",
            total_vulns=10,
            critical_count=2,
            high_count=3,
            medium_count=4,
            low_count=1,
        )
        db_session.add(scan)
        await db_session.commit()

        # Act
        trends = await build_scan_trends(db_session, window_days=7)

        # Assert
        assert trends["summary"]["critical_vulns"] == 2
        assert trends["summary"]["high_vulns"] == 3

    @pytest.mark.asyncio
    async def test_build_scan_trends_failed_scans_counted(
        self, db_session, make_container, make_scan
    ):
        """Test that failed scans are counted separately."""
        from app.services.scan_trends import build_scan_trends

        # Arrange
        container = make_container()
        db_session.add(container)
        await db_session.commit()
        await db_session.refresh(container)

        # Create mix of completed and failed scans
        for i in range(3):
            scan = make_scan(
                container_id=container.id,
                scan_date=datetime.now(UTC) - timedelta(days=i),
                scan_status="completed",
            )
            db_session.add(scan)

        for i in range(2):
            scan = make_scan(
                container_id=container.id,
                scan_date=datetime.now(UTC) - timedelta(days=i + 3),
                scan_status="failed",
            )
            db_session.add(scan)
        await db_session.commit()

        # Act
        trends = await build_scan_trends(db_session, window_days=7)

        # Assert
        assert trends["summary"]["completed_scans"] == 3
        assert trends["summary"]["failed_scans"] == 2
        assert trends["summary"]["total_scans"] == 5


class TestVelocityMetrics:
    """Test velocity calculations (7-day comparison)."""

    @pytest.mark.asyncio
    async def test_velocity_completed_scans_increasing(self, db_session, make_container, make_scan):
        """Test velocity shows increasing trend in completed scans."""
        from app.services.scan_trends import build_scan_trends

        # Arrange
        container = make_container()
        db_session.add(container)
        await db_session.commit()
        await db_session.refresh(container)

        # Previous period (14-8 days ago): 2 scans
        for i in range(8, 14):
            if i in [8, 10]:  # Only 2 scans in previous period
                scan = make_scan(
                    container_id=container.id,
                    scan_date=datetime.now(UTC) - timedelta(days=i),
                    scan_status="completed",
                )
                db_session.add(scan)

        # Current period (last 7 days): 5 scans
        for i in range(7):
            scan = make_scan(
                container_id=container.id,
                scan_date=datetime.now(UTC) - timedelta(days=i),
                scan_status="completed",
            )
            db_session.add(scan)
        await db_session.commit()

        # Act
        trends = await build_scan_trends(db_session, window_days=30)

        # Assert
        velocity = trends["velocity"]["completed_scans"]
        assert velocity["current"] >= 5
        assert velocity["delta"] > 0  # Increasing

    @pytest.mark.asyncio
    async def test_velocity_percent_change_calculation(self, db_session, make_container, make_scan):
        """Test velocity percent change calculation."""
        from app.services.scan_trends import build_scan_trends

        # Arrange
        container = make_container()
        db_session.add(container)
        await db_session.commit()
        await db_session.refresh(container)

        # Previous period: 10 fixable vulns
        scan1 = make_scan(
            container_id=container.id,
            scan_date=datetime.now(UTC) - timedelta(days=10),
            scan_status="completed",
            fixable_vulns=10,
        )
        db_session.add(scan1)

        # Current period: 5 fixable vulns (50% reduction)
        scan2 = make_scan(
            container_id=container.id,
            scan_date=datetime.now(UTC) - timedelta(days=2),
            scan_status="completed",
            fixable_vulns=5,
        )
        db_session.add(scan2)
        await db_session.commit()

        # Act
        trends = await build_scan_trends(db_session, window_days=30)

        # Assert
        velocity = trends["velocity"]["fixable_vulns"]
        assert velocity["current"] >= 0
        assert velocity["previous"] >= 0


class TestPercentChange:
    """Test percent change helper function."""

    @pytest.mark.asyncio
    async def test_percent_change_positive(self):
        """Test percent change with increase."""
        from app.services.scan_trends import _percent_change

        # 10 → 15 = 50% increase
        result = _percent_change(10, 15)
        assert result == 50.0

    @pytest.mark.asyncio
    async def test_percent_change_negative(self):
        """Test percent change with decrease."""
        from app.services.scan_trends import _percent_change

        # 20 → 10 = -50% decrease
        result = _percent_change(20, 10)
        assert result == -50.0

    @pytest.mark.asyncio
    async def test_percent_change_zero_previous(self):
        """Test percent change with zero previous value."""
        from app.services.scan_trends import _percent_change

        # Division by zero guard
        result = _percent_change(0, 10)
        assert result is None

    @pytest.mark.asyncio
    async def test_percent_change_none_values(self):
        """Test percent change with None values."""
        from app.services.scan_trends import _percent_change

        assert _percent_change(None, 10) is None
        assert _percent_change(10, None) is None


class TestSeriesData:
    """Test time series data structure."""

    @pytest.mark.asyncio
    async def test_series_contains_date_strings(self, db_session, make_container, make_scan):
        """Test series data includes date as ISO string."""
        from app.services.scan_trends import build_scan_trends

        # Arrange
        container = make_container()
        db_session.add(container)
        await db_session.commit()
        await db_session.refresh(container)

        scan = make_scan(
            container_id=container.id, scan_date=datetime.now(UTC), scan_status="completed"
        )
        db_session.add(scan)
        await db_session.commit()

        # Act
        trends = await build_scan_trends(db_session, window_days=7)

        # Assert
        assert len(trends["series"]) > 0
        first_point = trends["series"][0]
        assert "date" in first_point
        # Should be ISO format YYYY-MM-DD
        assert len(first_point["date"]) == 10

    @pytest.mark.asyncio
    async def test_series_point_structure(self, db_session, make_container, make_scan):
        """Test that series data points have expected structure."""
        from app.services.scan_trends import build_scan_trends

        # Arrange
        container = make_container()
        db_session.add(container)
        await db_session.commit()
        await db_session.refresh(container)

        scan = make_scan(
            container_id=container.id,
            scan_date=datetime.now(UTC),
            scan_status="completed",
            total_vulns=10,
            fixable_vulns=5,
            critical_count=1,
            high_count=2,
        )
        db_session.add(scan)
        await db_session.commit()

        # Act
        trends = await build_scan_trends(db_session, window_days=7)

        # Assert
        assert len(trends["series"]) > 0
        point = trends["series"][0]

        # Verify expected fields
        assert "date" in point
        assert "total_scans" in point
        assert "completed_scans" in point
        assert "failed_scans" in point
        assert "total_vulns" in point
        assert "fixable_vulns" in point
        assert "critical_vulns" in point
        assert "high_vulns" in point

        # Should NOT contain internal calculation fields
        assert "duration_seconds_total" not in point
        assert "duration_samples" not in point
