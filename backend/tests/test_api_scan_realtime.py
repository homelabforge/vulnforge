"""Regression tests for scan streaming and trends endpoints."""

from datetime import timedelta

import pytest

from app.utils.timezone import get_now


@pytest.mark.asyncio
class TestScanStreaming:
    """Validate Server-Sent Events for scan status updates."""

    def test_stream_provides_initial_snapshot(self, client):
        """The scan status snapshot endpoint should return queue information immediately."""
        response = client.get("/api/v1/scans/current")
        assert response.status_code == 200

        payload = response.json()
        assert payload["status"] in {"idle", "scanning"}
        assert "queue" in payload
        assert "queue_size" in payload["queue"]


@pytest.mark.asyncio
class TestScanTrendsEndpoint:
    """Tests for aggregated scan trends data."""

    async def test_trends_include_recent_activity(self, client, db_with_settings):
        """Ensure /scans/trends aggregates scanned data correctly."""
        from app.models import Container, Scan

        # Create a container to attach scan history
        container = Container(
            name="scan-trend-test",
            image="scan-trend",
            image_tag="latest",
            image_id="sha256:scantrend",
        )
        db_with_settings.add(container)
        await db_with_settings.commit()
        await db_with_settings.refresh(container)

        base_time = get_now() - timedelta(days=2)

        # Two completed scans and one failed scan across different days
        scans = [
            Scan(
                container_id=container.id,
                scan_date=base_time,
                scan_status="completed",
                image_scanned="scan-trend:latest",
                total_vulns=4,
                fixable_vulns=2,
                critical_count=1,
                high_count=1,
                medium_count=1,
                low_count=1,
                scan_duration_seconds=45.0,
            ),
            Scan(
                container_id=container.id,
                scan_date=base_time + timedelta(days=1),
                scan_status="completed",
                image_scanned="scan-trend:latest",
                total_vulns=3,
                fixable_vulns=1,
                critical_count=0,
                high_count=2,
                medium_count=1,
                low_count=0,
                scan_duration_seconds=30.0,
            ),
            Scan(
                container_id=container.id,
                scan_date=base_time + timedelta(days=1),
                scan_status="failed",
                image_scanned="scan-trend:latest",
                total_vulns=0,
                fixable_vulns=0,
                critical_count=0,
                high_count=0,
                medium_count=0,
                low_count=0,
                scan_duration_seconds=None,
            ),
        ]

        for entry in scans:
            db_with_settings.add(entry)
        await db_with_settings.commit()

        response = client.get("/api/v1/scans/trends?window_days=7")

        assert response.status_code == 200
        data = response.json()

        assert data["window_days"] == 7
        assert data["summary"]["completed_scans"] == 2
        assert data["summary"]["failed_scans"] == 1
        assert data["summary"]["total_vulns"] == 7
        assert data["summary"]["fixable_vulns"] == 3
        assert len(data["series"]) >= 2
        assert "velocity" in data

    async def test_trends_empty_response_defaults(self, client, db_with_settings):
        """Window with no scans should return zeroed summary and no crash."""
        response = client.get("/api/v1/scans/trends?window_days=3")

        assert response.status_code == 200
        data = response.json()

        assert data["summary"]["total_scans"] == 0
        assert data["summary"]["completed_scans"] == 0
        assert data["summary"]["failed_scans"] == 0
        assert data["summary"]["avg_duration_seconds"] is None

        velocity = data["velocity"]
        for metric in velocity.values():
            assert metric["current"] == 0 or metric["current"] is None
            assert metric["percent_change"] is None
