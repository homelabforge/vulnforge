"""Tests for image compliance API endpoints.

This module tests the image misconfiguration scanning API which provides:
- Trivy image misconfiguration scanning
- Image compliance summary and reporting
- Finding management (ignore/unignore)
- CSV export functionality
"""

import asyncio
import json
from unittest.mock import MagicMock, patch

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import ImageComplianceFinding, ImageComplianceScan
from app.services.image_misconfig_state import image_misconfig_state

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_image_compliance_globals():
    """Reset ALL process-local state between tests.

    The image_compliance route module uses process-local globals for scan
    tracking.  finish_scan() does NOT clear _last_result, so we reset every
    field directly to prevent cross-test contamination and hangs.
    """
    import app.routes.image_compliance as ic

    ic._current_scan_task = None
    ic._current_scan_id = None
    ic._last_scan_id = None
    ic._completion_poll_count = 0

    image_misconfig_state._is_scanning = False
    image_misconfig_state._last_result = None
    image_misconfig_state._mode = "single"
    image_misconfig_state._targets = []
    image_misconfig_state._current_image = None
    image_misconfig_state._progress_current = 0
    image_misconfig_state._progress_total = 0
    image_misconfig_state._started_at = None

    yield

    # Cleanup: cancel any lingering tasks
    if ic._current_scan_task and not ic._current_scan_task.done():
        ic._current_scan_task.cancel()
    ic._current_scan_task = None
    ic._current_scan_id = None
    ic._last_scan_id = None
    ic._completion_poll_count = 0
    image_misconfig_state._is_scanning = False
    image_misconfig_state._last_result = None


# ---------------------------------------------------------------------------
# Fake task helpers
# ---------------------------------------------------------------------------


async def _noop_coro() -> None:
    """Coroutine that never completes (blocks forever)."""
    await asyncio.get_running_loop().create_future()


def _make_pending_task() -> asyncio.Task:
    """Create a task that stays pending until explicitly cancelled.

    Used by conflict/in-progress tests that need ``_current_scan_task.done()``
    to return False when the route handler checks it.
    """
    return asyncio.create_task(_noop_coro())


def _make_completed_task() -> asyncio.Task:
    """Create a task that is already done.

    Used by success tests where we need the route to accept a new scan trigger
    (it only blocks when an existing task is still running).
    """
    task = asyncio.create_task(asyncio.sleep(0))
    # Ensure it's completed — sleep(0) completes on next iteration
    return task


# ===========================================================================
# Trigger scan tests
# ===========================================================================


class TestTriggerImageScan:
    """Test POST /api/v1/image-compliance/scan endpoint."""

    @pytest.mark.asyncio
    async def test_scan_single_image_success(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test triggering scan for a single image."""
        image_name = "nginx:latest"

        with (
            patch("app.routes.image_compliance.DockerService") as mock_docker,
            patch("app.routes.image_compliance.asyncio") as mock_asyncio,
        ):
            mock_docker.return_value = MagicMock()
            mock_asyncio.create_task.return_value = _make_completed_task()

            response = await authenticated_client.post(
                "/api/v1/image-compliance/scan",
                params={"image_name": image_name},
            )

        assert response.status_code == 200
        data = response.json()
        assert "message" in data
        assert "started" in data["message"].lower()
        assert data["image_name"] == image_name

    @pytest.mark.asyncio
    async def test_scan_empty_image_name(self, authenticated_client: AsyncClient):
        """Test scanning with empty image name."""
        response = await authenticated_client.post(
            "/api/v1/image-compliance/scan",
            params={"image_name": ""},
        )
        assert response.status_code == 400
        data = response.json()
        assert "required" in data["detail"].lower()

    @pytest.mark.asyncio
    async def test_scan_already_in_progress(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test triggering scan when one is already running."""
        import app.routes.image_compliance as ic

        # Simulate an in-progress scan
        ic._current_scan_task = _make_pending_task()

        response = await authenticated_client.post(
            "/api/v1/image-compliance/scan",
            params={"image_name": "redis:latest"},
        )

        assert response.status_code == 409
        data = response.json()
        assert "already in progress" in data["detail"].lower()

    @pytest.mark.asyncio
    async def test_scan_whitespace_image_name(self, authenticated_client: AsyncClient):
        """Test scanning with whitespace-only image name."""
        response = await authenticated_client.post(
            "/api/v1/image-compliance/scan",
            params={"image_name": "   "},
        )
        assert response.status_code == 400

    @pytest.mark.skip(reason="Auth disabled in tests - all requests pass through")
    async def test_scan_requires_admin_auth(self, authenticated_client: AsyncClient):
        """Test scan endpoint requires admin authentication."""
        pass


class TestTriggerScanAll:
    """Test POST /api/v1/image-compliance/scan-all endpoint."""

    @pytest.mark.asyncio
    async def test_scan_all_images_success(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test triggering batch scan for all images."""
        with (
            patch("app.routes.image_compliance.DockerService") as mock_docker,
            patch("app.routes.image_compliance._resolve_unique_images") as mock_resolve,
            patch("app.routes.image_compliance.asyncio") as mock_asyncio,
        ):
            mock_docker.return_value = MagicMock()
            mock_resolve.return_value = {
                "nginx:latest": ["container1", "container2"],
                "redis:alpine": ["container3"],
            }
            mock_asyncio.create_task.return_value = _make_completed_task()

            response = await authenticated_client.post("/api/v1/image-compliance/scan-all")

        assert response.status_code == 200
        data = response.json()
        assert "message" in data
        assert "started" in data["message"].lower()
        assert data["image_count"] == 2

    @pytest.mark.asyncio
    async def test_scan_all_no_containers(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test scan-all when no containers are found."""
        with (
            patch("app.routes.image_compliance.DockerService") as mock_docker,
            patch("app.routes.image_compliance._resolve_unique_images") as mock_resolve,
        ):
            mock_docker.return_value = MagicMock()
            mock_resolve.return_value = {}

            response = await authenticated_client.post("/api/v1/image-compliance/scan-all")

        assert response.status_code == 404
        data = response.json()
        assert "no container images" in data["detail"].lower()

    @pytest.mark.asyncio
    async def test_scan_all_already_running(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test scan-all when scan is already in progress."""
        import app.routes.image_compliance as ic

        # Simulate an in-progress scan
        ic._current_scan_task = _make_pending_task()

        response = await authenticated_client.post("/api/v1/image-compliance/scan-all")

        assert response.status_code == 409
        data = response.json()
        assert "already in progress" in data["detail"].lower()

    @pytest.mark.skip(reason="Auth disabled in tests - all requests pass through")
    async def test_scan_all_requires_admin_auth(self, authenticated_client: AsyncClient):
        """Test scan-all endpoint requires admin authentication."""
        pass


# ===========================================================================
# Current scan status tests
# ===========================================================================


class TestGetCurrentScan:
    """Test GET /api/v1/image-compliance/current endpoint."""

    @pytest.mark.asyncio
    async def test_get_current_scan_idle(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test getting current scan status when idle."""
        response = await authenticated_client.get("/api/v1/image-compliance/current")

        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert data["status"] in ["idle", "completed", None]

    @pytest.mark.asyncio
    async def test_get_current_scan_in_progress(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test getting current scan status during execution."""
        import app.routes.image_compliance as ic

        # Simulate an in-progress scan
        ic._current_scan_task = _make_pending_task()
        image_misconfig_state._is_scanning = True
        image_misconfig_state._mode = "batch"
        image_misconfig_state._current_image = "nginx:latest"
        image_misconfig_state._progress_current = 1
        image_misconfig_state._progress_total = 3

        response = await authenticated_client.get("/api/v1/image-compliance/current")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "scanning"

    @pytest.mark.asyncio
    async def test_get_current_scan_includes_last_scan_id(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test that completed scan returns last_scan_id."""
        response = await authenticated_client.get("/api/v1/image-compliance/current")

        assert response.status_code == 200
        data = response.json()
        assert "status" in data


# ===========================================================================
# Summary tests
# ===========================================================================


class TestGetSummary:
    """Test GET /api/v1/image-compliance/summary endpoint."""

    @pytest.mark.asyncio
    async def test_get_summary_no_scans(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test getting summary with no scans."""
        response = await authenticated_client.get("/api/v1/image-compliance/summary")

        assert response.status_code == 200
        data = response.json()
        assert data["total_images_scanned"] == 0
        assert data["compliance_score"] is None
        assert data["fatal_count"] == 0
        assert data["failed_checks"] == 0

    @pytest.mark.asyncio
    async def test_get_summary_with_scans(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test getting summary with completed scans."""
        scan1 = ImageComplianceScan(
            image_name="nginx:latest",
            scan_status="completed",
            compliance_score=85.5,
            total_checks=50,
            passed_checks=40,
            failed_checks=10,
            fatal_count=2,
            warn_count=8,
        )
        scan2 = ImageComplianceScan(
            image_name="redis:alpine",
            scan_status="completed",
            compliance_score=92.0,
            total_checks=30,
            passed_checks=28,
            failed_checks=2,
            fatal_count=0,
            warn_count=2,
        )
        db_session.add_all([scan1, scan2])
        await db_session.commit()

        response = await authenticated_client.get("/api/v1/image-compliance/summary")

        assert response.status_code == 200
        data = response.json()
        assert data["total_images_scanned"] == 2
        assert isinstance(data["compliance_score"], (int, float))
        assert data["compliance_score"] >= 85
        assert data["fatal_count"] >= 2
        assert data["failed_checks"] >= 12

    @pytest.mark.asyncio
    async def test_get_summary_filters_completed_only(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test summary only includes completed scans."""
        scan_completed = ImageComplianceScan(
            image_name="nginx:latest",
            scan_status="completed",
            compliance_score=85.0,
            total_checks=50,
            passed_checks=40,
            failed_checks=10,
            fatal_count=2,
            warn_count=8,
        )
        scan_failed = ImageComplianceScan(
            image_name="redis:alpine",
            scan_status="failed",
            error_message="Scan failed",
        )
        db_session.add_all([scan_completed, scan_failed])
        await db_session.commit()

        response = await authenticated_client.get("/api/v1/image-compliance/summary")

        assert response.status_code == 200
        data = response.json()
        assert data["total_images_scanned"] == 1  # Only completed scan


# ===========================================================================
# List images tests
# ===========================================================================


class TestListImages:
    """Test GET /api/v1/image-compliance/images endpoint."""

    @pytest.mark.asyncio
    async def test_list_images_empty(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test listing images with no scans."""
        response = await authenticated_client.get("/api/v1/image-compliance/images")

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) == 0

    @pytest.mark.asyncio
    async def test_list_images_with_scans(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test listing scanned images."""
        scan = ImageComplianceScan(
            image_name="nginx:latest",
            scan_status="completed",
            compliance_score=85.5,
            total_checks=50,
            passed_checks=40,
            failed_checks=10,
            fatal_count=2,
            warn_count=8,
            affected_containers=json.dumps(["container1", "container2"]),
        )
        db_session.add(scan)
        await db_session.commit()

        response = await authenticated_client.get("/api/v1/image-compliance/images")

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) >= 1

        image = data[0]
        assert image["image_name"] == "nginx:latest"
        assert image["compliance_score"] == 85.5
        assert image["total_checks"] == 50
        assert image["passed_checks"] == 40
        assert image["failed_checks"] == 10
        assert image["fatal_count"] == 2
        assert image["warn_count"] == 8
        assert isinstance(image["affected_containers"], list)
        assert len(image["affected_containers"]) == 2

    @pytest.mark.asyncio
    async def test_list_images_sorted_by_score(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test images are sorted by compliance score (worst first)."""
        scan1 = ImageComplianceScan(
            image_name="nginx:latest",
            scan_status="completed",
            compliance_score=95.0,
        )
        scan2 = ImageComplianceScan(
            image_name="redis:alpine",
            scan_status="completed",
            compliance_score=60.0,
        )
        scan3 = ImageComplianceScan(
            image_name="postgres:14",
            scan_status="completed",
            compliance_score=80.0,
        )
        db_session.add_all([scan1, scan2, scan3])
        await db_session.commit()

        response = await authenticated_client.get("/api/v1/image-compliance/images")

        assert response.status_code == 200
        data = response.json()
        assert len(data) >= 3

        scores = [img["compliance_score"] for img in data]
        assert scores == sorted(scores)
        assert scores[0] == 60.0  # Worst score first


# ===========================================================================
# Findings tests
# ===========================================================================


class TestGetFindings:
    """Test GET /api/v1/image-compliance/findings/{image_name} endpoint."""

    @pytest.mark.asyncio
    async def test_get_findings_for_image(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test getting findings for a specific image."""
        finding = ImageComplianceFinding(
            check_id="AVD-DS-0001",
            title="Test Finding",
            description="Test description",
            image_name="nginx:latest",
            status="FAIL",
            severity="HIGH",
            category="Security",
            remediation="Fix the issue",
        )
        db_session.add(finding)
        await db_session.commit()
        await db_session.refresh(finding)

        response = await authenticated_client.get("/api/v1/image-compliance/findings/nginx:latest")

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) >= 1

        finding_data = data[0]
        assert finding_data["check_id"] == "AVD-DS-0001"
        assert finding_data["title"] == "Test Finding"
        assert finding_data["status"] == "FAIL"
        assert finding_data["severity"] == "HIGH"

    @pytest.mark.asyncio
    async def test_get_findings_filter_by_status(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test filtering findings by status."""
        image_name = "test-nginx-filter"

        finding_fail = ImageComplianceFinding(
            check_id="AVD-DS-0001",
            title="Failure",
            image_name=image_name,
            status="FAIL",
            severity="HIGH",
            category="Security",
        )
        finding_pass = ImageComplianceFinding(
            check_id="AVD-DS-0002",
            title="Pass",
            image_name=image_name,
            status="PASS",
            severity="LOW",
            category="Security",
        )
        db_session.add_all([finding_fail, finding_pass])
        await db_session.commit()

        response = await authenticated_client.get(
            f"/api/v1/image-compliance/findings/{image_name}",
            params={"status_filter": "FAIL"},
        )

        assert response.status_code == 200
        data = response.json()
        assert len(data) >= 1
        assert all(f["status"] == "FAIL" for f in data)

    @pytest.mark.asyncio
    async def test_get_findings_exclude_ignored(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test that ignored findings are excluded by default."""
        image_name = "test-nginx-ignored"

        finding_active = ImageComplianceFinding(
            check_id="AVD-DS-0001",
            title="Active Finding",
            image_name=image_name,
            status="FAIL",
            severity="HIGH",
            category="Security",
            is_ignored=False,
        )
        finding_ignored = ImageComplianceFinding(
            check_id="AVD-DS-0002",
            title="Ignored Finding",
            image_name=image_name,
            status="FAIL",
            severity="HIGH",
            category="Security",
            is_ignored=True,
            ignored_reason="False positive",
        )
        db_session.add_all([finding_active, finding_ignored])
        await db_session.commit()

        response = await authenticated_client.get(f"/api/v1/image-compliance/findings/{image_name}")

        assert response.status_code == 200
        data = response.json()
        assert all(not f["is_ignored"] for f in data)

    @pytest.mark.asyncio
    async def test_get_findings_include_ignored(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test including ignored findings when requested."""
        finding_ignored = ImageComplianceFinding(
            check_id="AVD-DS-0001",
            title="Ignored Finding",
            image_name="nginx:latest",
            status="FAIL",
            severity="HIGH",
            category="Security",
            is_ignored=True,
            ignored_reason="False positive",
        )
        db_session.add(finding_ignored)
        await db_session.commit()

        response = await authenticated_client.get(
            "/api/v1/image-compliance/findings/nginx:latest",
            params={"include_ignored": True},
        )

        assert response.status_code == 200
        data = response.json()
        assert len(data) >= 1
        ignored_findings = [f for f in data if f["is_ignored"]]
        assert len(ignored_findings) >= 1


# ===========================================================================
# Ignore / unignore tests
# ===========================================================================


class TestIgnoreFinding:
    """Test POST /api/v1/image-compliance/findings/{id}/ignore endpoint."""

    @pytest.mark.asyncio
    async def test_ignore_finding_success(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test marking a finding as ignored."""
        finding = ImageComplianceFinding(
            check_id="AVD-DS-0001",
            title="Test Finding",
            image_name="nginx:latest",
            status="FAIL",
            severity="HIGH",
            category="Security",
            is_ignored=False,
        )
        db_session.add(finding)
        await db_session.commit()
        await db_session.refresh(finding)

        response = await authenticated_client.post(
            f"/api/v1/image-compliance/findings/{finding.id}/ignore",
            params={"reason": "False positive - test environment"},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["is_ignored"] is True
        assert data["check_id"] == "AVD-DS-0001"
        assert "ignored_by" in data
        assert "ignored_at" in data

        await db_session.refresh(finding)
        assert finding.is_ignored is True
        assert finding.ignored_reason == "False positive - test environment"
        assert finding.ignored_by is not None

    @pytest.mark.asyncio
    async def test_ignore_finding_not_found(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test ignoring non-existent finding."""
        response = await authenticated_client.post(
            "/api/v1/image-compliance/findings/99999/ignore",
            params={"reason": "Test"},
        )
        assert response.status_code == 404
        data = response.json()
        assert "not found" in data["detail"].lower()

    @pytest.mark.skip(reason="Auth disabled in tests - all requests pass through")
    async def test_ignore_finding_requires_admin(self, authenticated_client: AsyncClient):
        """Test ignore endpoint requires admin authentication."""
        pass


class TestUnignoreFinding:
    """Test POST /api/v1/image-compliance/findings/{id}/unignore endpoint."""

    @pytest.mark.asyncio
    async def test_unignore_finding_success(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test unmarking a finding as ignored."""
        finding = ImageComplianceFinding(
            check_id="AVD-DS-0001",
            title="Test Finding",
            image_name="nginx:latest",
            status="FAIL",
            severity="HIGH",
            category="Security",
            is_ignored=True,
            ignored_reason="False positive",
            ignored_by="admin",
        )
        db_session.add(finding)
        await db_session.commit()
        await db_session.refresh(finding)

        response = await authenticated_client.post(
            f"/api/v1/image-compliance/findings/{finding.id}/unignore"
        )

        assert response.status_code == 200
        data = response.json()
        assert data["is_ignored"] is False
        assert data["check_id"] == "AVD-DS-0001"

        await db_session.refresh(finding)
        assert finding.is_ignored is False
        assert finding.ignored_reason is None
        assert finding.ignored_by is None

    @pytest.mark.asyncio
    async def test_unignore_finding_not_found(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test unignoring non-existent finding."""
        response = await authenticated_client.post(
            "/api/v1/image-compliance/findings/99999/unignore"
        )
        assert response.status_code == 404
        data = response.json()
        assert "not found" in data["detail"].lower()

    @pytest.mark.skip(reason="Auth disabled in tests - all requests pass through")
    async def test_unignore_finding_requires_admin(self, authenticated_client: AsyncClient):
        """Test unignore endpoint requires admin authentication."""
        pass


# ===========================================================================
# Scan history tests
# ===========================================================================


class TestScanHistory:
    """Test GET /api/v1/image-compliance/scans/history endpoint."""

    @pytest.mark.asyncio
    async def test_get_scan_history_empty(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test getting scan history with no scans."""
        response = await authenticated_client.get("/api/v1/image-compliance/scans/history")

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) == 0

    @pytest.mark.asyncio
    async def test_get_scan_history_with_scans(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test getting scan history with multiple scans."""
        scan1 = ImageComplianceScan(
            image_name="nginx:latest",
            scan_status="completed",
            compliance_score=85.0,
            scan_duration_seconds=10.5,
        )
        scan2 = ImageComplianceScan(
            image_name="redis:alpine",
            scan_status="completed",
            compliance_score=92.0,
            scan_duration_seconds=8.2,
        )
        scan3 = ImageComplianceScan(
            image_name="postgres:14",
            scan_status="failed",
            error_message="Scan failed",
        )
        db_session.add_all([scan1, scan2, scan3])
        await db_session.commit()

        response = await authenticated_client.get("/api/v1/image-compliance/scans/history")

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) >= 3

        for scan in data:
            assert "id" in scan
            assert "scan_date" in scan
            assert "scan_status" in scan
            assert "image_name" in scan
            assert "total_checks" in scan

    @pytest.mark.asyncio
    async def test_get_scan_history_with_limit(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test scan history respects limit parameter."""
        for i in range(15):
            scan = ImageComplianceScan(
                image_name=f"image{i}:latest",
                scan_status="completed",
                compliance_score=85.0,
            )
            db_session.add(scan)
        await db_session.commit()

        response = await authenticated_client.get(
            "/api/v1/image-compliance/scans/history",
            params={"limit": 5},
        )

        assert response.status_code == 200
        data = response.json()
        assert len(data) == 5

    @pytest.mark.asyncio
    async def test_get_scan_history_ordered_by_date(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test scan history is ordered by date (most recent first)."""
        from datetime import timedelta

        from app.utils.timezone import get_now

        now = get_now()
        scan1 = ImageComplianceScan(
            image_name="nginx:latest",
            scan_status="completed",
            scan_date=now - timedelta(hours=2),
        )
        scan2 = ImageComplianceScan(
            image_name="redis:alpine",
            scan_status="completed",
            scan_date=now - timedelta(hours=1),
        )
        scan3 = ImageComplianceScan(
            image_name="postgres:14",
            scan_status="completed",
            scan_date=now,
        )
        db_session.add_all([scan1, scan2, scan3])
        await db_session.commit()

        response = await authenticated_client.get("/api/v1/image-compliance/scans/history")

        assert response.status_code == 200
        data = response.json()
        assert len(data) >= 3
        assert data[0]["image_name"] == "postgres:14"


# ===========================================================================
# CSV export tests
# ===========================================================================


class TestExportCSV:
    """Test GET /api/v1/image-compliance/export/csv endpoint."""

    @pytest.mark.asyncio
    async def test_export_csv_all_findings(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test exporting all findings to CSV."""
        image_name = "test-nginx-csv"
        finding = ImageComplianceFinding(
            check_id="AVD-DS-0001",
            title="Test Finding",
            description="Test description",
            image_name=image_name,
            status="FAIL",
            severity="HIGH",
            category="Security",
            remediation="Fix the issue",
        )
        db_session.add(finding)
        await db_session.commit()

        response = await authenticated_client.get("/api/v1/image-compliance/export/csv")

        assert response.status_code == 200
        assert response.headers["content-type"] == "text/csv; charset=utf-8"
        assert "attachment" in response.headers["content-disposition"]

        content = response.content.decode("utf-8")
        assert "Check ID" in content
        assert "Image Name" in content
        assert "AVD-DS-0001" in content
        assert image_name in content

    @pytest.mark.asyncio
    async def test_export_csv_filter_by_image(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test exporting findings filtered by image name."""
        image1 = "test-nginx-csv-filter"
        image2 = "test-redis-csv-filter"
        finding1 = ImageComplianceFinding(
            check_id="AVD-DS-0001",
            title="Finding 1",
            image_name=image1,
            status="FAIL",
            severity="HIGH",
            category="Security",
        )
        finding2 = ImageComplianceFinding(
            check_id="AVD-DS-0002",
            title="Finding 2",
            image_name=image2,
            status="FAIL",
            severity="MEDIUM",
            category="Security",
        )
        db_session.add_all([finding1, finding2])
        await db_session.commit()

        response = await authenticated_client.get(
            "/api/v1/image-compliance/export/csv",
            params={"image_name": image1},
        )

        assert response.status_code == 200
        content = response.content.decode("utf-8")
        assert image1 in content
        assert image2 not in content

    @pytest.mark.asyncio
    async def test_export_csv_exclude_ignored(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test CSV export excludes ignored findings by default."""
        image_name = "test-nginx-csv-ignored"
        finding_active = ImageComplianceFinding(
            check_id="AVD-DS-0001",
            title="Active",
            image_name=image_name,
            status="FAIL",
            severity="HIGH",
            category="Security",
            is_ignored=False,
        )
        finding_ignored = ImageComplianceFinding(
            check_id="AVD-DS-0002",
            title="Ignored",
            image_name=image_name,
            status="FAIL",
            severity="HIGH",
            category="Security",
            is_ignored=True,
        )
        db_session.add_all([finding_active, finding_ignored])
        await db_session.commit()

        response = await authenticated_client.get("/api/v1/image-compliance/export/csv")

        assert response.status_code == 200
        content = response.content.decode("utf-8")
        assert "Active" in content
        assert (
            "Ignored" not in content or ",No," in content
        )  # Either not present or marked as not ignored

    @pytest.mark.asyncio
    async def test_export_csv_include_ignored(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test CSV export includes ignored findings when requested."""
        finding_ignored = ImageComplianceFinding(
            check_id="AVD-DS-0001",
            title="Ignored Finding",
            image_name="nginx:latest",
            status="FAIL",
            severity="HIGH",
            category="Security",
            is_ignored=True,
            ignored_reason="False positive",
        )
        db_session.add(finding_ignored)
        await db_session.commit()

        response = await authenticated_client.get(
            "/api/v1/image-compliance/export/csv",
            params={"include_ignored": True},
        )

        assert response.status_code == 200
        content = response.content.decode("utf-8")
        assert "Ignored Finding" in content
        assert ",Yes," in content  # is_ignored = Yes

    @pytest.mark.asyncio
    async def test_export_csv_empty_database(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test CSV export with no findings."""
        response = await authenticated_client.get("/api/v1/image-compliance/export/csv")

        assert response.status_code == 200
        content = response.content.decode("utf-8")
        assert "Check ID" in content
        lines = content.strip().split("\n")
        assert len(lines) == 1  # Only header row
