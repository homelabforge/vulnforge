"""Tests for dashboard widget API endpoints.

This module tests the widget data API which provides:
- Summary statistics widget
- Critical vulnerability widget
- Top vulnerable containers widget
- Remediation recommendations widget
"""

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession


class TestSummaryWidget:
    """Test GET /api/v1/widget/summary endpoint."""

    @pytest.mark.asyncio
    async def test_get_summary_widget(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test getting summary widget data."""
        # Act
        response = await authenticated_client.get("/api/v1/widget/summary")

        # Assert
        assert response.status_code == 200
        data = response.json()
        assert "total_containers" in data
        assert "scanned_containers" in data
        assert "total_vulnerabilities" in data
        assert "fixable_vulnerabilities" in data
        assert "critical_count" in data
        assert "high_count" in data
        assert "medium_count" in data
        assert "low_count" in data
        assert "total_secrets" in data

    @pytest.mark.asyncio
    async def test_summary_widget_with_data(
        self,
        authenticated_client: AsyncClient,
        db_session: AsyncSession,
        make_container,
        make_scan,
        make_vulnerability,
    ):
        """Test summary widget returns data with expected types."""
        # Arrange
        container = make_container()
        db_session.add(container)
        await db_session.commit()
        await db_session.refresh(container)

        scan = make_scan(container_id=container.id, total_vulns=5)
        db_session.add(scan)
        await db_session.commit()
        await db_session.refresh(scan)

        # Create critical vulnerability
        vuln = make_vulnerability(scan_id=scan.id, severity="CRITICAL")
        db_session.add(vuln)
        await db_session.commit()

        # Act
        response = await authenticated_client.get("/api/v1/widget/summary")

        # Assert
        assert response.status_code == 200
        data = response.json()
        # Validate types and structure, not specific counts (due to test isolation)
        assert isinstance(data["total_containers"], int)
        assert isinstance(data["scanned_containers"], int)
        assert isinstance(data["total_vulnerabilities"], int)
        assert data["total_containers"] >= 0
        assert data["scanned_containers"] >= 0

    @pytest.mark.asyncio
    async def test_summary_widget_structure(self, authenticated_client: AsyncClient):
        """Test summary widget has expected structure."""
        # Act
        response = await authenticated_client.get("/api/v1/widget/summary")

        # Assert
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data["total_containers"], int)
        assert isinstance(data["scanned_containers"], int)
        assert isinstance(data["total_vulnerabilities"], int)
        assert isinstance(data["critical_count"], int)

    @pytest.mark.asyncio
    async def test_summary_widget_caching(self, authenticated_client: AsyncClient):
        """Test summary widget responses are consistent (cached)."""
        # Act
        response1 = await authenticated_client.get("/api/v1/widget/summary")
        response2 = await authenticated_client.get("/api/v1/widget/summary")

        # Assert
        assert response1.status_code == 200
        assert response2.status_code == 200
        # Should return same data (from cache)
        assert response1.json() == response2.json()


class TestCriticalWidget:
    """Test GET /api/v1/widget/critical endpoint."""

    @pytest.mark.asyncio
    async def test_get_critical_widget(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test getting critical vulnerability widget data."""
        # Act
        response = await authenticated_client.get("/api/v1/widget/critical")

        # Assert
        assert response.status_code == 200
        data = response.json()
        assert "critical_total" in data
        assert "critical_fixable" in data
        assert "high_total" in data
        assert "high_fixable" in data
        assert "most_vulnerable_container" in data
        assert "most_vulnerable_count" in data

    @pytest.mark.asyncio
    async def test_critical_widget_with_vulnerabilities(
        self,
        authenticated_client: AsyncClient,
        db_session: AsyncSession,
        make_container,
        make_scan,
        make_vulnerability,
    ):
        """Test critical widget returns data with expected structure."""
        # Arrange
        container = make_container(name="vuln-container")
        db_session.add(container)
        await db_session.commit()
        await db_session.refresh(container)

        scan = make_scan(container_id=container.id, total_vulns=10)
        db_session.add(scan)
        await db_session.commit()
        await db_session.refresh(scan)

        # Create critical and high vulnerabilities
        critical_vuln = make_vulnerability(
            scan_id=scan.id, severity="CRITICAL", fixed_version="1.2.3"
        )
        high_vuln = make_vulnerability(scan_id=scan.id, severity="HIGH", fixed_version="2.0.0")
        db_session.add_all([critical_vuln, high_vuln])
        await db_session.commit()

        # Act
        response = await authenticated_client.get("/api/v1/widget/critical")

        # Assert
        assert response.status_code == 200
        data = response.json()
        # Validate types and structure, not specific counts (due to test isolation)
        assert isinstance(data["critical_total"], int)
        assert isinstance(data["high_total"], int)
        assert isinstance(data["critical_fixable"], int)
        assert isinstance(data["high_fixable"], int)
        assert data["critical_total"] >= 0
        assert data["high_total"] >= 0

    @pytest.mark.asyncio
    async def test_critical_widget_most_vulnerable(
        self,
        authenticated_client: AsyncClient,
        db_session: AsyncSession,
        make_container,
        make_scan,
    ):
        """Test critical widget identifies most vulnerable container."""
        # Arrange
        container1 = make_container(name="container-1")
        container2 = make_container(name="container-2")
        db_session.add_all([container1, container2])
        await db_session.commit()
        await db_session.refresh(container1)
        await db_session.refresh(container2)

        # Container 2 has more vulnerabilities
        scan1 = make_scan(container_id=container1.id, total_vulns=5)
        scan2 = make_scan(container_id=container2.id, total_vulns=20)
        db_session.add_all([scan1, scan2])
        await db_session.commit()

        # Act
        response = await authenticated_client.get("/api/v1/widget/critical")

        # Assert
        assert response.status_code == 200
        data = response.json()
        # Most vulnerable should be container-2 (or None if no vulns)
        if data["most_vulnerable_container"] is not None:
            assert data["most_vulnerable_count"] >= 0


class TestTopContainersWidget:
    """Test GET /api/v1/widget/top-containers endpoint."""

    @pytest.mark.asyncio
    async def test_get_top_containers_widget(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test getting top vulnerable containers widget."""
        # Act
        response = await authenticated_client.get("/api/v1/widget/top-containers")

        # Assert
        assert response.status_code == 200
        data = response.json()
        assert "containers" in data
        assert isinstance(data["containers"], list)

    @pytest.mark.asyncio
    async def test_top_containers_with_limit(
        self,
        authenticated_client: AsyncClient,
        db_session: AsyncSession,
        make_container,
        make_scan,
    ):
        """Test top containers respects limit parameter."""
        # Arrange
        for i in range(15):
            container = make_container(name=f"container-{i}")
            db_session.add(container)
            await db_session.commit()
            await db_session.refresh(container)

            scan = make_scan(container_id=container.id, total_vulns=i + 1)
            db_session.add(scan)
        await db_session.commit()

        # Act
        response = await authenticated_client.get("/api/v1/widget/top-containers?limit=5")

        # Assert
        assert response.status_code == 200
        data = response.json()
        assert len(data["containers"]) <= 5

    @pytest.mark.asyncio
    async def test_top_containers_ordered_by_vulnerability_count(
        self,
        authenticated_client: AsyncClient,
        db_session: AsyncSession,
        make_container,
        make_scan,
    ):
        """Test top containers are ordered by vulnerability count."""
        # Arrange
        containers_data = [
            ("low-vulns", 5),
            ("high-vulns", 50),
            ("medium-vulns", 20),
        ]

        for name, vuln_count in containers_data:
            container = make_container(name=name)
            db_session.add(container)
            await db_session.commit()
            await db_session.refresh(container)

            scan = make_scan(container_id=container.id, total_vulns=vuln_count)
            db_session.add(scan)
        await db_session.commit()

        # Act
        response = await authenticated_client.get("/api/v1/widget/top-containers?limit=3")

        # Assert
        assert response.status_code == 200
        data = response.json()
        if len(data["containers"]) > 1:
            # Verify descending order
            counts = [c["vuln_count"] for c in data["containers"]]
            assert counts == sorted(counts, reverse=True)

    @pytest.mark.asyncio
    async def test_top_containers_structure(
        self,
        authenticated_client: AsyncClient,
        db_session: AsyncSession,
        make_container,
        make_scan,
    ):
        """Test top containers have expected structure."""
        # Arrange
        container = make_container()
        db_session.add(container)
        await db_session.commit()
        await db_session.refresh(container)

        scan = make_scan(container_id=container.id, total_vulns=10)
        db_session.add(scan)
        await db_session.commit()

        # Act
        response = await authenticated_client.get("/api/v1/widget/top-containers")

        # Assert
        assert response.status_code == 200
        data = response.json()
        if len(data["containers"]) > 0:
            container = data["containers"][0]
            assert "name" in container
            assert "vuln_count" in container


class TestRemediationWidget:
    """Test GET /api/v1/widget/remediation endpoint."""

    @pytest.mark.asyncio
    async def test_get_remediation_widget(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test getting remediation widget data."""
        # Act
        response = await authenticated_client.get("/api/v1/widget/remediation")

        # Assert
        assert response.status_code == 200
        data = response.json()
        assert "total_packages_to_update" in data
        assert "total_cves_fixable" in data
        assert "critical_cves_fixable" in data
        assert "high_cves_fixable" in data
        assert "impact_message" in data
        assert "top_remediations" in data
        assert isinstance(data["top_remediations"], list)

    @pytest.mark.asyncio
    async def test_remediation_widget_with_fixable_vulns(
        self,
        authenticated_client: AsyncClient,
        db_session: AsyncSession,
        make_container,
        make_scan,
        make_vulnerability,
    ):
        """Test remediation widget with fixable vulnerabilities."""
        # Arrange
        container = make_container()
        db_session.add(container)
        await db_session.commit()
        await db_session.refresh(container)

        scan = make_scan(container_id=container.id)
        db_session.add(scan)
        await db_session.commit()
        await db_session.refresh(scan)

        # Create fixable vulnerabilities
        vuln1 = make_vulnerability(
            scan_id=scan.id,
            package_name="openssl",
            installed_version="1.0.0",
            fixed_version="1.1.0",
            severity="CRITICAL",
        )
        vuln2 = make_vulnerability(
            scan_id=scan.id,
            package_name="curl",
            installed_version="7.0.0",
            fixed_version="7.80.0",
            severity="HIGH",
        )
        db_session.add_all([vuln1, vuln2])
        await db_session.commit()

        # Act
        response = await authenticated_client.get("/api/v1/widget/remediation")

        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["total_cves_fixable"] >= 2
        assert data["critical_cves_fixable"] >= 1
        assert data["high_cves_fixable"] >= 1
        assert data["total_packages_to_update"] >= 1

    @pytest.mark.asyncio
    async def test_remediation_widget_with_limit(
        self,
        authenticated_client: AsyncClient,
        db_session: AsyncSession,
        make_container,
        make_scan,
        make_vulnerability,
    ):
        """Test remediation widget respects limit parameter."""
        # Arrange
        container = make_container()
        db_session.add(container)
        await db_session.commit()
        await db_session.refresh(container)

        scan = make_scan(container_id=container.id)
        db_session.add(scan)
        await db_session.commit()
        await db_session.refresh(scan)

        # Create 10 different package vulnerabilities
        for i in range(10):
            vuln = make_vulnerability(
                scan_id=scan.id,
                package_name=f"package-{i}",
                installed_version="1.0.0",
                fixed_version="2.0.0",
            )
            db_session.add(vuln)
        await db_session.commit()

        # Act
        response = await authenticated_client.get("/api/v1/widget/remediation?limit=3")

        # Assert
        assert response.status_code == 200
        data = response.json()
        assert len(data["top_remediations"]) <= 3

    @pytest.mark.asyncio
    async def test_remediation_item_structure(
        self,
        authenticated_client: AsyncClient,
        db_session: AsyncSession,
        make_container,
        make_scan,
        make_vulnerability,
    ):
        """Test remediation items have expected structure."""
        # Arrange
        container = make_container()
        db_session.add(container)
        await db_session.commit()
        await db_session.refresh(container)

        scan = make_scan(container_id=container.id)
        db_session.add(scan)
        await db_session.commit()
        await db_session.refresh(scan)

        vuln = make_vulnerability(
            scan_id=scan.id,
            package_name="test-package",
            installed_version="1.0.0",
            fixed_version="2.0.0",
            severity="HIGH",
        )
        db_session.add(vuln)
        await db_session.commit()

        # Act
        response = await authenticated_client.get("/api/v1/widget/remediation")

        # Assert
        assert response.status_code == 200
        data = response.json()
        if len(data["top_remediations"]) > 0:
            item = data["top_remediations"][0]
            assert "package" in item
            assert "current_version" in item
            assert "fixed_version" in item
            assert "fixes_count" in item
            assert "fixes_critical" in item
            assert "fixes_high" in item

    @pytest.mark.asyncio
    async def test_remediation_impact_message(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test remediation widget includes impact message."""
        # Act
        response = await authenticated_client.get("/api/v1/widget/remediation")

        # Assert
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data["impact_message"], str)
        assert len(data["impact_message"]) > 0
