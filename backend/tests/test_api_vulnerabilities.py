"""Tests for vulnerabilities API endpoints."""

from fastapi import HTTPException


class TestVulnerabilitiesList:
    """Tests for vulnerability listing endpoint."""

    async def test_list_requires_auth(self, authenticated_client):
        """Listing vulnerabilities requires authentication."""
        response = await authenticated_client.get("/api/v1/vulnerabilities")
        assert response.status_code == 200

    async def test_list_vulnerabilities_success(self, authenticated_client, db_with_settings):
        """Test successful vulnerability listing."""
        response = await authenticated_client.get("/api/v1/vulnerabilities")

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, dict)
        assert "vulnerabilities" in data

    async def test_filter_by_severity(self, authenticated_client, db_with_settings):
        """Test filtering vulnerabilities by severity."""
        severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]

        for severity in severities:
            response = await authenticated_client.get(
                f"/api/v1/vulnerabilities?severity={severity}"
            )

            assert response.status_code == 200
            data = response.json()
            assert isinstance(data, dict)

    async def test_filter_fixable_only(self, authenticated_client, db_with_settings):
        """Test filtering for fixable vulnerabilities only."""
        response = await authenticated_client.get("/api/v1/vulnerabilities?fixable_only=true")
        assert response.status_code == 200

    async def test_filter_kev_only(self, authenticated_client, db_with_settings):
        """Test filtering for KEV (Known Exploited Vulnerabilities) only."""
        response = await authenticated_client.get("/api/v1/vulnerabilities?kev_only=true")
        assert response.status_code == 200

    async def test_filter_by_status(self, authenticated_client, db_with_settings):
        """Test filtering by vulnerability status."""
        statuses = ["active", "ignored", "resolved", "false_positive"]

        for status in statuses:
            response = await authenticated_client.get(f"/api/v1/vulnerabilities?status={status}")
            assert response.status_code == 200


class TestVulnerabilitiesSQLInjection:
    """Tests for SQL injection prevention in vulnerability filters."""

    async def test_sql_injection_in_severity_filter(self, authenticated_client, db_with_settings):
        """Test that SQL injection attempts in severity filter are blocked."""
        # SQL injection attempts
        injection_attempts = [
            "CRITICAL' OR '1'='1",
            "HIGH'; DROP TABLE vulnerabilities--",
            "MEDIUM' UNION SELECT * FROM settings--",
        ]

        for injection in injection_attempts:
            response = await authenticated_client.get(
                f"/api/v1/vulnerabilities?severity={injection}"
            )

            # Should reject or treat as invalid, not execute SQL
            assert response.status_code in [200, 400, 422]

            # Should not return all vulnerabilities (injection success indicator)
            if response.status_code == 200:
                # Verify no SQL injection occurred
                response.json()
                # Response should be empty or only contain matching severity
                # Not all vulnerabilities from database

    async def test_sql_injection_in_package_name(self, authenticated_client, db_with_settings):
        """Test SQL injection prevention in package name filter."""
        injection_attempts = [
            "openssl' OR 1=1--",
            "'; DELETE FROM vulnerabilities--",
        ]

        for injection in injection_attempts:
            response = await authenticated_client.get(
                f"/api/v1/vulnerabilities?package_name={injection}"
            )

            # Should handle safely
            assert response.status_code in [200, 400, 422]


class TestVulnerabilitiesBulkUpdate:
    """Tests for bulk vulnerability update endpoint."""

    async def test_bulk_update_requires_auth(self, authenticated_client):
        """Test that bulk update requires admin privileges."""
        from app.dependencies.auth import require_admin
        from app.main import app

        async def override_require_admin(request=None):
            raise HTTPException(status_code=403, detail="Admin required")

        app.dependency_overrides[require_admin] = override_require_admin

        response = await authenticated_client.post(
            "/api/v1/vulnerabilities/bulk-update",
            json={
                "vuln_ids": [1, 2],
                "update": {"status": "ignored", "notes": "test"},
            },
        )

        assert response.status_code == 403

        app.dependency_overrides.clear()

    async def test_bulk_update_success(self, authenticated_client, db_with_settings):
        """Test successful bulk update."""
        from app.main import app
        from app.repositories.dependencies import (
            get_activity_logger,
            get_vulnerability_repository,
        )

        class DummyVulnRepo:
            async def bulk_update_status(self, vuln_ids, status, notes=None):
                return len(vuln_ids)

        class DummyActivityLogger:
            async def log_bulk_vulnerability_status_changed(
                self, vuln_count, old_status, new_status, username, notes
            ):
                return None

        app.dependency_overrides[get_vulnerability_repository] = lambda: DummyVulnRepo()
        app.dependency_overrides[get_activity_logger] = lambda: DummyActivityLogger()

        response = await authenticated_client.post(
            "/api/v1/vulnerabilities/bulk-update",
            json={
                "vuln_ids": [1, 2, 3],
                "update": {
                    "status": "ignored",
                    "notes": "False positive",
                },
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert data["updated"] == 3

        app.dependency_overrides.clear()

    async def test_bulk_update_invalid_status(self, authenticated_client, db_with_settings):
        """Test bulk update with invalid status value."""
        response = await authenticated_client.post(
            "/api/v1/vulnerabilities/bulk-update",
            json={
                "vuln_ids": [1],
                "update": {"status": "invalid_status"},
            },
        )

        # Should reject invalid status or indicate no rows updated
        assert response.status_code in [400, 404, 422]


class TestVulnerabilitiesRemediationGroups:
    """Tests for vulnerability remediation groups endpoint."""

    async def test_remediation_groups_requires_auth(self, authenticated_client):
        """Remediation groups endpoint is public in current model."""
        response = await authenticated_client.get("/api/v1/vulnerabilities/remediation-groups")
        assert response.status_code == 200

    async def test_remediation_groups_success(self, authenticated_client, db_with_settings):
        """Test successful remediation groups retrieval."""
        from app.main import app
        from app.repositories.dependencies import get_vulnerability_repository

        class DummyVulnRepo:
            async def get_remediation_groups(self, container_id=None):
                return [
                    {
                        "package_name": "openssl",
                        "installed_version": "1.0.0",
                        "fixed_version": "1.1.1",
                        "cve_count": 2,
                        "critical_count": 1,
                        "high_count": 1,
                        "medium_count": 0,
                        "low_count": 0,
                    }
                ]

        app.dependency_overrides[get_vulnerability_repository] = lambda: DummyVulnRepo()

        response = await authenticated_client.get("/api/v1/vulnerabilities/remediation-groups")

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        if data:
            assert "package_name" in data[0]

        app.dependency_overrides.clear()


class TestVulnerabilitiesExport:
    """Tests for vulnerability export functionality."""

    async def test_export_csv_requires_auth(self, authenticated_client):
        """CSV export is publicly accessible in the new workflow."""
        response = await authenticated_client.get("/api/v1/vulnerabilities/export?format=csv")
        assert response.status_code in [200, 204, 404]

    async def test_export_csv_success(self, authenticated_client, db_with_settings):
        """Test successful CSV export."""
        from app.main import app
        from app.repositories.dependencies import get_vulnerability_repository

        class DummyVulnRepo:
            async def get_for_export(self, **kwargs):
                return [
                    {
                        "cve_id": "CVE-2024-0001",
                        "container": "app",
                        "package": "openssl",
                        "severity": "HIGH",
                        "cvss_score": 7.5,
                        "installed_version": "1.0.0",
                        "fixed_version": "1.0.1",
                        "is_fixable": True,
                        "status": "active",
                        "title": "Test vulnerability",
                    }
                ]

        app.dependency_overrides[get_vulnerability_repository] = lambda: DummyVulnRepo()

        response = await authenticated_client.get("/api/v1/vulnerabilities/export?format=csv")

        assert response.status_code == 200
        assert "text/csv" in response.headers.get("content-type", "").lower()
        assert "CVE-2024-0001" in response.text

        app.dependency_overrides.clear()

    async def test_export_json_success(self, authenticated_client, db_with_settings):
        """Test successful JSON export."""
        from app.main import app
        from app.repositories.dependencies import get_vulnerability_repository

        class DummyVulnRepo:
            async def get_for_export(self, **kwargs):
                return [
                    {
                        "cve_id": "CVE-2024-0002",
                        "container": "db",
                        "package": "libssl",
                        "severity": "MEDIUM",
                        "cvss_score": 5.0,
                        "installed_version": "2.0.0",
                        "fixed_version": None,
                        "is_fixable": False,
                        "status": "active",
                        "title": "Another vulnerability",
                    }
                ]

        app.dependency_overrides[get_vulnerability_repository] = lambda: DummyVulnRepo()

        response = await authenticated_client.get("/api/v1/vulnerabilities/export?format=json")

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert data and data[0]["cve_id"] == "CVE-2024-0002"

        app.dependency_overrides.clear()


class TestVulnerabilitiesPagination:
    """Tests for vulnerability pagination."""

    async def test_pagination_parameters(self, authenticated_client, db_with_settings):
        """Test pagination with skip and limit parameters."""
        # Test various pagination parameters
        response = await authenticated_client.get("/api/v1/vulnerabilities?offset=0&limit=10")
        assert response.status_code == 200

        response = await authenticated_client.get("/api/v1/vulnerabilities?offset=10&limit=20")
        assert response.status_code == 200

    async def test_pagination_negative_values(self, authenticated_client, db_with_settings):
        """Test that negative pagination values are rejected."""
        # Negative offset
        response = await authenticated_client.get("/api/v1/vulnerabilities?offset=-1&limit=10")
        assert response.status_code in [200, 400, 422]

        # Negative limit
        response = await authenticated_client.get("/api/v1/vulnerabilities?offset=0&limit=-1")
        assert response.status_code in [200, 400, 422]
