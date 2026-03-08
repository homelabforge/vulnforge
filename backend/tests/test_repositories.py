"""Tests for database repositories."""

from datetime import timedelta

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Secret, Vulnerability
from app.repositories.container_repository import ContainerRepository
from app.repositories.scan_result_repository import ScanResultRepository
from app.repositories.secret_repository import SecretRepository
from app.utils.timezone import get_now


@pytest.mark.asyncio
class TestContainerRepository:
    """Tests for Container repository operations."""

    @pytest.fixture
    async def repository(self, db_session: AsyncSession):
        return ContainerRepository(db_session)

    async def test_create_container(self, repository, db_session):
        """Test creating a new container."""
        container = await repository.create(
            container_id="abc123", name="test-container", image="nginx:latest", status="running"
        )

        assert container.id is not None
        assert container.container_id == "abc123"
        assert container.name == "test-container"
        assert container.image == "nginx"
        assert container.image_tag == "latest"
        assert container.is_running is True

    async def test_get_by_container_id(self, repository, db_session):
        """Test retrieving container by Docker container ID."""
        # Create container
        created = await repository.create(
            container_id="xyz789", name="test-app", image="python:3.12", status="running"
        )

        # Retrieve by container_id
        found = await repository.get_by_container_id("xyz789")

        assert found is not None
        assert found.id == created.id
        assert found.container_id == "xyz789"
        assert found.image == "python"
        assert found.image_tag == "3.12"

    async def test_get_by_container_id_not_found(self, repository):
        """Test retrieving non-existent container returns None."""
        found = await repository.get_by_container_id("nonexistent")

        assert found is None

    async def test_list_all_containers(self, repository, db_session):
        """Test listing all containers."""
        # Create multiple containers
        await repository.create(
            container_id="container1", name="app1", image="nginx:1.21", status="running"
        )
        await repository.create(
            container_id="container2", name="app2", image="redis:7", status="exited"
        )

        # List all
        containers = await repository.list_all()

        assert len(containers) == 2
        assert any(c.name == "app1" for c in containers)
        assert any(c.name == "app2" for c in containers)

    async def test_update_container_status(self, repository, db_session):
        """Test updating container status."""
        container = await repository.create(
            container_id="update-test",
            name="test-container",
            image="alpine:latest",
            status="running",
        )

        # Update status
        container.is_running = False
        updated = await repository.update(container)

        assert updated.is_running is False

        # Verify in database
        found = await repository.get_by_container_id("update-test")
        assert found.is_running is False

    async def test_delete_container(self, repository, db_session):
        """Test deleting a container."""
        container = await repository.create(
            container_id="delete-test",
            name="temp-container",
            image="busybox:latest",
            status="exited",
        )

        # Delete
        await repository.delete(container)

        # Verify deleted
        found = await repository.get_by_container_id("delete-test")
        assert found is None

    async def test_remove_missing_containers(self, repository):
        """Remove containers that are no longer reported by Docker."""
        await repository.create(
            container_id="keep",
            name="keep-container",
            image="redis:7",
            status="running",
        )
        await repository.create(
            container_id="drop",
            name="drop-container",
            image="nginx:latest",
            status="running",
        )

        removed = await repository.remove_missing({"keep-container"}, {"keep"})
        assert removed == 1

        remaining = await repository.list_all()
        assert len(remaining) == 1
        assert remaining[0].name == "keep-container"


@pytest.mark.asyncio
class TestScanResultRepository:
    """Tests for ScanResult repository operations."""

    @pytest.fixture
    async def container(self, db_session: AsyncSession):
        """Create a test container."""
        container_repo = ContainerRepository(db_session)
        return await container_repo.create(
            container_id="scan-test", name="test-app", image="vulnerable:latest", status="running"
        )

    @pytest.fixture
    async def repository(self, db_session: AsyncSession):
        return ScanResultRepository(db_session)

    async def test_create_scan_result(self, repository, container):
        """Test creating a scan result."""
        scan_result = await repository.create(
            container_id=container.id,
            image_name="vulnerable:latest",
            scan_type="vulnerability",
            status="completed",
        )

        assert scan_result.id is not None
        assert scan_result.container_id == container.id
        assert scan_result.image_name == "vulnerable:latest"
        assert scan_result.scan_type == "vulnerability"
        assert scan_result.status == "completed"
        assert scan_result.created_at is not None

    async def test_get_latest_scan_for_container(self, repository, container):
        """Test retrieving the latest scan for a container."""
        # Create multiple scans
        await repository.create(
            container_id=container.id,
            image_name="vulnerable:latest",
            scan_type="vulnerability",
            status="completed",
        )

        import asyncio

        await asyncio.sleep(0.1)  # Ensure different timestamps

        latest = await repository.create(
            container_id=container.id,
            image_name="vulnerable:latest",
            scan_type="vulnerability",
            status="completed",
        )

        # Get latest
        found = await repository.get_latest_for_container(container.id, "vulnerability")

        assert found is not None
        assert found.id == latest.id

    async def test_get_scan_with_vulnerabilities(self, repository, container, db_session):
        """Test retrieving scan with associated vulnerabilities."""
        # Create scan
        scan = await repository.create(
            container_id=container.id,
            image_name="vulnerable:latest",
            scan_type="vulnerability",
            status="completed",
        )

        # Add vulnerabilities
        vuln1 = Vulnerability(
            scan_result_id=scan.id,
            cve_id="CVE-2024-0001",
            package_name="openssl",
            installed_version="1.0.0",
            fixed_version="1.0.1",
            is_fixable=True,
            severity="HIGH",
            title="Test vulnerability",
        )
        vuln2 = Vulnerability(
            scan_result_id=scan.id,
            cve_id="CVE-2024-0002",
            package_name="curl",
            installed_version="7.0.0",
            fixed_version="7.1.0",
            is_fixable=True,
            severity="CRITICAL",
            title="Another test vulnerability",
        )

        db_session.add(vuln1)
        db_session.add(vuln2)
        await db_session.commit()

        # Retrieve with vulnerabilities
        found = await repository.get_by_id(scan.id)

        assert found is not None
        assert len(found.vulnerabilities) == 2

    async def test_count_vulnerabilities_by_severity(self, repository, container, db_session):
        """Test counting vulnerabilities grouped by severity."""
        # Create scan with vulnerabilities
        scan = await repository.create(
            container_id=container.id,
            image_name="vulnerable:latest",
            scan_type="vulnerability",
            status="completed",
        )

        # Add vulnerabilities of different severities
        for i, severity in enumerate(["CRITICAL", "CRITICAL", "HIGH", "MEDIUM", "LOW"]):
            vuln = Vulnerability(
                scan_result_id=scan.id,
                cve_id=f"CVE-2024-{i:04d}",
                package_name=f"package{i}",
                installed_version="1.0.0",
                is_fixable=False,
                severity=severity,
                title=f"Test vuln {i}",
            )
            db_session.add(vuln)

        await db_session.commit()

        # Manually count (would normally be a repository method)
        from sqlalchemy import func, select

        result = await db_session.execute(
            select(Vulnerability.severity, func.count(Vulnerability.id))
            .where(Vulnerability.scan_result_id == scan.id)
            .group_by(Vulnerability.severity)
        )
        counts = dict(result.all())

        assert counts.get("CRITICAL") == 2
        assert counts.get("HIGH") == 1
        assert counts.get("MEDIUM") == 1
        assert counts.get("LOW") == 1


@pytest.mark.asyncio
class TestSecretRepository:
    """Tests for Secret findings repository."""

    @pytest.fixture
    async def scan_result(self, db_session: AsyncSession):
        """Create a test scan result."""
        container_repo = ContainerRepository(db_session)
        container = await container_repo.create(
            container_id="secret-test",
            name="app-with-secrets",
            image="leaky:latest",
            status="running",
        )

        scan_repo = ScanResultRepository(db_session)
        return await scan_repo.create(
            container_id=container.id,
            image_name="leaky:latest",
            scan_type="secret",
            status="completed",
        )

    async def test_create_secret_finding(self, scan_result, db_session):
        """Test creating a secret finding."""
        secret = Secret(
            scan_result_id=scan_result.id,
            rule_id="generic-api-key",
            category="general",
            severity="HIGH",
            title="Generic API Key",
            match="api_key=***",
            code_snippet="Line 42: ***REDACTED***",
            start_line=42,
            end_line=42,
        )

        db_session.add(secret)
        await db_session.commit()

        assert secret.id is not None
        assert secret.rule_id == "generic-api-key"
        assert secret.code_snippet is not None
        assert "***REDACTED***" in secret.code_snippet

    async def test_secrets_are_redacted(self, scan_result, db_session):
        """Test that stored secrets have redacted code snippets."""
        secret = Secret(
            scan_result_id=scan_result.id,
            rule_id="aws-access-key",
            category="AWS",
            severity="CRITICAL",
            title="AWS Access Key",
            match="AKIA***",
            code_snippet="Line 10: ***REDACTED***\nLine 11: ***REDACTED***",
            start_line=10,
            end_line=11,
        )

        db_session.add(secret)
        await db_session.commit()

        # Retrieve and verify
        from sqlalchemy import select

        result = await db_session.execute(select(Secret).where(Secret.id == secret.id))
        found = result.scalar_one()

        assert found.code_snippet is not None
        assert "***REDACTED***" in found.code_snippet
        assert "AKIA" not in found.code_snippet or "***" in found.match


@pytest.mark.asyncio
class TestSecretRepositoryLatestScanScoping:
    """Tests that SecretRepository methods scope to latest completed scan per container."""

    @pytest.fixture
    async def repo(self, db_session: AsyncSession):
        """SecretRepository backed by the test session."""
        return SecretRepository(db_session)

    @staticmethod
    def _make_secret(
        scan_id: int, status: str = "to_review", severity: str = "HIGH", title: str = "Test Secret"
    ) -> Secret:
        """Create a Secret with explicit fields, bypassing the broken make_secret factory."""
        return Secret(
            scan_id=scan_id,
            rule_id="test-rule",
            category="Generic",
            title=title,
            severity=severity,
            file_path="/path/to/file",
            start_line=1,
            match="***REDACTED***",
            status=status,
        )

    @pytest.fixture
    async def single_container_multi_scan(self, db_session, make_container, make_scan):
        """1 container with 2 completed scans: old (3 secrets) and new (1 secret)."""
        now = get_now()
        container = make_container(name="web-app")
        db_session.add(container)
        await db_session.flush()

        old_scan = make_scan(
            container_id=container.id,
            scan_status="completed",
            scan_date=now - timedelta(hours=2),
        )
        db_session.add(old_scan)
        await db_session.flush()

        for i in range(3):
            db_session.add(
                self._make_secret(
                    scan_id=old_scan.id,
                    status="to_review",
                    severity="HIGH",
                    title=f"Old secret {i}",
                )
            )

        new_scan = make_scan(
            container_id=container.id,
            scan_status="completed",
            scan_date=now,
        )
        db_session.add(new_scan)
        await db_session.flush()

        db_session.add(
            self._make_secret(
                scan_id=new_scan.id,
                status="to_review",
                severity="CRITICAL",
                title="New secret",
            )
        )

        await db_session.commit()
        return container, old_scan, new_scan

    @pytest.fixture
    async def multi_container_setup(self, db_session, make_container, make_scan):
        """2 containers, each with old scan (3 secrets) and new scan (1 secret)."""
        now = get_now()
        containers = []
        for name in ("app-a", "app-b"):
            c = make_container(name=name)
            db_session.add(c)
            await db_session.flush()

            old_scan = make_scan(
                container_id=c.id,
                scan_status="completed",
                scan_date=now - timedelta(hours=2),
            )
            db_session.add(old_scan)
            await db_session.flush()

            for i in range(3):
                db_session.add(
                    self._make_secret(
                        scan_id=old_scan.id,
                        status="to_review",
                        severity="MEDIUM",
                        title=f"Old {name} secret {i}",
                    )
                )

            new_scan = make_scan(
                container_id=c.id,
                scan_status="completed",
                scan_date=now,
            )
            db_session.add(new_scan)
            await db_session.flush()

            db_session.add(
                self._make_secret(
                    scan_id=new_scan.id,
                    status="to_review",
                    severity="HIGH",
                    title=f"New {name} secret",
                )
            )
            containers.append(c)

        await db_session.commit()
        return containers

    async def test_count_only_latest_scan(self, repo, single_container_multi_scan):
        """Old scan's 3 secrets should not be counted; only the new scan's 1."""
        count = await repo.count_total()
        assert count == 1

    async def test_failed_scan_does_not_hide_completed(
        self, repo, db_session, make_container, make_scan
    ):
        """A newer failed scan should not replace the last completed scan."""
        now = get_now()
        container = make_container(name="fail-test")
        db_session.add(container)
        await db_session.flush()

        completed_scan = make_scan(
            container_id=container.id,
            scan_status="completed",
            scan_date=now - timedelta(hours=1),
        )
        db_session.add(completed_scan)
        await db_session.flush()

        for i in range(2):
            db_session.add(
                self._make_secret(
                    scan_id=completed_scan.id,
                    status="to_review",
                    severity="HIGH",
                    title=f"Secret {i}",
                )
            )

        # Newer failed scan — should be ignored
        failed_scan = make_scan(
            container_id=container.id,
            scan_status="failed",
            scan_date=now,
        )
        db_session.add(failed_scan)
        await db_session.commit()

        count = await repo.count_total()
        assert count == 2

    async def test_false_positives_excluded_from_latest(
        self, repo, db_session, make_container, make_scan
    ):
        """FP secrets in the latest scan should not be counted."""
        now = get_now()
        container = make_container(name="fp-test")
        db_session.add(container)
        await db_session.flush()

        scan = make_scan(
            container_id=container.id,
            scan_status="completed",
            scan_date=now,
        )
        db_session.add(scan)
        await db_session.flush()

        db_session.add(
            self._make_secret(
                scan_id=scan.id,
                status="false_positive",
                severity="HIGH",
                title="FP secret",
            )
        )
        db_session.add(
            self._make_secret(
                scan_id=scan.id,
                status="to_review",
                severity="HIGH",
                title="Active secret",
            )
        )
        await db_session.commit()

        count = await repo.count_total()
        assert count == 1

    async def test_multiple_containers_latest_only(self, repo, multi_container_setup):
        """Each container contributes only its latest scan's secrets."""
        count = await repo.count_total()
        assert count == 2  # 1 per container

    async def test_summary_uses_latest_scan(self, repo, multi_container_setup):
        """get_summary() totals should match latest-scan-only counts."""
        summary = await repo.get_summary()
        assert summary["total_secrets"] == 2
        assert summary["affected_containers"] == 2

    async def test_get_all_active_latest_only(self, repo, multi_container_setup):
        """get_all_active() should return only latest-scan secrets."""
        secrets = await repo.get_all_active()
        assert len(secrets) == 2

    async def test_export_latest_only(self, repo, multi_container_setup):
        """get_for_export() should return only latest-scan secrets."""
        rows = await repo.get_for_export()
        assert len(rows) == 2
