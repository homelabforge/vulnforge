"""Integration tests for vulnerability count consistency.

Verifies that when a vulnerability status changes to a non-actionable state
(false_positive, accepted), the container's denormalized counts are resynced
and the vulnerability list filtering excludes both statuses.
"""

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Vulnerability
from app.repositories.vulnerability_repository import VulnerabilityRepository
from app.services.vulnerability_status_service import VulnerabilityStatusService


@pytest.fixture
async def setup_container_with_vulns(db_session: AsyncSession, make_container, make_scan):
    """Create a container with a completed scan and 4 vulnerabilities of different severities."""
    container = make_container(
        name="count-test",
        total_vulns=4,
        fixable_vulns=2,
        critical_count=1,
        high_count=1,
        medium_count=1,
        low_count=1,
    )
    db_session.add(container)
    await db_session.flush()

    scan = make_scan(
        container_id=container.id,
        scan_status="completed",
        total_vulns=4,
        critical_count=1,
        high_count=1,
        medium_count=1,
        low_count=1,
    )
    db_session.add(scan)
    await db_session.flush()

    vulns = [
        Vulnerability(
            scan_id=scan.id,
            cve_id="CVE-2024-00001",
            package_name="openssl",
            severity="CRITICAL",
            installed_version="1.0.0",
            is_fixable=True,
            status="to_fix",
        ),
        Vulnerability(
            scan_id=scan.id,
            cve_id="CVE-2024-00002",
            package_name="curl",
            severity="HIGH",
            installed_version="7.88.0",
            is_fixable=True,
            status="to_fix",
        ),
        Vulnerability(
            scan_id=scan.id,
            cve_id="CVE-2024-00003",
            package_name="libpng",
            severity="MEDIUM",
            installed_version="1.6.0",
            is_fixable=False,
            status="to_fix",
        ),
        Vulnerability(
            scan_id=scan.id,
            cve_id="CVE-2024-00004",
            package_name="zlib",
            severity="LOW",
            installed_version="1.2.0",
            is_fixable=False,
            status="to_fix",
        ),
    ]
    db_session.add_all(vulns)
    await db_session.commit()

    # Refresh to get IDs
    for v in vulns:
        await db_session.refresh(v)

    return container, scan, vulns


class TestCountConsistencyAfterStatusChange:
    """Verify container counts resync after vulnerability status changes."""

    @pytest.mark.asyncio
    async def test_false_positive_drops_container_count(
        self, db_session: AsyncSession, setup_container_with_vulns
    ):
        """Marking a vuln as false_positive drops the container's count."""
        container, scan, vulns = setup_container_with_vulns
        critical_vuln = vulns[0]  # CRITICAL

        svc = VulnerabilityStatusService(db_session)
        await svc.update_single(critical_vuln.id, "false_positive")

        await db_session.refresh(container)
        assert container.total_vulns == 3
        assert container.critical_count == 0

        # Scan row counts remain immutable
        await db_session.refresh(scan)
        assert scan.total_vulns == 4
        assert scan.critical_count == 1

    @pytest.mark.asyncio
    async def test_accepted_drops_container_count(
        self, db_session: AsyncSession, setup_container_with_vulns
    ):
        """Marking a vuln as accepted also drops the container's count."""
        container, scan, vulns = setup_container_with_vulns
        high_vuln = vulns[1]  # HIGH

        svc = VulnerabilityStatusService(db_session)
        await svc.update_single(high_vuln.id, "accepted")

        await db_session.refresh(container)
        assert container.total_vulns == 3
        assert container.high_count == 0

    @pytest.mark.asyncio
    async def test_bulk_update_resyncs_counts(
        self, db_session: AsyncSession, setup_container_with_vulns
    ):
        """Bulk marking vulns as false_positive resyncs counts."""
        container, _scan, vulns = setup_container_with_vulns
        ids_to_update = [vulns[0].id, vulns[1].id]  # CRITICAL + HIGH

        svc = VulnerabilityStatusService(db_session)
        updated = await svc.update_bulk(ids_to_update, "false_positive")

        assert updated == 2
        await db_session.refresh(container)
        assert container.total_vulns == 2
        assert container.critical_count == 0
        assert container.high_count == 0
        assert container.medium_count == 1
        assert container.low_count == 1

    @pytest.mark.asyncio
    async def test_revert_to_actionable_restores_count(
        self, db_session: AsyncSession, setup_container_with_vulns
    ):
        """Reverting from false_positive to to_fix restores the count."""
        container, _scan, vulns = setup_container_with_vulns
        critical_vuln = vulns[0]

        svc = VulnerabilityStatusService(db_session)
        await svc.update_single(critical_vuln.id, "false_positive")

        await db_session.refresh(container)
        assert container.total_vulns == 3

        # Revert
        await svc.update_single(critical_vuln.id, "to_fix")

        await db_session.refresh(container)
        assert container.total_vulns == 4
        assert container.critical_count == 1


class TestVulnListExcludesBothStatuses:
    """Verify the vulnerability list excludes both false_positive and accepted."""

    @pytest.mark.asyncio
    async def test_get_all_excludes_accepted(
        self, db_session: AsyncSession, setup_container_with_vulns
    ):
        """get_all with default filtering excludes accepted vulns."""
        _container, _scan, vulns = setup_container_with_vulns

        # Mark one as accepted
        vulns[0].status = "accepted"
        await db_session.commit()

        repo = VulnerabilityRepository(db_session)
        results, total = await repo.get_all()

        assert total == 3
        cve_ids = {r["cve_id"] for r in results}
        assert "CVE-2024-00001" not in cve_ids

    @pytest.mark.asyncio
    async def test_get_all_excludes_false_positive(
        self, db_session: AsyncSession, setup_container_with_vulns
    ):
        """get_all with default filtering excludes false_positive vulns."""
        _container, _scan, vulns = setup_container_with_vulns

        vulns[1].status = "false_positive"
        await db_session.commit()

        repo = VulnerabilityRepository(db_session)
        results, total = await repo.get_all()

        assert total == 3
        cve_ids = {r["cve_id"] for r in results}
        assert "CVE-2024-00002" not in cve_ids

    @pytest.mark.asyncio
    async def test_get_all_includes_non_actionable_when_requested(
        self, db_session: AsyncSession, setup_container_with_vulns
    ):
        """get_all with exclude_non_actionable=False includes everything."""
        _container, _scan, vulns = setup_container_with_vulns

        vulns[0].status = "accepted"
        vulns[1].status = "false_positive"
        await db_session.commit()

        repo = VulnerabilityRepository(db_session)
        results, total = await repo.get_all(exclude_non_actionable=False)

        assert total == 4

    @pytest.mark.asyncio
    async def test_count_total_excludes_accepted(
        self, db_session: AsyncSession, setup_container_with_vulns
    ):
        """count_total excludes accepted vulns."""
        _container, _scan, vulns = setup_container_with_vulns

        vulns[0].status = "accepted"
        await db_session.commit()

        repo = VulnerabilityRepository(db_session)
        count = await repo.count_total()

        assert count == 3

    @pytest.mark.asyncio
    async def test_remediation_groups_exclude_accepted(
        self, db_session: AsyncSession, setup_container_with_vulns
    ):
        """get_remediation_groups excludes accepted vulns."""
        _container, _scan, vulns = setup_container_with_vulns

        # Mark the fixable CRITICAL as accepted
        vulns[0].status = "accepted"
        vulns[0].fixed_version = "1.0.1"
        vulns[1].fixed_version = "7.89.0"
        await db_session.commit()

        repo = VulnerabilityRepository(db_session)
        groups = await repo.get_remediation_groups()

        # Only curl should appear (openssl is accepted)
        package_names = {g["package_name"] for g in groups}
        assert "openssl" not in package_names
        assert "curl" in package_names
