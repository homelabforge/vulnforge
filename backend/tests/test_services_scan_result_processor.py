"""Characterization tests for ScanResultProcessor.

These tests document the current behavior of vulnerability storage (with KEV
enrichment), secret storage (with false-positive pattern matching), and
notification dispatch.  They exist so future refactors cannot silently change
observable behavior.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Container, Scan, Secret, Setting, Vulnerability
from app.services.scan_result_processor import ScanResultProcessor
from app.services.settings_manager import SettingsManager

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _vuln_data(
    cve_id: str = "CVE-2024-00001",
    *,
    severity: str = "HIGH",
    package_name: str = "openssl",
    installed_version: str = "1.0.0",
    is_fixable: bool = True,
    **overrides: object,
) -> dict:
    """Build a minimal vulnerability dict matching Trivy output."""
    base: dict = {
        "cve_id": cve_id,
        "severity": severity,
        "package_name": package_name,
        "installed_version": installed_version,
        "is_fixable": is_fixable,
    }
    base.update(overrides)
    return base


def _secret_data(
    rule_id: str = "generic-api-key",
    *,
    category: str = "Generic",
    title: str = "Generic API Key",
    severity: str = "HIGH",
    match: str = "***REDACTED***",
    **overrides: object,
) -> dict:
    """Build a minimal secret dict matching Trivy output."""
    base: dict = {
        "rule_id": rule_id,
        "category": category,
        "title": title,
        "severity": severity,
        "match": match,
    }
    base.update(overrides)
    return base


def _mock_kev_service(matches: dict[str, dict] | None = None):
    """Create a mock KEV service.  *matches* maps CVE ID → kev_info dict."""
    svc = MagicMock()
    svc.ensure_catalog_loaded = AsyncMock()
    if matches:
        svc.get_kev_info = lambda cve_id: matches.get(cve_id)
    else:
        svc.get_kev_info = lambda cve_id: None
    return svc


async def _set_setting(db: AsyncSession, key: str, value: str) -> None:
    """Update a setting row and flush the SettingsManager TTL cache."""
    result = await db.execute(select(Setting).where(Setting.key == key))
    setting = result.scalar_one_or_none()
    if setting:
        setting.value = value
    else:
        db.add(Setting(key=key, value=value))
    await db.commit()
    SettingsManager.invalidate_cache()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
async def container(db_session: AsyncSession, make_container) -> Container:
    c = make_container(name="test-nginx")
    db_session.add(c)
    await db_session.commit()
    await db_session.refresh(c)
    return c


@pytest.fixture
async def scan(db_session: AsyncSession, container: Container, make_scan) -> Scan:
    s = make_scan(container_id=container.id)
    db_session.add(s)
    await db_session.commit()
    await db_session.refresh(s)
    return s


# ===========================================================================
# store_vulnerabilities_with_kev
# ===========================================================================


class TestStoreVulnerabilitiesWithKev:
    """Characterize vulnerability storage and KEV enrichment."""

    @pytest.mark.asyncio
    async def test_basic_storage_kev_disabled(self, db_session: AsyncSession, scan: Scan):
        """All vulns stored, kev_count=0, all is_kev=False when KEV disabled."""
        await _set_setting(db_session, "kev_checking_enabled", "false")

        mock_kev = _mock_kev_service()
        with patch("app.services.kev.get_kev_service", return_value=mock_kev):
            processor = ScanResultProcessor(db_session)
            kev_count = await processor.store_vulnerabilities_with_kev(
                scan,
                [
                    _vuln_data("CVE-2024-00001"),
                    _vuln_data("CVE-2024-00002"),
                    _vuln_data("CVE-2024-00003"),
                ],
            )

        assert kev_count == 0
        await db_session.flush()
        result = await db_session.execute(
            select(Vulnerability).where(Vulnerability.scan_id == scan.id)
        )
        vulns = result.scalars().all()
        assert len(vulns) == 3
        assert all(not v.is_kev for v in vulns)

    @pytest.mark.asyncio
    async def test_kev_enrichment(self, db_session: AsyncSession, scan: Scan):
        """Matched vuln gets is_kev=True and dates populated."""
        await _set_setting(db_session, "kev_checking_enabled", "true")

        from datetime import datetime

        kev_added = datetime(2024, 1, 15)
        kev_due = datetime(2024, 2, 15)
        kev_match = {
            "CVE-2024-00001": {
                "date_added": kev_added,
                "due_date": kev_due,
            },
        }
        mock_kev = _mock_kev_service(matches=kev_match)
        with patch("app.services.kev.get_kev_service", return_value=mock_kev):
            processor = ScanResultProcessor(db_session)
            kev_count = await processor.store_vulnerabilities_with_kev(
                scan,
                [_vuln_data("CVE-2024-00001"), _vuln_data("CVE-2024-00002")],
            )

        assert kev_count == 1
        await db_session.flush()
        result = await db_session.execute(
            select(Vulnerability).where(Vulnerability.scan_id == scan.id)
        )
        vulns = {v.cve_id: v for v in result.scalars().all()}
        assert vulns["CVE-2024-00001"].is_kev is True
        assert vulns["CVE-2024-00001"].kev_added_date == kev_added
        assert vulns["CVE-2024-00001"].kev_due_date == kev_due
        assert vulns["CVE-2024-00002"].is_kev is False

    @pytest.mark.asyncio
    async def test_empty_vulnerability_list(self, db_session: AsyncSession, scan: Scan):
        """Empty list returns 0, no rows written."""
        mock_kev = _mock_kev_service()
        with patch("app.services.kev.get_kev_service", return_value=mock_kev):
            processor = ScanResultProcessor(db_session)
            kev_count = await processor.store_vulnerabilities_with_kev(scan, [])

        assert kev_count == 0
        await db_session.flush()
        result = await db_session.execute(
            select(Vulnerability).where(Vulnerability.scan_id == scan.id)
        )
        assert result.scalars().all() == []

    @pytest.mark.asyncio
    async def test_all_required_fields_mapped(self, db_session: AsyncSession, scan: Scan):
        """Verify all required Vulnerability fields come from vuln_data."""
        await _set_setting(db_session, "kev_checking_enabled", "false")
        mock_kev = _mock_kev_service()

        vuln = _vuln_data(
            "CVE-2024-99999",
            severity="CRITICAL",
            package_name="curl",
            installed_version="7.88.0",
            is_fixable=False,
        )
        with patch("app.services.kev.get_kev_service", return_value=mock_kev):
            processor = ScanResultProcessor(db_session)
            await processor.store_vulnerabilities_with_kev(scan, [vuln])

        await db_session.flush()
        result = await db_session.execute(
            select(Vulnerability).where(Vulnerability.scan_id == scan.id)
        )
        v = result.scalars().one()
        assert v.cve_id == "CVE-2024-99999"
        assert v.severity == "CRITICAL"
        assert v.package_name == "curl"
        assert v.installed_version == "7.88.0"
        assert v.is_fixable is False
        assert v.scan_id == scan.id

    @pytest.mark.asyncio
    async def test_optional_fields_default_to_none(self, db_session: AsyncSession, scan: Scan):
        """Missing optional fields are stored as None."""
        await _set_setting(db_session, "kev_checking_enabled", "false")
        mock_kev = _mock_kev_service()

        # Minimal vuln — no optional keys
        vuln = _vuln_data("CVE-2024-11111")
        with patch("app.services.kev.get_kev_service", return_value=mock_kev):
            processor = ScanResultProcessor(db_session)
            await processor.store_vulnerabilities_with_kev(scan, [vuln])

        await db_session.flush()
        result = await db_session.execute(
            select(Vulnerability).where(Vulnerability.scan_id == scan.id)
        )
        v = result.scalars().one()
        assert v.cvss_score is None
        assert v.title is None
        assert v.description is None
        assert v.fixed_version is None
        assert v.primary_url is None
        assert v.references is None
        assert v.confidence is None
        assert v.found_by_scanners is None


# ===========================================================================
# store_secrets_with_fp_matching
# ===========================================================================


class TestStoreSecretsWithFPMatching:
    """Characterize secret storage and false-positive pattern matching."""

    @pytest.mark.asyncio
    async def test_no_fp_match(self, db_session: AsyncSession, scan: Scan, container: Container):
        """All secrets stored as to_review when no patterns match."""
        with patch(
            "app.services.scan_result_processor.FalsePositivePatternRepository"
        ) as mock_fp_cls:
            mock_repo = mock_fp_cls.return_value
            mock_repo.matches_pattern = AsyncMock(return_value=None)

            processor = ScanResultProcessor(db_session)
            non_fp = await processor.store_secrets_with_fp_matching(
                scan,
                container,
                [_secret_data("rule-a"), _secret_data("rule-b")],
            )

        assert len(non_fp) == 2
        await db_session.flush()
        result = await db_session.execute(select(Secret).where(Secret.scan_id == scan.id))
        secrets = result.scalars().all()
        assert len(secrets) == 2
        assert all(s.status == "to_review" for s in secrets)

    @pytest.mark.asyncio
    async def test_fp_match(self, db_session: AsyncSession, scan: Scan, container: Container):
        """Matched secret stored as false_positive, record_match called, not in return list."""
        fp_pattern = MagicMock()
        fp_pattern.id = 42

        with patch(
            "app.services.scan_result_processor.FalsePositivePatternRepository"
        ) as mock_fp_cls:
            mock_repo = mock_fp_cls.return_value
            # First call matches, second does not
            mock_repo.matches_pattern = AsyncMock(side_effect=[fp_pattern, None])
            mock_repo.record_match = AsyncMock()

            processor = ScanResultProcessor(db_session)
            non_fp = await processor.store_secrets_with_fp_matching(
                scan,
                container,
                [_secret_data("rule-a"), _secret_data("rule-b")],
            )

        assert len(non_fp) == 1
        mock_repo.record_match.assert_awaited_once_with(42)

        await db_session.flush()
        result = await db_session.execute(select(Secret).where(Secret.scan_id == scan.id))
        secrets = {s.rule_id: s for s in result.scalars().all()}
        assert secrets["rule-a"].status == "false_positive"
        assert secrets["rule-b"].status == "to_review"

    @pytest.mark.asyncio
    async def test_all_fp_match(self, db_session: AsyncSession, scan: Scan, container: Container):
        """All secrets match FP → empty return list, all stored as false_positive."""
        fp_pattern = MagicMock()
        fp_pattern.id = 1

        with patch(
            "app.services.scan_result_processor.FalsePositivePatternRepository"
        ) as mock_fp_cls:
            mock_repo = mock_fp_cls.return_value
            mock_repo.matches_pattern = AsyncMock(return_value=fp_pattern)
            mock_repo.record_match = AsyncMock()

            processor = ScanResultProcessor(db_session)
            non_fp = await processor.store_secrets_with_fp_matching(
                scan,
                container,
                [_secret_data("rule-a"), _secret_data("rule-b")],
            )

        assert non_fp == []

        await db_session.flush()
        result = await db_session.execute(select(Secret).where(Secret.scan_id == scan.id))
        secrets = result.scalars().all()
        assert all(s.status == "false_positive" for s in secrets)

    @pytest.mark.asyncio
    async def test_empty_secrets_list(
        self, db_session: AsyncSession, scan: Scan, container: Container
    ):
        """Empty list → empty return, no DB writes."""
        with patch("app.services.scan_result_processor.FalsePositivePatternRepository"):
            processor = ScanResultProcessor(db_session)
            non_fp = await processor.store_secrets_with_fp_matching(scan, container, [])

        assert non_fp == []
        await db_session.flush()
        result = await db_session.execute(select(Secret).where(Secret.scan_id == scan.id))
        assert result.scalars().all() == []

    @pytest.mark.asyncio
    async def test_field_mapping(self, db_session: AsyncSession, scan: Scan, container: Container):
        """All Secret model fields correctly populated from secret_data dict."""
        secret = _secret_data(
            "aws-access-key",
            category="AWS",
            title="AWS Access Key",
            severity="CRITICAL",
            match="AKIA***REDACTED***",
            start_line=10,
            end_line=12,
            code_snippet="AKIA...",
            layer_digest="sha256:abc123",
            file_path="/app/.env",
        )

        with patch(
            "app.services.scan_result_processor.FalsePositivePatternRepository"
        ) as mock_fp_cls:
            mock_repo = mock_fp_cls.return_value
            mock_repo.matches_pattern = AsyncMock(return_value=None)

            processor = ScanResultProcessor(db_session)
            await processor.store_secrets_with_fp_matching(scan, container, [secret])

        await db_session.flush()
        result = await db_session.execute(select(Secret).where(Secret.scan_id == scan.id))
        s = result.scalars().one()
        assert s.rule_id == "aws-access-key"
        assert s.category == "AWS"
        assert s.title == "AWS Access Key"
        assert s.severity == "CRITICAL"
        assert s.match == "AKIA***REDACTED***"
        assert s.start_line == 10
        assert s.end_line == 12
        assert s.code_snippet == "AKIA..."
        assert s.layer_digest == "sha256:abc123"
        assert s.file_path == "/app/.env"
        assert s.status == "to_review"


# ===========================================================================
# notify_secrets_detected
# ===========================================================================


class TestNotifySecretsDetected:
    """Characterize notification dispatch and activity logging for secrets."""

    @pytest.mark.asyncio
    async def test_dispatches_notification(
        self, db_session: AsyncSession, scan: Scan, container: Container
    ):
        """NotificationDispatcher.notify_secrets_detected called with correct args."""
        secrets = [
            _secret_data(severity="CRITICAL", category="AWS"),
            _secret_data(severity="HIGH", category="Generic"),
            _secret_data(severity="MEDIUM", category="AWS"),
        ]

        mock_dispatcher = MagicMock()
        mock_dispatcher.notify_secrets_detected = AsyncMock()

        with (
            patch(
                "app.services.notifications.NotificationDispatcher",
                return_value=mock_dispatcher,
            ),
            patch("app.services.scan_result_processor.ActivityLogger") as mock_logger_cls,
        ):
            mock_logger_cls.return_value.log_secret_detected = AsyncMock()

            processor = ScanResultProcessor(db_session)
            await processor.notify_secrets_detected(container, scan, secrets)

        mock_dispatcher.notify_secrets_detected.assert_awaited_once()
        call_kwargs = mock_dispatcher.notify_secrets_detected.call_args.kwargs
        assert call_kwargs["container_name"] == container.name
        assert call_kwargs["total_secrets"] == 3
        assert call_kwargs["critical_count"] == 1
        assert call_kwargs["high_count"] == 1
        assert set(call_kwargs["categories"]) == {"AWS", "Generic"}

    @pytest.mark.asyncio
    async def test_logs_activity(self, db_session: AsyncSession, scan: Scan, container: Container):
        """ActivityLogger.log_secret_detected called with correct args."""
        secrets = [
            _secret_data(severity="CRITICAL", category="AWS"),
            _secret_data(severity="HIGH", category="Generic"),
        ]

        mock_logger = MagicMock()
        mock_logger.log_secret_detected = AsyncMock()

        with (
            patch("app.services.notifications.NotificationDispatcher") as mock_disp_cls,
            patch(
                "app.services.scan_result_processor.ActivityLogger",
                return_value=mock_logger,
            ),
        ):
            mock_disp_cls.return_value.notify_secrets_detected = AsyncMock()

            processor = ScanResultProcessor(db_session)
            await processor.notify_secrets_detected(container, scan, secrets)

        mock_logger.log_secret_detected.assert_awaited_once()
        call_kwargs = mock_logger.log_secret_detected.call_args.kwargs
        assert call_kwargs["container_name"] == container.name
        assert call_kwargs["container_id"] == container.id
        assert call_kwargs["scan_id"] == scan.id
        assert call_kwargs["total_secrets"] == 2
        assert call_kwargs["critical_count"] == 1
        assert call_kwargs["high_count"] == 1
        assert set(call_kwargs["categories"]) == {"AWS", "Generic"}

    @pytest.mark.asyncio
    async def test_activity_logger_exception_swallowed(
        self, db_session: AsyncSession, scan: Scan, container: Container
    ):
        """ActivityLogger exception is caught — no crash."""
        secrets = [_secret_data(severity="HIGH")]

        mock_logger = MagicMock()
        mock_logger.log_secret_detected = AsyncMock(side_effect=RuntimeError("DB write failed"))

        with (
            patch("app.services.notifications.NotificationDispatcher") as mock_disp_cls,
            patch(
                "app.services.scan_result_processor.ActivityLogger",
                return_value=mock_logger,
            ),
        ):
            mock_disp_cls.return_value.notify_secrets_detected = AsyncMock()

            processor = ScanResultProcessor(db_session)
            # Should NOT raise
            await processor.notify_secrets_detected(container, scan, secrets)

    @pytest.mark.asyncio
    async def test_dispatcher_exception_propagates(
        self, db_session: AsyncSession, scan: Scan, container: Container
    ):
        """NotificationDispatcher exception is NOT caught — propagates to caller.

        The current code has no try/except around the dispatcher call
        (scan_result_processor.py:140).  Pin this behavior.
        """
        secrets = [_secret_data(severity="HIGH")]

        with (
            patch("app.services.notifications.NotificationDispatcher") as mock_disp_cls,
            patch("app.services.scan_result_processor.ActivityLogger"),
        ):
            mock_disp_cls.return_value.notify_secrets_detected = AsyncMock(
                side_effect=RuntimeError("Notification send failed")
            )

            processor = ScanResultProcessor(db_session)
            with pytest.raises(RuntimeError, match="Notification send failed"):
                await processor.notify_secrets_detected(container, scan, secrets)

    @pytest.mark.asyncio
    async def test_severity_counting(
        self, db_session: AsyncSession, scan: Scan, container: Container
    ):
        """Mix of severities → correct counts; categories as set."""
        secrets = [
            _secret_data(severity="CRITICAL", category="AWS"),
            _secret_data(severity="CRITICAL", category="AWS"),
            _secret_data(severity="HIGH", category="Generic"),
            _secret_data(severity="MEDIUM", category="GitHub"),
        ]

        mock_dispatcher = MagicMock()
        mock_dispatcher.notify_secrets_detected = AsyncMock()

        with (
            patch(
                "app.services.notifications.NotificationDispatcher",
                return_value=mock_dispatcher,
            ),
            patch("app.services.scan_result_processor.ActivityLogger") as mock_logger_cls,
        ):
            mock_logger_cls.return_value.log_secret_detected = AsyncMock()

            processor = ScanResultProcessor(db_session)
            await processor.notify_secrets_detected(container, scan, secrets)

        call_kwargs = mock_dispatcher.notify_secrets_detected.call_args.kwargs
        assert call_kwargs["total_secrets"] == 4
        assert call_kwargs["critical_count"] == 2
        assert call_kwargs["high_count"] == 1
        assert set(call_kwargs["categories"]) == {"AWS", "Generic", "GitHub"}
