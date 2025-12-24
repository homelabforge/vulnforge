"""Pytest configuration and shared fixtures."""

import os
import sys
from collections.abc import AsyncGenerator
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

PROJECT_ROOT = Path(__file__).resolve().parents[1]
project_root_str = str(PROJECT_ROOT)
if project_root_str in sys.path:
    sys.path.remove(project_root_str)
sys.path.insert(0, project_root_str)

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("STRICT_MIGRATIONS", "false")  # Disable strict migrations in tests

# ruff: noqa: E402 - Imports must come after environment variable setup
from app.db import Base, get_db
from app.main import app
from app.models import Setting

# Use in-memory SQLite for tests
TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"


@pytest.fixture(autouse=True)
def _mock_docker_service_init(monkeypatch):
    """Prevent tests from establishing real Docker connections."""

    def fake_init(self):
        self.client = MagicMock()

    monkeypatch.setattr("app.services.docker_client.DockerService.__init__", fake_init)
    monkeypatch.setattr(
        "app.services.docker_client.DockerService.list_containers",
        lambda self, all_containers=True: [],
    )


@pytest.fixture(autouse=True)
def _mock_background_services(monkeypatch):
    """Stub long-running background services (scan queue, scheduler) during tests."""

    class _DummyQueue:
        def __init__(self):
            self.started = False
            self.batch_total = 0
            self.batch_completed = 0
            self._queued_containers = set()

        async def start(self, num_workers: int = 0):
            self.started = True

        async def stop(self):
            self.started = False
            self._queued_containers.clear()

        def start_batch(self, total: int):
            """Start a batch scan operation."""
            self.batch_total = total
            self.batch_completed = 0

        def get_status(self):
            return {
                "queue_size": len(self._queued_containers),
                "active_scans": 0,
                "current_scan": None,
                "workers_active": 0,
                "batch_total": self.batch_total,
                "batch_completed": self.batch_completed,
            }

        def get_progress_snapshot(self):
            status = self.get_status()
            return {
                "status": "idle",
                "scan": None,
                "queue": status,
            }

        async def get_scanner_health(self, max_age_hours: int = 24, stale_warning_hours: int = 72):
            return {
                "trivy": {"status": "healthy", "last_update_hours": 0},
                "grype": {"status": "healthy", "last_update_hours": 0},
                "overall_status": "healthy",
            }

        async def enqueue(self, container_id=None, *args, **kwargs):
            """Enqueue a scan, reject duplicates."""
            if container_id in self._queued_containers:
                return False  # Duplicate
            self._queued_containers.add(container_id)
            return True

        async def abort_scan(self, *args, **kwargs):
            return False

    dummy_queue = _DummyQueue()

    def get_dummy_queue():
        return dummy_queue

    # Patch both the service module and the already-imported reference in app.main
    monkeypatch.setattr("app.services.scan_queue.get_scan_queue", get_dummy_queue)
    monkeypatch.setattr("app.main.get_scan_queue", get_dummy_queue)

    class _DummyScheduler:
        def __init__(self):
            self.started = False

        def start(self, *args, **kwargs):
            self.started = True

        def stop(self):
            self.started = False

    monkeypatch.setattr("app.services.scheduler.ScanScheduler", _DummyScheduler)
    monkeypatch.setattr("app.main.ScanScheduler", _DummyScheduler)


@pytest.fixture(autouse=True)
def clear_settings_cache():
    """Clear any cached state between tests."""
    # New auth middleware doesn't have a settings cache
    # This fixture is kept for compatibility
    yield


@pytest.fixture
async def db_engine():
    """Create test database engine."""
    engine = create_async_engine(
        TEST_DATABASE_URL,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    # Create all tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Override the global async_session_maker so middleware and services use test database
    from app import db

    original_maker = db.async_session_maker
    db.async_session_maker = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    try:
        yield engine
    finally:
        # Restore original session maker
        db.async_session_maker = original_maker

        # Drop all tables
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)

        # Explicitly close and dispose engine
        await engine.dispose(close=True)


@pytest.fixture
async def db_session(db_engine) -> AsyncGenerator[AsyncSession]:
    """Create test database session."""
    from app.services.settings_manager import SettingsManager

    async_session = sessionmaker(db_engine, class_=AsyncSession, expire_on_commit=False)

    session = async_session()
    try:
        # Always initialize default settings to avoid middleware errors
        for key, value in SettingsManager.DEFAULTS.items():
            setting = Setting(key=key, value=value)
            session.add(setting)
        await session.commit()

        yield session
    finally:
        await session.close()


@pytest.fixture
async def db_with_settings(db_session: AsyncSession) -> AsyncSession:
    """Create database session with default settings.

    Note: Settings are now always initialized in db_session,
    so this fixture just returns the session for compatibility.
    """
    return db_session


@pytest.fixture
async def client(db_session: AsyncSession):
    """Create test client with database override.

    Note: Settings are automatically initialized in db_session fixture.
    """

    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db

    test_client = AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test", follow_redirects=True
    )

    try:
        yield test_client
    finally:
        await test_client.aclose()
        app.dependency_overrides.clear()


@pytest.fixture
async def api_key_client(client, api_key_user, db_session: AsyncSession):
    """AsyncClient with valid API key authentication.

    Provides an HTTP client pre-configured with API key header authentication.
    Uses the new dual authentication system (JWT for browsers, API keys for external tools).
    """
    # Set API key header for authentication
    client.headers["X-API-Key"] = api_key_user.api_key_value

    return client


# ============================================
# Factory Fixtures (TideWatch Pattern)
# ============================================


@pytest.fixture
def make_container():
    """Factory fixture to create Container instances with sensible defaults.

    Usage:
        container = make_container(name="nginx-prod", image="nginx", image_tag="1.25")

    All required fields have sensible defaults that can be overridden with kwargs.
    """

    def _make_container(**kwargs):
        import secrets

        from app.models import Container

        defaults = {
            "name": f"test-container-{secrets.token_hex(4)}",
            "image": "nginx",
            "image_tag": "latest",
            "image_id": f"sha256:{secrets.token_hex(32)}",
            "is_running": True,
        }
        return Container(**{**defaults, **kwargs})

    return _make_container


@pytest.fixture
def make_scan():
    """Factory fixture to create Scan instances with sensible defaults.

    Usage:
        scan = make_scan(container_id=1, scan_status="completed", total_vulns=10)

    Provides defaults for all required fields.
    """

    def _make_scan(**kwargs):
        from app.models import Scan

        defaults = {
            "container_id": 1,
            "image_scanned": "nginx:latest",
            "scan_status": "completed",
            "total_vulns": 0,
            "fixable_vulns": 0,
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
        }
        return Scan(**{**defaults, **kwargs})

    return _make_scan


@pytest.fixture
def make_vulnerability():
    """Factory fixture to create Vulnerability instances with sensible defaults.

    Usage:
        vuln = make_vulnerability(scan_id=1, severity="CRITICAL", is_fixable=True)

    Generates random CVE IDs and provides defaults for all required fields.
    """

    def _make_vulnerability(**kwargs):
        import secrets

        from app.models import Vulnerability

        defaults = {
            "scan_id": 1,
            "cve_id": f"CVE-2024-{secrets.randbelow(99999):05d}",
            "package_name": "test-package",
            "severity": "MEDIUM",
            "installed_version": "1.0.0",
            "is_fixable": True,
        }
        return Vulnerability(**{**defaults, **kwargs})

    return _make_vulnerability


@pytest.fixture
def make_secret():
    """Factory fixture to create Secret instances with sensible defaults.

    Usage:
        secret = make_secret(scan_id=1, severity="HIGH", title="API Key Found")

    Provides defaults for all required fields with automatic redaction.
    """

    def _make_secret(**kwargs):
        from app.models import Secret

        defaults = {
            "scan_id": 1,
            "title": "Test Secret",
            "rule_id": "test-rule",
            "severity": "HIGH",
            "file_path": "/path/to/file",
            "start_line": 1,
            "redacted_match": "***REDACTED***",
        }
        return Secret(**{**defaults, **kwargs})

    return _make_secret


@pytest.fixture
def make_notification_rule():
    """Factory fixture to create NotificationRule instances with sensible defaults.

    Usage:
        rule = make_notification_rule(name="Critical Alert", event_type="critical_vulnerability")

    Generates unique names and provides defaults for all required fields.
    """

    def _make_notification_rule(**kwargs):
        import secrets

        from app.models import NotificationRule

        defaults = {
            "name": f"test-rule-{secrets.token_hex(4)}",
            "event_type": "scan_completed",
            "message_template": "Test notification",
            "enabled": True,
            "send_to_ntfy": True,
        }
        return NotificationRule(**{**defaults, **kwargs})

    return _make_notification_rule


# ============================================
# Authentication Fixtures (TideWatch Pattern)
# ============================================


@pytest.fixture
async def admin_user(db_session: AsyncSession):
    """Create admin user for authentication tests.

    VulnForge uses JWT + API key authentication.
    Returns a mock user object with valid JWT token for testing.
    """
    from app.services.user_auth import create_access_token

    # Create JWT token for testing (mock admin user)
    admin_username = "admin"
    admin_email = "admin@example.com"
    admin_token = create_access_token({"username": admin_username, "email": admin_email})

    # Return a mock user object with token
    class MockAdminUser:
        def __init__(self):
            self.username = admin_username
            self.email = admin_email
            self.is_admin = True
            self.jwt_token = admin_token

    return MockAdminUser()


@pytest.fixture
async def api_key_user(db_session: AsyncSession):
    """Create API key user for API key auth tests.

    VulnForge uses API key authentication for external tools.
    Returns a mock user object with a valid API key for testing.
    """
    from app.services.api_key_service import APIKeyService

    # Create API key for testing
    api_key, plaintext_key = await APIKeyService.create_api_key(
        db=db_session,
        name="Test API Key",
        description="API key for testing",
        created_by="test_suite",
    )
    await db_session.commit()

    # Return a mock user object with API key
    class MockAPIKeyUser:
        username = api_key.name
        email = None
        is_admin = True
        api_key_value = plaintext_key
        api_key_id = api_key.id

    return MockAPIKeyUser()


@pytest.fixture
async def authenticated_client(client, admin_user, db_session: AsyncSession):
    """AsyncClient with valid JWT authentication.

    Provides an HTTP client pre-configured with JWT cookie authentication.
    Uses the new dual authentication system (JWT for browsers, API keys for external tools).
    """
    from app.services.user_auth import JWT_COOKIE_NAME

    # Set JWT cookie for authentication
    client.cookies.set(JWT_COOKIE_NAME, admin_user.jwt_token)

    return client


# ============================================
# Mock Service Fixtures (TideWatch Pattern)
# ============================================


@pytest.fixture
def mock_trivy_scanner(monkeypatch):
    """Mock Trivy scanner for scan tests.

    Provides realistic scan results without executing actual Trivy scans.
    Returns scan data with vulnerabilities, severity counts, and scan metadata.
    """

    async def mock_scan_image(self, image: str):
        return {
            "scan_duration_seconds": 5.2,
            "total_count": 10,
            "fixable_count": 5,
            "critical_count": 1,
            "high_count": 3,
            "medium_count": 4,
            "low_count": 2,
            "vulnerabilities": [
                {
                    "cve_id": "CVE-2024-12345",
                    "package_name": "openssl",
                    "severity": "CRITICAL",
                    "cvss_score": 9.8,
                    "title": "Critical OpenSSL Vulnerability",
                    "description": "Buffer overflow in OpenSSL",
                    "installed_version": "1.0.0",
                    "fixed_version": "1.0.1",
                    "is_fixable": True,
                    "primary_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-12345",
                    "references": ["https://cve.mitre.org/CVE-2024-12345"],
                }
            ],
        }

    monkeypatch.setattr("app.services.trivy_scanner.TrivyScanner.scan_image", mock_scan_image)
    return mock_scan_image


@pytest.fixture
def mock_notification_dispatcher(monkeypatch):
    """Mock notification dispatcher.

    Prevents actual notifications from being sent during tests.
    Tracks notification calls for verification in tests.
    """
    from unittest.mock import AsyncMock, MagicMock

    # Create mock dispatcher with async methods
    mock_dispatcher = MagicMock()
    mock_dispatcher.notify_scan_completed = AsyncMock()
    mock_dispatcher.notify_critical_vulnerabilities = AsyncMock()
    mock_dispatcher.notify_kev_detected = AsyncMock()
    mock_dispatcher.notify_scan_failed = AsyncMock()

    # Patch the NotificationDispatcher class
    def mock_init(self, db):
        self.db = db
        self.notify_scan_completed = mock_dispatcher.notify_scan_completed
        self.notify_critical_vulnerabilities = mock_dispatcher.notify_critical_vulnerabilities
        self.notify_kev_detected = mock_dispatcher.notify_kev_detected
        self.notify_scan_failed = mock_dispatcher.notify_scan_failed

    monkeypatch.setattr("app.services.notifications.NotificationDispatcher.__init__", mock_init)

    return mock_dispatcher


@pytest.fixture
def mock_docker_bench(monkeypatch):
    """Mock Docker Bench scanner for compliance tests.

    Returns CIS compliance scan results without executing Docker Bench Security.
    """

    async def mock_run_compliance_scan(self, container_name: str):
        return {
            "container": container_name,
            "total_checks": 50,
            "passed": 40,
            "warnings": 8,
            "failed": 2,
            "score": 80.0,
            "results": [
                {
                    "check_id": "5.1",
                    "description": "Verify AppArmor profile",
                    "result": "PASS",
                    "severity": "INFO",
                },
                {
                    "check_id": "5.2",
                    "description": "Verify SELinux security options",
                    "result": "WARN",
                    "severity": "MEDIUM",
                },
            ],
        }

    monkeypatch.setattr(
        "app.services.docker_bench_service.DockerBenchService.run_compliance_scan",
        mock_run_compliance_scan,
    )
    return mock_run_compliance_scan


@pytest.fixture
def mock_async_session_local(db_session):
    """Mock AsyncSessionLocal for services creating their own DB sessions.

    Essential for testing services that use AsyncSessionLocal() directly
    (like scan_queue, cleanup_service, scheduler) to ensure they use
    the test database instead of the production database.
    """

    class MockAsyncSessionLocal:
        """Mock async context manager for database sessions."""

        def __call__(self):
            """Return self to act as context manager."""
            return self

        async def __aenter__(self):
            """Enter context manager, return test db session."""
            return db_session

        async def __aexit__(self, exc_type, exc_val, exc_tb):
            """Exit context manager."""
            # Don't close the session - let the test fixture manage it
            return False

    mock_session_local = MockAsyncSessionLocal()

    # NOTE: Services use "from app.db import db_session" directly,
    # not async_session_maker, so no patching needed
    yield mock_session_local


@pytest.fixture
def mock_docker_service():
    """Provide a mock DockerService instance for testing.

    Returns a DockerService-like object with a mocked Docker client.
    Used by services that require DockerService dependency injection.
    """
    from app.services.docker_client import DockerService

    service = DockerService()
    # The client is already mocked by _mock_docker_service_init fixture
    return service


def pytest_sessionfinish(session, exitstatus):
    """Clean up asyncio resources after test session completes.

    Disabled to prevent hanging in CI environments.
    Pytest will handle cleanup automatically.
    """
    pass
