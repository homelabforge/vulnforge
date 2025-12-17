"""Pytest configuration and shared fixtures."""

import asyncio
import os
import sys
from typing import AsyncGenerator

from pathlib import Path
from unittest.mock import MagicMock

import pytest
from httpx import AsyncClient, ASGITransport
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

        async def start(self, num_workers: int = 0):
            self.started = True

        async def stop(self):
            self.started = False

        def get_status(self):
            return {
                "queue_size": 0,
                "active_scans": 0,
                "current_scan": None,
                "workers_active": 0,
                "batch_total": 0,
                "batch_completed": 0,
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

        async def enqueue(self, *args, **kwargs):
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
    """Clear the middleware settings cache between tests to avoid cross-contamination."""
    try:
        import asyncio
        from app.middleware import auth
        auth._settings_cache = None
        auth._settings_cache_time = 0
        # Recreate the lock for the current event loop to avoid "bound to different event loop" errors
        auth._settings_lock = asyncio.Lock()
    except (ImportError, AttributeError):
        # If middleware doesn't exist or doesn't have cache, skip
        pass
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
    db.async_session_maker = sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )

    yield engine

    # Restore original session maker
    db.async_session_maker = original_maker

    # Drop all tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

    await engine.dispose()


@pytest.fixture
async def db_session(db_engine) -> AsyncGenerator[AsyncSession, None]:
    """Create test database session."""
    from app.services.settings_manager import SettingsManager

    async_session = sessionmaker(
        db_engine, class_=AsyncSession, expire_on_commit=False
    )

    async with async_session() as session:
        # Always initialize default settings to avoid middleware errors
        for key, value in SettingsManager.DEFAULTS.items():
            setting = Setting(key=key, value=value)
            session.add(setting)
        await session.commit()

        yield session


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

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        follow_redirects=True
    ) as test_client:
        yield test_client

    app.dependency_overrides.clear()


@pytest.fixture
def mock_settings():
    """Mock settings dictionary for auth providers."""
    return {
        "auth_enabled": "true",
        "auth_provider": "authentik",
        "auth_authentik_header_username": "X-Authentik-Username",
        "auth_authentik_header_email": "X-Authentik-Email",
        "auth_authentik_header_groups": "X-Authentik-Groups",
        "auth_authentik_verify_secret": "",
        "auth_authentik_secret_header": "X-Authentik-Secret",
        "auth_authentik_trusted_proxies": '["127.0.0.1", "::1"]',
        "auth_admin_group": "Admin",
        "auth_admin_usernames": '["admin"]',
        "auth_api_keys": '[]',
        "auth_basic_users": '[]',
    }
