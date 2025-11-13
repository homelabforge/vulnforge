"""Pytest configuration and shared fixtures."""

import asyncio
import os
import sys
from typing import AsyncGenerator

from pathlib import Path
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

PROJECT_ROOT = Path(__file__).resolve().parents[1]
project_root_str = str(PROJECT_ROOT)
if project_root_str in sys.path:
    sys.path.remove(project_root_str)
sys.path.insert(0, project_root_str)

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")

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


@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for async tests."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


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

    yield engine

    # Drop all tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

    await engine.dispose()


@pytest.fixture
async def db_session(db_engine) -> AsyncGenerator[AsyncSession, None]:
    """Create test database session."""
    async_session = sessionmaker(
        db_engine, class_=AsyncSession, expire_on_commit=False
    )

    async with async_session() as session:
        yield session


@pytest.fixture
async def db_with_settings(db_session: AsyncSession) -> AsyncSession:
    """Create database session with default settings."""
    from app.services.settings_manager import SettingsManager

    # Add default settings
    for key, value in SettingsManager.DEFAULTS.items():
        setting = Setting(key=key, value=value)
        db_session.add(setting)

    await db_session.commit()
    return db_session


@pytest.fixture
def client(db_session: AsyncSession):
    """Create test client with database override."""

    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db

    with TestClient(app, raise_server_exceptions=False) as test_client:
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
