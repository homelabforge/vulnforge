"""Database connection and session management.

Transaction Convention
---------------------
Repositories use two patterns for persistence, chosen by composability:

- ``flush()`` — The repository makes changes visible within the current session
  but does NOT end the transaction.  The caller (service/orchestrator layer)
  decides when to ``commit()``.  Use this when the operation may be composed
  with other writes in a single atomic unit (e.g. scan pipeline stages).

- ``commit()`` — The repository ends the transaction itself.  Use this only
  for provably leaf operations that are never composed with other writes
  (e.g. single-row status updates called directly from API routes).

Methods that commit document the reason with an inline comment:
``# commit: leaf operation, not composed``.
"""

import logging
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from app.config import settings

logger = logging.getLogger(__name__)

# Ensure database directory exists
# Skip for in-memory databases or when directory creation fails (e.g., in tests)
if "sqlite" in settings.database_url and ":memory:" not in settings.database_url:
    _db_path = Path(settings.database_url.replace("sqlite+aiosqlite:///", ""))
    _db_dir = _db_path.parent
    if str(_db_dir) and not _db_dir.exists():
        try:
            _db_dir.mkdir(parents=True, exist_ok=True)
            logger.info(f"Created database directory: {_db_dir}")
        except PermissionError:
            # In tests or restricted environments, this is expected
            logger.debug(f"Skipping database directory creation (no permissions): {_db_dir}")

# Create async engine
# For SQLite, add timeout and other settings to handle concurrent writes
connect_args = {}
if "sqlite" in settings.database_url:
    connect_args = {
        "check_same_thread": False,
        "timeout": 30.0,  # 30 second timeout for database locks
    }

engine = create_async_engine(
    settings.database_url,
    echo=settings.log_level == "DEBUG",
    future=True,
    connect_args=connect_args,
    pool_pre_ping=True,  # Verify connections before using
)

# Create session factory
async_session_maker = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


class Base(DeclarativeBase):
    """Base class for all database models."""

    pass


@asynccontextmanager
async def db_session() -> AsyncGenerator[AsyncSession]:
    """
    Async context manager that yields a database session and ensures it closes.
    """
    async with async_session_maker() as session:
        yield session


async def init_db():
    """Initialize database - create all tables."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Enable WAL mode for better concurrency with SQLite
    if "sqlite" in settings.database_url:
        async with engine.connect() as conn:
            await conn.execute(text("PRAGMA journal_mode=WAL"))
            await conn.execute(text("PRAGMA synchronous=NORMAL"))
            await conn.execute(text("PRAGMA cache_size=-64000"))  # 64MB cache
            await conn.execute(text("PRAGMA busy_timeout=30000"))  # 30 second busy timeout
            await conn.commit()

    # Run migrations using the migration runner
    try:
        from app.migrations.runner import run_migrations

        migrations_dir = Path(__file__).parent / "migrations"
        await run_migrations(engine, migrations_dir)
    except Exception as e:
        logger.error(f"Migration error: {e}", exc_info=True)
        # Honor the documented contract (CLAUDE.md: "failure blocks startup").
        # strict_migrations defaults True (config.py); test envs set it False
        # (conftest sets STRICT_MIGRATIONS=false) so the suite is unaffected.
        if settings.strict_migrations:
            raise
        logger.warning("strict_migrations is False — continuing despite migration failure")

    logger.info("Database initialized successfully")


async def get_db() -> AsyncGenerator[AsyncSession]:
    """
    Dependency for getting database sessions.

    Yields:
        Database session
    """
    async with db_session() as session:
        yield session
