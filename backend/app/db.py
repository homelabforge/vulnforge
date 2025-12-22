"""Database connection and session management."""

import logging
import os
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
    db_path = settings.database_url.replace("sqlite+aiosqlite:///", "")
    db_dir = os.path.dirname(db_path)
    if db_dir and not os.path.exists(db_dir):
        try:
            os.makedirs(db_dir, exist_ok=True)
            logger.info(f"Created database directory: {db_dir}")
        except PermissionError:
            # In tests or restricted environments, this is expected
            logger.debug(f"Skipping database directory creation (no permissions): {db_dir}")

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
        # Don't fail startup - log error and continue

    logger.info("Database initialized successfully")


async def _run_migrations_legacy():
    """Run database migrations for schema updates.

    Tracks migration status and can fail strictly (raise) or gracefully (log)
    depending on settings.strict_migrations configuration.

    Raises:
        RuntimeError: If strict_migrations=True and any migration fails.
    """
    migrations_applied = []
    migrations_failed = []
    is_test_env = ":memory:" in settings.database_url

    async with engine.connect() as conn:
        # Migration 1: Add is_sensitive and category columns to settings table
        try:
            # Check if settings table exists first
            result = await conn.execute(
                text("SELECT name FROM sqlite_master WHERE type='table' AND name='settings'")
            )
            if not result.fetchone():
                logger.debug("Settings table doesn't exist yet - skipping settings migrations")
                return

            # Check if columns exist
            result = await conn.execute(text("PRAGMA table_info(settings)"))
            columns = [row[1] for row in result]

            # Add is_sensitive column
            if "is_sensitive" not in columns:
                logger.info("Running migration: Adding is_sensitive column to settings table")
                await conn.execute(
                    text("ALTER TABLE settings ADD COLUMN is_sensitive BOOLEAN DEFAULT 0")
                )

                # Update existing token/password fields to be marked as sensitive
                # Use parameterized query for better security
                sensitive_patterns = ["%token%", "%password%", "%secret%", "%key%", "%apikey%"]
                for i, pattern in enumerate(sensitive_patterns):
                    await conn.execute(
                        text(f"UPDATE settings SET is_sensitive = 1 WHERE key LIKE :pattern{i}"),
                        {f"pattern{i}": pattern},
                    )
                await conn.commit()
                migrations_applied.append("settings.is_sensitive")
                logger.info("✓ Migration completed: is_sensitive column added")

            # Add category column
            if "category" not in columns:
                logger.info("Running migration: Adding category column to settings table")
                await conn.execute(
                    text("ALTER TABLE settings ADD COLUMN category TEXT NOT NULL DEFAULT 'general'")
                )
                await conn.commit()
                migrations_applied.append("settings.category")
                logger.info("✓ Migration completed: category column added")
            else:
                # Fix NULL/empty categories
                await conn.execute(
                    text(
                        "UPDATE settings SET category = 'general' "
                        "WHERE category IS NULL OR TRIM(category) = ''"
                    )
                )
                await conn.commit()
        except Exception as e:
            error_msg = f"settings.is_sensitive/category: {e}"
            migrations_failed.append(error_msg)
            logger.error(f"✗ Error running migration: {e}")
            await conn.rollback()

            if settings.strict_migrations and not is_test_env:
                raise RuntimeError(f"Critical migration failed: {error_msg}") from e

        # Migration 2: Add is_my_project column to containers table
        try:
            # Check if containers table exists first
            result = await conn.execute(
                text("SELECT name FROM sqlite_master WHERE type='table' AND name='containers'")
            )
            if not result.fetchone():
                logger.debug("Containers table doesn't exist yet - skipping container migrations")
                # Log summary and return
                _log_migration_summary(migrations_applied, migrations_failed)
                return

            result = await conn.execute(text("PRAGMA table_info(containers)"))
            columns = [row[1] for row in result]

            if "is_my_project" not in columns:
                logger.info("Running migration: Adding is_my_project column to containers table")
                await conn.execute(
                    text("ALTER TABLE containers ADD COLUMN is_my_project BOOLEAN DEFAULT 0")
                )
                await conn.commit()
                migrations_applied.append("containers.is_my_project")
                logger.info("✓ Migration completed: is_my_project column added")
        except Exception as e:
            error_msg = f"containers.is_my_project: {e}"
            migrations_failed.append(error_msg)
            logger.error(f"✗ Error running migration for is_my_project: {e}")
            await conn.rollback()

            if settings.strict_migrations and not is_test_env:
                raise RuntimeError(f"Critical migration failed: {error_msg}") from e

        # Migration 3: Add CVE delta tracking columns to scans table
        try:
            # Check if scans table exists first
            result = await conn.execute(
                text("SELECT name FROM sqlite_master WHERE type='table' AND name='scans'")
            )
            if result.fetchone():
                result = await conn.execute(text("PRAGMA table_info(scans)"))
                columns = [row[1] for row in result]

                if "cves_fixed" not in columns:
                    logger.info("Running migration: Adding cves_fixed column to scans table")
                    await conn.execute(text("ALTER TABLE scans ADD COLUMN cves_fixed TEXT"))
                    await conn.commit()
                    migrations_applied.append("scans.cves_fixed")
                    logger.info("✓ Migration completed: cves_fixed column added")

                if "cves_introduced" not in columns:
                    logger.info("Running migration: Adding cves_introduced column to scans table")
                    await conn.execute(text("ALTER TABLE scans ADD COLUMN cves_introduced TEXT"))
                    await conn.commit()
                    migrations_applied.append("scans.cves_introduced")
                    logger.info("✓ Migration completed: cves_introduced column added")
        except Exception as e:
            error_msg = f"scans.cves_fixed/cves_introduced: {e}"
            migrations_failed.append(error_msg)
            logger.error(f"✗ Error running CVE delta migration: {e}")
            await conn.rollback()

            if settings.strict_migrations and not is_test_env:
                raise RuntimeError(f"Critical migration failed: {error_msg}") from e

    # Log summary
    _log_migration_summary(migrations_applied, migrations_failed)


def _log_migration_summary(applied: list[str], failed: list[str]):
    """Log migration results summary."""
    if applied:
        logger.info(f"Migrations applied successfully: {', '.join(applied)}")
    if failed:
        logger.warning(f"Migrations failed: {', '.join(failed)}")


async def get_db() -> AsyncGenerator[AsyncSession]:
    """
    Dependency for getting database sessions.

    Yields:
        Database session
    """
    async with db_session() as session:
        yield session
