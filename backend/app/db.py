"""Database connection and session management."""

import logging
import os
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from sqlalchemy import event, text
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
async def db_session() -> AsyncGenerator[AsyncSession, None]:
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

    # Run migrations
    await _run_migrations()

    logger.info("Database initialized successfully")


async def _run_migrations():
    """Run database migrations for schema updates."""
    async with engine.connect() as conn:
        # Migration: Add is_sensitive column to settings table if it doesn't exist
        try:
            # Check if column exists
            result = await conn.execute(text("PRAGMA table_info(settings)"))
            columns = [row[1] for row in result]

            if "is_sensitive" not in columns:
                logger.info("Running migration: Adding is_sensitive column to settings table")
                await conn.execute(text("ALTER TABLE settings ADD COLUMN is_sensitive BOOLEAN DEFAULT 0"))

                # Update existing token/password fields to be marked as sensitive
                await conn.execute(
                    text(
                        "UPDATE settings SET is_sensitive = 1 WHERE "
                        "key LIKE '%token%' OR key LIKE '%password%' OR "
                        "key LIKE '%secret%' OR key LIKE '%key%' OR key LIKE '%apikey%'"
                    )
                )
                await conn.commit()
                logger.info("Migration completed: is_sensitive column added")

            if "category" not in columns:
                logger.info("Running migration: Adding category column to settings table")
                await conn.execute(
                    text(
                        "ALTER TABLE settings ADD COLUMN category TEXT NOT NULL DEFAULT 'general'"
                    )
                )
                await conn.commit()
                logger.info("Migration completed: category column added")
            else:
                await conn.execute(
                    text(
                        "UPDATE settings SET category = 'general' "
                        "WHERE category IS NULL OR TRIM(category) = ''"
                    )
                )
                await conn.commit()
        except Exception as e:
            logger.error(f"Error running migration: {e}")
            await conn.rollback()


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Dependency for getting database sessions.

    Yields:
        Database session
    """
    async with db_session() as session:
        yield session
