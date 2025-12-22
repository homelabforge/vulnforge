"""Add is_my_project column to containers table."""

import logging

from sqlalchemy import text

logger = logging.getLogger(__name__)


async def upgrade(conn):
    """Add is_my_project column to containers table."""
    logger.info("Migration 002: Adding is_my_project column to containers")

    # Check if containers table exists
    result = await conn.execute(
        text("SELECT name FROM sqlite_master WHERE type='table' AND name='containers'")
    )
    if not result.fetchone():
        logger.debug("Containers table doesn't exist yet - skipping")
        return

    # Check if column exists
    result = await conn.execute(text("PRAGMA table_info(containers)"))
    columns = [row[1] for row in result]

    if "is_my_project" not in columns:
        logger.info("Adding is_my_project column to containers table")
        await conn.execute(
            text("ALTER TABLE containers ADD COLUMN is_my_project BOOLEAN DEFAULT 0")
        )
        logger.info("✓ is_my_project column added")

    logger.info("✓ Migration 002 completed")
