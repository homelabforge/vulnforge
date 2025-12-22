"""Add is_sensitive and category columns to settings table."""

import logging

from sqlalchemy import text

logger = logging.getLogger(__name__)


async def upgrade(conn):
    """Add is_sensitive and category columns to settings table."""
    logger.info("Migration 001: Adding is_sensitive and category columns to settings")

    # Check if settings table exists
    result = await conn.execute(
        text("SELECT name FROM sqlite_master WHERE type='table' AND name='settings'")
    )
    if not result.fetchone():
        logger.debug("Settings table doesn't exist yet - skipping")
        return

    # Check if columns exist
    result = await conn.execute(text("PRAGMA table_info(settings)"))
    columns = [row[1] for row in result]

    # Add is_sensitive column
    if "is_sensitive" not in columns:
        logger.info("Adding is_sensitive column to settings table")
        await conn.execute(text("ALTER TABLE settings ADD COLUMN is_sensitive BOOLEAN DEFAULT 0"))

        # Update existing token/password fields to be marked as sensitive
        sensitive_patterns = ["%token%", "%password%", "%secret%", "%key%", "%apikey%"]
        for i, pattern in enumerate(sensitive_patterns):
            await conn.execute(
                text(f"UPDATE settings SET is_sensitive = 1 WHERE key LIKE :pattern{i}"),
                {f"pattern{i}": pattern},
            )
        logger.info("✓ is_sensitive column added")

    # Add category column
    if "category" not in columns:
        logger.info("Adding category column to settings table")
        await conn.execute(
            text("ALTER TABLE settings ADD COLUMN category TEXT NOT NULL DEFAULT 'general'")
        )
        logger.info("✓ category column added")
    else:
        # Fix NULL/empty categories
        await conn.execute(
            text(
                "UPDATE settings SET category = 'general' WHERE category IS NULL OR TRIM(category) = ''"
            )
        )

    logger.info("✓ Migration 001 completed")
