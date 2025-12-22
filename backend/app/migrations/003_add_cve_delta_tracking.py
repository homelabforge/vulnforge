"""Add CVE delta tracking columns to scans table."""

import logging

from sqlalchemy import text

logger = logging.getLogger(__name__)


async def upgrade(conn):
    """Add cves_fixed and cves_introduced columns to scans table."""
    logger.info("Migration 003: Adding CVE delta tracking to scans")

    # Check if scans table exists
    result = await conn.execute(
        text("SELECT name FROM sqlite_master WHERE type='table' AND name='scans'")
    )
    if not result.fetchone():
        logger.debug("Scans table doesn't exist yet - skipping")
        return

    # Check if columns exist
    result = await conn.execute(text("PRAGMA table_info(scans)"))
    columns = [row[1] for row in result]

    if "cves_fixed" not in columns:
        logger.info("Adding cves_fixed column to scans table")
        await conn.execute(text("ALTER TABLE scans ADD COLUMN cves_fixed TEXT"))
        logger.info("✓ cves_fixed column added")

    if "cves_introduced" not in columns:
        logger.info("Adding cves_introduced column to scans table")
        await conn.execute(text("ALTER TABLE scans ADD COLUMN cves_introduced TEXT"))
        logger.info("✓ cves_introduced column added")

    logger.info("✓ Migration 003 completed")
