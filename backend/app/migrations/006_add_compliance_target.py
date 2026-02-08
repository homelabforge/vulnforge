"""Add target field to compliance_findings table.

The target field stores the container or image name for per-target checks,
enabling the native compliance checker to show results per container/image.
"""

import logging

from sqlalchemy import text

logger = logging.getLogger(__name__)


async def upgrade(connection):
    """Add target column to compliance_findings table."""
    # Check if column already exists
    result = await connection.execute(text("PRAGMA table_info(compliance_findings)"))
    existing_columns = {row[1] for row in result.fetchall()}

    if "target" in existing_columns:
        logger.info("  → Column 'target' already exists, skipping")
        return

    # Add target column
    await connection.execute(
        text("""
            ALTER TABLE compliance_findings
            ADD COLUMN target VARCHAR(255)
        """)
    )
    logger.info("  Added 'target' column to compliance_findings")

    # Create index for target column
    result = await connection.execute(
        text(
            "SELECT name FROM sqlite_master WHERE type='index' AND name='ix_compliance_findings_target'"
        )
    )
    if not result.fetchone():
        await connection.execute(
            text("CREATE INDEX ix_compliance_findings_target ON compliance_findings(target)")
        )
        logger.info("  Created index on 'target' column")


async def downgrade(connection):
    """Remove target column (not supported in SQLite)."""
    logger.info("  Downgrade not supported for SQLite (cannot drop columns)")
