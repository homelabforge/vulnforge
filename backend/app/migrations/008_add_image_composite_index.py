"""Add composite index for image-based container lookups.

Supports the new GET /api/v1/containers/by-image endpoint used by TideWatch
for O(1) image-based vulnerability lookups instead of fetching all containers.
"""

import logging

from sqlalchemy import text

logger = logging.getLogger(__name__)


async def upgrade(connection):
    """Add composite index on (image, image_tag)."""
    result = await connection.execute(
        text("SELECT name FROM sqlite_master WHERE type='index' AND name='ix_container_image_tag'")
    )
    if result.fetchone():
        logger.info("  -> Index 'ix_container_image_tag' already exists, skipping")
        return

    await connection.execute(
        text("CREATE INDEX ix_container_image_tag ON containers(image, image_tag)")
    )
    logger.info("  Created composite index 'ix_container_image_tag'")


async def downgrade(connection):
    """Remove composite index."""
    await connection.execute(text("DROP INDEX IF EXISTS ix_container_image_tag"))
    logger.info("  Dropped index 'ix_container_image_tag'")
