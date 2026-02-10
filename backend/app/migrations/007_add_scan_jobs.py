"""Add scan_jobs table for scan correlation tracking.

The scan_jobs table provides correlation IDs for scans triggered via API.
External consumers (TideWatch) can poll job status by job_id and retrieve
the linked scan_id once the queue worker processes the job.
"""

import logging

from sqlalchemy import text

logger = logging.getLogger(__name__)


async def upgrade(connection):
    """Create scan_jobs table."""
    # Check if table already exists
    result = await connection.execute(
        text("SELECT name FROM sqlite_master WHERE type='table' AND name='scan_jobs'")
    )
    if result.fetchone():
        logger.info("  -> Table 'scan_jobs' already exists, skipping")
        return

    await connection.execute(
        text("""
            CREATE TABLE scan_jobs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                container_id INTEGER NOT NULL,
                container_name VARCHAR(255) NOT NULL,
                status VARCHAR(50) NOT NULL DEFAULT 'queued',
                scan_id INTEGER,
                error_message TEXT,
                created_at DATETIME NOT NULL,
                completed_at DATETIME,
                FOREIGN KEY (container_id) REFERENCES containers(id),
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            )
        """)
    )
    logger.info("  Created 'scan_jobs' table")

    # Index on status for worker polling
    await connection.execute(text("CREATE INDEX ix_scan_jobs_status ON scan_jobs(status)"))
    logger.info("  Created index on 'status' column")

    # Index on container_id for lookups
    await connection.execute(
        text("CREATE INDEX ix_scan_jobs_container_id ON scan_jobs(container_id)")
    )
    logger.info("  Created index on 'container_id' column")


async def downgrade(connection):
    """Remove scan_jobs table (not supported in SQLite)."""
    logger.info("  Downgrade not supported for SQLite (cannot drop tables safely)")
