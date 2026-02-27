"""Fix secret scanner: add start_line to FP patterns, fix invalid statuses.

Adds start_line column to false_positive_patterns for precise FP matching
(hybrid mode: NULL = wildcard for legacy patterns, specific line for new ones).
Uses SQLite-safe table rebuild to change unique constraint.
Also normalizes any invalid secret status values to 'to_review'.
"""

import logging

from sqlalchemy import text

logger = logging.getLogger(__name__)


async def upgrade(connection):
    """Apply secret scanner fixes."""

    # --- 1. Add start_line to false_positive_patterns via table rebuild ---
    result = await connection.execute(text("PRAGMA table_info(false_positive_patterns)"))
    columns = [row[1] for row in result]

    if "start_line" not in columns:
        logger.info("  Rebuilding false_positive_patterns with start_line column...")

        # Create new table with updated schema
        await connection.execute(
            text("""
                CREATE TABLE false_positive_patterns_new (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    container_name VARCHAR(255) NOT NULL,
                    file_path VARCHAR(500) NOT NULL,
                    rule_id VARCHAR(100) NOT NULL,
                    start_line INTEGER,
                    reason TEXT,
                    created_by VARCHAR(50) NOT NULL DEFAULT 'user',
                    created_at DATETIME NOT NULL,
                    match_count INTEGER NOT NULL DEFAULT 0,
                    last_matched DATETIME,
                    CONSTRAINT uix_fp_pattern_v2
                        UNIQUE (container_name, file_path, rule_id, start_line)
                )
            """)
        )

        # Copy existing data (start_line defaults to NULL = wildcard)
        await connection.execute(
            text("""
                INSERT INTO false_positive_patterns_new
                    (id, container_name, file_path, rule_id, start_line, reason,
                     created_by, created_at, match_count, last_matched)
                SELECT id, container_name, file_path, rule_id, NULL, reason,
                       created_by, created_at, match_count, last_matched
                FROM false_positive_patterns
            """)
        )

        # Swap tables
        await connection.execute(text("DROP TABLE false_positive_patterns"))
        await connection.execute(
            text("ALTER TABLE false_positive_patterns_new RENAME TO false_positive_patterns")
        )
        logger.info("  Added start_line column to false_positive_patterns (table rebuild)")
    else:
        logger.info("  -> start_line column already exists, skipping table rebuild")

    # --- 2. Fix any invalid secret statuses ---
    await connection.execute(
        text(
            "UPDATE secrets SET status = 'to_review' "
            "WHERE status NOT IN ('to_review', 'false_positive', 'confirmed', 'accepted_risk')"
        )
    )
    logger.info("  Normalized invalid secret statuses to 'to_review'")

    logger.info("  Migration 009 completed")


async def downgrade(connection):
    """Revert: rebuild table without start_line, restore old unique constraint."""
    result = await connection.execute(text("PRAGMA table_info(false_positive_patterns)"))
    columns = [row[1] for row in result]

    if "start_line" in columns:
        await connection.execute(
            text("""
                CREATE TABLE false_positive_patterns_old (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    container_name VARCHAR(255) NOT NULL,
                    file_path VARCHAR(500) NOT NULL,
                    rule_id VARCHAR(100) NOT NULL,
                    reason TEXT,
                    created_by VARCHAR(50) NOT NULL DEFAULT 'user',
                    created_at DATETIME NOT NULL,
                    match_count INTEGER NOT NULL DEFAULT 0,
                    last_matched DATETIME,
                    CONSTRAINT uix_fp_pattern
                        UNIQUE (container_name, file_path, rule_id)
                )
            """)
        )
        await connection.execute(
            text("""
                INSERT OR IGNORE INTO false_positive_patterns_old
                    (id, container_name, file_path, rule_id, reason,
                     created_by, created_at, match_count, last_matched)
                SELECT id, container_name, file_path, rule_id, reason,
                       created_by, created_at, match_count, last_matched
                FROM false_positive_patterns
            """)
        )
        await connection.execute(text("DROP TABLE false_positive_patterns"))
        await connection.execute(
            text("ALTER TABLE false_positive_patterns_old RENAME TO false_positive_patterns")
        )
        logger.info("  Reverted false_positive_patterns (removed start_line)")
