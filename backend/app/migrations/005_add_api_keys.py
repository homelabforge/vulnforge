"""
Migration 005: Add API Keys Table

Creates a dedicated table for API key management with secure token hashing.
Replaces complex multi-provider authentication with simple API key tokens.
"""

import logging

from sqlalchemy import text

logger = logging.getLogger(__name__)


async def upgrade(conn):
    """Add api_keys table for secure API authentication."""
    logger.info("Migration 005: Adding api_keys table")

    # Create api_keys table
    await conn.execute(
        text("""
        CREATE TABLE IF NOT EXISTS api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            key_hash TEXT NOT NULL UNIQUE,
            key_prefix TEXT NOT NULL,
            created_at TEXT NOT NULL,
            last_used_at TEXT,
            revoked_at TEXT,
            created_by TEXT DEFAULT 'admin'
        )
    """)
    )
    logger.info("✓ api_keys table created")

    # Create index for fast lookups
    await conn.execute(
        text("""
        CREATE INDEX IF NOT EXISTS idx_api_keys_key_hash
        ON api_keys(key_hash)
    """)
    )
    logger.info("✓ idx_api_keys_key_hash index created")

    await conn.execute(
        text("""
        CREATE INDEX IF NOT EXISTS idx_api_keys_revoked
        ON api_keys(revoked_at)
    """)
    )
    logger.info("✓ idx_api_keys_revoked index created")

    # Disable old auth providers by default (migration to API keys only)
    await conn.execute(
        text("""
        UPDATE settings
        SET value = 'false'
        WHERE key = 'auth_enabled'
    """)
    )
    logger.info("✓ Disabled auth_enabled setting")

    await conn.execute(
        text("""
        UPDATE settings
        SET value = 'none'
        WHERE key = 'auth_provider'
    """)
    )
    logger.info("✓ Set auth_provider to 'none'")

    logger.info("✓ Migration 005 completed")
