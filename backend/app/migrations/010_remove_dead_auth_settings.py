"""Remove dead header-based auth settings from the database.

These settings were defined for a header-based authentication system
(Authentik, custom headers, basic auth, API key JSON arrays) that was
superseded by the JWT + API key middleware and never consumed.
"""

import logging

from sqlalchemy import text

logger = logging.getLogger(__name__)

DEAD_AUTH_KEYS = [
    "auth_enabled",
    "auth_provider",
    "auth_authentik_header_username",
    "auth_authentik_header_email",
    "auth_authentik_header_groups",
    "auth_authentik_verify_secret",
    "auth_authentik_secret_header",
    "auth_authentik_trusted_proxies",
    "auth_custom_header_username",
    "auth_custom_header_email",
    "auth_custom_header_groups",
    "auth_custom_header_verify_secret",
    "auth_custom_header_secret_header",
    "auth_custom_header_trusted_proxies",
    "auth_api_keys",
    "auth_basic_users",
    "auth_require_admin",
    "auth_admin_group",
    "auth_admin_usernames",
]


async def migrate(conn) -> None:
    """Remove dead auth settings rows from the settings table."""
    # Check which keys actually exist before deleting
    result = await conn.execute(text("SELECT key FROM settings WHERE key LIKE 'auth_%'"))
    existing = [row[0] for row in result.fetchall()]

    if not existing:
        logger.info("No auth_* settings found in database, skipping")
        return

    # Delete only the known dead keys (not any future auth keys)
    placeholders = ", ".join(f"'{k}'" for k in DEAD_AUTH_KEYS)
    result = await conn.execute(
        text(f"DELETE FROM settings WHERE key IN ({placeholders})")  # noqa: S608
    )
    deleted = result.rowcount
    logger.info(f"Removed {deleted} dead auth settings from database")
