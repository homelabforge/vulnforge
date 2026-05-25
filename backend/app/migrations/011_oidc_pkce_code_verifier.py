"""Add ``oidc_states.code_verifier`` column for PKCE S256.

The OIDC login flow now generates a PKCE ``code_verifier`` at
authorization time and stores it alongside the state so the callback
handler can send it in the token exchange (RFC 7636). Nullable so any
in-flight states issued before the upgrade still complete cleanly.
"""

import logging

from sqlalchemy import text

logger = logging.getLogger(__name__)


async def upgrade(conn) -> None:
    info = await conn.execute(text("PRAGMA table_info(oidc_states)"))
    columns = {row[1] for row in info.fetchall()}
    if "code_verifier" in columns:
        logger.info("oidc_states.code_verifier already present, skipping")
        return
    await conn.execute(text("ALTER TABLE oidc_states ADD COLUMN code_verifier VARCHAR(128)"))
    logger.info("Added oidc_states.code_verifier (nullable)")
