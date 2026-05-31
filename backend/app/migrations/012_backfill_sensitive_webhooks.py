"""Backfill ``is_sensitive`` for webhook settings (consistency backfill).

C3 settings masking is classification-driven (plan §6): the route masks a
setting when EITHER ``is_sensitive`` is set OR ``_is_sensitive_key`` matches,
and that classifier now covers ``webhook``. This migration is therefore a
*consistency* backfill of the stored column for any other consumer of
``is_sensitive`` — it is NOT a security gate, and a failed run does not expose
secrets (masking holds regardless).

Idempotent: the ``AND is_sensitive = 0`` predicate makes re-runs a no-op, and
only existing rows are touched (brand-new installs seed empty webhook values
via ``initialize_defaults`` after migrations run).
"""

import logging

from sqlalchemy import text

logger = logging.getLogger(__name__)


async def upgrade(conn) -> None:
    result = await conn.execute(
        text(
            "UPDATE settings SET is_sensitive = 1 "
            "WHERE key IN ('slack_webhook_url', 'discord_webhook_url') "
            "AND is_sensitive = 0"
        )
    )
    updated = result.rowcount or 0  # type: ignore[union-attr]
    logger.info("Backfilled is_sensitive on %d webhook setting(s)", updated)
