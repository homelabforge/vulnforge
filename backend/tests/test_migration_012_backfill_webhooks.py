"""C3: migration 012 backfills is_sensitive on webhook rows, idempotently.

This is a consistency backfill (plan §6/§16), not a security gate — but it must
still flip existing slack/discord webhook rows to sensitive and be safe to
re-run.
"""

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import StaticPool

from app.migrations import runner as migration_runner


async def _run_012(conn) -> None:
    # Load the migration module the same way the runner does and invoke upgrade.
    import importlib.util
    from pathlib import Path

    path = Path(migration_runner.__file__).parent / "012_backfill_sensitive_webhooks.py"
    spec = importlib.util.spec_from_file_location("mig012", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    await module.upgrade(conn)


@pytest.mark.asyncio
async def test_012_flips_webhooks_and_is_idempotent():
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    try:
        async with engine.begin() as conn:
            await conn.execute(
                text(
                    "CREATE TABLE settings ("
                    "key VARCHAR PRIMARY KEY, value TEXT NOT NULL, "
                    "is_sensitive BOOLEAN DEFAULT 0)"
                )
            )
            await conn.execute(
                text(
                    "INSERT INTO settings (key, value, is_sensitive) VALUES "
                    "('slack_webhook_url', 'https://hooks/x', 0), "
                    "('discord_webhook_url', 'https://discord/x', 0), "
                    "('ntfy_topic', 'vulnforge', 0)"
                )
            )

        async with engine.begin() as conn:
            await _run_012(conn)

        async with engine.begin() as conn:
            rows = dict(
                (k, s)
                for k, s in (
                    await conn.execute(text("SELECT key, is_sensitive FROM settings"))
                ).all()
            )
        assert rows["slack_webhook_url"] == 1
        assert rows["discord_webhook_url"] == 1
        assert rows["ntfy_topic"] == 0  # untouched

        # Idempotent: a second run is a no-op and does not error.
        async with engine.begin() as conn:
            await _run_012(conn)
        async with engine.begin() as conn:
            rows2 = dict(
                (k, s)
                for k, s in (
                    await conn.execute(text("SELECT key, is_sensitive FROM settings"))
                ).all()
            )
        assert rows2["slack_webhook_url"] == 1
        assert rows2["discord_webhook_url"] == 1
    finally:
        await engine.dispose(close=True)
