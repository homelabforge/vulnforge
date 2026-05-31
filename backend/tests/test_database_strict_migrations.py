"""R1-H1: init_db honors settings.strict_migrations on migration failure (§16).

When a migration raises, init_db must re-raise iff strict_migrations is True
(the documented "failure blocks startup" contract) and otherwise swallow it.
The test suite runs with strict_migrations=False (conftest sets
STRICT_MIGRATIONS=false), so the existing suite is unaffected by the re-raise.
"""

import pytest

from app import database


async def _boom(*_args, **_kwargs):
    raise RuntimeError("migration boom")


@pytest.mark.asyncio
async def test_init_db_reraises_when_strict(monkeypatch):
    monkeypatch.setattr("app.migrations.runner.run_migrations", _boom)
    monkeypatch.setattr(database.settings, "strict_migrations", True)
    with pytest.raises(RuntimeError, match="migration boom"):
        await database.init_db()


@pytest.mark.asyncio
async def test_init_db_swallows_when_not_strict(monkeypatch):
    monkeypatch.setattr("app.migrations.runner.run_migrations", _boom)
    monkeypatch.setattr(database.settings, "strict_migrations", False)
    # Must NOT raise — migration failure is logged and startup continues.
    await database.init_db()


def test_conftest_sets_strict_migrations_false():
    """Proof gate: the suite runs non-strict so the failure-injection is isolated."""
    import os

    assert os.environ.get("STRICT_MIGRATIONS", "").lower() == "false"
