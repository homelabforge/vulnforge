"""C3: sensitive settings are masked in responses and preserved on placeholder.

Plan §6: list/get/put/bulk must return "********" (never the raw value) for a
sensitive setting; a PUT/bulk carrying the mask (or empty) must preserve the
stored value; a real new value updates it; non-sensitive settings are unchanged.
Masking is classification-driven (key matches _is_sensitive_key OR the DB flag),
so it holds independent of migration 012.
"""

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Setting

MASK = "********"


async def _set_raw(db: AsyncSession, key: str, value: str, is_sensitive: bool = False) -> None:
    existing = await db.execute(select(Setting).where(Setting.key == key))
    row = existing.scalar_one_or_none()
    if row:
        row.value = value
        row.is_sensitive = is_sensitive
    else:
        db.add(Setting(key=key, value=value, is_sensitive=is_sensitive))
    await db.commit()


@pytest.mark.asyncio
class TestSensitiveMasking:
    async def test_list_masks_sensitive(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        await _set_raw(db_session, "slack_webhook_url", "https://hooks.example/secret")
        await _set_raw(db_session, "telegram_bot_token", "123:ABCsecret")

        resp = await authenticated_client.get("/api/v1/settings")
        assert resp.status_code == 200
        by_key = {s["key"]: s["value"] for s in resp.json()}
        assert by_key["slack_webhook_url"] == MASK
        assert by_key["telegram_bot_token"] == MASK
        # non-sensitive unaffected
        assert by_key["ntfy_topic"] != MASK

    async def test_get_masks_sensitive(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        await _set_raw(db_session, "discord_webhook_url", "https://discord/secret")
        resp = await authenticated_client.get("/api/v1/settings/discord_webhook_url")
        assert resp.status_code == 200
        assert resp.json()["value"] == MASK

    async def test_get_empty_sensitive_is_empty_not_mask(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        await _set_raw(db_session, "slack_webhook_url", "")
        resp = await authenticated_client.get("/api/v1/settings/slack_webhook_url")
        assert resp.status_code == 200
        assert resp.json()["value"] == ""

    async def test_put_mask_preserves_stored(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        await _set_raw(db_session, "slack_webhook_url", "https://hooks.example/keepme")

        resp = await authenticated_client.put(
            "/api/v1/settings/slack_webhook_url", json={"value": MASK}
        )
        assert resp.status_code == 200
        assert resp.json()["setting"]["value"] == MASK  # response stays masked

        row = (
            await db_session.execute(select(Setting).where(Setting.key == "slack_webhook_url"))
        ).scalar_one()
        await db_session.refresh(row)
        assert row.value == "https://hooks.example/keepme"  # DB unchanged

    async def test_put_empty_preserves_stored(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        await _set_raw(db_session, "telegram_bot_token", "123:KEEP")
        resp = await authenticated_client.put(
            "/api/v1/settings/telegram_bot_token", json={"value": ""}
        )
        assert resp.status_code == 200
        row = (
            await db_session.execute(select(Setting).where(Setting.key == "telegram_bot_token"))
        ).scalar_one()
        await db_session.refresh(row)
        assert row.value == "123:KEEP"

    async def test_put_real_value_updates(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        await _set_raw(db_session, "slack_webhook_url", "https://hooks.example/old")
        resp = await authenticated_client.put(
            "/api/v1/settings/slack_webhook_url",
            json={"value": "https://hooks.example/new"},
        )
        assert resp.status_code == 200
        # response is masked, but the DB now holds the new secret
        assert resp.json()["setting"]["value"] == MASK
        row = (
            await db_session.execute(select(Setting).where(Setting.key == "slack_webhook_url"))
        ).scalar_one()
        await db_session.refresh(row)
        assert row.value == "https://hooks.example/new"

    async def test_bulk_mask_preserves_and_real_updates(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        await _set_raw(db_session, "slack_webhook_url", "https://hooks.example/keep")
        await _set_raw(db_session, "discord_webhook_url", "https://discord/old")

        resp = await authenticated_client.post(
            "/api/v1/settings/bulk",
            json={
                "settings": {
                    "slack_webhook_url": MASK,  # preserve
                    "discord_webhook_url": "https://discord/new",  # update
                }
            },
        )
        assert resp.status_code == 200

        slack = (
            await db_session.execute(select(Setting).where(Setting.key == "slack_webhook_url"))
        ).scalar_one()
        discord = (
            await db_session.execute(select(Setting).where(Setting.key == "discord_webhook_url"))
        ).scalar_one()
        await db_session.refresh(slack)
        await db_session.refresh(discord)
        assert slack.value == "https://hooks.example/keep"
        assert discord.value == "https://discord/new"

    async def test_non_sensitive_put_unaffected(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        await _set_raw(db_session, "ntfy_topic", "old-topic")
        resp = await authenticated_client.put(
            "/api/v1/settings/ntfy_topic", json={"value": "new-topic"}
        )
        assert resp.status_code == 200
        assert resp.json()["setting"]["value"] == "new-topic"
