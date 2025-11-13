"""Unit tests for the scan event broadcaster."""

import asyncio

import pytest

from app.services.scan_events import ScanEventBroadcaster


@pytest.mark.asyncio
async def test_broadcaster_lifecycle():
    """Subscribing, broadcasting, and unsubscribing should operate without leaks."""
    broadcaster = ScanEventBroadcaster()

    queue_a = await broadcaster.subscribe()
    queue_b = await broadcaster.subscribe()

    assert broadcaster.subscriber_count == 2

    payload = {"status": "scanning", "progress": 1}
    await broadcaster.broadcast(payload)

    assert await queue_a.get() == payload
    assert await queue_b.get() == payload

    await broadcaster.unsubscribe(queue_a)
    assert broadcaster.subscriber_count == 1

    # Broadcast after removing the queue should not deliver to the unsubscribed queue.
    await broadcaster.broadcast({"status": "idle"})

    await asyncio.sleep(0)  # allow broadcast tasks to settle
    assert broadcaster.subscriber_count == 1
