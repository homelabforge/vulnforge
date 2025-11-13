"""Realtime scan event broadcasting utilities."""

from __future__ import annotations

import asyncio
from typing import Any, Dict, Set


class ScanEventBroadcaster:
    """Manage subscriptions and delivery for scan status events."""

    def __init__(self) -> None:
        self._subscribers: Set[asyncio.Queue[Dict[str, Any]]] = set()
        self._lock = asyncio.Lock()

    async def subscribe(self) -> asyncio.Queue[Dict[str, Any]]:
        """Register a new subscriber queue."""
        queue: asyncio.Queue[Dict[str, Any]] = asyncio.Queue(maxsize=20)
        async with self._lock:
            self._subscribers.add(queue)
        return queue

    async def unsubscribe(self, queue: asyncio.Queue[Dict[str, Any]]) -> None:
        """Remove a subscriber queue."""
        async with self._lock:
            self._subscribers.discard(queue)

    async def broadcast(self, event: Dict[str, Any]) -> None:
        """Broadcast an event to all subscribers."""
        async with self._lock:
            subscribers = list(self._subscribers)

        stalled: list[asyncio.Queue[Dict[str, Any]]] = []
        for queue in subscribers:
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                # Drop the oldest event to make room for the latest snapshot.
                try:
                    queue.get_nowait()
                    queue.put_nowait(event)
                except (asyncio.QueueEmpty, asyncio.QueueFull):
                    stalled.append(queue)

        if stalled:
            async with self._lock:
                for queue in stalled:
                    self._subscribers.discard(queue)

    def schedule_broadcast(self, event: Dict[str, Any]) -> None:
        """Fire-and-forget broadcast helper for sync contexts."""
        asyncio.create_task(self.broadcast(event))

    @property
    def subscriber_count(self) -> int:
        """Return the current number of subscribers."""
        return len(self._subscribers)


# Module-level singleton for shared usage.
scan_events = ScanEventBroadcaster()
