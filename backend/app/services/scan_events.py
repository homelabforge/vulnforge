"""Realtime scan event broadcasting utilities."""

from __future__ import annotations

import asyncio
from typing import Any


class ScanEventBroadcaster:
    """Manage subscriptions and delivery for scan status events."""

    def __init__(self) -> None:
        self._subscribers: set[asyncio.Queue[dict[str, Any]]] = set()
        self._lock = asyncio.Lock()
        self._broadcast_tasks: set[asyncio.Task[None]] = set()

    async def subscribe(self) -> asyncio.Queue[dict[str, Any]]:
        """Register a new subscriber queue."""
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=20)
        async with self._lock:
            self._subscribers.add(queue)
        return queue

    async def unsubscribe(self, queue: asyncio.Queue[dict[str, Any]]) -> None:
        """Remove a subscriber queue."""
        async with self._lock:
            self._subscribers.discard(queue)

    async def broadcast(self, event: dict[str, Any]) -> None:
        """Broadcast an event to all subscribers."""
        async with self._lock:
            subscribers = list(self._subscribers)

        stalled: list[asyncio.Queue[dict[str, Any]]] = []
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

    def schedule_broadcast(self, event: dict[str, Any]) -> None:
        """Fire-and-forget broadcast helper for sync contexts."""
        task = asyncio.create_task(self.broadcast(event))
        self._broadcast_tasks.add(task)
        task.add_done_callback(self._broadcast_tasks.discard)

    async def cleanup_tasks(self) -> None:
        """Cancel and await all pending broadcast tasks.

        This should be called during shutdown to ensure clean termination
        of all background broadcast operations.
        """
        if not self._broadcast_tasks:
            return

        # Cancel all pending tasks
        for task in self._broadcast_tasks:
            task.cancel()

        # Wait for cancellation to complete, ignoring CancelledError
        await asyncio.gather(*self._broadcast_tasks, return_exceptions=True)

        # Clear the task set
        self._broadcast_tasks.clear()

    @property
    def subscriber_count(self) -> int:
        """Return the current number of subscribers."""
        return len(self._subscribers)


# Module-level singleton for shared usage.
scan_events = ScanEventBroadcaster()
