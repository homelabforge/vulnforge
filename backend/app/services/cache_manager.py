"""Cache manager for frequently accessed data."""

import asyncio
import logging
from collections.abc import Callable
from typing import Any

from app.utils.timezone import get_now

logger = logging.getLogger(__name__)


class CacheEntry:
    """Represents a cached value with expiration."""

    def __init__(self, value: Any, ttl_seconds: int):
        """Initialize cache entry."""
        self.value = value
        self.cached_at = get_now()
        self.ttl_seconds = ttl_seconds

    def is_expired(self) -> bool:
        """Check if cache entry has expired."""
        if self.ttl_seconds == 0:
            return False  # Never expires
        age = (get_now() - self.cached_at).total_seconds()
        return age > self.ttl_seconds


class CacheManager:
    """Simple in-memory cache manager with TTL support."""

    def __init__(self):
        """Initialize cache manager."""
        self._cache: dict[str, CacheEntry] = {}
        self._locks: dict[str, asyncio.Lock] = {}
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> Any | None:
        """
        Get cached value.

        Args:
            key: Cache key

        Returns:
            Cached value or None if not found/expired
        """
        if key not in self._cache:
            return None

        entry = self._cache[key]

        if entry.is_expired():
            # Remove expired entry
            async with self._lock:
                if key in self._cache:
                    del self._cache[key]
                if key in self._locks:
                    del self._locks[key]
            return None

        return entry.value

    async def set(self, key: str, value: Any, ttl_seconds: int = 60):
        """
        Set cached value.

        Args:
            key: Cache key
            value: Value to cache
            ttl_seconds: Time to live in seconds (0 = never expires)
        """
        async with self._lock:
            self._cache[key] = CacheEntry(value, ttl_seconds)

    async def delete(self, key: str):
        """Delete cached value."""
        async with self._lock:
            if key in self._cache:
                del self._cache[key]
            if key in self._locks:
                del self._locks[key]

    async def clear(self):
        """Clear all cached values."""
        async with self._lock:
            self._cache.clear()
            self._locks.clear()

    async def invalidate_pattern(self, pattern: str):
        """
        Invalidate all keys matching a pattern.

        Args:
            pattern: String pattern to match (supports '*' wildcard)
        """
        async with self._lock:
            keys_to_delete = []

            for key in self._cache.keys():
                if self._matches_pattern(key, pattern):
                    keys_to_delete.append(key)

            for key in keys_to_delete:
                if key in self._cache:
                    del self._cache[key]
                if key in self._locks:
                    del self._locks[key]

            if keys_to_delete:
                logger.info(f"Invalidated {len(keys_to_delete)} cache entries matching '{pattern}'")

    async def get_or_compute(
        self,
        key: str,
        compute_fn: Callable,
        ttl_seconds: int = 60,
    ) -> Any:
        """
        Get cached value or compute and cache it.

        Args:
            key: Cache key
            compute_fn: Async function to compute value if not cached
            ttl_seconds: Time to live in seconds

        Returns:
            Cached or computed value
        """
        # Try to get from cache
        cached = await self.get(key)
        if cached is not None:
            return cached

        # Get or create lock for this key
        async with self._lock:
            if key not in self._locks:
                self._locks[key] = asyncio.Lock()
            key_lock = self._locks[key]

        # Acquire key-specific lock to prevent duplicate computation
        async with key_lock:
            # Double-check cache after acquiring lock
            cached = await self.get(key)
            if cached is not None:
                return cached

            # Compute value
            value = await compute_fn()

            # Cache it
            await self.set(key, value, ttl_seconds)

            return value

    @staticmethod
    def _matches_pattern(text: str, pattern: str) -> bool:
        """Check if text matches pattern with * wildcard."""
        if "*" not in pattern:
            return text == pattern

        parts = pattern.split("*")
        if not text.startswith(parts[0]):
            return False

        pos = len(parts[0])
        for part in parts[1:-1]:
            if part:
                idx = text.find(part, pos)
                if idx == -1:
                    return False
                pos = idx + len(part)

        if parts[-1] and not text.endswith(parts[-1]):
            return False

        return True

    def get_stats(self) -> dict[str, Any]:
        """Get cache statistics."""
        total_entries = len(self._cache)
        expired_entries = sum(1 for entry in self._cache.values() if entry.is_expired())

        return {
            "total_entries": total_entries,
            "active_entries": total_entries - expired_entries,
            "expired_entries": expired_entries,
        }


# Global cache instance
_cache_manager: CacheManager | None = None


def get_cache() -> CacheManager:
    """Get or create the global cache manager instance."""
    global _cache_manager
    if _cache_manager is None:
        _cache_manager = CacheManager()
    return _cache_manager
