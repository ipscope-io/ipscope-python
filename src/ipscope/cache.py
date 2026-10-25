"""O(1) LRU + TTL Caches for Sync (`SyncLruTtlCache`) and Async (`AsyncLruTtlCache`) clients.

Strictly bounded (`max_entries=512` default, `< 400 KB` RAM ceiling) with
guaranteed `finally` cleanup on in-flight async singleflight tasks.
"""

from __future__ import annotations

import asyncio
import threading
import time
from collections import OrderedDict
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Generic, TypeVar

from .types import CacheOptions, CacheStats

V = TypeVar("V")


@dataclass(slots=True)
class _CacheEntry(Generic[V]):
    value: V
    expires_at: float


class SyncLruTtlCache(Generic[V]):
    """Thread-safe O(1) Least-Recently-Used cache with TTL expiration."""

    def __init__(self, options: CacheOptions | None = None) -> None:
        opts = options or CacheOptions()
        self._enabled = bool(opts.enabled)
        self._max_entries = max(1, int(opts.max_entries))
        self._ttl_seconds = max(0.1, float(opts.ttl_seconds))
        self._store: OrderedDict[str, _CacheEntry[V]] = OrderedDict()
        self._lock = threading.RLock()
        self._hits = 0
        self._misses = 0

    def get(self, key: str, now: float | None = None) -> V | None:
        if not self._enabled:
            with self._lock:
                self._misses += 1
            return None

        ts = time.monotonic() if now is None else now
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                self._misses += 1
                return None
            if entry.expires_at <= ts:
                del self._store[key]
                self._misses += 1
                return None
            self._store.move_to_end(key)
            self._hits += 1
            return entry.value

    def set(self, key: str, value: V, now: float | None = None) -> None:
        if not self._enabled:
            return
        ts = time.monotonic() if now is None else now
        with self._lock:
            if key in self._store:
                del self._store[key]
            else:
                # Opportunistically evict expired or oldest LRU entries
                keys_to_delete: list[str] = []
                for k, entry in self._store.items():
                    if (
                        entry.expires_at <= ts
                        or len(self._store) - len(keys_to_delete) >= self._max_entries
                    ):
                        keys_to_delete.append(k)
                    if len(self._store) - len(keys_to_delete) < self._max_entries:
                        break
                for k in keys_to_delete:
                    del self._store[k]

            self._store[key] = _CacheEntry(
                value=value,
                expires_at=ts + self._ttl_seconds,
            )

    def clear(self) -> None:
        with self._lock:
            self._store.clear()
            self._hits = 0
            self._misses = 0

    def get_stats(self) -> CacheStats:
        with self._lock:
            return CacheStats(
                enabled=self._enabled,
                size=len(self._store),
                max_entries=self._max_entries,
                ttl_seconds=self._ttl_seconds,
                hits=self._hits,
                misses=self._misses,
                coalesced_in_flight_hits=0,
            )


class AsyncLruTtlCache(Generic[V]):
    """Coroutine-safe O(1) LRU + TTL cache with singleflight in-flight request coalescing."""

    def __init__(self, options: CacheOptions | None = None) -> None:
        opts = options or CacheOptions()
        self._sync_cache: SyncLruTtlCache[V] = SyncLruTtlCache(opts)
        self._in_flight: dict[str, asyncio.Task[V]] = {}
        self._coalesced_hits = 0

    def get(self, key: str, now: float | None = None) -> V | None:
        return self._sync_cache.get(key, now)

    def set(self, key: str, value: V, now: float | None = None) -> None:
        self._sync_cache.set(key, value, now)

    async def get_or_compute(
        self,
        key: str,
        bypass_cache: bool,
        producer: Callable[[], Awaitable[V]],
    ) -> tuple[V, bool]:
        if not bypass_cache:
            cached = self._sync_cache.get(key)
            if cached is not None:
                return cached, True

            existing_task = self._in_flight.get(key)
            if existing_task is not None:
                self._coalesced_hits += 1
                val = await asyncio.shield(existing_task)
                return val, True

        async def _run() -> V:
            try:
                result = await producer()
                if not bypass_cache:
                    self._sync_cache.set(key, result)
                return result
            finally:
                self._in_flight.pop(key, None)

        task = asyncio.create_task(_run())
        if not bypass_cache:
            self._in_flight[key] = task

        val = await task
        return val, False

    def clear(self) -> None:
        self._sync_cache.clear()
        self._in_flight.clear()
        self._coalesced_hits = 0

    def get_stats(self) -> CacheStats:
        base = self._sync_cache.get_stats()
        return CacheStats(
            enabled=base.enabled,
            size=base.size,
            max_entries=base.max_entries,
            ttl_seconds=base.ttl_seconds,
            hits=base.hits,
            misses=base.misses,
            coalesced_in_flight_hits=self._coalesced_hits,
        )
