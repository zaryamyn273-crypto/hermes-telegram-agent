"""
Prometheus OSINT Suite - High-Performance In-Memory Async TTL & LRU Cache Engine.
Provides sub-millisecond retrieval for frequently requested network, DNS, WHOIS, IP, and threat data.
"""

import time
import asyncio
from collections import OrderedDict
from typing import Any, Optional, Callable, Dict, Tuple
import logging

logger = logging.getLogger("OSINT_Cache")


class AsyncTTLCache:
    """
    Thread-safe & asyncio-safe LRU cache with time-to-live (TTL) expiration.
    """
    def __init__(self, maxsize: int = 1000, default_ttl: float = 600.0):
        self.maxsize = maxsize
        self.default_ttl = default_ttl
        self._cache: OrderedDict[str, Tuple[Any, float]] = OrderedDict()
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> Optional[Any]:
        async with self._lock:
            if key not in self._cache:
                return None
            val, expire_at = self._cache[key]
            if time.monotonic() > expire_at:
                del self._cache[key]
                return None
            # Move to end (MRU)
            self._cache.move_to_end(key)
            return val

    async def set(self, key: str, value: Any, ttl: Optional[float] = None) -> None:
        async with self._lock:
            if key in self._cache:
                del self._cache[key]
            elif len(self._cache) >= self.maxsize:
                # Evict oldest (LRU)
                self._cache.popitem(last=False)
            
            effective_ttl = ttl if ttl is not None else self.default_ttl
            expire_at = time.monotonic() + effective_ttl
            self._cache[key] = (value, expire_at)

    async def clear(self) -> None:
        async with self._lock:
            self._cache.clear()

    async def size(self) -> int:
        async with self._lock:
            return len(self._cache)


# Global Specialized Cache Instances
dns_cache = AsyncTTLCache(maxsize=2000, default_ttl=600.0)         # 10 minutes
whois_cache = AsyncTTLCache(maxsize=1000, default_ttl=1800.0)      # 30 minutes
ip_intel_cache = AsyncTTLCache(maxsize=2000, default_ttl=3600.0)   # 1 hour
threat_intel_cache = AsyncTTLCache(maxsize=2000, default_ttl=900.0)# 15 minutes
bgp_cache = AsyncTTLCache(maxsize=1000, default_ttl=3600.0)        # 1 hour
mac_cache = AsyncTTLCache(maxsize=5000, default_ttl=86400.0)       # 24 hours
phish_cache = AsyncTTLCache(maxsize=2000, default_ttl=600.0)       # 10 minutes
