"""
DNS CACHE

Thread-safe in-memory TTL + LRU cache.

Cache key:
    (domain, query_type)

Cache value:
    raw DNS response bytes + expiry time

Features:
- TTL expiration
- LRU eviction
- Maximum cache size
- Thread safety
- Cache hit/miss statistics
"""

import time
import threading

from collections import OrderedDict


class DNSCache:

    def __init__(self, max_size=10000):

        self.max_size = max_size

        # OrderedDict gives us LRU behavior.
        #
        # Oldest item:
        #     first
        #
        # Newest item:
        #     last
        self._cache = OrderedDict()

        # Multiple DNS requests can be handled by
        # different threads.
        self._lock = threading.RLock()

        self._hits = 0
        self._misses = 0


    # -----------------------------------------------------
    # GET
    # -----------------------------------------------------

    def get(self, domain, qtype):
        """
        Return cached response if present and not expired.

        Returns:
            bytes
            OR
            None
        """

        key = (
            domain.lower().rstrip("."),
            qtype
        )

        with self._lock:

            entry = self._cache.get(key)

            # No entry
            if entry is None:

                self._misses += 1

                return None


            response_bytes = entry["response"]
            expires_at = entry["expires_at"]


            # -------------------------------------------------
            # Check TTL
            # -------------------------------------------------

            if time.time() >= expires_at:

                # Expired entry
                del self._cache[key]

                self._misses += 1

                return None


            # -------------------------------------------------
            # Cache HIT
            # -------------------------------------------------

            self._hits += 1

            # Move item to end because it was recently used.
            self._cache.move_to_end(key)

            return response_bytes


    # -----------------------------------------------------
    # SET
    # -----------------------------------------------------

    def set(
        self,
        domain,
        qtype,
        response_bytes,
        ttl
    ):
        """
        Store a DNS response.

        ttl:
            lifetime in seconds.
        """

        # Don't cache invalid responses forever.
        ttl = max(1, int(ttl))

        key = (
            domain.lower().rstrip("."),
            qtype
        )

        expires_at = time.time() + ttl

        entry = {
            "response": response_bytes,
            "expires_at": expires_at
        }

        with self._lock:

            # If key already exists, replace it.
            if key in self._cache:
                del self._cache[key]

            self._cache[key] = entry

            # Keep newest item at the end.
            self._cache.move_to_end(key)

            # -------------------------------------------------
            # LRU eviction
            # -------------------------------------------------

            while len(self._cache) > self.max_size:

                self._cache.popitem(
                    last=False
                )


    # -----------------------------------------------------
    # DELETE
    # -----------------------------------------------------

    def delete(self, domain, qtype):

        key = (
            domain.lower().rstrip("."),
            qtype
        )

        with self._lock:

            self._cache.pop(
                key,
                None
            )


    # -----------------------------------------------------
    # CLEAR
    # -----------------------------------------------------

    def clear(self):

        with self._lock:

            self._cache.clear()


    # -----------------------------------------------------
    # STATS
    # -----------------------------------------------------

    def stats(self):

        with self._lock:

            total = (
                self._hits +
                self._misses
            )

            hit_rate = (
                self._hits / total
                if total > 0
                else 0
            )

            return {
                "entries": len(self._cache),
                "hits": self._hits,
                "misses": self._misses,
                "hit_rate": hit_rate
            }