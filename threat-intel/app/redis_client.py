"""
Redis connection for the Threat Intel module.

Keeps a single shared connection pool and exposes small helper
functions so the rest of the app (lookup.py, sync.py) never has
to touch the redis library directly.
"""

import json
import logging
from typing import Optional

import redis

from app.config import settings

logger = logging.getLogger(__name__)

# Single shared connection pool — reused across the whole app.
# decode_responses=True means we get plain Python strings back,
# not bytes, which keeps json.loads/dumps simple everywhere else.
redis_pool = redis.ConnectionPool(
    host=settings.redis_host,
    port=settings.redis_port,
    db=settings.redis_db,
    decode_responses=True,
)

redis_client = redis.Redis(connection_pool=redis_pool)

# All threat intel keys use this prefix so they're easy to find/clear
# separately from any other data other modules might store in the
# same Redis instance (e.g. Person 5's forensics module).
KEY_PREFIX = "intel:"


def ping() -> bool:
    """Quick health check — call this at startup to confirm Redis is reachable."""
    try:
        return redis_client.ping()
    except redis.exceptions.ConnectionError as e:
        logger.error(f"Redis connection failed: {e}")
        return False


def set_indicator(domain: str, data: dict, ttl_seconds: Optional[int] = None) -> None:
    """
    Store a threat indicator for a domain.

    data should look like:
        {"is_blacklisted": True, "source": "AlienVault_OTX", "threat_type": "phishing"}

    ttl_seconds is optional — set it if you want entries to auto-expire
    (useful so stale indicators don't linger forever between syncs).
    """
    key = f"{KEY_PREFIX}{domain.lower().strip()}"
    value = json.dumps(data)
    if ttl_seconds:
        redis_client.setex(key, ttl_seconds, value)
    else:
        redis_client.set(key, value)


def get_indicator(domain: str) -> Optional[dict]:
    """Fetch a stored indicator for a domain, or None if not found."""
    key = f"{KEY_PREFIX}{domain.lower().strip()}"
    value = redis_client.get(key)
    if value is None:
        return None
    return json.loads(value)


def delete_indicator(domain: str) -> None:
    """Remove a domain from the blacklist (e.g. if a feed retracts it)."""
    key = f"{KEY_PREFIX}{domain.lower().strip()}"
    redis_client.delete(key)


def count_indicators() -> int:
    """Count how many domains are currently blacklisted — handy for logs/demo metrics."""
    return len(redis_client.keys(f"{KEY_PREFIX}*"))


def bulk_set_indicators(domains_with_data: dict[str, dict], ttl_seconds: Optional[int] = None) -> None:
    """
    Store many indicators at once using a Redis pipeline, much faster
    than calling set_indicator() in a loop for large feeds (e.g. URLhaus
    CSV with thousands of rows).
    """
    pipe = redis_client.pipeline()
    for domain, data in domains_with_data.items():
        key = f"{KEY_PREFIX}{domain.lower().strip()}"
        value = json.dumps(data)
        if ttl_seconds:
            pipe.setex(key, ttl_seconds, value)
        else:
            pipe.set(key, value)
    pipe.execute()
    logger.info(f"Bulk-stored {len(domains_with_data)} indicators in Redis.")