"""
The check_intel(domain) function — this is the core deliverable of
Module 3. Person 1 (DNS server) and Person 4 (risk aggregator) call
this, either as a direct Python import or via the /check endpoint
in main.py, to find out if a domain is known-malicious.
"""

import logging

from app.models import IntelCheckResponse
from app.redis_client import get_indicator

logger = logging.getLogger(__name__)


def normalize_domain(domain: str) -> str:
    """
    Clean up a domain before lookup so equivalent forms all hit the
    same Redis key: strip whitespace, lowercase, drop a trailing dot
    (FQDNs sometimes have one), and drop a leading 'www.'.
    """
    d = domain.strip().lower().rstrip(".")
    if d.startswith("www."):
        d = d[4:]
    return d


def check_intel(domain: str) -> IntelCheckResponse:
    """
    THE contract function. Given a domain, returns whether it's
    blacklisted and by whom.

    Always returns an IntelCheckResponse — never raises for a domain
    that simply isn't found, since "not blacklisted" is a valid,
    expected result (not an error).
    """
    if not domain:
        logger.warning("check_intel called with empty domain")
        return IntelCheckResponse(is_blacklisted=False)

    clean_domain = normalize_domain(domain)

    try:
        record = get_indicator(clean_domain)
    except Exception as e:
        # If Redis is down, fail SAFE (treat as not-blacklisted) rather
        # than crashing the DNS resolution path. Log it loudly though —
        # this should never go unnoticed in the demo or in production.
        logger.error(f"Redis lookup failed for domain='{clean_domain}': {e}")
        return IntelCheckResponse(is_blacklisted=False)

    if record is None:
        return IntelCheckResponse(is_blacklisted=False)

    return IntelCheckResponse(
        is_blacklisted=record.get("is_blacklisted", True),
        source=record.get("source"),
        threat_type=record.get("threat_type"),
    )