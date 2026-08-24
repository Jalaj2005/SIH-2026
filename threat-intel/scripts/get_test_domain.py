"""
Quick helper: prints a real domain from Redis you can paste into
/check?domain=... for manual testing. Properly skips IP addresses
(with or without a port) so you get an actual testable domain name.

Run with:
    python scripts/get_test_domain.py
"""

import ipaddress

import redis

r = redis.Redis(host="localhost", port=6379, decode_responses=True)


def is_ip_like(host: str) -> bool:
    """True if host is a bare IP, optionally with a :port suffix."""
    candidate = host.split(":", 1)[0]  # strip port if present
    try:
        ipaddress.ip_address(candidate)
        return True
    except ValueError:
        return False


keys = r.keys("intel:*")
domains = [
    k.split(":", 1)[1] for k in keys
    if not is_ip_like(k.split(":", 1)[1])
]

if domains:
    print("Try testing this domain:", domains[0])
    print(f"(found {len(domains)} real domains out of {len(keys)} total entries)")
else:
    print("No real domain entries found — only IPs in Redis right now.")
    print("Make sure you've applied the parser.py fix and re-run clear_intel_data.py + a fresh sync.")