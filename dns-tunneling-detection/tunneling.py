"""
Module 4 - DNS Tunneling Sub-Detector
=======================================
Computes Tunneling_Score in [0.0, 1.0] from four signals:
  1. Shannon entropy of the leftmost (payload-bearing) subdomain label
  2. Subdomain length
  3. Query type (TXT / NULL are exfil-friendly record types)
  4. Query burst behaviour (many unique subdomains from one client, fast)

This mirrors the entropy-only prototype (calculate_entropy) but extends it
per the architecture doc (section 6.4): length + query-type + burst volume.
"""

import math
import time
from collections import defaultdict, deque

from config import (
    TUNNEL_ENTROPY_WEIGHT,
    TUNNEL_LENGTH_WEIGHT,
    TUNNEL_QTYPE_WEIGHT,
    TUNNEL_BURST_WEIGHT,
    TUNNEL_LENGTH_SATURATION,
    TUNNEL_LENGTH_FLOOR,
    SUSPICIOUS_QUERY_TYPES,
    BURST_WINDOW_SECONDS,
    BURST_UNIQUE_SUBDOMAIN_THRESHOLD,
)


def shannon_entropy(text: str) -> float:
    """Shannon entropy of a string, normalized to [0.0, 1.0].

    Raw entropy for typical DNS-label alphabets tops out around 4.0-4.5
    bits/char, so we normalize by 4.5 to keep this composable with the
    other 0-1 sub-scores. Clamped to 1.0 for anomalous cases.
    """
    if not text:
        return 0.0
    freq = defaultdict(int)
    for ch in text:
        freq[ch] += 1
    length = len(text)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log(p, 2)
    normalized = entropy / 4.5
    return min(normalized, 1.0)


def extract_leftmost_label(domain: str) -> str:
    """The leftmost label is where tunneling payload data is usually
    stuffed, e.g. 'aW5mb3JtYXRpb24' in 'aW5mb3JtYXRpb24.data.attacker.com'.
    """
    parts = domain.strip(".").split(".")
    return parts[0] if parts else ""


def length_score(label: str) -> float:
    """Linear ramp between FLOOR (normal) and SATURATION (fully suspicious)."""
    n = len(label)
    if n <= TUNNEL_LENGTH_FLOOR:
        return 0.0
    if n >= TUNNEL_LENGTH_SATURATION:
        return 1.0
    span = TUNNEL_LENGTH_SATURATION - TUNNEL_LENGTH_FLOOR
    return (n - TUNNEL_LENGTH_FLOOR) / span


def query_type_score(query_type: str) -> float:
    return SUSPICIOUS_QUERY_TYPES.get((query_type or "").upper(), 0.0)


class BurstTracker:
    """In-memory sliding-window tracker: how many *unique* subdomains has
    a given client thrown at a given root domain in the last N seconds.

    NOTE: in-memory only — fine for a single-process demo/hackathon build.
    For multi-worker/production deployment swap this for Redis (Person 3
    already runs a Redis instance for threat intel, so it's a natural fit).
    """

    def __init__(self, window_seconds: int = BURST_WINDOW_SECONDS):
        self.window_seconds = window_seconds
        # key: (client_ip, root_domain) -> deque[(timestamp, subdomain_label)]
        self._history: dict[tuple[str, str], deque] = defaultdict(deque)

    @staticmethod
    def root_domain(domain: str) -> str:
        parts = domain.strip(".").split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else domain

    def record_and_score(self, client_ip: str | None, domain: str) -> float:
        if not client_ip:
            # No client attribution available (e.g. offline/forensic batch
            # mode) -> burst signal can't be computed, contribute nothing.
            return 0.0

        root = self.root_domain(domain)
        label = extract_leftmost_label(domain)
        key = (client_ip, root)
        now = time.time()
        hist = self._history[key]

        hist.append((now, label))
        cutoff = now - self.window_seconds
        while hist and hist[0][0] < cutoff:
            hist.popleft()

        unique_labels = {lbl for _, lbl in hist}
        count = len(unique_labels)
        if count >= BURST_UNIQUE_SUBDOMAIN_THRESHOLD:
            return 1.0
        return count / BURST_UNIQUE_SUBDOMAIN_THRESHOLD


# Module-level singleton so the FastAPI app shares one tracker across requests.
burst_tracker = BurstTracker()


def compute_tunneling_score(domain: str, query_type: str, client_ip: str | None = None) -> dict:
    """Returns the composite Tunneling_Score plus the individual signals
    (useful for the 'reason' field and for debugging/dashboarding).
    """
    label = extract_leftmost_label(domain)

    entropy = shannon_entropy(label)
    length = length_score(label)
    qtype = query_type_score(query_type)
    burst = burst_tracker.record_and_score(client_ip, domain)

    score = (
        TUNNEL_ENTROPY_WEIGHT * entropy
        + TUNNEL_LENGTH_WEIGHT * length
        + TUNNEL_QTYPE_WEIGHT * qtype
        + TUNNEL_BURST_WEIGHT * burst
    )
    score = max(0.0, min(score, 1.0))

    return {
        "tunneling_score": round(score, 4),
        "signals": {
            "entropy": round(entropy, 4),
            "length": round(length, 4),
            "query_type": round(qtype, 4),
            "burst": round(burst, 4),
        },
    }
