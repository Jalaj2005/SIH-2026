"""
Module 5 - Detection logic
Lightweight, dependency-free heuristics so this module works standalone
BEFORE Module 2 (ML DGA classifier) and Module 3 (Threat Intel) exist.

Once your teammates' services are live, swap the bodies of `is_dga()`
and `is_blacklisted()` for real HTTP calls to their APIs -- the rest
of this file (and the JSON output shape) does not need to change.
"""

import math
from pathlib import Path

BLACKLIST_PATH = Path(__file__).parent / "sample_data" / "blacklist.txt"

DGA_ENTROPY_THRESHOLD = 3.5
TUNNELING_LABEL_LENGTH = 50
SUSPICIOUS_KEYWORDS = ["verify", "login", "secure", "auth", "update", "account"]


def _load_blacklist() -> set:
    if not BLACKLIST_PATH.exists():
        return set()
    with open(BLACKLIST_PATH) as f:
        return {line.strip().lower() for line in f if line.strip() and not line.startswith("#")}


_BLACKLIST = _load_blacklist()


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {c: s.count(c) for c in set(s)}
    length = len(s)
    return -sum((f / length) * math.log2(f / length) for f in freq.values())


def is_blacklisted(domain: str) -> bool:
    domain = domain.lower().rstrip(".")
    return domain in _BLACKLIST or any(domain.endswith("." + b) for b in _BLACKLIST)


def is_dga(domain: str) -> bool:
    core = domain.split(".")[0]
    entropy = shannon_entropy(core)
    digit_ratio = sum(c.isdigit() for c in core) / max(len(core), 1)
    return entropy > DGA_ENTROPY_THRESHOLD or digit_ratio > 0.4


def is_tunneling(domain: str, query_type: str = "A") -> bool:
    labels = domain.split(".")
    longest_label = max((len(l) for l in labels), default=0)
    if longest_label > TUNNELING_LABEL_LENGTH:
        return True
    if query_type.upper() in ("TXT", "NULL") and shannon_entropy(domain) > DGA_ENTROPY_THRESHOLD:
        return True
    return False


def is_suspicious_keyword_stack(domain: str) -> bool:
    hits = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in domain.lower())
    return hits >= 2


def classify(record: dict):
    """Runs one record through the pipeline. Returns a compromise dict, or None if benign."""
    domain = record["domain"]
    qtype = record.get("query_type", "A")

    if is_blacklisted(domain):
        reason = "Threat_Intel_Blacklist"
    elif is_tunneling(domain, qtype):
        reason = "DNS_Tunneling"
    elif is_suspicious_keyword_stack(domain):
        reason = "Phishing_Keyword_Stack"
    elif is_dga(domain):
        reason = "ML_DGA"
    else:
        return None

    return {
        "src_ip": record["src_ip"],
        "domain": domain,
        "detected_by": reason,
        "timestamp": record["timestamp"],
    }


def analyze(records: list) -> list:
    """Runs classify() over every record, returns only the flagged (compromised) ones."""
    results = []
    for r in records:
        verdict = classify(r)
        if verdict:
            results.append(verdict)
    return results
