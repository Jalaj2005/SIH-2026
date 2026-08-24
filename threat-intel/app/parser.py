"""
Parsing logic for threat feeds.

Turns raw STIX 2.1 indicator objects (from TAXII feeds like OTX) and
raw URLhaus CSV rows into a common internal shape (IndicatorRecord)
that sync.py can hand off to redis_client.py for storage.

Kept separate from sync.py on purpose: sync.py handles WHEN to fetch
and WHERE from, parser.py handles HOW to turn raw feed data into
clean domain records. Makes both easier to test independently.
"""

import csv
import io
import ipaddress
import logging
import re
from typing import Iterable

from app.models import IndicatorRecord, ThreatType

logger = logging.getLogger(__name__)

# STIX indicator patterns look like:
#   [domain-name:value = 'evil.com']
#   [url:value = 'http://evil.com/payload.exe']
#   [domain-name:value = 'evil.com' OR domain-name:value = 'evil2.com']
# This regex pulls out any domain-name:value or url:value literal.
_DOMAIN_PATTERN_RE = re.compile(
    r"(?:domain-name|url):value\s*=\s*'([^']+)'"
)

# Very small helper to strip a URL down to just its hostname, since
# some indicators are full URLs, not bare domains.
_URL_HOST_RE = re.compile(r"^[a-zA-Z]+://([^/]+)")


def _extract_hostname(value: str) -> str:
    """
    If value is a URL, pull out just the hostname — stripping any
    port number and userinfo (user:pass@host), since a real DNS
    query is only ever for a bare domain, never 'domain.com:8080'.
    """
    match = _URL_HOST_RE.match(value)
    host = match.group(1) if match else value

    # Strip userinfo, e.g. "user:pass@evil.com" -> "evil.com"
    if "@" in host:
        host = host.rsplit("@", 1)[-1]

    # Strip a port number, e.g. "evil.com:8080" -> "evil.com"
    # (safe for IPv4/hostnames; IPv6 literals are rare in these feeds
    # and are filtered out separately by _is_ip_address anyway)
    host = host.split(":", 1)[0]

    return host


def _is_ip_address(host: str) -> bool:
    """
    True if host is a bare IPv4/IPv6 address rather than a domain name.
    DNS filtering (Person 1) only ever looks up domain names, so IP-only
    IOCs aren't actionable here and would just be noise in the blacklist.
    """
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def parse_stix_indicator(stix_object: dict, source: str) -> list[IndicatorRecord]:
    """
    Parse a single STIX 'indicator' object into zero or more
    IndicatorRecords (a pattern can reference multiple domains
    joined with OR).

    stix_object is expected to be a dict as returned by the stix2
    library's `.serialize()` + json.loads(), or accessed via
    obj.pattern / obj.created directly if you're working with stix2
    Indicator objects — adjust the .get() calls below if you pass
    stix2 objects instead of plain dicts.
    """
    if stix_object.get("type") != "indicator":
        return []

    pattern = stix_object.get("pattern", "")
    matches = _DOMAIN_PATTERN_RE.findall(pattern)

    if not matches:
        return []

    threat_type = _guess_threat_type(stix_object)
    first_seen = stix_object.get("created") or stix_object.get("valid_from")

    records = []
    for raw_value in matches:
        domain = _extract_hostname(raw_value).lower().strip()
        if not domain or _is_ip_address(domain):
            continue
        records.append(
            IndicatorRecord(
                domain=domain,
                source=source,
                threat_type=threat_type,
                first_seen=first_seen,
            )
        )
    return records


def _guess_threat_type(stix_object: dict) -> ThreatType:
    """
    STIX indicators often carry 'indicator_types' or labels like
    ['malicious-activity']. Feeds aren't always consistent, so this
    does a best-effort keyword match and falls back to UNKNOWN.
    """
    labels = " ".join(
        stix_object.get("indicator_types", [])
        + stix_object.get("labels", [])
    ).lower()

    if "phish" in labels:
        return ThreatType.PHISHING
    if "c2" in labels or "command-and-control" in labels or "botnet" in labels:
        return ThreatType.C2
    if "malware" in labels:
        return ThreatType.MALWARE
    if "scam" in labels or "fraud" in labels:
        return ThreatType.SCAM
    if "spam" in labels:
        return ThreatType.SPAM
    return ThreatType.UNKNOWN


def parse_stix_bundle(bundle: dict, source: str) -> list[IndicatorRecord]:
    """
    A STIX 'bundle' is the envelope TAXII servers usually return,
    containing a list of objects under 'objects'. This pulls out
    every indicator in the bundle.
    """
    objects = bundle.get("objects", [])
    records: list[IndicatorRecord] = []
    for obj in objects:
        records.extend(parse_stix_indicator(obj, source=source))
    logger.info(f"Parsed {len(records)} indicators from STIX bundle (source={source}).")
    return records


def parse_urlhaus_csv(csv_text: str, source: str = "URLhaus") -> list[IndicatorRecord]:
    """
    URLhaus's 'recent' feed is a CSV with a comment header (#) and
    columns like: id,dateadded,url,url_status,threat,tags,...

    We only need the 'url' column, from which we extract the hostname.
    This feed has no signup/API key required — good as a quick
    fallback source or for testing before OTX access is set up.
    """
    records: list[IndicatorRecord] = []
    # Strip comment lines (URLhaus prefixes metadata with '#')
    lines = [line for line in csv_text.splitlines() if not line.startswith("#")]
    reader = csv.reader(io.StringIO("\n".join(lines)))

    for row in reader:
        if len(row) < 6:
            continue
        try:
            _id, _dateadded, url, _status, threat, tags = row[:6]
        except ValueError:
            continue

        domain = _extract_hostname(url).lower().strip()
        if not domain or _is_ip_address(domain):
            continue

        threat_lower = threat.lower()
        if "phish" in threat_lower:
            threat_type = ThreatType.PHISHING
        elif "malware" in threat_lower:
            threat_type = ThreatType.MALWARE
        else:
            threat_type = ThreatType.UNKNOWN

        records.append(
            IndicatorRecord(
                domain=domain,
                source=source,
                threat_type=threat_type,
            )
        )

    logger.info(f"Parsed {len(records)} indicators from URLhaus CSV.")
    return records


def deduplicate(records: Iterable[IndicatorRecord]) -> list[IndicatorRecord]:
    """
    Multiple feeds can flag the same domain. Keep the first
    occurrence (source of truth = whichever feed you sync first)
    so Redis doesn't do redundant writes.
    """
    seen: dict[str, IndicatorRecord] = {}
    for record in records:
        if record.domain not in seen:
            seen[record.domain] = record
    return list(seen.values())