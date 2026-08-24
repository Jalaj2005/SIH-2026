"""
Pydantic request/response models for the Threat Intel module.

These schemas ARE the contract Person 1 (DNS server) and Person 4
(risk aggregator) depend on. Keep this shape stable once other
people start integrating against it — change it only after telling
the team, since it will break their code too.
"""

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class ThreatType(str, Enum):
    """Known categories a blacklisted domain can fall under."""
    PHISHING = "phishing"
    MALWARE = "malware"
    C2 = "c2"                # command-and-control / botnet
    SCAM = "scam"
    SPAM = "spam"
    UNKNOWN = "unknown"


class IntelCheckResponse(BaseModel):
    """
    The exact response shape defined in the project contract:

        {"is_blacklisted": true, "source": "AlienVault_OTX", "threat_type": "phishing"}

    This is what check_intel(domain) / GET /check returns, and what
    Person 1 and Person 4 will parse in their own code.
    """
    is_blacklisted: bool
    source: Optional[str] = Field(
        default=None,
        description="Which feed flagged this domain, e.g. 'AlienVault_OTX', 'URLhaus'.",
    )
    threat_type: Optional[ThreatType] = Field(
        default=None,
        description="Category of threat, e.g. 'phishing', 'malware', 'c2'.",
    )

    class Config:
        json_schema_extra = {
            "example": {
                "is_blacklisted": True,
                "source": "AlienVault_OTX",
                "threat_type": "phishing",
            }
        }


class IndicatorRecord(BaseModel):
    """
    Internal representation of a single threat indicator, used when
    parsing STIX objects (parser.py) and before writing to Redis
    (sync.py / redis_client.py).
    """
    domain: str
    source: str
    threat_type: ThreatType = ThreatType.UNKNOWN
    first_seen: Optional[str] = None  # ISO timestamp string, if the feed provides one


class SyncStatus(BaseModel):
    """
    Response shape for an optional /sync-status endpoint, useful for
    the dashboard (Person 6) to show when feeds last updated and how
    many indicators are loaded — good demo material too.
    """
    last_sync_time: Optional[str] = None
    total_indicators: int = 0
    sources: list[str] = Field(default_factory=list)