"""
Module 4 - Composite Risk Aggregator
=======================================
Combines:
  - DGA_Score        <- supplied by Person 2 (ML DGA classifier)
  - Tunneling_Score   <- computed locally (tunneling.py)
  - Reputation_Score  <- lightweight local heuristic (TLD risk table)

into:
  Composite Risk = w1*DGA_Score + w2*Tunneling_Score + w3*Reputation_Score

and produces the final verdict JSON matching the team's Module 4 contract:
  {"composite_risk": 0.88, "verdict": "BLOCK", "reason": "DGA_Detected"}
"""

from config import (
    WEIGHT_DGA,
    WEIGHT_TUNNELING,
    WEIGHT_REPUTATION,
    BLOCK_THRESHOLD,
    HIGH_RISK_TLDS,
    REPUTATION_HIGH_RISK_SCORE,
    REPUTATION_DEFAULT_SCORE,
)
from tunneling import compute_tunneling_score


def reputation_score(domain: str) -> float:
    """Placeholder reputation heuristic: flags known-risky TLDs.
    Swap this out for a real domain-age / historical-pattern lookup if the
    team assigns that scope to Module 4 later.
    """
    tld = domain.strip(".").rsplit(".", 1)[-1].lower() if "." in domain else ""
    if tld in HIGH_RISK_TLDS:
        return REPUTATION_HIGH_RISK_SCORE
    return REPUTATION_DEFAULT_SCORE


def _pick_reason(intel_match: bool, dga_score: float, tunneling_score: float, reputation: float) -> str:
    """Attribute the block/allow decision to whichever signal drove it,
    so the dashboard (Person 6) and forensics log (Person 5) can show a
    human-readable cause rather than just a number.
    """
    if intel_match:
        return "THREAT_INTEL_MATCH"

    contributions = {
        "DGA_Detected": WEIGHT_DGA * dga_score,
        "DNS_Tunneling_Detected": WEIGHT_TUNNELING * tunneling_score,
        "Reputation_Risk": WEIGHT_REPUTATION * reputation,
    }
    return max(contributions, key=contributions.get)


def score_query(
    domain: str,
    query_type: str,
    dga_score: float,
    intel_match: bool = False,
    client_ip: str | None = None,
) -> dict:
    """Main entry point matching the Module 4 input/output contract.

    Input fields (per team spec):
      domain, query_type, dga_score, intel_match
      + client_ip (optional, added for burst detection — not in the
        original contract snippet, but required to compute burst score;
        Person 1/6 can pass it through if available, otherwise burst
        contribution safely degrades to 0).

    Output:
      {"composite_risk": float, "verdict": "BLOCK"|"ALLOW", "reason": str}
    """
    # Stage 2 (deterministic intel/blacklist match) should normally short
    # circuit before reaching Module 4 at all, per the pipeline doc.
    # We still honor it here defensively in case Module 4 is called directly.
    if intel_match:
        return {
            "composite_risk": 1.0,
            "verdict": "BLOCK",
            "reason": "THREAT_INTEL_MATCH",
        }

    tunnel_result = compute_tunneling_score(domain, query_type, client_ip)
    tunneling = tunnel_result["tunneling_score"]
    reputation = reputation_score(domain)

    composite = (
        WEIGHT_DGA * dga_score
        + WEIGHT_TUNNELING * tunneling
        + WEIGHT_REPUTATION * reputation
    )
    composite = round(max(0.0, min(composite, 1.0)), 4)

    verdict = "BLOCK" if composite > BLOCK_THRESHOLD else "ALLOW"
    reason = _pick_reason(False, dga_score, tunneling, reputation) if verdict == "BLOCK" else "WITHIN_THRESHOLD"

    return {
        "composite_risk": composite,
        "verdict": verdict,
        "reason": reason,
        # extra debug fields — harmless for other modules to ignore,
        # useful for Person 5 (forensics) / Person 6 (dashboard) drill-down
        "_debug": {
            "dga_score": dga_score,
            "tunneling_score": tunneling,
            "reputation_score": reputation,
            "tunneling_signals": tunnel_result["signals"],
        },
    }
