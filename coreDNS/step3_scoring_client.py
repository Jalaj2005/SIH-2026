"""
STEP 3: Talk to the scoring engine (Module 4).

Contract from the doc:
  Module 4 Input:  {"domain": "...", "query_type": "TXT", "dga_score": 0.94, "intel_match": false}
  Module 4 Output: {"composite_risk": 0.88, "verdict": "BLOCK", "reason": "DGA_Detected"}

Until Module 4 is live, we mock it so Module 1 can be built/tested standalone.
Swap USE_MOCK = False once the real endpoint exists.
"""

import requests

USE_MOCK = True
SCORING_ENGINE_URL = "http://localhost:5000/score"   # Person 4's endpoint (placeholder)

QTYPE_NAMES = {1: "A", 16: "TXT", 28: "AAAA", 2: "NS", 5: "CNAME"}


def mock_scoring_engine(domain: str, query_type: str) -> dict:
    """Fake Module 4 for local testing. Flags obviously random-looking domains."""
    suspicious = any(c.isdigit() for c in domain.split(".")[0]) and len(domain) > 10
    return {
        "composite_risk": 0.88 if suspicious else 0.05,
        "verdict": "BLOCK" if suspicious else "ALLOW",
        "reason": "DGA_Detected" if suspicious else "Clean"
    }


def get_verdict(domain: str, qtype_code: int) -> dict:
    """
    Sends domain to the scoring engine, returns its verdict dict.
    This function is the ONLY thing that needs to change when Module 4
    goes from mock -> real, keeping the rest of Module 1 untouched.
    """
    query_type = QTYPE_NAMES.get(qtype_code, "UNKNOWN")
    payload = {"domain": domain, "query_type": query_type}

    if USE_MOCK:
        return mock_scoring_engine(domain, query_type)

    try:
        resp = requests.post(SCORING_ENGINE_URL, json=payload, timeout=0.5)
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException as e:
        # Fail-safe: if scoring engine is down, don't break DNS resolution
        print(f"[WARN] Scoring engine unreachable ({e}), defaulting to ALLOW")
        return {"composite_risk": 0.0, "verdict": "ALLOW", "reason": "ScoringEngineDown"}


if __name__ == "__main__":
    print(get_verdict("x89vf2qlmn3.top", 1))   # expect BLOCK-ish
    print(get_verdict("google.com", 1))        # expect ALLOW