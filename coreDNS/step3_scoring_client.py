"""
STEP 3: The Orchestrator / Risk Aggregator

This module takes the domain and IP from Step 2/5, calls the required 
microservices (Modules 2, 3, and 4), and computes the final verdict.
"""

import requests

# Service URLs
INTEL_URL = "http://localhost:8003/check"        # Module 3 (Threat Intel)
DGA_URL = "http://localhost:8000/predict"        # Module 2 (DGA)
TUNNELING_URL = "http://localhost:8004/score"    # Module 4 (Tunneling)

USE_MOCK = False  # Set to True if you want to test without the APIs running

# --- MOVED FROM MODULE 4: Risk Aggregation Config ---
WEIGHT_DGA = 0.5
WEIGHT_TUNNELING = 0.5
BLOCK_THRESHOLD = 0.70

QTYPE_NAMES = {1: "A", 16: "TXT", 28: "AAAA", 2: "NS", 5: "CNAME"}

def get_verdict(domain: str, qtype_code: int, client_ip: str) -> dict:
    """Calls external modules and calculates the final risk."""
    query_type = QTYPE_NAMES.get(qtype_code, "UNKNOWN")

    if USE_MOCK:
        # Simple mock if services are down
        suspicious = any(c.isdigit() for c in domain.split(".")[0]) and len(domain) > 10
        return {
            "composite_risk": 0.88 if suspicious else 0.05,
            "verdict": "BLOCK" if suspicious else "ALLOW",
            "reason": "DGA_Detected (Mocked)" if suspicious else "Clean (Mocked)"
        }

    try:
        # 1. Check Threat Intel First (Short-Circuit)
        intel_resp = requests.get(INTEL_URL, params={"domain": domain}, timeout=0.5).json()
        if intel_resp.get("is_blacklisted"):
            return {"composite_risk": 1.0, "verdict": "BLOCK", "reason": f"Intel Match: {intel_resp.get('source')}"}

        # 2. Fetch DGA Score (Module 2)
        dga_resp = requests.post(DGA_URL, json={"domain": domain}, timeout=0.5).json()
        dga_score = dga_resp.get("probability", 0.0)

        # 3. Fetch Tunneling Score (Module 4)
        tunnel_payload = {"domain": domain, "query_type": query_type, "client_ip": client_ip}
        tunnel_resp = requests.post(TUNNELING_URL, json=tunnel_payload, timeout=0.5).json()
        tunneling_score = tunnel_resp.get("tunneling_score", 0.0)

        # 4. Aggregate Risk (The math moved from Module 4)
        composite_risk = (WEIGHT_DGA * dga_score) + (WEIGHT_TUNNELING * tunneling_score)
        
        is_block = composite_risk >= BLOCK_THRESHOLD
        
        return {
            "composite_risk": round(composite_risk, 2),
            "verdict": "BLOCK" if is_block else "ALLOW",
            "reason": "High Composite Risk" if is_block else "Clean"
        }

    except requests.RequestException as e:
        print(f"[WARN] Microservice unreachable ({e}), defaulting to ALLOW")
        return {"composite_risk": 0.0, "verdict": "ALLOW", "reason": "Service Down Fallback"}