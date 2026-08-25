"""
Module 4 - DNS Tunneling & Risk Aggregator
=============================================
FastAPI microservice. Called by Person 1's DNS resolver (directly or via
Person 6's API gateway) for every query that survives the Stage 2
cache/blacklist fast-path.

Run:
    uvicorn main:app --host 0.0.0.0 --port 8004 --reload

Contract:
    POST /score
    Request:
        {"domain": "x89vf2qlmn3.top", "query_type": "TXT",
         "dga_score": 0.94, "intel_match": false}
    Response:
        {"composite_risk": 0.88, "verdict": "BLOCK", "reason": "DGA_Detected"}
"""

from typing import Optional

from fastapi import FastAPI
from pydantic import BaseModel, Field

from scoring import score_query

app = FastAPI(
    title="Module 4 - DNS Tunneling & Risk Aggregator",
    description="Combines DGA, tunneling, and reputation signals into a composite risk verdict.",
    version="1.0.0",
)


class ScoreRequest(BaseModel):
    domain: str = Field(..., examples=["x89vf2qlmn3.top"])
    query_type: str = Field(..., examples=["TXT"])
    dga_score: float = Field(..., ge=0.0, le=1.0, examples=[0.94])
    intel_match: bool = Field(default=False)
    # Not in the original contract snippet, but needed for burst detection.
    # Optional so Module 4 still works if the caller can't supply it
    # (e.g. Person 5's offline PCAP batch mode).
    client_ip: Optional[str] = Field(default=None, examples=["192.168.1.15"])


class ScoreResponse(BaseModel):
    composite_risk: float
    verdict: str
    reason: str


@app.get("/health")
def health():
    return {"status": "ok", "module": "risk-aggregator"}


@app.post("/score", response_model=ScoreResponse)
def score(req: ScoreRequest):
    result = score_query(
        domain=req.domain,
        query_type=req.query_type,
        dga_score=req.dga_score,
        intel_match=req.intel_match,
        client_ip=req.client_ip,
    )
    # Strip internal debug block for the contractual response shape;
    # keep it available via /score/debug for Person 5/6 if useful.
    return {
        "composite_risk": result["composite_risk"],
        "verdict": result["verdict"],
        "reason": result["reason"],
    }


@app.post("/score/debug")
def score_debug(req: ScoreRequest):
    """Same as /score but returns the full breakdown — handy for the
    dashboard's drill-down view and for tuning weights in config.py.
    """
    return score_query(
        domain=req.domain,
        query_type=req.query_type,
        dga_score=req.dga_score,
        intel_match=req.intel_match,
        client_ip=req.client_ip,
    )
