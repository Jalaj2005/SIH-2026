"""
Module 4 - DNS Tunneling Sub-Detector
=============================================
FastAPI microservice. Called by Person 1's orchestrator (Module 1).

Run:
    uvicorn main:app --host 0.0.0.0 --port 8004 --reload
"""

from typing import Optional
from fastapi import FastAPI
from pydantic import BaseModel, Field

# IMPORT DIRECTLY FROM TUNNELING NOW (Since scoring.py is deleted)
from tunneling import compute_tunneling_score 

app = FastAPI(
    title="Module 4 - DNS Tunneling Detector",
    description="Computes DNS tunneling risk based on entropy, length, and burst behavior.",
    version="2.0.0",
)

# Simplified Request Model (No longer needs dga_score or intel_match)
class TunnelingRequest(BaseModel):
    domain: str = Field(..., examples=["aW5mb3JtYXRpb24.x89vf2qlmn3.top"])
    query_type: str = Field(..., examples=["TXT"])
    client_ip: Optional[str] = Field(default=None, examples=["192.168.1.15"])

@app.get("/health")
def health():
    return {"status": "ok", "module": "tunneling-detector"}

@app.post("/score")
def score(req: TunnelingRequest):
    """
    Returns the tunneling score and the breakdown of signals.
    """
    result = compute_tunneling_score(
        domain=req.domain,
        query_type=req.query_type,
        client_ip=req.client_ip,
    )
    return result