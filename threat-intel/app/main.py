"""
FastAPI entrypoint for the Threat Intel module.

Run with:
    uvicorn app.main:app --host 0.0.0.0 --port 8003 --reload

Exposes:
    GET /check?domain=evil.com   -> IntelCheckResponse (the module contract)
    GET /sync-status             -> SyncStatus (for the dashboard)
    GET /health                  -> quick liveness check
"""

import logging

from fastapi import FastAPI, HTTPException, Query

from app.config import settings
from app.lookup import check_intel
from app.models import IntelCheckResponse, SyncStatus
from app.redis_client import count_indicators, ping as redis_ping
from app.sync import get_last_sync_info, start_scheduler

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Threat Intel & Feeds Service",
    description="Module 3 — STIX/TAXII ingestion and domain blacklist lookups.",
    version="1.0.0",
)


@app.on_event("startup")
def on_startup() -> None:
    if not redis_ping():
        logger.error(
            "Redis is not reachable at startup! Sync and lookups will fail "
            "until Redis is running. Check REDIS_HOST/REDIS_PORT in .env."
        )
    else:
        logger.info("Redis connection OK.")

    start_scheduler()


@app.get("/health")
def health() -> dict:
    """Basic liveness check — useful for docker-compose healthchecks later."""
    return {"status": "ok", "redis_connected": redis_ping()}


@app.get("/check", response_model=IntelCheckResponse)
def check(domain: str = Query(..., description="Domain to check, e.g. evil.com")) -> IntelCheckResponse:
    """
    THE main contract endpoint. Person 1 / Person 4 call this to find
    out if a domain is a known threat.

    Example: GET /check?domain=evil.com
    """
    if not domain or not domain.strip():
        raise HTTPException(status_code=400, detail="domain query parameter is required")

    return check_intel(domain)


@app.get("/sync-status", response_model=SyncStatus)
def sync_status() -> SyncStatus:
    """Lets the dashboard (Person 6) show when feeds last updated and how much data is loaded."""
    info = get_last_sync_info()
    return SyncStatus(
        last_sync_time=info["last_sync_time"],
        total_indicators=info["total_indicators"] or count_indicators(),
        sources=info["sources"],
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app.main:app", host=settings.app_host, port=settings.app_port, reload=True)