"""
Background sync job — the "WHEN and WHERE FROM" half of ingestion
(parser.py is the "HOW to parse" half).

Fetches from OTX (TAXII) and URLhaus (plain CSV), hands raw data to
parser.py, deduplicates, and bulk-writes to Redis. Runs on a
schedule via APScheduler so the blacklist stays fresh without manual
intervention.
"""

import logging
from datetime import datetime, timezone

import requests
from apscheduler.schedulers.background import BackgroundScheduler
from taxii2client.v21 import Collection

from app.config import settings
from app.models import IndicatorRecord
from app.parser import deduplicate, parse_stix_bundle, parse_urlhaus_csv
from app.redis_client import bulk_set_indicators, redis_client

logger = logging.getLogger(__name__)

# Track last sync so it can be surfaced via SyncStatus (main.py)
_last_sync_info = {
    "last_sync_time": None,
    "total_indicators": 0,
    "sources": [],
}


def fetch_otx_indicators() -> list[IndicatorRecord]:
    """
    Pull the latest indicators from MITRE ATT&CK TAXII 2.1 collection.
    Requires OTX_COLLECTION_ID to be set in .env.
    """
    if not settings.otx_collection_id:
        logger.warning("TAXII collection not configured (missing collection ID) — skipping.")
        return []

    try:
        collection_url = f"{settings.otx_taxii_url.rstrip('/')}/collections/{settings.otx_collection_id}/"
        collection = Collection(collection_url)
        
        all_records: list[IndicatorRecord] = []
        
        # get_objects() returns the entire STIX bundle dictionary directly!
        bundle = collection.get_objects()
        
        # Pass the dictionary straight to the parser
        all_records.extend(parse_stix_bundle(bundle, source="MITRE_ATTACK"))
        
        return all_records
    except Exception as e:
        logger.error(f"TAXII fetch failed: {e}")
        return []


def fetch_urlhaus_indicators() -> list[IndicatorRecord]:
    """
    Pull the latest URLhaus 'recent' CSV feed. No API key required —
    good fallback source and useful for testing before OTX is set up.
    """
    try:
        response = requests.get(settings.urlhaus_csv_url, timeout=15)
        response.raise_for_status()
        return parse_urlhaus_csv(response.text, source="URLhaus")
    except requests.RequestException as e:
        logger.error(f"URLhaus fetch failed: {e}")
        return []


def run_sync() -> None:
    """
    The actual job APScheduler calls on a timer. Fetches from every
    configured source, merges + deduplicates, and writes to Redis.

    Deliberately never raises — a failed sync should log loudly but
    NOT crash the scheduler thread or the FastAPI app around it.
    """
    logger.info("Starting threat intel sync...")

    otx_records = fetch_otx_indicators()
    urlhaus_records = fetch_urlhaus_indicators()

    all_records = deduplicate(otx_records + urlhaus_records)

    if not all_records:
        logger.warning("Sync completed with 0 new indicators (check feed configs/connectivity).")
        return

    domains_with_data = {
        record.domain: {
            "is_blacklisted": True,
            "source": record.source,
            "threat_type": record.threat_type.value,
        }
        for record in all_records
    }

    bulk_set_indicators(domains_with_data)

    _last_sync_info["last_sync_time"] = datetime.now(timezone.utc).isoformat()
    _last_sync_info["total_indicators"] = len(domains_with_data)
    _last_sync_info["sources"] = list({r.source for r in all_records})

    logger.info(
        f"Sync complete: {len(domains_with_data)} indicators stored "
        f"from sources {_last_sync_info['sources']}."
    )


def get_last_sync_info() -> dict:
    """Used by main.py's /sync-status endpoint (feeds SyncStatus model)."""
    return _last_sync_info


def start_scheduler() -> BackgroundScheduler:
    """
    Call this once at FastAPI startup (see main.py). Runs run_sync()
    immediately on boot, then every SYNC_INTERVAL_MINUTES afterward.
    """
    scheduler = BackgroundScheduler()
    scheduler.add_job(
        run_sync,
        "interval",
        minutes=settings.sync_interval_minutes,
        id="threat_intel_sync",
        next_run_time=datetime.now(timezone.utc),  # run once immediately on startup
    )
    scheduler.start()
    logger.info(
        f"Scheduler started — syncing every {settings.sync_interval_minutes} minutes."
    )
    return scheduler