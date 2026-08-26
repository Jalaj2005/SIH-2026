# Threat Intel & Feeds — Module 3

Background service that ingests known-malicious domains from threat intelligence
feeds (STIX/TAXII, URLhaus) and exposes a fast lookup API so other modules can
check whether a domain is a known threat.

Owned by: **Person 3**

---

## What this module does

1. Periodically pulls indicators from threat feeds (currently: URLhaus; OTX
   support is built in but needs an API key — see Configuration below).
2. Parses raw feed data (STIX bundles / CSV) into clean domain records.
3. Stores them in Redis for sub-millisecond lookups.
4. Exposes a `check_intel(domain)` function and a matching HTTP endpoint so
   any other module — regardless of language — can check a domain instantly.

---

## How to run it

```bash
cd threat-intel
python -m venv venv
source venv/Scripts/activate      # Windows Git Bash
# venv\Scripts\activate           # Windows cmd/PowerShell
# source venv/bin/activate        # Mac/Linux

pip install -r requirements.txt
cp .env.example .env              # fill in values if needed, defaults work out of the box

uvicorn app.main:app --host 0.0.0.0 --port 8003 --reload
```

Redis must be running first:
```bash
docker run -p 6379:6379 redis
```

On startup the service immediately syncs threat feeds into Redis, then
repeats every `SYNC_INTERVAL_MINUTES` (default 30). Check the terminal logs
for `Sync complete: N indicators stored`.

Interactive API docs: **http://localhost:8003/docs**

---

## How to connect to this module (for Person 1 and Person 4)

### Option A — HTTP request (recommended, works from any language)

```
GET http://localhost:8003/check?domain=evil-c2.com
```

**Python example:**
```python
import requests

response = requests.get(
    "http://localhost:8003/check",
    params={"domain": "evil-c2.com"}
)
intel_data = response.json()
```

**Go example:**
```go
resp, err := http.Get("http://localhost:8003/check?domain=evil-c2.com")
```

### Option B — Direct Python import (only if running in the same Python process/monorepo)

```python
from app.lookup import check_intel
result = check_intel("evil-c2.com")
```

### Response shape (the contract)

```json
{
  "is_blacklisted": true,
  "source": "URLhaus",
  "threat_type": "malware"
}
```

- `is_blacklisted` (bool) — always present.
- `source` (string or null) — which feed flagged it, e.g. `"URLhaus"`, `"AlienVault_OTX"`. `null` if not blacklisted.
- `threat_type` (string or null) — one of `"phishing"`, `"malware"`, `"c2"`, `"scam"`, `"spam"`, `"unknown"`. `null` if not blacklisted.

Unknown/safe domains simply return `{"is_blacklisted": false, "source": null, "threat_type": null}` — this is never an error, always a 200 response.

---

## Other endpoints

| Endpoint | Purpose |
|---|---|
| `GET /check?domain=<domain>` | The main contract endpoint — is this domain malicious? |
| `GET /sync-status` | Last sync time, total indicators loaded, active sources — useful for the dashboard (Person 6) |
| `GET /health` | Liveness check, confirms Redis connectivity — useful for `docker-compose` healthchecks |

---

## Configuration

All config lives in `.env` (copy from `.env.example`). Defaults work with zero
setup for URLhaus. To enable OTX as an additional source, set `OTX_API_KEY`
and `OTX_COLLECTION_ID` (see `scripts/discover_otx_collections.py` to find
your collection ID).

| Variable | Purpose | Required? |
|---|---|---|
| `REDIS_HOST`, `REDIS_PORT` | Where Redis is running | Yes |
| `URLHAUS_CSV_URL` | Free feed, no key needed | Already set, no action needed |
| `OTX_API_KEY`, `OTX_COLLECTION_ID` | Enables AlienVault OTX as a second feed | Optional |
| `SYNC_INTERVAL_MINUTES` | How often feeds refresh | Optional, defaults to 30 |
| `APP_PORT` | Port this service runs on | Optional, defaults to 8003 |

---

## Folder structure

```
threat-intel/
├── app/
│   ├── config.py          # settings & environment variables
│   ├── models.py          # Pydantic contract models
│   ├── redis_client.py    # Redis connection + get/set helpers
│   ├── lookup.py          # check_intel(domain) — the core function
│   ├── parser.py          # parses STIX/TAXII + URLhaus CSV into domain records
│   ├── sync.py            # background scheduler that pulls feeds periodically
│   └── main.py            # FastAPI app — run this
├── scripts/
│   ├── discover_otx_collections.py   # one-off: find your OTX/TAXII collection ID
│   ├── clear_intel_data.py           # one-off: wipe Redis intel data for a clean resync
│   └── get_test_domain.py            # dev helper: prints a real domain to test with
├── tests/
│   └── test_lookup.py
├── requirements.txt
├── .env.example
└── README.md
```

---

## Notes for integration

- **Fails safe**: if Redis is unreachable, `check_intel()` returns
  `is_blacklisted: false` rather than crashing, and logs the error. Don't
  assume "not blacklisted" always means Redis was actually checked — if you
  need to know Redis is healthy, hit `/health` first.
- **Domain normalization is handled here**, not by callers — trailing dots,
  `www.` prefixes, and casing are all normalized internally before lookup, so
  just pass the raw domain from a DNS query as-is.
- Only real domain names are stored — bare IP addresses from feeds are
  filtered out, since DNS queries are never made for a raw IP.
