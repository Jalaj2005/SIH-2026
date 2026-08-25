# Module 6 — SOC Web Dashboard

Person 6's deliverable per the team's distribution plan: a React/Next.js frontend
plus a backend REST + WebSocket gateway, running on mock telemetry from hour 1 so
you never block on Modules 1–5.

```
module6-soc-dashboard/
├── backend/     Express + Socket.io gateway, mock DNS telemetry generator
├── frontend/    Next.js dashboard (Tailwind, recharts, socket.io-client)
└── docker-compose.yml
```

## Quick start (local dev, two terminals)

```bash
# Terminal 1 — backend gateway (port 4000)
cd backend
npm install
npm run dev

# Terminal 2 — frontend (port 3000)
cd frontend
npm install
npm run dev
```

Open http://localhost:3000. You should see queries streaming in every ~1.2s,
stat cards updating, client health, a threat breakdown chart, and a PCAP/Zeek
log uploader.

## Docker (one command)

```bash
docker-compose up --build
```

## What's mocked vs. real

The backend generates realistic synthetic DNS query events (safe traffic, DGA
domains, phishing/typosquats, tunneling) at a steady interval and pushes them
over both REST and WebSocket. **The response shapes exactly mirror the
contracts your teammates are building**, so swapping mock → real is a small,
contained change in `backend/server.js` and `backend/mockData.js` — nothing in
the frontend needs to change.

| From distribution.docx | Mock stand-in today | Swap point |
|---|---|---|
| Module 2 — `{"dga_score":0.94,"is_dga":true,"inference_time_ms":2.1}` | `generateEvent()` fabricates this per query | Call Module 2's endpoint instead, merge into event |
| Module 3 — `check_intel(domain)` → `{"is_blacklisted":true,"source":"AlienVault_OTX","threat_type":"phishing"}` | Randomly rolled per query | Call Module 3's Redis-backed lookup |
| Module 4 — `{"composite_risk":0.88,"verdict":"BLOCK","reason":"DGA_Detected"}` | Computed in `generateEvent()` | Call Module 4's aggregator with the real 2+3 outputs |
| Module 5 — `[{"src_ip":...,"domain":...,"detected_by":...,"timestamp":...}]` | `/api/forensics/upload` fabricates a report | Proxy the uploaded file to Module 5's parser, return its real JSON |
| Module 1 — DNS server itself | N/A (dashboard doesn't run DNS) | Module 1 should POST/stream events into this gateway once live, e.g. `POST /api/ingest` (add this endpoint when Module 1 is ready) |

## Gateway API (backend)

- `GET /api/health` — liveness check
- `GET /api/queries?limit=50` — recent DNS telemetry events, newest first
- `GET /api/stats` — aggregate counts, block rate, avg latency, threats by reason
- `GET /api/clients` — per-client device health (healthy / suspicious / compromised)
- `GET /api/threats/recent?limit=20` — recent non-ALLOW events
- `POST /api/forensics/upload` — multipart file upload (`.pcap`, `.pcapng`, `.tsv`, `.log`), returns a forensic report
- `GET /api/forensics/reports` — history of uploaded/processed reports
- WebSocket `dns:snapshot` (on connect) and `dns:event` (per new query) — same shape as `/api/queries` items

## Event shape (streamed + REST)

```json
{
  "id": "evt_...",
  "timestamp": "2026-08-25T08:53:20.627Z",
  "client_ip": "192.168.1.12",
  "client_hostname": "SRV-FILE-02",
  "domain": "x89vf2qlmn3.top",
  "query_type": "A",
  "dga_score": 0.94,
  "is_dga": true,
  "intel_match": false,
  "is_blacklisted": false,
  "threat_source": null,
  "threat_type": null,
  "composite_risk": 0.96,
  "verdict": "BLOCK",
  "reason": "DGA_Detected",
  "response_time_ms": 5.2,
  "inference_time_ms": 2.1
}
```

## Config

Frontend reads `NEXT_PUBLIC_API_URL` (see `frontend/.env.local`, defaults to
`http://localhost:4000`). Point this at wherever the gateway ends up running —
no other frontend code needs to change.

## Notes for integration day (per the team's golden rules)

- This dashboard never blocks on the other 5 modules — it already has its own
  believable data.
- When Module 1's DNS engine is ready to stream real telemetry, add a
  `POST /api/ingest` route to `backend/server.js` that accepts the same event
  shape shown above and calls `pushEvent()` — then just turn off the
  `setInterval` mock generator.
- `backend/mockData.js` is isolated on purpose so it's a one-file delete once
  real modules are wired in.
