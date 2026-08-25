# Module 4 — DNS Tunneling & Risk Aggregator

This is Person 4's module in the SIH1524 DNS filtering project. It sits
between Person 1 (DNS resolver), Person 2 (DGA classifier), and Person 3
(threat intel), and produces the final BLOCK/ALLOW verdict.

## Run it

```bash
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8004 --reload
```

Interactive docs at `http://localhost:8004/docs` once running.

## API

### `POST /score`

Request:
```json
{
  "domain": "x89vf2qlmn3.top",
  "query_type": "TXT",
  "dga_score": 0.94,
  "intel_match": false,
  "client_ip": "192.168.1.15"
}
```
`client_ip` is optional — needed for burst detection but not in the
original team contract. If the caller (Person 1/6) can pass it, do;
otherwise burst just contributes 0 and everything else still works.

Response (matches team contract exactly):
```json
{"composite_risk": 0.65, "verdict": "BLOCK", "reason": "DGA_Detected"}
```

### `POST /score/debug`

Same input, but returns the full breakdown (individual sub-scores,
tunneling signals) — useful for Person 6's dashboard drill-down view and
for tuning weights.

### `GET /health`

Liveness check for docker-compose / the API gateway.

## How the score is built

```
Composite Risk = WEIGHT_DGA * dga_score
                + WEIGHT_TUNNELING * tunneling_score
                + WEIGHT_REPUTATION * reputation_score
```

- **dga_score** — passed in from Person 2, used as-is.
- **tunneling_score** — computed here from 4 signals (see
  `tunneling.py`): entropy of the leftmost subdomain label, subdomain
  length, query type (TXT/NULL are exfil-friendly), and burst behaviour
  (many unique subdomains from one client hitting one root domain fast).
- **reputation_score** — a placeholder TLD-risk heuristic (see
  `scoring.py`). Real domain-age/WHOIS reputation wasn't assigned to any
  module in the plan — swap in a real source here if the team wants it,
  or leave it as a low-weight placeholder.

If `intel_match` is `true`, Module 4 short-circuits straight to
`BLOCK` / `THREAT_INTEL_MATCH` regardless of the other scores (Stage 2
in the pipeline doc should normally catch this before Module 4 is even
called — this is just a defensive fallback).

## Tuning

All weights and the `BLOCK_THRESHOLD` live in `config.py`. **These are
placeholder values** — calibrate them once you have labeled data (e.g.
the `dnsqueriesdataset` train/test CSVs from the tunneling notebook).
Important gotcha: if a single sub-score's weight is lower than
`BLOCK_THRESHOLD`, that signal can never trigger BLOCK on its own no
matter how confident it is — keep threshold ≤ your largest weight if you
want single strong signals to be decisive.

## Known limitations / next steps

- `BurstTracker` is in-memory and per-process. Fine for a hackathon demo;
  for real multi-worker deployment, move it to the Redis instance Person 3
  already runs (natural shared store for both of you).
- `reputation_score` is a placeholder heuristic, not a real reputation
  system.
- No auth/rate-limiting on the endpoint — add if this is exposed beyond
  the internal docker-compose network.

## Files

| File | Purpose |
|---|---|
| `main.py` | FastAPI app, request/response models, endpoints |
| `scoring.py` | Composite risk aggregation + reputation heuristic |
| `tunneling.py` | Entropy / length / query-type / burst sub-scores |
| `config.py` | All tunable weights, thresholds, TLD list |
