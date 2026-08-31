# Module 5 — Passive Forensics Engine

Your part of the SIH1524 DNS filtering project. This service takes a
`.pcap` capture or a Zeek `dns.log` (TSV) file, extracts every DNS
query in it, runs each one through detection heuristics, and returns
a JSON list of compromised devices — matching the contract in the
project spec exactly:

```json
[{"src_ip": "192.168.1.15", "domain": "malicious-c2.com", "detected_by": "ML_DGA", "timestamp": "2026-08-24 10:00:00"}]
```

## Files

| File | What it does |
|---|---|
| `parser.py` | Reads `.pcap`/`.pcapng` (via scapy) or Zeek `dns.log` (TSV) and turns them into a plain list of `{src_ip, domain, timestamp, query_type}` |
| `detector.py` | Runs each parsed query through 4 checks: blacklist match, DNS tunneling, phishing keyword stacking, DGA (entropy-based) |
| `app.py` | FastAPI server with one endpoint, `POST /analyze`, that Person 6's dashboard will call |
| `test_local.py` | Runs the whole pipeline locally without needing the server — good for quick debugging |
| `generate_sample_pcap.py` | One-off script that builds a tiny test `.pcap` file |
| `sample_data/` | Sample Zeek log, sample blacklist, and (after you run the generator) a sample pcap |

## 1. Set up in VS Code

```bash
# from inside the "forensics" folder
python3 -m venv venv
source venv/bin/activate        # on Windows: venv\Scripts\activate
pip install -r requirements.txt
```

Open the folder in VS Code, make sure the bottom-right Python
interpreter is set to `venv`, and you're ready to run/debug.

## 2. Test it with no server at all (fastest way to check your logic)

```bash
python generate_sample_pcap.py   # only needed once, builds sample_data/sample.pcap
python test_local.py
```

You should see something like:

```
=== Testing sample_data/sample_dns.log ===
Parsed 7 DNS queries
Found 3 compromises:
[
  {
    "src_ip": "192.168.1.15",
    "domain": "malicious-c2.com",
    "detected_by": "Threat_Intel_Blacklist",
    "timestamp": "2025-08-24 09:20:01"
  },
  ...
]
```

If you change `parser.py` or `detector.py`, just rerun `python
test_local.py` — no server needed to see if your fix worked.

## 3. Run the actual API (what Person 6 will call)

```bash
uvicorn app:app --reload --port 8005
```

Leave that running, then in a **second terminal**:

```bash
curl -F "file=@sample_data/sample_dns.log" http://127.0.0.1:8005/analyze
```

Or open `http://127.0.0.1:8005/docs` in your browser — FastAPI gives
you a free UI where you can click "Try it out", upload a file, and
see the JSON response, no curl needed.

## 4. Testing with a REAL pcap file (not just the sample)

If you want to test against a real capture instead of the synthetic
one:
- Wireshark can save any live capture as `.pcap`
- Or download a sample malware-traffic `.pcap` from
  [malware-traffic-analysis.net](https://www.malware-traffic-analysis.net/)
  for realistic testing
- Drop it in `sample_data/` and either:
  - run `python -c "from parser import parse_file; from detector import analyze; import json; print(json.dumps(analyze(parse_file('sample_data/your_file.pcap')), indent=2))"`
  - or upload it via `/docs` or `curl`

## 5. Fixing bugs / tuning detection

All the detection thresholds live at the top of `detector.py`:

```python
DGA_ENTROPY_THRESHOLD = 3.5      # higher = stricter (fewer false positives, more missed DGAs)
TUNNELING_LABEL_LENGTH = 50      # subdomain length that counts as suspicious
SUSPICIOUS_KEYWORDS = [...]      # phishing keyword list
```

If your team's real DGA classifier (Person 2) or threat intel feed
(Person 3) is ready before the demo, swap the bodies of `is_dga()`
and `is_blacklisted()` in `detector.py` for real HTTP calls to their
services — the JSON output shape doesn't need to change, so nothing
else in the pipeline breaks.

## 6. Uploading to the shared GitHub repo

Per the team's plan, everyone gets their own folder inside one repo.
From inside this `forensics` folder:

```bash
# one-time setup if the shared repo doesn't exist locally yet
git clone <the-shared-repo-url>
cd <repo-name>
mkdir -p forensics
# copy all the files from this project into that forensics/ folder

git add forensics/
git commit -m "Module 5: Passive Forensics Engine (pcap + Zeek log parser, detection heuristics, FastAPI endpoint)"
git push
```

If the repo already exists and you just need to add your folder:

```bash
git clone <the-shared-repo-url>
cd <repo-name>
cp -r /path/to/this/forensics ./forensics
git add forensics/
git commit -m "Add Module 5: Passive Forensics Engine"
git push
```

## 7. Quick sanity checklist before the demo

- [ ] `python test_local.py` runs with no errors and shows compromises
- [ ] `uvicorn app:app --port 8005` starts without errors
- [ ] `http://127.0.0.1:8005/docs` loads in browser and you can upload a file
- [ ] Output JSON has exactly the 4 fields: `src_ip`, `domain`, `detected_by`, `timestamp`
- [ ] `requirements.txt` is committed so teammates can `pip install -r requirements.txt` and run it too
