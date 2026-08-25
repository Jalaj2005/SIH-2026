"""
Module 5 - Passive Forensics Engine API
Exposes a single upload endpoint that Module 6 (Dashboard) calls.

Run:
    uvicorn app:app --reload --port 8005

Test (in another terminal):
    curl -F "file=@sample_data/sample_dns.log" http://127.0.0.1:8005/analyze
"""

import shutil
import tempfile
from pathlib import Path

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from parser import parse_file
from detector import analyze

app = FastAPI(title="Module 5 - Passive Forensics Engine")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def health():
    return {"status": "ok", "module": "Passive Forensics Engine"}


@app.post("/analyze")
async def analyze_upload(file: UploadFile = File(...)):
    suffix = Path(file.filename).suffix.lower()
    if suffix not in (".pcap", ".pcapng", ".log", ".tsv", ".txt"):
        raise HTTPException(status_code=400, detail="Unsupported file type. Upload .pcap, .pcapng, .log or .tsv")

    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        shutil.copyfileobj(file.file, tmp)
        tmp_path = tmp.name

    try:
        records = parse_file(tmp_path)
        compromises = analyze(records)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        Path(tmp_path).unlink(missing_ok=True)

    return {
        "total_queries_analyzed": len(records),
        "compromises_found": len(compromises),
        "results": compromises,
    }
