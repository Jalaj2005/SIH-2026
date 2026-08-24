"""
Clears all existing threat intel entries from Redis so the next sync
repopulates cleanly with the fixed parser logic (no more IP:port
entries mixed in with real domains).

Run with:
    python scripts/clear_intel_data.py
"""

import redis

r = redis.Redis(host="localhost", port=6379, decode_responses=True)

keys = r.keys("intel:*")
if keys:
    r.delete(*keys)
    print(f"Deleted {len(keys)} old intel: entries from Redis.")
else:
    print("No intel: entries found — nothing to clear.")