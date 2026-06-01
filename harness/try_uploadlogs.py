#!/usr/bin/env python3
"""Try /api/uploadLogs as an alternative to addEvents. We POST each line of
the JSONL as a raw event - SDL's json parser will extract fields automatically.

Per docs: max 6 MB per request, 10 GB/day per tenant, parser=json supports
auto-flattening of all keys."""
from __future__ import annotations

import json
import sys
import time
import uuid
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
CFG = json.loads((ROOT / "config.json").read_text())

BASE = CFG["base_url"].rstrip("/")
WRITE = CFG["log_write_key"]

JSONL = ROOT / "sample_data" / "events.jsonl"

PROBE = uuid.uuid4().hex[:8]
print(f"probe = {PROBE}")

# Stamp each line with the probe marker
lines = []
for line in JSONL.read_text().splitlines():
    if not line.strip():
        continue
    rec = json.loads(line)
    rec["upload_probe"] = PROBE
    lines.append(json.dumps(rec))
body = "\n".join(lines)
print(f"body size = {len(body)} bytes ({len(lines)} lines)")

headers = {
    "Authorization": f"Bearer {WRITE}",
    "Content-Type": "text/plain",
    "parser": "json",
    "server-host": "kql-proof",
    "logfile": "kql-proof.jsonl",
}
r = requests.post(f"{BASE}/api/uploadLogs",
                  data=body.encode(), headers=headers,
                  timeout=120, verify=True)
print(f"HTTP {r.status_code} -> {r.text[:500]}")

print("\nWaiting 15 s ...")
time.sleep(15)

# Query for the probe value
from harness.sdl_client import power_query
q = f"upload_probe='{PROBE}' | group n=count() by event_type"
res = power_query(q, "30m")
print(f"\nQuery result: matching={res.get('matchingEvents')}")
cols = [c.get("name") if isinstance(c, dict) else c for c in (res.get("columns") or [])]
for row in res.get("values") or []:
    print(f"  {dict(zip(cols, row))}")
