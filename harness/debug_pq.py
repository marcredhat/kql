#!/usr/bin/env python3
"""Probe what data is actually queryable in SDL after ingestion."""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from harness.sdl_client import power_query  # noqa: E402

QUERIES = [
    ("any serverHost=kql-proof",
     "serverHost='kql-proof' | columns event_type, UserPrincipalName, ts_epoch_ms | limit 5"),
    ("count by event_type",
     "serverHost='kql-proof' | group n=count() by event_type"),
    ("SigninLogs by user",
     "serverHost='kql-proof' event_type='SigninLogs' | group n=count() by UserPrincipalName"),
    ("SigninLogs min/max ts_epoch_ms",
     "serverHost='kql-proof' event_type='SigninLogs' | group mn=min(ts_epoch_ms), mx=max(ts_epoch_ms), n=count()"),
    ("recent SigninLogs (no time filter)",
     "serverHost='kql-proof' event_type='SigninLogs' Location='RU' | columns UserPrincipalName, Location | limit 10"),
    ("SecurityEvent EventID column type",
     "serverHost='kql-proof' event_type='SecurityEvent' | columns EventID, NewProcessName | limit 5"),
    ("Audit OperationName",
     "serverHost='kql-proof' event_type='AuditLogs' | columns OperationName | limit 10"),
]

for name, q in QUERIES:
    print("=" * 80)
    print(f"# {name}")
    print(f"  query: {q}")
    t = time.time()
    r = power_query(q, start_time="30d")
    rows = r.get("values") or []
    cols = [c.get("name") if isinstance(c, dict) else c
            for c in (r.get("columns") or [])]
    print(f"  status={r.get('status')} matching={r.get('matchingEvents')} "
          f"rows={len(rows)} took={time.time()-t:.1f}s")
    if r.get("status", "").startswith("error/"):
        print(f"  ERROR_BODY: {json.dumps(r, indent=2)[:800]}")
    if rows:
        print(f"  cols: {cols}")
        for row in rows[:5]:
            print("    ", dict(zip(cols, row)))
