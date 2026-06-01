#!/usr/bin/env python3
"""Wider probe: try a variety of filters and start windows to find our data."""
import sys, time, json
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from harness.sdl_client import power_query

QUERIES = [
    ("event_type=SigninLogs 7d (no serverHost)",
     "event_type='SigninLogs' | columns UserPrincipalName | limit 5", "7d"),
    ("event_type=SigninLogs 1h",
     "event_type='SigninLogs' | columns UserPrincipalName, ts_epoch_ms | limit 5", "1h"),
    ("UserPrincipalName matching contoso",
     "UserPrincipalName='alice@contoso.com' | columns event_type, UserPrincipalName | limit 5", "1d"),
    ("anything from xdr tenant 1h",
     "* | columns event_type, serverHost, logfile | limit 5", "1h"),
    ("logfile contains kql-proof",
     "logfile contains 'kql-proof' | columns event_type | limit 5", "7d"),
    ("contoso.com in attrs",
     "Identity contains 'contoso.com' | columns event_type, Identity | limit 5", "1d"),
    ("test: count any events tenant-wide 5m",
     "* | group n=count()", "5m"),
]

for name, q, window in QUERIES:
    print("=" * 80)
    print(f"# {name}  (start={window})")
    print(f"  q: {q}")
    t = time.time()
    r = power_query(q, start_time=window)
    rows = r.get("values") or []
    cols = [c.get("name") if isinstance(c, dict) else c
            for c in (r.get("columns") or [])]
    print(f"  status={r.get('status')} matching={r.get('matchingEvents')} "
          f"rows={len(rows)} took={time.time()-t:.1f}s")
    if r.get("status", "").startswith("error/"):
        print(f"  ERROR: {json.dumps(r)[:500]}")
    if rows:
        for row in rows[:5]:
            print("    ", dict(zip(cols, row)))
