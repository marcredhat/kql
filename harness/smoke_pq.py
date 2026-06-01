#!/usr/bin/env python3
"""Minimal PowerQuery smoke test against SDL."""
import sys, json, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from harness.sdl_client import power_query, power_query_long_running

NOW_MS = int(time.time() * 1000)
START = NOW_MS - 30 * 24 * 3600 * 1000  # 30d back
END = NOW_MS

q = "dataset='kql-proof' | group n = count() by event_type"
print(f"Query: {q}")
print(f"Window: {START} .. {END}")
t0 = time.time()
r = power_query(q, START, END)
print(f"Initial response in {time.time()-t0:.2f}s:")
print(json.dumps({k: (v if k != 'values' else f'<{len(v)} rows>') for k, v in r.items()},
                 indent=2, default=str))
if r.get("continuationToken") or r.get("token"):
    print("\nPolling for completion ...")
    r = power_query_long_running(q, START, END, max_wait_sec=30)
    print(json.dumps({k: (v if k != 'values' else f'<{len(v)} rows>') for k, v in r.items()},
                     indent=2, default=str))
print("\nColumns:", r.get("columns"))
print("First 20 values:", r.get("values", [])[:20])
