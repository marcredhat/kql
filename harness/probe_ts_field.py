#!/usr/bin/env python3
"""Check how SDL stores ts_epoch_ms: number vs string."""
import sys, json, time
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT))
from harness.sdl_client import power_query

# Use the most recent run_id from the log
log = (ROOT / "reports" / "run.log").read_text()
import re
m = re.findall(r"proof_run_id=([A-Za-z0-9-]+)", log)
RUN = m[-1] if m else None
print(f"run_id = {RUN}")

CASES = [
    ("show 3 SigninLogs with ts_epoch_ms",
     f"proof_run_id='{RUN}' event_type='SigninLogs' | columns ts_epoch_ms, UserPrincipalName | limit 3"),
    ("count where ts_epoch_ms exists (any)",
     f"proof_run_id='{RUN}' ts_epoch_ms=* | group n=count()"),
    ("count where ts_epoch_ms > number",
     f"proof_run_id='{RUN}' | filter ts_epoch_ms > 1000000000000 | group n=count()"),
    ("count where ts_epoch_ms (as string) > '0'",
     f"proof_run_id='{RUN}' | filter ts_epoch_ms > '0' | group n=count()"),
    ("count where ts_epoch_ms >= NOW-2h numeric",
     f"proof_run_id='{RUN}' | filter ts_epoch_ms >= " + str(int(time.time()*1000) - 2*3600*1000) + " | group n=count()"),
    ("min/max ts_epoch_ms aggregate",
     f"proof_run_id='{RUN}' | group mn=min(ts_epoch_ms), mx=max(ts_epoch_ms), n=count()"),
    ("event_type filter alone",
     f"proof_run_id='{RUN}' event_type='SigninLogs' | group n=count()"),
]
for name, q in CASES:
    print("=" * 80)
    print(f"# {name}")
    print(f"  q: {q}")
    r = power_query(q, "30m")
    cols = [c.get("name") if isinstance(c, dict) else c for c in (r.get("columns") or [])]
    vals = r.get("values") or []
    print(f"  status={r.get('status')} matching={r.get('matchingEvents')}")
    for row in vals[:5]:
        print(f"    {dict(zip(cols, row))}")
