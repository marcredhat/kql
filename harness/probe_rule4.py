#!/usr/bin/env python3
"""Manually run rule 4's query against the latest run_id."""
import sys, json, time
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT))
from harness.sdl_client import power_query

log = (ROOT / "reports" / "run.log").read_text()
import re
RUN = re.findall(r"proof_run_id=([A-Za-z0-9-]+)", log)[-1]
RECENT_MS = re.findall(r"RECENT_MS = (\d+)", log)[-1]
print(f"RUN = {RUN}\nRECENT_MS = {RECENT_MS}\n")

QS = [
    "rule 4 exact",
    f"proof_run_id='{RUN}' event_type='SigninLogs' | filter ts_epoch_ms >= {RECENT_MS} | group LocationCount = estimate_distinct(Location), DistinctSourceIp = estimate_distinct(IPAddress), LogonCount = count() by AppDisplayName, UserPrincipalName",
    "rule 4 without ts filter",
    f"proof_run_id='{RUN}' event_type='SigninLogs' | group LocationCount = estimate_distinct(Location), DistinctSourceIp = estimate_distinct(IPAddress), LogonCount = count() by AppDisplayName, UserPrincipalName",
    "show 5 SigninLogs columns",
    f"proof_run_id='{RUN}' event_type='SigninLogs' | columns AppDisplayName, UserPrincipalName, Location, IPAddress, ts_epoch_ms | limit 5",
]
for label, q in zip(QS[0::2], QS[1::2]):
    print("=" * 80)
    print(f"# {label}")
    print(f"  q: {q[:200]}")
    r = power_query(q, "30m")
    cols = [c.get("name") for c in (r.get("columns") or [])]
    vals = r.get("values") or []
    print(f"  status={r.get('status')} matching={r.get('matchingEvents')} rows={len(vals)}")
    for row in vals[:8]:
        print(f"    {dict(zip(cols, row))}")
    if r.get("status", "").startswith("error/"):
        print(f"  ERROR: {json.dumps(r)[:400]}")
