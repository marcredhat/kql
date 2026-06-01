#!/usr/bin/env python3
"""After bash run_proof.sh, check what's queryable for the latest run."""
import sys, json, time
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT))
from harness.sdl_client import power_query

# Look at the latest proof_run_id from the log
log = (ROOT / "reports" / "run.log").read_text()
import re
m = re.search(r"proof_run_id=([A-Za-z0-9-]+)", log)
RUN_ID = m.group(1) if m else None
print(f"Latest proof_run_id from log: {RUN_ID}")

QUERIES = [
    "any event for this run",
    f"proof_run_id='{RUN_ID}' | group n=count()",
    "by event_type for this run",
    f"proof_run_id='{RUN_ID}' | group n=count() by event_type",
    "all kql-proof logfile (any run)",
    "logfile contains 'kql-proof' | group n=count() by event_type",
    "rule 1 raw query that errors",
    f"proof_run_id='{RUN_ID}' event_type='SigninLogs' | filter ts_epoch_ms >= 0 "
    "| group LocationCount = estimate_distinct(Location), "
    "LocationList = group_unique_values(Location), LogonCount = count() "
    "by UserPrincipalName, AppDisplayName | filter LocationCount >= 3",
]

for label_or_q in zip(QUERIES[0::2], QUERIES[1::2]):
    label, q = label_or_q
    print()
    print("=" * 80)
    print(f"# {label}")
    print(f"  q: {q}")
    t = time.time()
    r = power_query(q, "1h")
    print(f"  status={r.get('status')} matching={r.get('matchingEvents')} took={time.time()-t:.1f}s")
    if r.get("status", "").startswith("error/"):
        print(f"  ERROR: {json.dumps(r)[:600]}")
    for row in (r.get("values") or [])[:10]:
        cols = [c.get("name") if isinstance(c, dict) else c for c in (r.get("columns") or [])]
        print("    ", dict(zip(cols, row)))
