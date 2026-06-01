#!/usr/bin/env python3
"""Probe: does SDL index JSON keys that contain literal dots?

If yes, we can ship synthetic OCSF events with keys like
`"event.category": "logins"` and query them with the same dotted
syntax the published runnable example uses, keeping the OCSF
look-and-feel without needing a server-side parser to flatten
nested objects.
"""
from __future__ import annotations

import json
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from harness.sdl_client import upload_logs, power_query  # noqa: E402


def main() -> int:
    run_id = f"dot-probe-{uuid.uuid4().hex[:8]}"
    now = datetime.now(timezone.utc).replace(microsecond=0)
    ts_ms = int((now - timedelta(seconds=30)).timestamp() * 1000)

    e = {
        "TimeGenerated": now.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "ts_epoch_ms": ts_ms,
        "proof_run_id": run_id,
        # literal dots in the key (NOT nested objects)
        "event.category": "logins",
        "event.login.userName": "alice@contoso.com",
        "event.login.loginIsSuccessful": False,
        "endpoint.name": "host-alpha",
    }
    r = upload_logs(json.dumps(e))
    print("upload:", r.get("status"))

    print("indexing", end="", flush=True)
    n = 0
    for _ in range(20):
        time.sleep(2)
        rr = power_query(f"proof_run_id='{run_id}' | group n=count()", "5m")
        vals = rr.get("values") or []
        n = int(vals[0][0]) if vals and vals[0] and vals[0][0] is not None else 0
        print(f" {n}", end="", flush=True)
        if n >= 1:
            break
    print()

    if n == 0:
        print("event did not become queryable; aborting")
        return 1

    probes = [
        ("filter event.category",
         f"proof_run_id='{run_id}' AND event.category='logins' | limit 2"),
        ("project event.category",
         f"proof_run_id='{run_id}' | columns c=event.category | limit 2"),
        ("project endpoint.name",
         f"proof_run_id='{run_id}' | columns h=endpoint.name | limit 2"),
        ("project event.login.userName",
         f"proof_run_id='{run_id}' | columns u=event.login.userName | limit 2"),
        ("filter event.login.loginIsSuccessful",
         f"proof_run_id='{run_id}' AND event.login.loginIsSuccessful='false' | limit 2"),
        ("bracket access",
         f"proof_run_id='{run_id}' AND \"event.category\"='logins' | limit 2"),
        ("see all top-level cols of one row",
         f"proof_run_id='{run_id}' | limit 1"),
    ]
    for label, q in probes:
        r = power_query(q, "5m")
        status = r.get("status")
        matching = r.get("matchingEvents")
        msg = (r.get("message") or "")[:140]
        print(f"\n[{label}]")
        print(f"  q     : {q}")
        print(f"  status: {status}  matching: {matching}  msg: {msg}")
        cols = r.get("columns") or []
        col_names = [c.get("name") if isinstance(c, dict) else c for c in cols]
        print(f"  cols  : {col_names}")
        for v in (r.get("values") or [])[:2]:
            v_str = str(v)
            print(f"  val   : {v_str[:200]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
