#!/usr/bin/env python3
"""Compare the EXACT addEvents payload used by ingest_jsonl with a known-good
manual one. Add a unique probe marker so we can tell whether it actually
landed in SDL."""
from __future__ import annotations

import json
import sys
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from harness.sdl_client import add_events, power_query, _clean_attrs  # noqa: E402

JSONL = ROOT / "sample_data" / "events.jsonl"
PROBE = uuid.uuid4().hex[:8]

# Take the first 3 lines of JSONL, decorate with probe, send via the SAME
# code path as ingest_jsonl does (but inlined here so we can print everything).
events = []
with JSONL.open() as f:
    for line in f:
        if len(events) >= 3:
            break
        rec = json.loads(line)
        rec["probe"] = f"{PROBE}_{len(events)}"
        ts_ms = int(rec["ts_epoch_ms"])
        attrs = _clean_attrs(rec)
        events.append({"ts": str(ts_ms * 1_000_000), "sev": 3,
                       "thread": "T1", "attrs": attrs})

print(f"=== Payload ({len(events)} events) ===")
print(json.dumps(events, indent=2, default=str)[:3000])
print()
print(f"=== Submitting (probe prefix={PROBE}) ===")
r = add_events(events)
print(f"addEvents -> {json.dumps(r)}")

print("\nWaiting 12 s for indexing ...")
time.sleep(12)

q = f"probe contains '{PROBE}' | columns event_type, probe, ts_epoch_ms | limit 10"
print(f"\nQuery: {q}")
res = power_query(q, "10m")
print(f"Result -> matching={res.get('matchingEvents')}")
for row in res.get("values") or []:
    print("  ", row)

# Also: show TS skew vs real now
import datetime as dt
real_now_ms = int(time.time() * 1000)
print(f"\nreal_now_ms = {real_now_ms}")
for e in events:
    ts_ns = int(e["ts"])
    ts_ms = ts_ns // 1_000_000
    age_min = (real_now_ms - ts_ms) / 60000
    print(f"  event ts_ms={ts_ms}  age={age_min:.2f} min  attrs.event_type={e['attrs']['event_type']}")
