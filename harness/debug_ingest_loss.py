#!/usr/bin/env python3
"""Diagnose why most of our 445 generated events are not queryable in SDL.

Strategy:
  1. Take 5 CommonSecurityLog events straight from the generated JSONL,
     decorate them with a unique probe marker, and ingest as a single batch.
  2. Wait 10 s for indexing.
  3. Query for the marker to confirm they are queryable.
  4. Then bulk-ingest the entire JSONL and report per-event-type counts in SDL
     vs counts in the local file - to expose where the loss happens.
"""
from __future__ import annotations

import json
import sys
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from harness.sdl_client import add_events, power_query, ingest_jsonl, _clean_attrs  # noqa: E402

JSONL = ROOT / "sample_data" / "events.jsonl"
MARKER = f"loss-probe-{int(time.time())}"

# ---------------------------------------------------------------------------
# Step 1: per-type counts in the local file
# ---------------------------------------------------------------------------
local_counts = Counter()
with JSONL.open() as f:
    for line in f:
        rec = json.loads(line)
        local_counts[rec["event_type"]] += 1

print("=" * 80)
print("Local JSONL event_type counts")
print("=" * 80)
for k, v in sorted(local_counts.items()):
    print(f"  {k:30s} {v}")
print(f"  {'TOTAL':30s} {sum(local_counts.values())}")

# ---------------------------------------------------------------------------
# Step 2: pick 5 CSL events from disk, mark them, ingest, query
# ---------------------------------------------------------------------------
csl_events = []
with JSONL.open() as f:
    for line in f:
        rec = json.loads(line)
        if rec["event_type"] == "CommonSecurityLog":
            rec["loss_marker"] = MARKER
            ts_ms = int(rec["ts_epoch_ms"])
            cleaned = _clean_attrs(rec)
            csl_events.append({"ts": str(ts_ms * 1_000_000), "sev": 3,
                               "thread": "T1", "attrs": cleaned})
            if len(csl_events) >= 5:
                break

print()
print("=" * 80)
print(f"Step 2: ingesting 5 marker-tagged CSL events ({MARKER})")
print("=" * 80)
r = add_events(csl_events)
print(f"addEvents -> {json.dumps(r)}")
print("waiting 10 s for indexing ...")
time.sleep(10)

probe_q = f"loss_marker='{MARKER}' | group n = count() by event_type"
r = power_query(probe_q, "1h")
print(f"probe query (1h) -> matching={r.get('matchingEvents')}, rows={r.get('values')}")

# ---------------------------------------------------------------------------
# Step 3: full bulk ingest of the file via the harness helper
# ---------------------------------------------------------------------------
print()
print("=" * 80)
print("Step 3: full bulk ingest of every event in JSONL")
print("=" * 80)
sent = ingest_jsonl(JSONL)
print(f"ingest_jsonl reports {sent} events sent")
print("waiting 20 s for indexing ...")
time.sleep(20)

# ---------------------------------------------------------------------------
# Step 4: per-event-type count in SDL
# ---------------------------------------------------------------------------
print()
print("=" * 80)
print("Step 4: SDL counts by event_type")
print("=" * 80)
print(f"{'event_type':30s} {'local':>8} {'SDL':>8} {'loss%':>8}")
print("-" * 60)
for et in sorted(local_counts):
    q = f"event_type='{et}' | group n = count()"
    r = power_query(q, "1h")
    sdl_n = 0
    if r.get("values"):
        sdl_n = int(r["values"][0][0] or 0)
    local_n = local_counts[et]
    loss = 100 * (local_n - sdl_n) / local_n if local_n else 0
    print(f"{et:30s} {local_n:>8} {sdl_n:>8} {loss:>7.0f}%")
