#!/usr/bin/env python3
"""Run every .pq file in pq/ AND docs/runnable_examples/ for startTime=2h
and assert each returns matching > 0.

Prereqs:
  * sample_data/events.jsonl ingested via prove_equivalence.py --ingest
    (drives all 17 rule PQs in pq/)
  * seed_runnable_examples.py executed (drives docs/runnable_examples/*.pq)

Outputs a one-line-per-query report and exits 0 iff every query returned
at least one row.
"""
from __future__ import annotations

import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from harness.sdl_client import power_query  # noqa: E402


def strip_comments(text: str) -> str:
    return "\n".join(l for l in text.splitlines()
                     if not l.lstrip().startswith("//")).strip()


DIRS = [ROOT / "pq", ROOT / "docs" / "runnable_examples"]
files = []
for d in DIRS:
    files.extend(sorted(d.glob("*.pq")))

if not files:
    print("No .pq files found.")
    sys.exit(1)

print(f"Running {len(files)} PowerQueries (startTime=2h, assert matching>0)\n")

passed: list[str] = []
failed: list[tuple[str, str]] = []  # (relpath, reason)

for f in files:
    body = strip_comments(f.read_text())
    rel = f.relative_to(ROOT)
    t0 = time.time()
    try:
        r = power_query(body, start_time="2h")
    except Exception as e:
        failed.append((str(rel), f"exception: {e}"))
        print(f"  ✗ {rel}  exception: {e}")
        continue
    elapsed = time.time() - t0
    status = r.get("status", "")
    matching = r.get("matchingEvents", 0) or 0
    if status != "success":
        msg = r.get("message", "")[:200]
        failed.append((str(rel), f"{status}: {msg}"))
        print(f"  ✗ {rel}  [{status}] {msg}")
        continue
    if matching <= 0:
        failed.append((str(rel), "matching=0"))
        print(f"  ✗ {rel}  matching=0 ({elapsed:.1f}s)")
        continue
    print(f"  ✓ {rel}  matching={matching} ({elapsed:.1f}s)")
    passed.append(str(rel))

print()
print(f"PASS: {len(passed)}    FAIL: {len(failed)}    TOTAL: {len(files)}")

if failed:
    print("\nFailed queries:")
    for rel, why in failed:
        print(f"  {rel}: {why}")
    sys.exit(1)

print("\nAll PowerQueries returned results within the last 2h ✓")
