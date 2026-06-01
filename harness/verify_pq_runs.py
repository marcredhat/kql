#!/usr/bin/env python3
"""Independent post-export verification.

Reads every file in `pq/` AS WRITTEN ON DISK (no template substitution,
no scope prefix, no harness magic) and POSTs it to /api/powerQuery on
the configured tenant. The script asserts each file:

  * parses cleanly (no 'error/client/badParam' status),
  * returns a syntactically valid response (status='success').

It does NOT assert that the query returns any rows — empty results are
fine. The purpose is to catch syntax / field / function errors so the
published .pq files are guaranteed runnable by anyone who copies them.
"""
from __future__ import annotations

import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from harness.sdl_client import power_query  # noqa: E402

PQ_DIR = ROOT / "pq"
files = sorted(PQ_DIR.glob("*.pq"))


def strip_comments(text: str) -> str:
    return "\n".join(l for l in text.splitlines()
                     if not l.lstrip().startswith("//")).strip()


def collapse_whitespace(body: str) -> str:
    """Single-line form: same query, all whitespace collapsed to one space.

    This simulates what happens when a user pastes the query into a web
    textbox that strips newlines. A correctly-formatted PQ must survive
    this transformation — every `|` between stages must be present.
    """
    return re.sub(r"\s+", " ", body).strip()


print(f"Verifying {len(files)} .pq files run cleanly on SDL ...")
print("(Each file tested in TWO forms: as-written and whitespace-collapsed.)")
print()

passed: list[str] = []
failed: list[tuple[str, str, str]] = []  # (file, variant, reason)


def run(name: str, variant: str, body: str) -> bool:
    t0 = time.time()
    try:
        r = power_query(body, start_time="2h")
    except Exception as e:
        failed.append((name, variant, f"exception: {e}"))
        return False
    elapsed = time.time() - t0
    status = r.get("status", "")
    if status == "success":
        matching = r.get("matchingEvents", 0)
        print(f"  ✓ {name:<48} [{variant:<9}] "
              f"matching={matching} ({elapsed:.1f}s)")
        return True
    msg = r.get("message", "")[:200]
    print(f"  ✗ {name:<48} [{variant:<9}] {status} :: {msg}")
    failed.append((name, variant, f"{status}: {msg}"))
    return False


for f in files:
    text = f.read_text()
    body = strip_comments(text)
    if not body:
        failed.append((f.name, "as-written", "empty after stripping comments"))
        continue

    ok1 = run(f.name, "as-written", body)
    ok2 = run(f.name, "collapsed", collapse_whitespace(body))
    if ok1 and ok2:
        passed.append(f.name)

print()
print(f"PASS: {len(passed)}    FAIL: {len(failed)}")
if failed:
    print()
    print("Failed queries:")
    for name, variant, why in failed:
        print(f"  {name} [{variant}]: {why}")
    sys.exit(1)
