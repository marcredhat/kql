#!/usr/bin/env python3
"""Send one event per batch (separate addEvents call) at different ages,
each with a fresh session. This isolates whether SDL is rejecting based on
mixed-age batches or just on event age."""
import json, sys, time, uuid, importlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT))

PROBE = uuid.uuid4().hex[:8]
ages_min = [0.5, 5, 30, 60, 120, 240, 480, 720, 1440]

# Force a fresh session for *every* probe so we eliminate session dedup
import harness.sdl_client as sdl

results = []
for i, age in enumerate(ages_min):
    importlib.reload(sdl)         # re-roll the SESSION UUID
    ts_ms = int(time.time() * 1000) - int(age * 60 * 1000)
    pv = f"{PROBE}_{i:02d}"
    ev = {"ts": str(ts_ms * 1_000_000), "sev": 3, "thread": "T1",
          "attrs": {"event_type": "CommonSecurityLog", "probe": pv,
                    "age_min": age}}
    r = sdl.add_events([ev])
    print(f"age={age:>6} min  session={sdl.SESSION[-12:]}  addEvents={r}")
    results.append((age, pv))

print("\nWaiting 12 s ...")
time.sleep(12)

q = f"probe contains '{PROBE}' | columns probe, age_min | limit 100"
res = sdl.power_query(q, "48h")
n = res.get("matchingEvents", 0)
vals = res.get("values") or []
print(f"\nQuery matching={n}")
got = {row[1] for row in vals}
print(f"\n{'age_min':>8}  {'queryable':>10}")
for age, _ in results:
    landed = "YES" if age in got else "NO"
    print(f"  {age:>6}     {landed:>10}")
