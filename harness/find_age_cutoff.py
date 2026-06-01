#!/usr/bin/env python3
"""Find SDL's age cutoff for addEvents by sending probe events at increasing
ages and seeing which ones become queryable."""
import json, sys, time, uuid
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT))
from harness.sdl_client import add_events, power_query

TS_NOW_MS = int(time.time() * 1000)
PROBE = uuid.uuid4().hex[:8]

# 30s, 5min, 30min, 1h, 2h, 4h, 6h, 12h, 24h
ages_min = [0.5, 5, 30, 60, 120, 240, 360, 720, 1440]
events = []
for i, age in enumerate(ages_min):
    ts_ms = TS_NOW_MS - int(age * 60 * 1000)
    events.append({
        "ts": str(ts_ms * 1_000_000), "sev": 3, "thread": "T1",
        "attrs": {"event_type": "CommonSecurityLog",
                  "probe": f"{PROBE}_{i:02d}", "age_min": age},
    })

print(f"Sending {len(events)} events at ages {ages_min} min")
r = add_events(events)
print(f"addEvents -> {json.dumps(r)}")

print("\nWaiting 12 s ...")
time.sleep(12)

print(f"\nQuerying probe '{PROBE}' over last 48h ...")
res = power_query(f"probe contains '{PROBE}' | columns probe, age_min | limit 100", "48h")
n = res.get("matchingEvents", 0)
vals = res.get("values") or []
print(f"matching={n}")
got = {row[1] for row in vals}
print(f"\n{'age_min':>8}  {'sent':>6}  {'queryable':>10}")
for age in ages_min:
    landed = "YES" if age in got else "NO"
    print(f"  {age:>6}     {'yes':>6}  {landed:>10}")
