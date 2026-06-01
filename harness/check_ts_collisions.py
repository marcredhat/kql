#!/usr/bin/env python3
"""Count duplicate timestamps within the generated JSONL.

SDL appears to dedupe addEvents by (session, ts) - events sharing a ts
within the same session are silently dropped. If our generator emits many
events at colliding ts_epoch_ms values, only one of each cluster survives.
"""
import json
from collections import Counter, defaultdict
from pathlib import Path

JSONL = Path(__file__).resolve().parents[1] / "sample_data" / "events.jsonl"

per_type_total = Counter()
per_type_unique = defaultdict(set)
per_type_max_collision = defaultdict(int)
with JSONL.open() as f:
    for line in f:
        r = json.loads(line)
        et = r["event_type"]
        ts = r["ts_epoch_ms"]
        per_type_total[et] += 1
        per_type_unique[et].add(ts)

print(f"{'event_type':30s} {'events':>8} {'uniq_ts':>8} {'collision_loss%':>16}")
print("-" * 70)
for et in sorted(per_type_total):
    n = per_type_total[et]
    u = len(per_type_unique[et])
    loss = 100 * (n - u) / n if n else 0
    print(f"{et:30s} {n:>8} {u:>8} {loss:>15.1f}%")
print("-" * 70)
print(f"{'TOTAL':30s} {sum(per_type_total.values()):>8} "
      f"{sum(len(s) for s in per_type_unique.values()):>8}")
