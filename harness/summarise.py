#!/usr/bin/env python3
"""Pretty-print the PROOF.json summary as a table."""
import json
from pathlib import Path

p = Path(__file__).resolve().parents[1] / "reports" / "PROOF.json"
data = json.loads(p.read_text())
local = data["local"]
pq = data.get("pq") or {}

print(f"{'Rule':<46} {'Ref rows':>9} {'SDL rows':>9} {'Status':<10}")
print("-" * 80)
match = diff = err = 0
for rid, l in local.items():
    ref_keys = sorted([tuple(k) for k in l["fired_keys"]], key=str)
    p_entry = pq.get(rid) or {}
    if not pq:
        status = "—"; sdl_n = "n/a"
    elif not p_entry.get("ok"):
        status = "ERROR"; sdl_n = "?"; err += 1
    else:
        sdl_n = p_entry.get("rowcount", 0)
        status = "OK" if sdl_n > 0 else "EMPTY"
        if sdl_n > 0: match += 1
        else: diff += 1
    print(f"{rid:<46} {l['n']:>9} {str(sdl_n):>9} {status:<10}")
print("-" * 80)
if pq:
    print(f"OK: {match}   EMPTY: {diff}   ERROR: {err}")
print(f"\nFull report: reports/PROOF.md")
