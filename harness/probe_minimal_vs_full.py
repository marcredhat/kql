#!/usr/bin/env python3
"""Find out what attribute(s) in our generated events cause SDL to reject them.

Send increasingly complex events under unique markers and see which ones
SDL accepts (queryable within 10s) vs silently drops.
"""
from __future__ import annotations

import json
import sys
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from harness.sdl_client import add_events, power_query, _clean_attrs  # noqa: E402

TS_NOW_MS = int(time.time() * 1000)


def mk(attrs: dict, offset_sec: int = 0):
    return {
        "ts": str((TS_NOW_MS - offset_sec * 1000) * 1_000_000),
        "sev": 3, "thread": "T1",
        "attrs": attrs,
    }


PROBE = uuid.uuid4().hex[:8]
cases = [
    ("A_minimal_2_attrs",
     mk({"event_type": "CommonSecurityLog", "probe": f"{PROBE}_A"}, 60)),
    ("B_one_int_attr",
     mk({"event_type": "CommonSecurityLog", "probe": f"{PROBE}_B",
         "SentBytes": 2048}, 55)),
    ("C_one_negative_int",
     mk({"event_type": "CommonSecurityLog", "probe": f"{PROBE}_C",
         "SentBytes": 2048, "LogSeverity": 5}, 50)),
    ("D_with_special_chars",
     mk({"event_type": "CommonSecurityLog", "probe": f"{PROBE}_D",
         "Message": "allow web access to 142.250.74.110 port 443"}, 45)),
    ("E_with_backslashes",
     mk({"event_type": "SecurityEvent", "probe": f"{PROBE}_E",
         "NewProcessName": "C:\\Windows\\System32\\svchost.exe"}, 40)),
    ("F_realistic_csl_via_clean",
     mk(_clean_attrs({
         "event_type": "CommonSecurityLog", "probe": f"{PROBE}_F",
         "TimeGenerated": "2026-05-31T16:50:00.000Z",
         "ts_epoch_ms": TS_NOW_MS - 30000,
         "DeviceVendor": "Palo Alto Networks", "Activity": "TRAFFIC",
         "DeviceName": "pa-fw-01", "SourceUserID": "alice",
         "SourceIP": "10.0.1.10", "SourcePort": 49000,
         "DestinationIP": "142.250.74.110", "DestinationPort": 443,
         "SentBytes": 2048, "ReceivedBytes": 16384,
         "Message": "allow", "DeviceEventClassID": "end", "LogSeverity": 3,
         "DeviceAction": "allow", "DeviceProduct": "PAN-OS",
     }), 30)),
    ("G_realistic_csl_with_None",
     mk(_clean_attrs({
         "event_type": "CommonSecurityLog", "probe": f"{PROBE}_G",
         "TimeGenerated": "2026-05-31T16:50:00.000Z",
         "ts_epoch_ms": TS_NOW_MS - 20000,
         "DeviceVendor": "Palo Alto Networks", "Activity": None,
         "Message": None,
     }), 20)),
]

print(f"=== Sending {len(cases)} probe events ===")
r = add_events([c[1] for c in cases])
print(f"addEvents -> {json.dumps(r)}")

print("\nWaiting 12 s for indexing ...")
time.sleep(12)

print("\n=== Per-case verification ===")
for name, ev in cases:
    probe_val = ev["attrs"]["probe"]
    q = f"probe='{probe_val}' | columns event_type, probe | limit 1"
    res = power_query(q, "10m")
    n = res.get("matchingEvents", 0)
    status = "OK" if n and n > 0 else "MISSING"
    rows = res.get("values") or []
    print(f"  {name:35s} matching={n}  status={status}  -> {rows}")
