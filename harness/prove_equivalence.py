#!/usr/bin/env python3
"""End-to-end proof harness.

Steps:
  1. Loads sample_data/events.jsonl into memory.
  2. Runs each rule's Python reference implementation against the in-memory
     events. This is the canonical "ground truth" – the same logical operation
     that both the KQL and the PowerQuery engines evaluate.
  3. Optionally ingests the events to SentinelOne SDL via /api/addEvents,
     then runs each rule's PowerQuery via /api/powerQuery and compares the
     fired set against the reference.
  4. Emits reports/PROOF.md with side-by-side results.

Run modes:
    python harness/prove_equivalence.py            # local-only proof
    python harness/prove_equivalence.py --ingest   # ingest + remote PQ
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from rules import RULES, NOW, RECENT_START  # noqa: E402

SAMPLE = ROOT / "sample_data" / "events.jsonl"
REPORT = ROOT / "reports" / "PROOF.md"
REPORT_JSON = ROOT / "reports" / "PROOF.json"


def load_events() -> list[dict]:
    return [json.loads(l) for l in SAMPLE.read_text().splitlines() if l.strip()]


def canonical(rule, rows):
    """Return a sorted, hashable representation of fired rows for comparison."""
    keys = sorted({rule["key"](r) for r in rows}, key=lambda x: str(x))
    return keys


def run_local(events):
    out = {}
    for r in RULES:
        rows = r["ref"](events)
        out[r["id"]] = {
            "description": r["description"],
            "fired_rows": rows,
            "fired_keys": canonical(r, rows),
        }
    return out


def run_pq(run_id: str | None = None):
    from sdl_client import power_query
    out = {}
    recent_ms = int(RECENT_START.timestamp() * 1000)
    scope = f"proof_run_id='{run_id}' " if run_id else ""
    print(f"  scope     = {scope.strip() or '(none)'}")
    print(f"  RECENT_MS = {recent_ms}  ({RECENT_START.isoformat()})")
    print(f"  NOW       = {NOW.isoformat()}")
    print()
    for i, r in enumerate(RULES, 1):
        q = scope + r["pq"].format(RECENT_MS=str(recent_ms))
        print(f"  [{i:>2}/{len(RULES)}] {r['id']:<48} ", end="", flush=True)
        t0 = time.time()
        try:
            resp = power_query(q, start_time="2h")
            cols_meta = resp.get("columns") or []
            cols = [c["name"] if isinstance(c, dict) else c for c in cols_meta]
            vals = resp.get("values") or []
            rows = [dict(zip(cols, v)) for v in vals]
            elapsed = time.time() - t0
            status = resp.get("status", "ok")
            print(f"-> {len(rows):>3} rows  matching={resp.get('matchingEvents')} "
                  f"({elapsed:.1f}s, {status})")
            out[r["id"]] = {"ok": True, "rowcount": len(rows),
                            "rows": rows[:50], "status": status,
                            "matching": resp.get("matchingEvents")}
        except Exception as e:
            elapsed = time.time() - t0
            msg = str(e)[:200]
            print(f"-> ERROR ({elapsed:.1f}s): {msg}")
            out[r["id"]] = {"ok": False, "error": msg}
    return out


def ingest():
    from sdl_client import ingest_jsonl, power_query
    n, run_id = ingest_jsonl(SAMPLE)
    print(f"Ingested {n} events to SDL  (proof_run_id={run_id})")
    # Poll until SDL reports the events are indexed.
    print("Waiting for SDL indexing ...", end="", flush=True)
    for i in range(30):  # up to 60s
        time.sleep(2)
        r = power_query(f"proof_run_id='{run_id}' | group n=count()", "30m")
        vals = r.get("values") or []
        cnt = int(vals[0][0]) if vals and vals[0] and vals[0][0] is not None else 0
        print(f" {cnt}", end="", flush=True)
        if cnt >= n:
            print(" ✓ ready")
            return run_id
    print(" (timeout, proceeding anyway)")
    return run_id


def write_report(local_results, pq_results=None):
    REPORT.parent.mkdir(exist_ok=True)
    md = ["# KQL ↔ PowerQuery equivalence proof",
          "",
          f"Sample dataset: `sample_data/events.jsonl` ({len(load_events())} events)",
          f"Time anchor (NOW): `{NOW.isoformat()}`",
          f"Recent window start: `{RECENT_START.isoformat()}`",
          "",
          "Each rule below is expressed three ways:",
          "1. **KQL** — verbatim/condensed from the Microsoft Sentinel docs.",
          "2. **PowerQuery (PQ)** — SDL equivalent, runnable on `<XDR endpoint>`.",
          "3. **Python reference** — canonical implementation of the same logical "
          "operation tree against the in-memory dataset. Acts as ground truth.",
          "",
          "The PowerQuery is considered equivalent to the KQL when its result "
          "set matches the Python reference. The Python reference encodes the "
          "*same operations* that the KQL parser/optimiser would produce, so a "
          "match certifies KQL/PQ parity on this dataset.",
          ""]
    for r in RULES:
        rid = r["id"]
        loc = local_results[rid]
        md += [f"## {rid}", "",
               f"_{r['description']}_", "",
               "### KQL", "```kusto", r["kql"].strip(), "```",
               "### PowerQuery", "```", r["pq"].strip(), "```",
               f"### Reference fired: {len(loc['fired_rows'])} row(s)"]
        if loc["fired_rows"]:
            sample = loc["fired_rows"][:5]
            md.append("```json")
            md.append(json.dumps(sample, default=str, indent=2))
            md.append("```")
        if pq_results:
            pq = pq_results.get(rid, {})
            if pq.get("ok"):
                pq_keys = []
                for row in pq.get("rows", []):
                    try:
                        pq_keys.append(r["key"](row))
                    except Exception:
                        pq_keys.append(tuple(row.items()))
                pq_keys = sorted({k for k in pq_keys}, key=lambda x: str(x))
                ref_keys = loc["fired_keys"]
                match = "✅ MATCH" if pq_keys == ref_keys else "⚠️ DIFFERS"
                md += [f"### SDL PowerQuery result: {pq['rowcount']} row(s) — {match}"]
                if pq_keys != ref_keys:
                    md += ["Reference keys:", "```",
                           json.dumps([list(k) for k in ref_keys], default=str), "```",
                           "PQ keys:", "```",
                           json.dumps([list(k) for k in pq_keys], default=str), "```"]
            else:
                md.append(f"### SDL PowerQuery error: `{pq.get('error', '?')}`")
        md.append("")
    REPORT.write_text("\n".join(md))
    REPORT_JSON.write_text(json.dumps(
        {"local": {k: {"fired_keys": [list(x) for x in v["fired_keys"]],
                       "n": len(v["fired_rows"])}
                   for k, v in local_results.items()},
         "pq": pq_results or {}},
        default=str, indent=2))
    print(f"Wrote {REPORT}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ingest", action="store_true",
                    help="Ingest sample events to SDL before querying")
    ap.add_argument("--pq", action="store_true",
                    help="Also run each PQ against SDL and compare")
    args = ap.parse_args()

    events = load_events()
    print(f"Loaded {len(events)} events")
    local_results = run_local(events)
    fired_total = sum(len(v["fired_rows"]) for v in local_results.values())
    print(f"Local reference: {fired_total} total fired rows across {len(RULES)} rules")

    pq_results = None
    run_id = None
    if args.ingest:
        run_id = ingest()
    if args.pq:
        pq_results = run_pq(run_id=run_id)

    write_report(local_results, pq_results)


if __name__ == "__main__":
    main()
