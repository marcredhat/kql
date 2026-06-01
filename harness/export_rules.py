#!/usr/bin/env python3
"""Export each rule's KQL and PowerQuery to disk.

The exported `.pq` files are:
  * SELF-CONTAINED and RUNNABLE — every template placeholder
    (`{RECENT_MS}`) is substituted with a concrete value from the
    current time anchor, so you can paste straight into SDL.
  * PRETTY-PRINTED — one pipeline stage per line with continuation
    indents, matching the style in pmoses-s1/claude-skills.
  * HEADER-DECORATED — a `//`-comment block names the rule, describes
    intent, lists field references, and tells the reader what
    `startTime` to use when running the query.
  * VALIDATED — after writing, every `.pq` is parsed for known
    anti-patterns from the SentinelOne PowerQuery skill's pitfalls
    list (literal `{` braces, deprecated `first()`/`last()`/
    `percentile()`, leading `*` filter, missing leading pipe before
    `join`/`union`, etc.). Errors abort the export so the published
    repo never contains broken queries.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from rules import RULES, NOW, RECENT_START, BASELINE_START  # noqa: E402


# ---------------------------------------------------------------------------
# Pretty-printer: turn a single-line PQ string into multi-line idiomatic form.
# ---------------------------------------------------------------------------
def pretty(pq: str) -> str:
    """Break a one-line PQ into idiomatic multi-line form.

    Rule: every `|` that introduces a stage starts a new line; multi-clause
    `group ... by ...` is split so each agg sits on its own indented line
    and `by ...` lines up under `group`.
    """
    # Normalise whitespace
    pq = re.sub(r"\s+", " ", pq).strip()

    # Split on " | " into stages, but keep the leading initial filter
    parts = pq.split(" | ")
    head, stages = parts[0].strip(), [s.strip() for s in parts[1:]]

    lines: list[str] = [head] if head else []
    for s in stages:
        # Break a long `group a=count(), b=sum(x) by f1, f2` into multi-line.
        m = re.match(
            r"^group\s+(.+?)\s+by\s+(.+)$", s, flags=re.IGNORECASE | re.DOTALL)
        if m:
            aggs_raw, bys = m.group(1), m.group(2)
            # Split aggs on commas NOT inside parentheses
            aggs = _split_top_level_commas(aggs_raw)
            lines.append("| group " + aggs[0].strip() + ("," if len(aggs) > 1 else ""))
            for a in aggs[1:-1]:
                lines.append("        " + a.strip() + ",")
            if len(aggs) > 1:
                lines.append("        " + aggs[-1].strip())
            lines.append("    by " + bys.strip())
            continue

        # Default: one stage per line
        lines.append("| " + s)

    return "\n".join(lines)


def _split_top_level_commas(s: str) -> list[str]:
    out: list[str] = []
    depth, cur = 0, []
    for ch in s:
        if ch == "(":
            depth += 1; cur.append(ch)
        elif ch == ")":
            depth -= 1; cur.append(ch)
        elif ch == "," and depth == 0:
            out.append("".join(cur)); cur = []
        else:
            cur.append(ch)
    if cur:
        out.append("".join(cur))
    return out


# ---------------------------------------------------------------------------
# Anti-pattern scanner — refuses to write a file containing known landmines.
# ---------------------------------------------------------------------------
PITFALLS: list[tuple[str, str]] = [
    (r"\{[A-Za-z_]+\}",
     "Unsubstituted template placeholder (e.g. {RECENT_MS}). "
     "Substitute before writing."),
    (r"\bfirst\s*\(",
     "first(x) is unreliable — use min_by(x, ts_epoch_ms)."),
    (r"\blast\s*\(",
     "last(x) is unreliable — use max_by(x, ts_epoch_ms)."),
    (r"\bpercentile\s*\(",
     "percentile(x, N) is not a real function — use p50/p95/p99."),
    (r"\bgroup_unique_values\s*\(",
     "group_unique_values does not exist — use array_agg_distinct(x, N)."),
    (r"(?m)^\s*\*\s*(\||$)",
     "Bare `*` as initial filter returns 500 — use `| limit 5` or "
     "`field = *`."),
    (r"(?m)^\s*(join|union)\b",
     "join/union must start with a leading `|`."),
    (r"(?m)^\s*#(cmdline|name|hash|ip|storylineid|username|dns)\b",
     "Shortcut fields (#cmdline, …) are unreliable across tenants — "
     "use the explicit field name."),
]


def scan(text: str) -> list[str]:
    return [msg for pat, msg in PITFALLS if re.search(pat, text)]


# ---------------------------------------------------------------------------
# Header builder
# ---------------------------------------------------------------------------
def header(rule: dict, recent_iso: str, now_iso: str) -> str:
    field_refs = sorted({f for f in re.findall(
        r"\b[A-Z][A-Za-z0-9_]+\b", rule["pq"])
        if f.lower() not in {"and", "or", "not", "true", "false",
                              "filter", "group", "by", "let", "columns",
                              "sort", "limit", "join", "union", "in",
                              "contains", "matches"}})
    lines = [
        f"// Rule: {rule['id']}",
        f"// {rule['description']}",
        f"//",
        "// Source KQL: see ../kql/" + rule['id'] + ".kql",
        "//",
        "// HOW TO RUN",
        "//   curl POST {sdl}/api/powerQuery with this body, OR paste in",
        "//   the SDL console. Set startTime = '2h' (or wider) so the API",
        "//   scans the freshly-ingested epochs that contain the events.",
        "//",
        f"// Time anchor at export: NOW = {now_iso}",
        f"// Recent-window cutoff:  {recent_iso}",
        "//   (`ts_epoch_ms` below is that cutoff expressed in ms.",
        "//   Re-run harness/export_rules.py to refresh after regenerating",
        "//   sample_data/events.jsonl.)",
        "//",
        "// Fields referenced: " + ", ".join(field_refs[:10])
        + ("…" if len(field_refs) > 10 else ""),
        "//",
        "// EDITING NOTE",
        "//   Every line that starts with `|` is a pipeline stage. Each `|`",
        "//   is REQUIRED. If you delete one (e.g. while changing a literal",
        "//   on the same line as a stage), SDL re-parses the keyword that",
        "//   follows as a search term and rejects the query with errors",
        "//   like `'estimate_distinct' is a grouping function`.",
    ]
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    recent_ms = int(RECENT_START.timestamp() * 1000)
    recent_iso = RECENT_START.isoformat()
    now_iso = NOW.isoformat()

    failures: list[tuple[str, list[str]]] = []
    for r in RULES:
        # 1. substitute placeholders
        body = r["pq"].replace("{RECENT_MS}", str(recent_ms))
        # 2. pretty-print
        body = pretty(body)
        # 3. scan
        bad = scan(body)
        if bad:
            failures.append((r["id"], bad))
            continue
        # 4. write
        text = header(r, recent_iso, now_iso) + "\n" + body + "\n"
        (ROOT / "pq" / f"{r['id']}.pq").write_text(text)

        # Mirror the .kql (verbatim, no substitution)
        (ROOT / "kql" / f"{r['id']}.kql").write_text(r["kql"].strip() + "\n")

    if failures:
        print("✗ Export failed — anti-patterns detected:")
        for rid, msgs in failures:
            print(f"  {rid}")
            for m in msgs:
                print(f"    - {m}")
        sys.exit(1)

    print(f"✓ Exported {len(RULES)} rules to kql/ and pq/")
    print(f"  (RECENT_MS = {recent_ms} = {recent_iso})")


if __name__ == "__main__":
    main()
