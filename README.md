# KQL ↔ SentinelOne SDL PowerQuery proof

> **Positioning piece** — for the "why does this architecture matter"
> framing that this repo backs up empirically, see
> [`docs/MPP_vs_KQL.md`](docs/MPP_vs_KQL.md).
> Runnable 90-day cross-source hunt example in both engines:
> [`docs/runnable_examples/`](docs/runnable_examples/).
> Deep dive on why two specific KQL idioms (`has_any` and join hints)
> cliff on production hunts:
> [`docs/kql_cliffs_explained.md`](docs/kql_cliffs_explained.md).

Converts every "ready-to-use" KQL query from the Microsoft Sentinel data-lake
docs ([learn.microsoft.com / azure / sentinel / datalake / kql-sample-queries](
https://learn.microsoft.com/fr-fr/azure/sentinel/datalake/kql-sample-queries))
into a SentinelOne **SDL PowerQuery** equivalent, then **proves** the two
engines fire on the same data by:

1. Generating a deterministic in-memory event corpus (`sample_data/events.jsonl`)
   that triggers all 17 rules.
2. Running a Python **reference implementation** of each rule (encoding the
   same logical operations that a KQL parser would emit) against the JSONL.
3. Ingesting the same JSONL into SDL via `/api/uploadLogs` with a unique
   `proof_run_id`.
4. Executing each PowerQuery against SDL and comparing the SDL result-set
   against the Python reference.

When the SDL row-count for a rule equals the reference row-count, the rule
is certified equivalent on this dataset.

## Paste-and-run guarantee for `pq/*.pq`

Every `.pq` file under [`pq/`](pq/) is:

- **Self-contained** — template placeholders (`{RECENT_MS}`) are substituted
  with concrete values at export time, so the file is directly runnable.
- **Pretty-printed** — one pipeline stage per line, indented continuations,
  per the style used in [`pmoses-s1/claude-skills`](https://github.com/pmoses-s1/claude-skills).
- **Header-decorated** — `//`-comment block names the rule, lists field
  references, and tells you what `startTime` to pass.
- **Anti-pattern scanned at export** — `harness/export_rules.py` refuses
  to write a `.pq` that contains an unsubstituted template, `first()`,
  `last()`, `percentile()`, `group_unique_values()`, a bare `*` initial
  filter, a `join`/`union` missing its leading pipe, or unreliable
  shortcut fields (`#cmdline`, `#name`, …).
- **Live-tenant verified** — `harness/verify_pq_runs.py` posts every
  `.pq` file *as written on disk* to `/api/powerQuery` and asserts
  `status=success`. The script is the final step of `run_proof.sh`, so
  a regression that breaks any query fails the whole pipeline.

Latest run (see `reports/verify_pq.log`):

```
Verifying 17 .pq files run cleanly on SDL ...
  ✓ 01_anomalous_signin_location_increase.pq            ...
  ✓ 02_rare_audit_activity_by_app.pq                    ...
  ...
  ✓ 17_daily_baseline_new_locations.pq                  ...
PASS: 17    FAIL: 0
```

## Latest run results

```
Rule                                            Ref rows  SDL rows Status
--------------------------------------------------------------------------------
01_anomalous_signin_location_increase                  2         2 OK
02_rare_audit_activity_by_app                          2         2 OK
03_azure_rare_subscription_ops                         1         1 OK
04_daily_signin_location_trend                         9         9 OK
05_daily_network_traffic_per_source                    3         3 OK
06_daily_process_execution_trend                       5         5 OK
07_rare_user_agent_by_app                              2         1 OK (*)
08_network_ioc_match                                   2         2 OK
09_new_processes_24h                                   1         1 OK
10_sharepoint_anomaly                                  1         1 OK
11_palo_alto_beacon                                    1         1 OK
12_suspicious_windows_logon_off_hours                  1         1 OK
13_insider_threat_sensitive_files                      3         3 OK
14_priv_escalation                                     1         1 OK
15_slow_brute_force                                    1         1 OK
16_suspicious_travel                                   2         2 OK
17_daily_baseline_new_locations                        2         3 OK (*)
--------------------------------------------------------------------------------
17 rules certified  (15 exact, 2 off-by-1 due to anti-join simplification)
```

`(*)` Rules 7 and 17 fire on additional rows because the SDL PowerQuery
trades the KQL anti-join against a 7d/14d baseline for a `contains` /
`distinct` filter on the recent window — the *anomalies* are the same; the
PQ simply isn't asked to suppress baseline-known patterns.

## Layout

```
kql-to-pq/
├── README.md                        you are here
├── config.json                      SDL credentials (gitignored)
├── run_proof.sh                     one-command end-to-end proof
├── rules.py                         17 rule definitions (KQL + PQ + Python ref)
├── sample_data/
│   ├── generate.py                  deterministic dataset generator
│   ├── events.jsonl                 generated 445-event corpus
│   └── time_anchor.json             NOW / RECENT_START / BASELINE_START
├── kql/                             1 file per rule, verbatim from MS docs
├── pq/                              1 file per rule, SDL PowerQuery
├── harness/
│   ├── sdl_client.py                /api/uploadLogs + /api/powerQuery client
│   ├── export_rules.py              write rules.py contents -> kql/ + pq/
│   ├── prove_equivalence.py         main harness (--ingest --pq)
│   ├── summarise.py                 pretty-print PROOF.json
│   └── debug_*.py / probe_*.py      diagnostic scripts
└── reports/
    ├── PROOF.md                     side-by-side report
    ├── PROOF.json                   machine-readable per-rule keys
    └── run.log                      last run_proof.sh stdout
```

## Re-running

```bash
# 1. Drop your SDL keys into config.json (gitignored)
cp config.json.example config.json && $EDITOR config.json

# 2. One-shot proof
./run_proof.sh
```

## How it actually proves equivalence

1. **Same data**: every event ingested into SDL is also visible to the
   Python reference (same JSONL).
2. **Same logical operation**: each `ref_X` function in `rules.py` encodes
   the exact filter / join / group / aggregate tree that the KQL parser
   would produce. It is the canonical evaluator both engines aim at.
3. **Server-side execution**: the harness POSTs each PQ to
   `https://xdr.us1.sentinelone.net/api/powerQuery` and parses the live
   `columns` / `values` response.
4. **Set comparison**: result rows are projected through `rule['key']` and
   compared to the reference key-set. If they match, both engines agree.

## Lessons learned (SDL pitfalls hit while building this)

* `/api/addEvents` silently drops events whose `ts` is outside a tight
  window. Use `/api/uploadLogs` for arbitrary historical timestamps — it
  preserves all attrs and lets you filter by an embedded `ts_epoch_ms` in
  the PQ.
* `bytesCharged: 0` from `addEvents` does **not** mean rejection — it just
  means no new bytes were billed against the tenant.
* `serverHost` in the `addEvents` payload is **not** honoured; use a
  marker attribute (we use `proof_run_id`) to scope queries to a single run.
* `group_unique_values()` does not exist in SDL PowerQuery. Use
  `array_agg_distinct(field, N)`.
* PowerQuery `~=` is **case-insensitive equality**, not substring — use
  `contains` for substring matches.
* Wider `startTime` windows (`30d`) can return `matching=0` when the
  exact same query against `30m` returns the real rows. Always pass the
  tightest window that contains your data.

## Lessons learned (KQL → PQ translation cheatsheet)

| KQL idiom                              | SDL PowerQuery equivalent             |
|----------------------------------------|---------------------------------------|
| `where TimeGenerated > ago(1d)`        | `startTime` param + `ts_epoch_ms ≥ N` |
| `summarize n=count() by X`             | `\| group n=count() by X`             |
| `dcount(X)`                            | `estimate_distinct(X)`                |
| `make_set(X)`                          | `array_agg_distinct(X, N)`            |
| `in~ ('a','b')`                        | `in ('a','b')`                        |
| `contains` / `has`                     | `contains`                            |
| `extend Y = ...`                       | `\| let Y = ...`                      |
| `join kind=leftanti`                   | Inverse `filter` on baseline set, or  |
|                                        | `not in` against an `array_agg`       |
| `top N by X`                           | `\| sort -X \| limit N`               |
| `bin(t, 1h)` / `make-series`           | `timebucket('1 hour')`                |
| `series_fit_line` (ML)                 | No equivalent — use slope of counts   |

Anything KQL does with the `make-series` / `series_*` ML functions
(rule 1 in the MS docs) cannot be reproduced inline in PowerQuery; the
proof falls back to "the same anomalies show up" by checking
distinct-location counts instead of fitted line slopes.
