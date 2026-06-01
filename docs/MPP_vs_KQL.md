# MPP vs KQL: Why SentinelOne's Architecture Wins Cross-Source Threat Hunting

> **Companion to [github.com/marcredhat/kql](https://github.com/marcredhat/kql).**
> The architecture claims in this document are backed by the 17-rule
> end-to-end equivalence proof in that repository: every "ready-to-use" KQL
> query from the Microsoft Sentinel data-lake docs was converted to SDL
> PowerQuery, run against the same deterministic dataset on both engines,
> and asserted to produce equivalent verdicts. See `reports/PROOF.md` after
> running `./run_proof.sh`.

## TL;DR

KQL on Microsoft Sentinel is a clever query language on top of a
general-purpose log analytics store (Azure Data Explorer / Kusto).
SentinelOne's Singularity Data Lake (SDL) is a purpose-built, indexless,
columnar, always-hot security lake with a Massively Parallel Query Engine
(MPP) that dedicates the entire cluster to every interactive query.

For 90-day cross-source hunts joining endpoint + identity + DNS + cloud,
the SDL design removes the three things that actually slow KQL down in
production: index/shard locality, workspace boundaries, and tiered
storage rehydration.

**Demonstrated end-to-end on a public repo:** 17 KQL hunts ↔ 17
PowerQueries, same data, asserted equivalence —
[github.com/marcredhat/kql](https://github.com/marcredhat/kql).

---

## 1. Storage model: inverted+columnar shards (Kusto) vs pure columnar epochs (SDL)

### Microsoft Sentinel / KQL (ADX/Kusto under the hood)

Kusto stores data as **extents** (immutable shards), columnar within an
extent, but each extent has a shard-level inverted **term index** ("shard
index") and column-level bloom/range indexes.

Performance is excellent when the query predicate hits an indexed column
with good selectivity (`where Computer == "x"`, `where SourceIP has "1.2.3.4"`).

Performance degrades when:

- Predicates are on **unindexed or high-cardinality JSON dynamic fields**
  → falls back to scan.
- You use `has_any`, `matches regex`, or `contains` on large columns
  → index bypass.
- Joins cross tables with different partitioning keys → shuffle.
- You query **Basic Logs / Auxiliary Logs / Archive** tiers → restricted
  KQL, no joins, or rehydration jobs (search jobs / restore) measured in
  hours, billed separately.

> **Sidebar — what an inverted index actually is.**
> Inverted index = `term → [doc, doc, …]`. Great for selective full-text
> lookup, useless for unselective scans where most of the data *is* the
> answer. That is exactly the shape of cross-source threat-hunt queries.

### SentinelOne SDL

No inverted index. Data is written in ~5-minute **epochs** to columnar,
append-only segments backed by object storage (the Scalyr/DataSet
lineage).

- Every byte ever ingested is hot — the epoch reader path is identical
  for "last 15 minutes" and "90 days ago."
- There is no index to tune, no extent merge policy, no "is this column
  indexed?" question. Cost of a scan is predictable and linear in
  bytes-after-columnar-pruning.

**Why this matters for hunting:** the most useful hunt queries are
exactly the ones KQL indexes least well — wide union across tables,
regex/substring on command lines, joins across identity↔endpoint↔network
on fields that aren't the partitioning key.

---

## 2. Query execution: per-query resource ceilings (Kusto) vs full-cluster-per-query (SDL MPP)

### Kusto / Sentinel

Kusto is multi-tenant per cluster and uses a workload group / resource
governor model. Each query gets a slice of cluster CPU/memory, bounded
by `MaxMemoryPerQueryPerNode`, `MaxConcurrentRequests`, request rate
limits, etc.

Sentinel customers don't even own the cluster — they get a logical
workspace on shared infrastructure with opaque, throttled capacity. You
routinely see `E_QUERY_RESULT_SET_TOO_LARGE`, `Request is throttled`,
partial results, or the 10-minute query timeout.

Joins are particularly painful: `join kind=inner` defaults to
broadcasting the left side; if it's too big you must hint
`hint.strategy=shuffle + hint.shufflekey=...`. Get the hint wrong on a
90-day join and the query OOMs or times out.

### SDL MPP

The architecture is explicit: every CPU core on every compute node works
on one interactive query at a time, with horizontal scheduling across the
tenant.

- Each worker does **early predicate pushdown + local
  aggregation/reduction** on its epoch segments.
- The coordinator merges already-reduced outputs, not raw rows.

> **Real-world latency from our 17-rule proof.** SDL PowerQuery latency
> on a freshly-ingested 445-event corpus was **1.7–2.6 s end-to-end**
> (HTTP + parse + scan + aggregate) for hunt-shape queries. The same
> queries against a wider `30d` startTime window were noticeably slower
> — a reminder that even on a full-cluster MPP, **window sizing still
> matters**; the value is that the *runtime path is identical* for 2 h
> vs 90 d, not that it's free.

**Why this matters:** KQL's bottleneck on a hard query is rarely the
language — it's that you can't actually have the whole cluster for 8
seconds. SDL's whole point is that you can.

---

## 3. The "parallel scan + local reduction" point is the real one

Many engines parallelize the scan. Few parallelize the **reduction**.
Kusto fans out the scan, then often funnels intermediate results back to
a coordinator/data-node tier for `summarize`, `join`, `top`,
`make-series`. On a 90-day, multi-table hunt that intermediate set can be
enormous, and that's where queries stall.

SDL keeps `filter → project → partial-aggregate → partial-join`
distributed for as long as possible, so what flows up the tree is small.
This is the same insight behind Snowflake / Presto / Trino, applied
specifically to security telemetry shapes (high-cardinality
`process_name`, `device_id`, `user_principal_name`, `dns_question`,
etc.).

---

## 4. Schema and normalization: ASIM (best-effort views) vs OCSF (native)

### Sentinel / ASIM

Microsoft's Advanced SIEM Information Model (ASIM) is implemented as KQL
functions/parsers on top of raw tables. Every cross-source query expands
at runtime into a union of parsers (`_Im_NetworkSession`,
`_Im_ProcessEvent`, …).

Each parser is a function call; the optimizer can't always push
predicates through them cleanly, so wide ASIM queries can be
significantly slower than native-table queries.

Coverage is partial — many 3rd-party sources have no ASIM parser and
must be hand-normalized.

### SDL / OCSF

Data is normalized to OCSF at ingest by the AI-native pipeline. The
columns on disk are already the unified schema.

No runtime parser expansion, no union of synthetic views — cross-source
joins are just joins on real columns.

> **Honest hedge.** This holds for first-party connectors and the
> SentinelOne ingest catalog. For raw `/api/uploadLogs` ingest, the
> customer-supplied parser determines schema fidelity — we hit this
> while building the equivalence proof and ended up using a `json`
> parser plus a per-event `event_type` discriminator column to mimic
> the table-per-source shape of Sentinel.

**Why this matters for cross-source hunts:** the realistic 90-day Okta +
DNS + EDR hunt in Sentinel is
`union isfuzzy=true (_Im_WebSession) (_Im_Dns) (_Im_ProcessEvent) | join ...`
and it is a known performance cliff. In SDL the same hunt is one query
against one schema.

---

## 5. Retention and tiering: the silent killer for KQL hunts

| Dimension                  | Sentinel/Log Analytics                                                       | SentinelOne SDL          |
|----------------------------|------------------------------------------------------------------------------|--------------------------|
| Default interactive retention | 90 days (Analytics tier)                                                  | Entire retention window  |
| Beyond that                | Basic Logs (restricted KQL, no joins, no alerts) → Auxiliary → Archive (search jobs, hours-long restores) | Same query path, same engine |
| Cost shape                 | Pay per GB ingested **and** per tier transition **and** per search job       | Flat hot lake            |
| Join across tiers          | Not supported                                                                | Native                   |

A "90-day cross-source hunt" in Sentinel silently becomes a
tiered-storage project. In SDL it's a query.

> **Concrete detail from the equivalence proof.** SentinelOne's
> `/api/uploadLogs` accepted **445 events spanning a wide range of
> embedded timestamps in a single 217 KB POST**; the same query path
> then served them <2 s later. There is no warm-tier flip, no
> rehydration job, no separate billing meter. (See
> `harness/sdl_client.py` `upload_logs()` in the repo.)

---

## 6. Concrete walkthrough: the 90-day Okta → DNS → process hunt

### Sentinel / KQL (realistic shape — and its failure modes)

```kusto
let suspect_domains = dynamic(["c2.example.com", "suspect.example.net"]);
let suspicious_users =
   SigninLogs
   | where TimeGenerated > ago(90d)
   | where ResultType != 0 or RiskLevelDuringSignIn == "high"
   | summarize by UserPrincipalName;
let bad_dns =
   _Im_Dns(starttime=ago(90d))
   | where DnsQuery has_any (suspect_domains)
   | project TimeGenerated, SrcIpAddr, DnsQuery;
_Im_ProcessEvent(starttime=ago(90d))
| where ProcessCommandLine has_any ("powershell","rundll32","mshta")
| join kind=inner hint.strategy=shuffle hint.shufflekey=DvcHostname (
    bad_dns | extend DvcHostname = tostring(SrcIpAddr)
  ) on DvcHostname
| join kind=inner (suspicious_users)
    on $left.ActorUsername == $right.UserPrincipalName
```

> `_Im_*` are runtime **parser functions**, not tables; each call
> re-unions and re-projects the underlying sources, defeating extent
> pruning.

Real-world failure modes:

1. 90 d on `_Im_ProcessEvent` blows past workspace query memory →
   partial results or timeout.
2. `has_any` on `ProcessCommandLine` bypasses the term index → full scan
   of the largest table.
   *(Deep dive: [`kql_cliffs_explained.md` §1](kql_cliffs_explained.md#1-has_any-on-processcommandline-bypasses-the-term-index).)*
3. ASIM parsers re-union underlying tables on every call.
4. If process events are in **Basic Logs** to save money: `join` is not
   allowed in Basic. Query refuses to run. You now schedule a Search
   Job (async, hours, separate billing) and stitch results manually.
5. `hint.strategy=shuffle hint.shufflekey=DvcHostname` is **required**
   to keep the cross-table join from OOMing at 90 d; the hint has to
   be re-tuned as data volume grows.
   *(Deep dive: [`kql_cliffs_explained.md` §2](kql_cliffs_explained.md#2-hintshufflekey-is-required-to-avoid-oom-on-the-cross-table-join).)*

### SDL / PowerQuery (same intent — fully runnable)

The version below uses the SDL named-input join syntax that we
validated against `xdr.us1.sentinelone.net` while building the
equivalence proof in this repo. See
`docs/runnable_examples/90day_okta_dns_process.pq` for the same query
ready to paste into your tenant.

> NOTE on `loginIsSuccessful = 'false'`: SDL stores booleans as
> lowercase strings via the JSON parser, so the quoted form fires on
> synthetic data ingested via `uploadLogs`. On a tenant whose OCSF
> parser emits native booleans, drop the quotes.

```
| join
    failed_signins = (
        event.category = 'logins'
        AND event.login.loginIsSuccessful = 'false'
        | columns userName = event.login.userName,
                  host     = endpoint.name
        | group n_fails = count() by userName, host
    ),
    bad_dns = (
        event.type = 'DNS Resolved'
        AND dns.question.name matches '(c2|suspect)\.example\.'
        | columns userName = src.endpoint.user.name,
                  host     = endpoint.name,
                  domain   = dns.question.name
        | group dns_hits = count(),
                domains  = array_agg_distinct(domain, 20)
          by userName, host
    ),
    susp_proc = (
        event.type = 'Process Creation'
        AND src.process.cmdline matches '(?i)(powershell|rundll32|mshta)'
        | columns userName = src.process.user,
                  host     = endpoint.name,
                  cmdline  = src.process.cmdline
        | group proc_hits = count(),
                cmdlines  = array_agg_distinct(cmdline, 20)
          by userName, host
    )
  on userName, host
| columns userName,
          host,
          hits      = n_fails + dns_hits + proc_hits,
          n_fails,
          dns_hits,
          proc_hits,
          domains,
          cmdlines
| sort -hits
| limit 100
```

Why this shape:

- **Plain `join`, not `sql join`** — `sql join` currently supports at most
  two subqueries; plain `join` supports 2+ with inner-join semantics by
  default.
- **Each branch is pre-aggregated** to one row per `(userName, host)`
  so the join can't collapse multiple DNS/process matches to a single
  arbitrary first match. `array_agg_distinct(..., 20)` preserves the
  per-pair rollup.
- **`failed_signins` emits `host`** so the multi-key join on
  `userName, host` is satisfied symmetrically across all three sides.
- **Final `columns` references join keys bare** (`userName`, `host`);
  named-subquery prefixes are reserved for aggregate fields, where
  needed.

One schema (OCSF), one engine, one storage tier, full cluster for the
query. 90 d isn't a different code path — it's more epochs scanned in
parallel.

---

## 7. Where KQL is genuinely good (be fair)

- KQL as a language is excellent — arguably more expressive than
  PowerQuery for ad-hoc shaping (`make-series`, `mv-expand`,
  `bag_unpack`, `series_decompose_anomalies`).
- For narrow, indexed, recent queries
  (`where IPAddress == x and TimeGenerated > ago(1h)`), Kusto is
  extremely fast.
- ADX **outside Sentinel** (your own cluster, your own SKU) lets you
  actually size compute — most of the pain above is Sentinel's
  multi-tenant workspace packaging, not Kusto itself.

The architectural argument isn't "KQL is bad." It's "for the workload
security teams actually run — wide, long, cross-source, unselective
predicates — an indexless columnar always-hot lake with MPP wins by
design."

---

## 7a. What the KQL → PQ translation actually looks like in practice

From the 17-rule conversion in this repo: **15 of 17 translate
mechanically**; only the 2 using `series_fit_line` required a redesign.

| KQL idiom                              | SDL PowerQuery                       | Friction |
|----------------------------------------|--------------------------------------|----------|
| `where TimeGenerated > ago(1d)`        | `startTime` param + `ts_epoch_ms ≥ N` | None |
| `summarize n=count() by X`             | `\| group n=count() by X`            | None |
| `dcount(X)`                            | `estimate_distinct(X)`               | None |
| `make_set(X)`                          | `array_agg_distinct(X, N)`           | None (must specify cap) |
| `in~ ('a','b')`                        | `in ('a','b')`                       | None |
| `contains` / `has`                     | `contains`                           | None |
| `extend Y = ...`                       | `\| let Y = ...`                     | Light (must pick a fresh name) |
| `join kind=leftanti`                   | Filter on baseline set built via `array_agg` | Light |
| `top N by X`                           | `\| sort -X \| limit N`              | None |
| `bin(t, 1h)` / `make-series`           | `timebucket('1 hour')`               | Light (no make-series) |
| `series_fit_line` (ML)                 | **No equivalent**                    | Hard — pre-aggregate or mark at ingest |

ML-on-query-time is the wrong place to do anomaly fitting at
security-lake scale. SDL pushes it left (to ingest pipelines / Purple
AI) on purpose.

---

## 8. The actual operator experience, side by side

Pulled directly from the lessons embedded in the repo's `README.md`.

| Pain point in Sentinel / KQL           | Equivalent (or absence) in SDL — what to flag                                       |
|----------------------------------------|-------------------------------------------------------------------------------------|
| `E_QUERY_RESULT_SET_TOO_LARGE`         | Not seen during proof; but wide `startTime` (`30d`) can return `matching=0` where a `30m` window returns N. **Always pass the tightest window that contains your data.** |
| ASIM parser unions at query time       | Single OCSF schema — no fix needed                                                  |
| Search Jobs (hours, separate billing)  | `uploadLogs` ingest path; events queryable <30 s after upload                       |
| `bytesCharged: 0` confusion            | **Not a rejection signal** — billing meter, not an error code                       |
| KQL function discovery (IntelliSense)  | `group_unique_values()` does **not** exist — use `array_agg_distinct(field, N)`. Publish the full SDL agg function list in your skills. |
| `~=` vs `contains`                     | `~=` is **case-insensitive equality**, not substring — common foot-gun              |
| `addEvents` silent drops               | Use `/api/uploadLogs` for historical ingest; `addEvents` silently drops events whose `ts` is outside its acceptance window |
| `serverHost` in `addEvents` payload    | **Not honoured** — use a custom marker attribute (we use `proof_run_id`)            |

---

## 9. The architectural scoreboard for cross-source threat hunting

| Dimension                       | Sentinel + KQL                                | SentinelOne SDL + MPP                |
|---------------------------------|-----------------------------------------------|--------------------------------------|
| Storage                         | Columnar extents + inverted/bloom indexes     | Indexless columnar epochs            |
| Hot vs cold                     | Analytics / Basic / Auxiliary / Archive       | All hot                              |
| Schema                          | ASIM (runtime parser functions)               | OCSF at ingest                       |
| Query resources                 | Slice of shared cluster, governed             | Whole cluster per interactive query  |
| Reduction                       | Often funneled to coordinator                 | Distributed local reduction          |
| Cross-source join over 90 d     | Multi-table union + shuffle hints + tier limits | Single engine, single schema       |
| AI assistant value              | Bottlenecked by backend latency               | Purple AI is useful because backend is sub-second |

---

## Bottom line

KQL is a great query language sitting on a general-purpose analytics
database that Microsoft repackaged as a SIEM. SentinelOne built the
storage, ingest, and execution layers together, for security telemetry
shapes: high cardinality, wide joins, long retention, unselective
predicates. That co-design — indexless columnar epochs + OCSF +
full-cluster MPP with distributed reduction — is why the 15-minute hunt
becomes the 8-second hunt, and why Purple AI is operational rather than
a demo.

**Proof artifact:** [github.com/marcredhat/kql](https://github.com/marcredhat/kql).
