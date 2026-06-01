# Two Kusto performance cliffs explained

Companion deep-dive to [`MPP_vs_KQL.md`](MPP_vs_KQL.md) §6. Two phrases in
the annotated KQL block point at real, well-known performance cliffs that
deserve their own explanation rather than a footnote:

1. `has_any on ProcessCommandLine bypasses the term index`
2. `hint.shufflekey is required to avoid OOM on the cross-table join`

---

## 1. `has_any` on `ProcessCommandLine` bypasses the term index

### What the term index actually does

Kusto builds a **per-shard inverted term index** on string columns. At
ingest time each string value is tokenized into "terms" using a fixed
tokenizer that splits on non-alphanumeric ASCII (whitespace,
punctuation, `\`, `/`, `.`, `-`, etc.) and lowercases. The resulting
tokens are written to the shard's inverted index alongside the columnar
data.

When you write `where Col has "x"`, Kusto:

1. Tokenizes `"x"` the **same way** the indexer did at ingest.
2. Looks up the resulting term in the shard's inverted index.
3. Reads **only the rows in shards whose index says "this term might be
   present here"** — entire shards get skipped.

This is the difference between a 50 ms hunt and a 5-minute one.

### Why `has_any` on `ProcessCommandLine` falls out of that fast path

Three independent reasons compound:

**a) The needle contains characters that the tokenizer treats as separators.**

`ProcessCommandLine` values look like:

```
"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -nop -w hidden -enc JABzAD0A...
```

If you write `has_any ("powershell.exe", "rundll32.exe")` you're not
searching for one token — `powershell.exe` is the **two tokens**
`powershell` and `exe` joined by a `.` (a separator). The index never
stored `powershell.exe` as a single term, so the lookup misses and Kusto
falls back to a row scan.

Quick fix: search for the bare token (`has_any ("powershell", "rundll32")`)
— Kusto's planner will index-prune on each individual token. But
analysts almost never write it that way because they're thinking "the
binary is `powershell.exe`."

**b) `has_any` blows past the term-index cardinality threshold.**

For each candidate term in the `has_any` list, Kusto has to consult the
inverted index, accumulate row-id sets, then union them. The query
optimizer has an internal threshold: above some number of needles (or
above some estimated selectivity), it gives up on index lookups and
just scans, because the OR-merge of many indexed lookups costs more
than the scan would.

The exact threshold is undocumented and changes between versions;
empirically it kicks in fast on `ProcessCommandLine` because that column
has the highest term cardinality in the schema — most of those terms
are unique GUIDs, paths, base64 blobs, hashes, etc. — so the inverted
index is huge and per-term lookup is expensive.

**c) `ProcessCommandLine` itself blows up the indexer's effectiveness.**

Even when you do hit the index, the **selectivity** is terrible. A term
like `powershell` matches a large fraction of all process-creation rows
on a typical workstation fleet. The index tells Kusto "this shard might
contain it" — but every shard *does* contain it, so no shards get
pruned. You still scan everything.

This is the deepest reason of the three: even a perfectly written,
single-token, indexed `has` query on `ProcessCommandLine` gives you the
*index path's CPU cost* on top of *the scan you were going to do anyway*.

### The escape hatch most people don't know about

If you must do this in KQL, push the substring match into a `where`
clause that the planner can convert into a true scan-with-early-exit,
and pre-narrow with something that *is* selective:

```kusto
SecurityEvent
| where TimeGenerated > ago(1h)        // narrow time first — selective
| where EventID == 4688                 // narrow event-id — selective
| where ProcessCommandLine matches regex @"(?i)powershell|rundll32|mshta"
```

Two hours of data and an `EventID` filter is usually enough that the
scan-after-prune is cheap. **At 90 days with no narrowing predicate,
you've lost.** That's the cliff the doc refers to.

### What SDL does instead

No index, so no "did I hit the index?" cliff. Every query is a columnar
scan over the epochs that overlap the time window, with column-level
prefix pruning and run-length compression doing the heavy lifting.
`matches "(powershell|rundll32|mshta)"` on `src.process.cmdline` at 90
days is the same code path as at 1 hour — just more epochs in parallel.

---

## 2. `hint.shufflekey` is required to avoid OOM on the cross-table join

### How Kusto's distributed join works by default

Kusto is distributed. Tables are split into extents (shards), and
extents live on different data nodes. When you write:

```kusto
A | join kind=inner B on Key
```

Kusto picks one of two physical strategies:

- **Broadcast** (the default for "small × large"): take the smaller
  side, replicate it to every node holding the larger side, then do
  local hash joins. Fast when small really is small.
- **Shuffle**: hash both sides on `Key`, send all rows with hash bucket
  *i* to node *i*, then do local hash joins. Needed when both sides are
  big.

The planner chooses based on a **statistics estimate** of how big each
side is *after* the upstream `where` filters apply.

### Where the OOM comes from

For a 90-day cross-source hunt the planner's estimate is almost always
wrong:

1. `bad_dns` after the `has_any (suspect_domains)` filter is **probably**
   small — but if the IOC list has 200 entries or a wildcard sneaks in,
   it can be millions of rows.
2. The planner picks **broadcast** because it estimates `bad_dns` is
   small.
3. At runtime, `bad_dns` turns out to be huge.
4. Kusto tries to ship the entire `bad_dns` payload to every node
   holding `_Im_ProcessEvent` extents (which at 90 d is **every node**).
5. Each node tries to hold the broadcasted copy in memory while
   streaming `_Im_ProcessEvent` past it.
6. `MaxMemoryPerQueryPerNode` (a tenant-level resource governor knob;
   on Sentinel it's a shared, opaque value) gets hit.
7. You get `Request was aborted due to exceeding query memory limits`
   — or worse, partial results with no warning.

The same shape, with a left side just under the broadcast limit, OOMs
intermittently as data volume grows day to day. That's the "silent
regression" that makes 90-day Sentinel hunts unreliable in production.

### What `hint.shufflekey` does

```kusto
A | join kind=inner hint.strategy=shuffle hint.shufflekey=Key (B) on Key
```

You override the planner's estimate and force the shuffle strategy on
`Key`. Both sides get re-hashed by `Key`, sent across the network into
hash buckets, joined locally. No node has to hold all of either side —
each node holds only **its bucket's slice**, so memory grows linearly
with cluster size instead of quadratically with data size.

### Why this is a footgun

1. **You have to know to use it.** The default broadcast looks fine on
   a 1-day window and silently breaks at 90 days.
2. **You have to pick the right key.** If `hint.shufflekey` is something
   with high skew (e.g. one user has 95% of the events), one node still
   OOMs while the others sit idle. You'd then add `hint.num_partitions=N`
   and tune it. Production hunts often have 3+ hints stacked just to
   keep them stable.
3. **You can't compose well.** Two joins in the same query each need
   their own carefully chosen shuffle key. Get one wrong and the second
   join breaks.
4. **The hints are advisory, not contractual.** A future Kusto version
   may ignore your hint if its own cost model thinks broadcast is
   better. Sentinel's update cadence means a query stable today can
   regress on a Tuesday with no warning.

### What SDL does instead

The reduction is distributed **by construction** — there is no
broadcast vs shuffle planner because the engine never moves un-reduced
rows across the network. Each worker filters → projects →
partial-aggregates → partial-joins on its local epochs and sends only
the reduced state up to the coordinator. The 90-day join in the SDL
example in [`MPP_vs_KQL.md`](MPP_vs_KQL.md) §6 needs **zero hints**:
the joiner doesn't need to estimate sizes because it never decides to
broadcast.

---

## TL;DR sentences (drop-in for sidebars)

> **`has_any` cliff.** Kusto's term index tokenizes string columns at
> ingest. `has_any` on `ProcessCommandLine` defeats it three ways at
> once: the needles often contain separator characters (so the indexed
> terms don't match), the OR-merge of many needles exceeds the
> planner's index-vs-scan threshold, and `ProcessCommandLine` has such
> a long-tail term distribution that index lookups rarely prune shards
> anyway. At 90 d the scan that results is the largest single column
> scan in the workspace.

> **`hint.shufflekey` cliff.** Kusto's join planner picks broadcast vs
> shuffle from an estimated cardinality. On a 90-day cross-source hunt
> the estimate is almost always wrong, the planner picks broadcast, and
> the smaller side turns out to be tens of millions of rows. Without
> `hint.strategy=shuffle hint.shufflekey=...` the query OOMs against
> `MaxMemoryPerQueryPerNode`. The hint is required for stability and
> has to be re-tuned per query and per data-volume change — a
> maintenance tax SDL's distributed-reduction engine doesn't impose.
