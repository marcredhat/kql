#!/usr/bin/env bash
# Make every PowerQuery under pq/ and docs/runnable_examples/ return at
# least one row when run for startTime=2h on the live SDL tenant.
#
# Pipeline:
#   1. regenerate deterministic sample data (anchored to NOW)
#   2. export pq/*.pq with fresh RECENT_MS substituted
#   3. ingest pq/ dataset + run each rule PQ scoped by proof_run_id
#   4. seed synthetic OCSF events for docs/runnable_examples/*.pq
#   5. run every .pq in both dirs WITHOUT run_id scoping, assert matching>0
#
# Exits non-zero if any .pq returns zero matching events.

set -euo pipefail
cd "$(dirname "$0")"

banner() {
    printf '\n==================================================================\n'
    printf '%s\n' "$1"
    printf '==================================================================\n'
}

banner "Step 1/5  Regenerate deterministic sample dataset"
python3 sample_data/generate.py

banner "Step 2/5  Export pq/*.pq with fresh RECENT_MS"
python3 harness/export_rules.py

banner "Step 3/5  Ingest rule sample data + run rule PQs (scoped)"
python3 harness/prove_equivalence.py --ingest --pq

banner "Step 4/5  Seed synthetic OCSF events for runnable examples"
python3 harness/seed_runnable_examples.py

banner "Step 5/5  Run every .pq for startTime=2h and assert matching>0"
python3 harness/run_all_pq.py
