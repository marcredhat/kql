#!/usr/bin/env bash
# End-to-end proof: regenerate sample data, export pretty .pq files,
# verify each .pq runs cleanly on SDL as-written, ingest to SDL, run
# every PowerQuery against SDL, and compare against the Python reference.
set -euo pipefail

cd "$(dirname "$0")"

echo "=================================================================="
echo "STEP 1/5  Regenerate deterministic sample dataset"
echo "=================================================================="
python3 -u sample_data/generate.py

echo
echo "=================================================================="
echo "STEP 2/5  Export KQL and PowerQuery files (with anti-pattern scan)"
echo "=================================================================="
python3 -u harness/export_rules.py
echo "KQL files:"; ls -1 kql/ | sed 's/^/  /'
echo "PQ  files:"; ls -1 pq/  | sed 's/^/  /'

echo
echo "=================================================================="
echo "STEP 3/5  Ingest sample dataset to SDL + execute PowerQueries"
echo "=================================================================="
python3 -u harness/prove_equivalence.py --ingest --pq

echo
echo "=================================================================="
echo "STEP 4/5  Side-by-side comparison summary"
echo "=================================================================="
python3 -u harness/summarise.py

echo
echo "=================================================================="
echo "STEP 5/5  Verify each pq/*.pq runs cleanly on SDL as-written"
echo "          (proof that pasted-as-is queries return status=success)"
echo "=================================================================="
python3 -u harness/verify_pq_runs.py
