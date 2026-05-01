#!/usr/bin/env bash
# Recipe: orient
#
# v0.2 composite shape — the 30-second "where do I stand on security
# right now" rollup. Multi-source: walks several primary nouns, counts
# by status/severity, surfaces top-N for each.
#
#   sidestep orient
#     ≈
#   parallel:
#     sidestep list detections | sidestep filter ... | count
#     sidestep list policies   | sidestep filter ... | count
#     sidestep list incidents  | sidestep filter ... | count
#   then assemble into a dashboard-shaped emit
#
# This recipe surfaces a real gap: **count/aggregate is not a v0.1
# primitive.** v0.1 primitives transform streams; they don't summarize
# them. In a shell pipeline that's `wc -l` or `jq 'length'`, which
# works but isn't a sidestep verb. The Rust impl could grow:
#   - emit --format summary  (an output mode that aggregates)
#   - count primitive        (rank's cousin, returns a single record)
#   - or leave aggregation to the shell (wc -l, jq 'length')
#
# Status: BENDS — the recipe runs (using shell aggregation), but the
# composition isn't pure-primitive. Not a missing primitive in the
# strict sense, but a v0.2 design question worth filing.

set -euo pipefail
cd "$(dirname "$0")/.."

count_kind_pred() {
  # cat fixture | filter _kind=$1 | filter $2 | count
  local fixture="$1"; local pred="$2"
  jq -c "select($pred)" "$fixture" | grep -c . || echo 0
}

open_critical=$(count_kind_pred fixtures/detection.jsonl '._kind == "detection" and .status == "open" and .severity == "critical"')
open_high=$(count_kind_pred fixtures/detection.jsonl     '._kind == "detection" and .status == "open" and .severity == "high"')
open_total=$(count_kind_pred fixtures/detection.jsonl    '._kind == "detection" and .status == "open"')
suppressed=$(count_kind_pred fixtures/detection.jsonl    '._kind == "detection" and .status == "suppressed"')
orphan_policies=$(count_kind_pred fixtures/policy.jsonl  '._kind == "policy" and (.attached_repos | length) == 0')
stale_policies=$(count_kind_pred fixtures/policy.jsonl   '._kind == "policy" and .last_evaluated_at == null')
runs_failed=$(count_kind_pred fixtures/run.jsonl         '._kind == "run" and .status == "failed"')

cat <<EOF
== orient: where do I stand =========================
detections (open):       $open_total  (critical: $open_critical, high: $open_high)
detections (suppressed): $suppressed
policies (orphan):       $orphan_policies   (attached to 0 repos)
policies (stale):        $stale_policies   (never evaluated)
runs (failed):           $runs_failed
=====================================================
EOF
