#!/usr/bin/env bash
# Assert 3: rank-stability — sort by severity desc, then by ts (created_at) desc,
# is byte-identical across two runs.
#
# Simulates the rank primitive (deferred to v0.2 per finding-001 / bd
# aae-orc-emap, but the SORT itself is what we're testing here):
#   sidestep rank --by 'severity desc, created_at desc'
#     ≈  jq | sort_by([severity_int, ts]) | reverse
#
# Catches: under-specified sort keys, non-deterministic ordering on ties,
# severity-enum ordering ambiguity (must be defined explicitly, not lexical).
#
# Severity ordering (closed enum, must be explicit):
#   critical=4, high=3, medium=2, low=1, info=0

set -euo pipefail
cd "$(dirname "$0")/.."

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "  ok  $*"; }

echo "== assert 03: rank-stability =="

rank_detections() {
  jq -c 'select(._kind == "detection")
    | . + {_sev_rank: ({"critical":4,"high":3,"medium":2,"low":1,"info":0}[.severity] // -1)}
    ' fixtures/detection.jsonl \
    | jq -s -c 'sort_by([-._sev_rank, (.created_at | -fromdateiso8601)]) | .[]' \
    | jq -c 'del(._sev_rank)'
}

# Run twice, compare.
out1=$(rank_detections)
out2=$(rank_detections)

[[ "$out1" == "$out2" ]] || fail "rank output non-deterministic across two runs"
pass "ranking deterministic across two runs"

# Verify rank is correct: top record is critical, bottom is info.
top_severity=$(echo "$out1" | head -1 | jq -r '.severity')
bot_severity=$(echo "$out1" | tail -1 | jq -r '.severity')
[[ "$top_severity" == "critical" ]] || fail "top record should be critical, got $top_severity"
[[ "$bot_severity" == "info" ]] || fail "bottom record should be info, got $bot_severity"
pass "severity ordering: critical first, info last"

# Verify within-severity tiebreak by ts desc — det_002 (high, 2026-04-30) should
# come before any other high-or-lower-severity record. Our fixtures have one
# record per severity level, so this is a degenerate test. Add a manual case:
# inject two synthetic high-severity records with different timestamps and
# verify newer one comes first.
synth=$(jq -c '. | .[] | select(._kind == "detection") | .severity = "high"' <<EOF
[
  {"_kind":"detection","id":"synth_1","severity":"high","created_at":"2026-04-01T00:00:00Z","_source":{"operation_id":"synth","response_index":0,"fetched_at":"2026-04-30T10:00:00Z"},"status":"open","repo":{"owner":"x","name":"y"},"workflow_path":".github/workflows/x.yml","action_ref":null,"run_id":"r","detection_pattern":"p"},
  {"_kind":"detection","id":"synth_2","severity":"high","created_at":"2026-04-29T00:00:00Z","_source":{"operation_id":"synth","response_index":1,"fetched_at":"2026-04-30T10:00:00Z"},"status":"open","repo":{"owner":"x","name":"y"},"workflow_path":".github/workflows/x.yml","action_ref":null,"run_id":"r","detection_pattern":"p"}
]
EOF
)

ranked_synth=$(echo "$synth" \
  | jq -c '. + {_sev_rank: ({"critical":4,"high":3,"medium":2,"low":1,"info":0}[.severity] // -1)}' \
  | jq -s -c 'sort_by([-._sev_rank, (.created_at | -fromdateiso8601)]) | .[]' \
  | jq -c 'del(._sev_rank)')

first_id=$(echo "$ranked_synth" | head -1 | jq -r '.id')
[[ "$first_id" == "synth_2" ]] || fail "newer high-severity record should rank first, got $first_id"
pass "tiebreak by created_at desc within same severity"

echo "  PASS rank-stability"
