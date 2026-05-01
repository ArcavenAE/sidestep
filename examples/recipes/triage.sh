#!/usr/bin/env bash
# Recipe: triage <noun>
#
# v0.2 composite shape:
#
#   sidestep triage detections --policy critical-first
#     ≈
#   sidestep list detections \
#     | sidestep enrich --with severity-roll-up \
#     | sidestep filter --where 'severity in ["critical","high"] && status == "open"' \
#     | sidestep rank --by 'severity desc, created_at desc' \
#     | sidestep emit --format table
#
# Difference from inventory: the filter policy is opinionated
# ("critical-first" = severity ≥ high && open). v0.2 sugar will let
# users name the policy; v0.1 they write the CEL inline.
#
# Status: WORKS — same primitives as inventory.sh, narrower predicate.

set -euo pipefail
cd "$(dirname "$0")/.."

echo "== triage detections (critical-first policy) =="

cat fixtures/detection.jsonl \
  | jq -c 'select(._kind == "detection")' \
  | jq -c 'select((.severity == "critical" or .severity == "high") and .status == "open")' \
  | jq -c '. + {_sev_rank: ({"critical":4,"high":3,"medium":2,"low":1,"info":0}[.severity] // -1)}' \
  | jq -s -c 'sort_by([-._sev_rank, (.created_at | -fromdateiso8601)]) | .[]' \
  | jq -c 'del(._sev_rank)' \
  | jq -r '"\(.severity | ascii_upcase)\t\(.repo.owner)/\(.repo.name)\t\(.workflow_path)\t\(.detection_pattern)"'
