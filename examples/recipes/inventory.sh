#!/usr/bin/env bash
# Recipe: inventory <noun>
#
# v0.2 composite shape:
#
#   sidestep inventory detections
#     ≈
#   sidestep list detections \
#     | sidestep enrich --with severity-roll-up \
#     | sidestep filter --where 'status == "open"' \
#     | sidestep rank --by 'severity desc, created_at desc' \
#     | sidestep emit --format table
#
# Result: a deep enumeration of the noun, enriched with the
# information the v0.1 user wants to see, ranked deterministically.
# This is what the WebUI cannot export cleanly.
#
# Primitives used: list, enrich (skipped here, no enrichment fixture
# yet), filter, rank, emit. All present in v0.1.
#
# Status: WORKS — composable in 4 pipes from primitives we ship.

set -euo pipefail
cd "$(dirname "$0")/.."

echo "== inventory detections (open, ranked by severity) =="

# list detections (simulated: cat fixture)
cat fixtures/detection.jsonl \
  | jq -c 'select(._kind == "detection")' \
  | jq -c 'select(.status == "open")' \
  | jq -c '. + {_sev_rank: ({"critical":4,"high":3,"medium":2,"low":1,"info":0}[.severity] // -1)}' \
  | jq -s -c 'sort_by([-._sev_rank, (.created_at | -fromdateiso8601)]) | .[]' \
  | jq -c 'del(._sev_rank)' \
  | jq -r '"\(.severity | ascii_upcase)\t\(.repo.owner)/\(.repo.name)\t\(.workflow_path)\t\(.detection_pattern)"'
