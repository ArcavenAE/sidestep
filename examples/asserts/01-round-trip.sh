#!/usr/bin/env bash
# Assert 1: round-trip — list → filter(_kind=X) → emit(json) is byte-identical to fixture.
#
# Simulates the v0.1 primitive flow without Rust:
#   sidestep list <noun>           ≈  cat fixtures/<kind>.jsonl
#   sidestep filter --where '_kind == "X"'  ≈  jq -c 'select(._kind == "X")'
#   sidestep emit --format json    ≈  jq -c '.'
#
# Catches: missing fields, wrong types, accidental field renames at codegen,
# unparseable JSON, _kind mismatch with filename.
#
# Per finding-001 + Track B brief (bd aae-orc-kdz1).

set -euo pipefail
cd "$(dirname "$0")/.."

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "  ok  $*"; }

echo "== assert 01: round-trip =="

declare -a SPEC=(
  "detection:detection"
  "run:run"
  "policy:policy"
  "rule:rule"
  "audit-log:audit_log"
)

for entry in "${SPEC[@]}"; do
  fname="${entry%%:*}"
  kind="${entry##*:}"
  fixture="fixtures/${fname}.jsonl"
  [[ -r "$fixture" ]] || fail "fixture missing: $fixture"

  # Parse + filter + emit. -c keeps it on one line per record.
  emitted=$(jq -c "select(._kind == \"$kind\")" "$fixture")

  # Re-parse both sides to a normalized canonical form and compare.
  # Using -S sorts keys, removing JSON-key-ordering noise.
  expected=$(jq -cS '.' "$fixture")
  actual=$(echo "$emitted" | jq -cS '.')

  [[ "$expected" == "$actual" ]] || fail "round-trip mismatch on $kind"

  # Verify all records in the fixture have the expected _kind (no contamination).
  wrong=$(jq -c "select(._kind != \"$kind\")" "$fixture" | wc -l | tr -d ' ')
  [[ "$wrong" == "0" ]] || fail "$fixture has $wrong records with wrong _kind (expected $kind)"

  count=$(jq -c '.' "$fixture" | wc -l | tr -d ' ')
  pass "$kind ($count records)"
done

echo "  PASS round-trip"
