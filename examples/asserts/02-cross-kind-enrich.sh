#!/usr/bin/env bash
# Assert 2: cross-kind enrich — get policy P → enrich(rules) → filter(_kind=rule)
# finds the rules.
#
# Simulates the enrichment seam where one kind's records reference another's:
#   sidestep get policy pol_001                ≈  jq 'select(.id == "pol_001")'
#   sidestep enrich --with rules               ≈  jq inner-join on policy_id
#   sidestep filter --where '_kind == "rule"'  ≈  jq 'select(._kind == "rule")'
#
# This is the foreign-key shape problem — schemas usually fail silently when
# join keys don't match. Per finding-001 + Murat's 3-asserts spec.

set -euo pipefail
cd "$(dirname "$0")/.."

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "  ok  $*"; }

echo "== assert 02: cross-kind enrich =="

# Case A: pol_001 has 3 rules (rule_001, rule_003, rule_004).
policy_id="pol_001"
expected_rule_count=3

# "get policy" — find the policy by id
policy=$(jq -c "select(.id == \"$policy_id\")" fixtures/policy.jsonl)
[[ -n "$policy" ]] || fail "policy $policy_id not found in fixtures"

# "enrich --with rules" — for the policy in scope, emit rules whose
# policy_id matches. The semantic: enrichment produces a stream where each
# rule record carries the policy context.
rules=$(jq -c --arg pid "$policy_id" 'select(._kind == "rule" and .policy_id == $pid)' fixtures/rule.jsonl)
actual_rule_count=$(echo "$rules" | grep -c . || true)

[[ "$actual_rule_count" == "$expected_rule_count" ]] \
  || fail "expected $expected_rule_count rules for $policy_id, got $actual_rule_count"
pass "$policy_id has $actual_rule_count rules (rule_001, rule_003, rule_004)"

# Case B: pol_002 has 1 rule (rule_002).
policy_id="pol_002"
expected_rule_count=1
actual_rule_count=$(jq -c --arg pid "$policy_id" 'select(._kind == "rule" and .policy_id == $pid)' fixtures/rule.jsonl | grep -c . || true)
[[ "$actual_rule_count" == "$expected_rule_count" ]] \
  || fail "expected $expected_rule_count rules for $policy_id, got $actual_rule_count"
pass "$policy_id has $actual_rule_count rule (rule_002)"

# Case C: pol_003 has 0 rules (orphan policy, exercises empty-set semantics).
policy_id="pol_003"
expected_rule_count=0
actual_rule_count=$(jq -c --arg pid "$policy_id" 'select(._kind == "rule" and .policy_id == $pid)' fixtures/rule.jsonl | grep -c . || true)
[[ "$actual_rule_count" == "$expected_rule_count" ]] \
  || fail "expected $expected_rule_count rules for $policy_id, got $actual_rule_count"
pass "$policy_id has $actual_rule_count rules (orphan policy)"

# Case D: rule_005 is an orphan rule (policy_id pol_999 doesn't exist).
# This catches the inverse: enrichment that walks rules → policies should
# surface orphans, not silently drop them.
orphan=$(jq -c 'select(._kind == "rule" and .id == "rule_005")' fixtures/rule.jsonl)
[[ -n "$orphan" ]] || fail "orphan rule_005 not found"
parent_exists=$(jq -c --slurpfile rules <(echo "$orphan") '
  ._kind == "policy" and .id == ($rules | .[0].policy_id)
' fixtures/policy.jsonl | grep -c '^true$' || true)
[[ "$parent_exists" == "0" ]] || fail "rule_005 should be orphan (parent pol_999 should not exist)"
pass "rule_005 correctly identified as orphan (parent pol_999 absent)"

echo "  PASS cross-kind enrich"
