#!/usr/bin/env bash
# Recipe: verify <plan-file>
#
# v0.2 composite shape — given a prior plan (stream of ActionItem ids
# + targets), re-fetch current state and report which items are FIXED
# (no longer present), STILL-OPEN, or NEW (not in plan).
#
#   sidestep verify exposure-2026-04-25.md
#     ≈
#   sidestep list detections | sidestep filter ... | sidestep enrich ... | (assemble ActionItems)
#     |> diff against the prior plan's ActionItem ids
#     |> emit --format markdown
#
# This recipe surfaces the **strongest missing-primitive signal in
# Track C**: there is no v0.1 primitive for SET DIFFERENCE on streams.
# verify needs to compute:
#   - prior_set ∩ current_set    = still-open
#   - prior_set \ current_set    = fixed
#   - current_set \ prior_set    = new
#
# None of {list, get, search, enrich, filter, rank, emit} composes to
# a set diff. You can simulate it in shell (comm, diff, awk, jq with
# slurpfile) but the recipe is *not* primitive-pure.
#
# Cousin recipe: changed-pinning.sh. Same diff need.
#
# Conclusion: file `diff` as a v0.2 primitive (cousin to rank, replay,
# act in finding-001's deferred set). See the new bd ticket filed
# alongside Track C closure.
#
# Status: BREAKS without `diff` primitive. Below is a shell-glue
# simulation that proves the workflow is real and frequently needed,
# while making the missing-primitive case concrete.

set -euo pipefail
cd "$(dirname "$0")/.."

# Synthesize a "prior plan" from a previous run — for the demo, three
# detection ids that were "open" in a prior snapshot. In real verify,
# this would be parsed out of the plan markdown / json that emit
# produced last week.
prior_open_ids=(det_001 det_002 det_003)

# "current state" — list detections, filter open, project ids
current_open_ids=$(jq -r 'select(._kind == "detection" and .status == "open") | .id' fixtures/detection.jsonl | sort)

# DIFF (the missing primitive — done in shell here):
prior_sorted=$(printf "%s\n" "${prior_open_ids[@]}" | sort)
fixed=$(comm -23 <(echo "$prior_sorted") <(echo "$current_open_ids"))
still_open=$(comm -12 <(echo "$prior_sorted") <(echo "$current_open_ids"))
newly_open=$(comm -13 <(echo "$prior_sorted") <(echo "$current_open_ids"))

cat <<EOF
== verify: prior plan vs current state =====================
prior plan items:       ${#prior_open_ids[@]}
still open (carry):     $(echo "$still_open" | grep -c . || echo 0)  [$(echo "$still_open" | tr '\n' ' ')]
fixed since last run:   $(echo "$fixed"      | grep -c . || echo 0)  [$(echo "$fixed"      | tr '\n' ' ')]
newly open (not in plan): $(echo "$newly_open" | grep -c . || echo 0)  [$(echo "$newly_open" | tr '\n' ' ')]
============================================================

NOTE: this recipe required shell-glue (comm) for the diff step. The
primitive set as designed in v0.1 cannot express set difference over
two streams. See the bd ticket for diff primitive (filed alongside
Track C closure).
EOF
