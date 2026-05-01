#!/usr/bin/env bash
# Recipe: changed-pinning  (the deliberate failing recipe)
#
# Per Winston's Track C addition (finding-001): pick something a
# security engineer would plausibly want that you suspect the
# primitives can't express cleanly. Negative results sharpen the
# boundary faster than positive ones.
#
# Goal: "show me actions whose pinning status changed between last
# week and this week." The kind of question a security engineer asks
# after a tj-actions-style supply-chain attack — *who's drifting*,
# not just *who's vulnerable now*.
#
# v0.2 composite shape (the version we WISH we could write):
#
#   sidestep changed-pinning --since 7d
#     ≈
#   sidestep list workflows --as-of 'now-7d' \
#     | sidestep enrich --with maintained-actions \
#     | sidestep tee /tmp/baseline.jsonl \
#     ;
#   sidestep list workflows \
#     | sidestep enrich --with maintained-actions \
#     | sidestep diff /tmp/baseline.jsonl --on '(action_ref, pinned_status)' \
#     | sidestep emit --format markdown
#
# Two missing primitives surface here:
#
#   1. **`diff`** — set-difference / change-detection over two streams
#      keyed on a tuple of fields. (Same primitive verify.sh demands.)
#   2. **temporal lookups** — `list ... --as-of <time>` requires either
#      a fact-base substrate (Carson's v0.3 stress-test pick) OR
#      `replay <trace_id>` (bd aae-orc-jsai) over a stored audit-trail
#      snapshot. The audit trail HAS the raw data; v0.1 primitives
#      have no read path INTO the trail (replay is v0.2).
#
# Status: BREAKS — needs `diff` AND a way to access prior state.
# The verify.sh recipe also demands `diff`, so `diff` is the
# strongest single missing-primitive signal from Track C.
# Temporal access is satisfied indirectly by replay (already filed
# as aae-orc-jsai).
#
# Conclusion (this recipe's contribution): file `diff` as a v0.2
# primitive ticket. This is the "≤1 missing primitive" outcome the
# brief hoped for — and notably the SAME primitive that verify
# demands, so we get two real composites for one ticket.

set -euo pipefail
cd "$(dirname "$0")/.."

cat <<'EOF'
== changed-pinning: BREAKS in v0.1 =============================

This recipe cannot be expressed in v0.1 primitives. It needs:

  1. `diff` primitive (set difference / change detection over two
     streams keyed on a tuple). Also needed by verify.sh.

  2. Temporal access to prior state — either:
     a. `replay <trace_id>` (bd aae-orc-jsai, already filed for v0.2),
        which reads from the audit trail without re-fetching, or
     b. fact-base substrate (Carson's v0.3 stress-test pick — local
        SQLite/Dolt accumulating prior states for time-travel queries).

The audit trail's `shape_hash` field (B4 + finding-001) was DESIGNED
to support this — historical `list workflows` calls emit lines with
shape_hash matching today's call, and replay surfaces them. Track C's
job is to verify the primitives compose; this recipe correctly does
not compose, by design.

Recommended action: file `aae-orc-<new>` for the `diff` primitive
alongside Track C closure. Replay (aae-orc-jsai) is already deferred.

================================================================
EOF
