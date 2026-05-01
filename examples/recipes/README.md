# sidestep recipes

Track C deliverable (bd `aae-orc-ldq1`) — recipe sketches that
validate the v0.1 primitive set composes into the v0.2 composites
the user wants. Per finding-001: composites (`inventory`, `triage`,
`orient`, `verify`) emerge as v0.2 sugar over the primitives shipped
in v0.1; Track C is the validation that the primitives are sufficient.

## The five recipes

| Recipe | Status | What it does | Notes |
|---|---|---|---|
| `inventory.sh` | ✓ works | List + filter + rank + emit a deep enumeration of one noun | Pure primitive composition |
| `triage.sh` | ✓ works | Same as inventory with an opinionated filter ("critical-first") | Pure primitive composition |
| `orient.sh` | ⚠ bends | Multi-source rollup ("where do I stand on security right now") | Uses shell-level count; aggregation is not a v0.1 primitive |
| `verify.sh` | ✗ breaks | Compare prior plan vs current state (still-open / fixed / new) | Demands `diff` primitive |
| `changed-pinning.sh` | ✗ breaks | Action drift detection week-over-week (deliberate failing recipe per Winston) | Demands `diff` + temporal access (replay) |

Run each: `bash examples/recipes/<name>.sh`.

Or run all: `for r in examples/recipes/*.sh; do bash "$r"; done`.

## Findings

### 1. `diff` is the missing v0.2 primitive

Both `verify.sh` and `changed-pinning.sh` demand set difference over
two streams keyed on a tuple. Neither composes from {list, get,
search, enrich, filter, rank, emit}. Filed as **bd `aae-orc-08gd`**
alongside Track C closure.

This is the strongest "≤1 missing primitive" signal Track C produced
— two distinct, real composite recipes blocked on the same primitive.
That's the bar Winston's failing-recipe technique was designed to
surface.

### 2. `orient` bends but doesn't break

`orient.sh` works, but the count/aggregate step is shell-level
(`grep -c .`), not a sidestep primitive. Three v0.2 candidate
resolutions:

- `emit --format summary`: an output mode that aggregates rather than
  rendering each record. Simplest. Doesn't require a new primitive.
- `count` primitive: rank's cousin, returns a single record with
  totals and breakdowns. Symmetric with rank.
- Leave aggregation to the shell: `wc -l`, `jq 'length'`. Honest but
  ugly.

Not filing a separate ticket — the v0.2 sugar layer (bd
`aae-orc-vjc6`) will surface the right answer from audit-trail
evidence about how users actually compose orient flows.

### 3. Temporal access composes through `replay`

`changed-pinning.sh` needs to read state "as of last week" to compare
against current. The audit trail's `shape_hash` field (B4 +
finding-001) was designed to make this addressable: historical
`list workflows` calls emit lines with `shape_hash` matching today's
call structure, so `replay <trace_id-from-7d-ago>` surfaces them.

`replay` is already filed as **bd `aae-orc-jsai`** (Carson's A-grade
trail primitive). Track C confirms it's not optional — at least one
real recipe (changed-pinning) demands it.

### 4. The four working composites map cleanly

Per the brief's success criterion ("4 read naturally"):

- `inventory.sh`: `list | filter | rank | emit` — 4-pipe pipeline
- `triage.sh`: same shape, narrower predicate
- `orient.sh`: 7 short pipelines (one per stat) glued by shell;
  works, isn't pretty
- `verify.sh`: 2 pipelines (current state, prior plan) plus shell
  diff; works once `diff` ships

Three of four read as kubectl-shaped pipelines. `orient` is the
outlier and the v0.2 sugar layer will smooth it.

## What this means for v0.1 ship

The v0.1 primitive set (6 primitives + `api` peer) is **sufficient
for inventory and triage flows** — the highest-volume use cases. It
is **insufficient for verify and time-travel flows**, which gate on
`diff` (aae-orc-08gd) and `replay` (aae-orc-jsai), both v0.2.

Acceptance criterion (John, finding-001): "v0.1 is done when an agent
or operator runs a sidestep pipeline against a live tenant, gets a
structured stream, filters+ranks with CEL, and emits a Jira-ready or
PR-ready artifact end-to-end with audit trail proving every API
call." This is the inventory/triage path, which Track C confirms
v0.1 primitives serve cleanly.

## Cross-references

- Brief: `_kos/probes/brief-primitive-layer-v01.md`
- Finding: `_kos/findings/finding-001-primitives-over-composites.md`
- Bedrock: `elem-primitives-over-composites`, `elem-action-item-schema`
- Track A: `docs/research/action-item-schema.md` (5-field shape)
- Track B: `examples/{fixtures,asserts}/` (regression contract)
- bd: `aae-orc-lyeh` (umbrella, ready to start), `aae-orc-08gd`
  (diff primitive, v0.2), `aae-orc-jsai` (replay primitive, v0.2)
