---
id: finding-006
type: finding
date: 2026-05-02
session: session-044
title: "v0.1 primitive layer shipped — five-slice ship trace + caveats + deferred items"
related_nodes:
  - elem-primitives-over-composites
  - elem-audit-trail-schema
related_findings:
  - finding-001-primitives-over-composites
extracted_session: session-049
extracted_at: "2026-05-13"
---

# finding-006: v0.1 primitive layer shipped

## Summary

The v0.1 verb surface from finding-001 (`elem-primitives-over-composites`)
is implemented and on `main`. Five slices, each its own commit, each
green at all gates (clippy + deny + 98 tests + Track B shell asserts).

This finding captures the slice-by-slice ship trace, the caveats
discovered during shipping, and the v0.2-deferred items — content
previously inlined in charter B7 prose, extracted per orc finding-047.

## The five ship slices

### Slice 1 — `da6d220` (stream contract + 9-kind table + list + emit)

- Stream contract: `_kind`-tagged JSONL is the text that primitives
  compose over
- 9-kind table: rule, finding, policy, alert, repo, workflow_run,
  workflow_run_event, action_lock, scan_run
- `list <kind>`: produces a stream of `_kind`-tagged JSONL
- `emit --format jsonl|md`: round-trips bytes-for-bytes when source
  is JSONL (end-to-end test: `cat fixture | sidestep emit --format
  jsonl` produces byte-identical output)

### Slice 2 — `b8d62fe` (filter --where '<CEL>')

- `filter --where '<CEL>'`: predicate-based stream transform
- `--explain`: prints the parsed CEL AST + the resolved field paths
  before evaluation, for predicate authoring debugging
- Raw CEL via `cel-interpreter` 0.10 with the canonical adapter from
  finding-001 (rule-to-CEL translation: nested-record mapping,
  arithmetic identity, time arithmetic)
- Track C's `triage.sh` predicate runs verbatim through sidestep —
  validates the predicate-language choice end-to-end

### Slice 3 — `d0f4db1` (get + search + --limit + --since)

- `get <kind> <id>`: single-record fetch + `_kind`-tagged JSONL
- `search <kind> <query>`: API-shape stream with `_kind` tag
- `--limit`: streaming cap
- `--since`: CEL post-filter implemented as
  `<ts_field> > now - duration("...")` with hand-rolled
  Go-duration validator that fail-fasts before any network call
  (no `?since=` upstream)

### Slice 4 — `0e7c6d8` (enrich --with <recipe>)

Three recipes shipped:

- `policy-context` — rule → parent policy join
- `severity-roll-up` — `max(rule, parent)` when both present, else
  copy-rename
- `repo-owner` — hoist `repo.owner` to top-level for filter
  convenience

Auxiliary records via `--policies <FILE>`; API-fetched aux is
follow-up (see `aae-orc-if85` / finding-004).

### Slice 5 — `332d420` (audit schema_version 1 → 2)

Audit format extended with verb-shape fields:

- `verb_phase` — names the call's lifecycle stage
- `synthesis_keys` — the keys produced by the verb (for downstream
  joining)
- `recipe_id` (enrich) — names the recipe applied
- `predicate_text` (filter) — the raw CEL string
- `predicate_ast_shape` (filter) — literal-stripped sha256 of the
  parsed Program (lets analytics group "structurally equivalent"
  predicates without exposing user inputs)
- `predicate_outcome` (filter) — pass/fail/error counts per
  evaluation
- Stream-transform verbs (filter, enrich) emit verb-shape audit
  lines via `Span::finish_as_verb`; API-shape lines
  (list/get/search/api) ride along with `verb_phase` +
  `synthesis_keys`

## Caveats captured

- **cel-interpreter 0.10's antlr4rust parser** panics on some
  malformed predicates rather than returning Err
  (`aae-orc-qvk9`, P3). Defensive: validate predicates before
  evaluation in a future pass; for now, the panic is contained
  by the verb-process boundary.
- **`paste 1.0.15` advisory** (RUSTSEC-2024-0436, unmaintained,
  no known vulnerability) ignored in `deny.toml`. Acceptable
  per cargo-deny policy; revisit if `paste`'s indirect callers
  introduce real concerns.

## Deferred to v0.2 (per finding-001 + this slice's notes)

Each deferred item has a tracking ticket and a reason:

- **`field_paths_referenced` + `literal_values_by_path` audit
  fields** — `aae-orc-deux` (P2). AST-walk work that completes
  Murat's evidence set for v0.2 sugar design. Gated on `aae-orc-deux`.
- **rank, replay, act primitives** — `aae-orc-emap` (rank),
  `aae-orc-jsai` (replay), `aae-orc-7nhb` (act). Each one
  earns its place when audit-trail evidence shows the recipe
  pattern is real and stable.
- **diff primitive** — `aae-orc-08gd`. Same evidence gate.
- **CEL sugar layer** — `aae-orc-vjc6`. The choice between
  raw-CEL and sugar is itself deferred until invocation patterns
  show what's worth sugaring.
- **5 deferred kinds + 2 deferred enrichments** — `aae-orc-t3mc`.
  Out-of-scope for v0.1 minimum-viable; the priority order
  follows audit-trail evidence.
- **SDK base-URL override + wiremock integration tests** —
  `aae-orc-if85` (now closed; see finding-004 for the harness
  implementation).

## Evidence

- bd `aae-orc-lyeh` closed with full slice provenance (2026-05-02)
- 98 tests green at close: 45 SDK unit + 33 CLI integration + 14
  sub-test groups + 3 MCP + Track B shell asserts + 3 doc tests
- All five commit SHAs verifiable: `da6d220`, `b8d62fe`, `d0f4db1`,
  `0e7c6d8`, `332d420`

## What this finding does

Captures the v0.1 ship trace as a durable artifact, separate from
charter B7 prose. The bedrock claim ("v0.1 primitive layer shipped")
stays in charter; the ship trace, caveats, and deferred-items list
live here. Charter prose B7 reduced to a brief summary + finding
pointer (per orc finding-047 reduction recommendation).

The provenance discipline this captures:

- Each shipped slice has a commit SHA — bedrock provenance is
  git-traceable, not prose-summarized
- Each caveat has a ticket — friction is filed, not handwaved
  (per orc `.claude/rules/tooling-friction.md`)
- Each deferred item has a ticket + a reason — out-of-scope work
  is tracked, not lost

This is the sidestep harvest pattern: ship narrowly, document
broadly, defer with provenance.
