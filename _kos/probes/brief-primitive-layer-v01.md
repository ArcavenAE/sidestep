# sidestep v0.1 Primitive Layer — Exploration Brief

Session: 041 (2026-05-01)
Supersedes: `brief-curated-cli-verbs-v01.md`
Related: `_kos/findings/finding-001-primitives-over-composites.md`,
charter F2 → B6, B4 (audit trail), F3 (audit-trail mining), F5 (permissions).

---

## Problem statement

`sidestep api <operationId>` ships (charter B2 + SDK MVP). v0.1 needs to
add a layer that produces deliverables the spec passthrough cannot —
exported action plans for the user's stated loop: `orient → plan →
verify → improve`. The first design pass proposed composite verbs
(`inventory`, `triage`, `plan`); the user reframed: **establish primitives
first, let composites emerge from real usage in v0.2**.

## Hypothesis

Six primitives + a typed-stream contract + raw CEL + schema-aware tooling
compose into every composite the user-felt value-prop families need. The
audit trail captures evidence for the v0.2 sugar/composite layer.

If the hypothesis is right: the three v0.1 experiments below converge on
a verb set humans AND LLM agents both reach for; the audit trail emits a
predicate-clustering dataset rich enough to design v0.2 sugar from
evidence; no v0.1 user journey requires a primitive we don't ship.

## Locked v0.1 surface

**Primitives:** `list <noun>`, `get <noun> <id>`, `search <noun> <name>`,
`enrich --with <kind>`, `filter --where '<CEL>'`, `emit --format <fmt>`.
Plus `api <opId>` peer.

**Stream contract:** JSON-lines, `_kind`-tagged. Each record:
`{ _kind: <string>, _source: { operation_id, response_index, fetched_at },
...domain_fields }`. Primitives compose stdin → stdout.

**`_kind` types (9):** run, detection, check, policy, rule, incident,
audit_log, repo, threat_intel.

**Enrichment recipes (3):** policy-context, repo-owner, severity-roll-up.

**Predicate language:** raw CEL (`cel-rust`) with canonical adapter rules
in finding-001.

**Sugar freebies (2):** `--limit N`, `--since <duration>`.

**Schema-aware tooling:** `filter --explain` (dry-run: schema + AST +
`now` + `_kind`) and column-accurate, schema-suggesting error messages.

**Output formats:** json (default non-TTY), table (default TTY), md, csv,
sarif.

**Audit metadata:** `verb_phase`, `synthesis_keys`, `recipe_id`,
`step_index`, `predicate_text`, `predicate_ast_shape`,
`field_paths_referenced`, `literal_values_by_path`, `predicate_outcome`,
`retry_chain_id`, `time_to_next_invocation`. Schema_version 1 → 2,
additive.

## Three parallel experiments (~4 hr wall-clock)

### Track A — `ActionItem` schema (~30 min)

Generative. Output: `docs/research/action-item-schema.md`.

Define the 5-field `ActionItem` shape: `id`, `kind`, `target`, `severity`,
`evidence`. Document why each field is load-bearing and how it ladders
back to the engineer's action.

Success: every field maps back to "what does the engineer need to act on
this." Any field that doesn't is suspect.

### Track B — Spine fixtures + 3 asserts (~4 hr)

Mechanical. Output: `examples/fixtures/{detection,run,policy,audit-log}.jsonl`
+ `make assert` target.

Pick 4 spine kinds with the most distinct schema shapes. Write fixture
records. Implement three asserts:

1. **Round-trip:** `list → filter(_kind=X) → emit(json)` is byte-identical
   to fixture.
2. **Cross-kind enrich:** `get policy P → enrich(rules) → filter(_kind=rule)`
   finds the rules.
3. **Rank-stability:** sorting on multi-key produces deterministic order
   across two runs.

Success: all three green on the spine. Any failure stops Track C.

### Track C — Recipe sketches incl. failing recipe (~2 hr)

Validation. Output: `examples/recipes/{inventory,triage,orient,verify,
changed-pinning}.sh`.

Write four composite recipes as primitive pipelines, plus one deliberate
failing recipe (Winston's idea): "actions whose pinning status changed
between last week and this week." If `diff` over two `list` calls isn't
expressible, that's the most valuable pre-Rust finding.

Success: the four read naturally; the failing recipe surfaces ≤1 missing
primitive (acceptable to defer to v0.2 with a named ticket).

## Acceptance criterion (John's "v0.1 is done when")

A Claude Code agent (or human operator) runs a sidestep pipeline against
a live StepSecurity tenant, gets a structured stream, filters+ranks with
CEL, and emits a Jira-ready or PR-ready artifact end-to-end with an audit
trail proving every API call. If the CLI cannot carry one real triage
from "what's broken" to "here's the ticket," it isn't v0.1.

## Success metric

5+ audit-trail JSONL lines per week from ≥2 distinct users, sustained
for 4 weeks post-ship. Below that, design v0.2 from accumulated data
isn't statistically defensible.

## Out of scope (v0.2+)

- `rank` primitive (P-1 in rescue poll; 3 votes; documented for v0.2)
- `replay <trace_id>` primitive (Carson's A-grade; orthogonal to API path;
  v0.2 ticket)
- `act` / state-transition primitive (Mary's 8th; covers writes:
  suppress, attach-policy, accept-PR; v0.2 ticket)
- 5 deferred `_kind`s: baseline, ai_agent, mcp_server, npm_package,
  pypi_package
- 2 deferred enrichments: baseline-diff, incident-correlation
- CEL sugar layer (designed from audit-trail evidence; ~8–12 weeks of
  data minimum per Murat's threshold)
- Schema-aware autocomplete / lint (beyond `--explain`)
- Interactive triage TUI
- MCP server beyond placeholder (charter B1)
- Write operations against the 17 POST + 6 DELETE + 3 PUT API ops

## Risks

- **CEL ergonomics may bounce humans off** (Sally's Tuesday-morning Maya
  scenario). Mitigation: `--explain` + ruthless errors + recipes corpus.
  v0.2 sugar from audit data closes the gap.
- **`cel-rust` rough edges** (Amelia's gotchas). Mitigation: canonical
  adapter rules in finding-001.
- **Cross-kind joins** can't be sugared from theory. Audit data required.
  v0.1 ships raw; users hit the friction; trail captures it.
- **StepSecurity ships their own CLI in 6–12 months** (Victor). Mitigation:
  3 design partners + audit trail as the unique moat.
- **Audit volume below threshold** (Murat). Mitigation: dogfooding in
  aae-orc + i-orc operations during the 4-week post-ship window.

## Artifacts

- `_kos/findings/finding-001-primitives-over-composites.md` (this convergence)
- `docs/research/noun-inventory.md` (11-cluster API map)
- `docs/research/value-propositions.md` (10 value-prop families)
- `docs/research/stepsecurity-llms-full.txt` (vendored 711KB upstream)
- After Track A: `docs/research/action-item-schema.md`
- After Track B: `examples/fixtures/*.jsonl` + `make assert`
- After Track C: `examples/recipes/*.sh`
