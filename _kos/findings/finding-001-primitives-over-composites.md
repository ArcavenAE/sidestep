---
id: finding-001
slug: primitives-over-composites
date: 2026-05-01
session: 041
probe: brief-curated-cli-verbs-v01 (superseded by brief-primitive-layer-v01)
confidence: frontier
tags: [cli, design, primitives, schema, cel]
---

# Primitives over composites — sidestep v0.1 design convergence

## What we set out to find

Brief `brief-curated-cli-verbs-v01` proposed two phases: explore the live
StepSecurity instance to map data shape and workflows, then design 4–6
curated verbs from observed evidence. Five party-mode rounds + value-prop
research replaced "design composite verbs" with a sharper question.

## What changed

The user reframed the design problem mid-probe with three load-bearing
clarifications:

1. **The job-to-be-done is `orient → plan → verify → improve`** — produce
   exported, actionable plans for end-users (devs cleaning their stuff)
   and DevOps pros, where the StepSecurity WebUI fails. Goal: humans AND
   LLM agents both prefer the CLI for this loop.

2. **Triage is not a primitive.** It's `filter + rank + maybe enrich`
   with one opinionated default policy. Shipping `triage` as a verb
   hardcodes a policy. The real building blocks are one step above raw
   API: query primitives + transformation primitives, composing into the
   composite verbs.

3. **Establish primitives first; let composites emerge.** The
   value-prop-driven verbs (`triage`, `inventory`, `plan`, `orient`,
   `verify`) are the destination, not the v0.1 surface.

## What we landed on

**v0.1 ships the primitive algebra:**

- 6 primitives: `list <noun>`, `get <noun> <id>`, `search <noun> <name>`,
  `enrich --with <kind>`, `filter --where '<CEL>'`, `emit --format <fmt>`
- 1 escape: `api <operationId>` (already shipping)
- 9 `_kind` types: run, detection, check, policy, rule, incident,
  audit_log, repo, **threat_intel** (rescued, 7/9 vote)
- 3 enrichment recipes: policy-context, repo-owner, **severity-roll-up**
  (rescued, 4/9 vote)
- Streams: JSON-lines, `_kind`-tagged, primitives compose stdin→stdout

**Predicate language: raw CEL** with strict canonical adapter:
- `*_at` fields parsed to `Value::Timestamp` at ingest
- Absent fields omit keys (no `"null"` strings); `has()` works
- Enrichment-bound collections are always `Value::List<T>` with concrete `T`
- Field access against fields not in `_kind` schema → evaluation error,
  not silent null
- `now` symbol bound by SDK per query

**Two trivial sugar freebies:** `--limit N`, `--since <duration>`. Universal,
zero-ambiguity desugar. No comprehensive sugar layer until v0.2.

**Schema-aware tooling beats sugar flags** (Quinn's reframe):
- `filter --explain` dry-run prints resolved schema + parsed AST + `now` +
  active `_kind`. Collapses discovery + validation + iteration friction.
- Ruthless error messages: column-accurate, schema-suggesting ("did you
  mean `created_at`?").

**Audit instrumentation as the v0.2 sugar-design dataset** (Murat's set):
`predicate_text`, `parse_error`, `predicate_ast_shape`, `field_paths_referenced`,
`literal_values_by_path`, `predicate_outcome`, `retry_chain_id`,
`time_to_next_invocation`, plus `verb_phase`, `synthesis_keys`, `recipe_id`,
`step_index` for composite traces.

## Why we know this is right (and where we don't)

**Strong evidence:**
- 9-agent rescue poll on John's scope cut: K-2 (threat_intel) at 78%,
  E-3 (severity-roll-up) at 44% — landslide convergence on what cannot
  be cut.
- Sally's CEL stress test: 3 of 5 real predicates revealed she didn't
  know she'd hit a cross-kind join until she wrote it. Sugar over a
  single kind is easy; sugar that anticipates joins is the part that
  must be data-driven.
- Amelia's cel-rust audit: gotchas #3 (cross-kind) and #5
  (enrichment-shape) are categorically un-presugarable.
- Quinn's Theory-of-Constraints reframe: 4 of 5 predicate-friction sources
  are discovery/validation/iteration bottlenecks, not typing friction.
  Sugar flags only widen typing.

**Weaker evidence:**
- The 9 v0.1 kinds and 3 enrichments are the right primary set. Could be
  wrong; rescue poll may have missed a less obvious noun. v0.1 audit data
  will surface this.
- CEL specifically vs jq-ish or SQL-ish. CEL is industry-blessed for
  predicate-over-typed-records (k8s admission, GCP IAM). No empirical
  comparison run; `cel-rust` ergonomics taken on Amelia's read.
- 8–12 weeks at ~5–10 invocations/day as the threshold for sugar-from-data
  (Murat). Estimate, not measurement.

## What this changed

- Charter F2 (Curated v0.1 CLI Verb Set) → resolves to **B6: Primitives
  over composites**.
- Brief replaced: `brief-primitive-layer-v01.md`.
- v0.1 surface decreases (no `triage`/`inventory`/`plan`/`orient`/`verify`
  composites) but the audit-trail capture increases (sugar-design dataset).
- Deferred to v0.2 with named bd tickets: `rank` primitive, `replay
  <trace_id>` primitive, `act`/state-transition family, 5 deferred kinds
  (baseline, ai_agent, mcp_server, npm_package, pypi_package), 2 deferred
  enrichments (baseline-diff, incident-correlation), CEL sugar layer.

## Cross-references

- `docs/research/noun-inventory.md` — 11-cluster API surface map
- `docs/research/value-propositions.md` — 10 value-prop families
- `docs/research/stepsecurity-llms-full.txt` — 711KB upstream docs (vendored)
- Brief: `_kos/probes/brief-primitive-layer-v01.md`
- Charter: B6 (new), F2 RESOLVED
- Orc charter: B14 (agent taxonomy) — sidestep is one of the agent's tools
