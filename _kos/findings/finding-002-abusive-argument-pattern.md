# Finding 002 — The Abusive Argument Pattern: B5 Generalized

**Date:** 2026-05-03
**Session:** 045 (post-v0.1 review)
**Probe:** orient-on-sidestep / `--owner` defaulting

## Context

Session-045 began with an orient pass on sidestep. The user surfaced
a concrete UX question: why does `sidestep list rules` (and every
v0.1 verb) require `--owner` when the StepSecurity token is already
bound to a single GitHub org for the lifetime of the credential?

The investigation was short: every `/github/{owner}/...` path uses
`{owner}` as a path parameter; the spec has no `/me` or `/whoami`
endpoint that would let us auto-discover it; the CLI scaffold
treated path params uniformly via `build_params(raw, owner, repo,
extras)`; and there is no resolution chain for owner — only the
flag.

Filing the fix (`aae-orc-y7lq`) was straightforward. The interesting
finding was the *category* of the missing rule.

## What we found

`elem-auth-three-layer` (B5) is **not just an auth pattern.** It is
one instance of a broader rule: any near-constant value the tool
needs should be reachable through a layered resolution chain
(flag → env → config → derivation → error), with the resolved source
recorded in the audit trail. The audit schema already does this for
auth (`auth_source`); v0.1 should have done it for owner from day
one.

The CLI scaffold missed it because path params were treated as a
homogenous set when in fact `{owner}` (and `{customer}` for tenant-
scoped endpoints) are categorically different from `{runid}` or
`{head_sha}`. Owner is bookkeeping; runid is the call's content.
Bookkeeping that is constant per credential is **abusive** when
required per call.

## The Abusive Argument test (codified)

A flag is abusive iff it is all four:

1. Near-constant for a given user/credential/environment
2. Not derivable on this call (no upstream exposes it)
3. Has no resolution chain (flag is the only path)
4. Required (tool errors when omitted)

`--owner` checked all four boxes.

## Why each box matters

- **Near-constant** — the sole reason a default is sensible.
- **Not derivable** — if the upstream exposes it, derivation is the
  best chain step (no caller burden at all). For sidestep+
  StepSecurity, no `/me` exists, so derivation is unavailable.
- **No resolution chain** — the gap that turns "near-constant" into
  "tax."
- **Required** — without this, the tax is opt-in, not mandatory; the
  tool degrades gracefully.

If any single box is false, the case is weaker. If derivation is
available, prefer it (auth's `auth_source` records `null` for
`Client::with_token` because the SDK consumer supplied it directly).

## The cost we were about to pay

Three callers, three taxes, all compounding:

1. **Human caller.** `--owner 1898andCo` typed verbatim on every
   list/get/search. Recipes pass it through unchanged.
2. **LLM caller.** Every redundant flag is tokens — input tokens on
   the prompt, output tokens on the generated command, both billed.
   Multiply by every step of every recipe.
3. **Audit-trail caller.** F3 (question-audit-mining) is designed to
   mine the JSONL for usage patterns. `path_params.owner` would have
   been a constant-valued field on every line of the dataset, drowning
   out per-call intent (Murat's threshold of 200 distinct
   `predicate_text` values × 10 contexts gets polluted by the same
   noise on every record).

The fix is the same shape as B5: chain + source-of-resolution recorded
in audit. One pattern, applied wherever the test triggers.

## What changed in the graph

- **New value node:** `val-resolution-chain` — names the principle
  generally so future near-constant values inherit it.
- **`elem-auth-three-layer` (B5)** gains an `instantiates` edge to the
  new value: B5 is the canonical instance.
- **`question-audit-mining` (F3)** gains a note that `aae-orc-y7lq`
  reduces noise floor; signal-to-noise is part of the threshold story.
- **New rule file:** `.claude/rules/cli-philosophy.md` — behavior-trigger
  rule that fires before `arg(required = true)` is typed for anything
  but per-call identity. Codifies the four-box test, the chain pattern,
  and the broader Unix + agent-first principles (rule of silence,
  stdout-as-contract, exit codes, TTY auto-detect, XDG paths, schema
  stability, determinism, repair-friendly errors). Drawn from McIlroy
  1978, Gancarz 1995, Raymond 2003, Pike, POSIX XBD §12, XDG, 12-factor
  §III, plus two new constraints (LLM-in-pipe token tax, audit-mining
  noise floor) not in the canonical Unix philosophy.

## Implications for v0.2 design

When a v0.2 verb adds a path parameter, run the four-box test before
exposing it as a flag. If the test fails (i.e., the value is per-call
intent), require it. If the test passes, build the chain.

Two near-term v0.2 verbs to watch:

- `replay <trace_id>` (`aae-orc-jsai`) — `trace_id` is per-call
  identity; not abusive.
- `act` / state-transitions (`aae-orc-7nhb`) — TBD; depends on which
  endpoints land in the family. Apply the test per-flag.

The CEL sugar layer (`aae-orc-vjc6`) is a sibling concern: sugar
collapses verbose predicates, the chain collapses verbose path params.
Both compound the v0.2 ergonomics win.

## Cross-references

- Charter B5 (auth UX) — the canonical instance
- Charter F3 (audit-mining surface) — noise-floor consumer
- `.claude/rules/cli-philosophy.md` — the rule
- `aae-orc-y7lq` — the fix work item
- finding-001 (primitives over composites) — the rule's compositional
  half (one ergonomic axis); this finding is the other (resolution axis)
- orc `.claude/rules/tooling-friction.md` — same behavior-trigger shape
