# Finding 003 — Owner/Customer Resolution Chain Shipped

**Date:** 2026-05-04
**Session:** 046
**Probe:** `aae-orc-y7lq` — implement the abusive-argument fix from finding-002

## Context

Finding-002 (session-045) named the abusive-argument pattern, promoted
`val-resolution-chain` to bedrock, codified the rule in
`.claude/rules/cli-philosophy.md`, and filed `aae-orc-y7lq` as the
concrete first application of the rule. This finding records the
implementation outcome.

## What was built

A second instantiation of `val-resolution-chain` (B5 was the first,
for the bearer token), now applied to `owner` and `customer` path
parameters:

- `SIDESTEP_OWNER` / `SIDESTEP_CUSTOMER` env vars.
- `[default] owner` / `[default] customer` in
  `~/.config/sidestep/config.toml`.
- `auth::resolve_owner(flag) -> Result<Option<ResolvedParam>>` and
  `auth::resolve_customer(flag) -> Result<Option<ResolvedParam>>`
  walk flag → env → config → `None`. The caller decides whether the
  underlying operation actually requires the param and surfaces a
  missing-param error from the existing path-binding layer.
- `auth::write_config(impl FnOnce(&mut Config))` reads the existing
  config, applies the closure, writes back — preserving every section
  the caller did not touch. This is the reusable shape; `auth login`
  and the new `config set/unset` subcommands all go through it.

CLI surface added:

- `sidestep auth login --owner <slug> --customer <slug>` —
  optionally without `--token`. At least one of token/owner/customer
  must be provided.
- `sidestep auth status` — now reports owner + source and customer +
  source alongside token + source. Token absence no longer hides the
  owner/customer report.
- `sidestep config show / path / set <key> <value> / unset <key>` —
  generic config introspection. Keys: `owner`, `customer`,
  `auth.token` (with a nudge toward the keyring for tokens).
- `sidestep list / get / search` — `--customer <slug>` added
  symmetrically with `--owner`. Both walk the chain via the rewritten
  `build_params` helper that returns both the merged params object
  and a `BTreeMap<String, ParamSource>` for audit emission.

Audit schema (additive — `schema_version` stays at 2):

- New top-level `path_params_source` field on every API-shape audit
  line (`list`, `get`, `search`, `api`). Sibling of `operation`. Maps
  param-name → source string (`flag` | `env` | `config`). Only present
  when the caller resolved at least one chain-tracked param.
- `flag` sources are recorded too — the F3 mining surface needs the
  per-call-intent signal, not just the chain-resolved cases.

Coverage:

- 6 new SDK auth unit tests (parse `[default]`, parse
  default-only-no-auth, parse `ParamSource::*` strings, serialize
  skips empty sections, round-trip default-only).
- 3 new SDK audit unit tests (`base_record_emits_path_params_source`
  with two values, omits when empty, records `flag` source).
- 10 new CLI integration tests (`tests/auth_chain.rs`): error names
  the chain when no source provided; `auth login --owner` persists
  without token; `--owner --customer` together; existing token +
  customer preserved when only owner is added; `auth status` reports
  env-source / config-source / env-beats-config; `config show` redacts
  token length; `config set/unset` round-trip; unknown keys list the
  known ones.

All 115 tests green at this commit. clippy + cargo deny + nightly fmt
clean.

## What this validates

`val-resolution-chain` (bedrock) generalizes cleanly. The same
`Option<&str>` flag → env → config → result-or-None walk works for
both an opaque secret (token, with keyring as an extra layer) and
plain identifiers (owner/customer, where keyring would be overkill).
The `ParamSource` / `TokenSource` split is real — keyring is a
sensitive-storage-only layer — but otherwise the chains are
isomorphic.

The `write_config(closure)` shape is the right abstraction. `auth
login` mutates two distinct sections (`[auth]` via the keyring,
`[default]` via the closure) in one invocation; `config set` mutates
one section; both go through the same read-merge-write helper. New
sections added in the future inherit preservation for free.

The audit-trail decision to record `flag` alongside `env`/`config`
is load-bearing: without it, the F3 mining surface can only tell
"someone set a default" — but cannot tell which calls *intentionally
overrode* it. The per-call-intent signal is the whole reason the
chain exists.

## What this does NOT change

- `--repo` is still a flag-only path parameter. Repo varies per
  question; no constant default makes sense (per ticket scope note
  and cli-philosophy.md "what does NOT trigger this rule").
- No `/me` endpoint discovered, so derivation is not implemented.
  `ParamSource::Derived` is reserved in the cli-philosophy.md text
  but not in the enum yet. Add when the spec gains an endpoint.
- The audit schema bump (v2 → v3) was not needed: the new field is
  additive and miners that ignore unknown keys remain compatible.

## Impact on the F3 audit-mining surface

Before: `path_params.owner` recorded the *value* of owner on every
line. The mining surface saw `owner = "1898andCo"` on every call and
couldn't distinguish a per-call override from the constant default
that dominates the credential's lifetime.

After: `path_params_source.owner` records the *source* on every line.
Mining can now group calls by source — `flag` lines are the per-call-
intent signal worth correlating with response shape; `env`/`config`
lines are the noise floor. The two cluster differently in the F3
dataset and v0.2 sugar candidates derived from intent-only patterns
have a much better signal-to-noise floor.

This was the second motivation in finding-002 (the first was the
keystroke / token tax on every invocation). Both are now resolved.

## Cross-references

- Finding 002: `_kos/findings/finding-002-abusive-argument-pattern.md`
- Bedrock node: `_kos/nodes/bedrock/val-resolution-chain.yaml`
- Rule: `.claude/rules/cli-philosophy.md`
- Charter: B5 (token chain — first instantiation), B7 slice 5 (audit v2
  schema), F3 (audit-mining surface)
- Ticket: `aae-orc-y7lq` (closed at this commit)
- Sibling work in orc rule shape: `aae-orc/.claude/rules/tooling-friction.md`
