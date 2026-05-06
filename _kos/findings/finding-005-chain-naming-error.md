# Finding 005 — Chain-Naming Error for Missing Owner/Customer

**Date:** 2026-05-06
**Session:** 047 (same-day follow-on to finding-004)
**Probe:** `aae-orc-1mgo` — `MissingParam` should name the chain per cli-philosophy.md

## Context

Finding-002 (session-045) named the abusive-argument pattern and codified
the rule in `.claude/rules/cli-philosophy.md`. The "The fix — Argument
Resolution Chain" section reads:

> Error, with a message naming all four sources that failed and one
> concrete next step for each (`set SIDESTEP_OWNER=…`,
> `sidestep config set owner …`).

Finding-003 (session-046) implemented the chain (flag → env → config) and
the audit signal but left the error message unchanged. `sidestep list rule`
with no owner anywhere produced:

```
sidestep: missing required parameter 'owner' for operation 'get_github_owner_actions_rules'
```

That's the bare `SidestepError::MissingParam` from the SDK — accurate but
useless. It doesn't name the chain, doesn't say "here are the four ways to
fix this," doesn't even hint that owner is persistable. A user hitting it
fresh would have no idea where to set it.

## What was built

A CLI-side guard that runs *before* the SDK call. The cleanest split:

- **SDK** keeps `MissingParam` generic. `runid` / `repo` / `head_sha` and
  every other non-chain-tracked path param continue to use it. The SDK
  has no business knowing which params are chain-tracked.
- **CLI** runs `check_required_chain_params(op_id, sources)` right after
  `build_params` returns its `(params, sources)` tuple. The CLI consults
  `registry().find(op_id).path_params` and, for each name in the closed
  set `CHAIN_PARAMS = ["owner", "customer"]`, checks: if the op's path
  template requires it AND the source map doesn't contain it, fail
  early with a chain-naming message.

The closed `CHAIN_PARAMS` constant is the inventory: any future
chain-tracked param (none planned) gets added there in one place. The
formatter consults the same constant via a match in `format_chain_error`.

The new error shape:

```
sidestep: no owner resolved through any layer of the chain. Set one of:
  - --owner <slug>  (per-call override)
  - SIDESTEP_OWNER=<slug>  (per-shell default)
  - `sidestep auth login --owner <slug>`  (persisted in /Users/.../config.toml)
  - `sidestep config set owner <slug>`  (same persistence, no token write)
```

Four sources, four concrete next steps, the resolved config path
substituted in. Mirrors the cli-philosophy.md text near-verbatim.

## What changed

**`crates/sidestep-cli/src/main.rs`:**
- New `CHAIN_PARAMS: &[&str]` constant. Single source of truth for
  which path params are chain-tracked.
- New `check_required_chain_params(op_id, &sources)` helper — consults
  `registry().find(op_id).path_params` and the source map.
- New `format_chain_error(param)` helper — emits the four-source
  message with `auth::OWNER_ENV` / `auth::CUSTOMER_ENV` and
  `auth::config_path()` substituted in.
- Wired into `run_list` / `run_get` / `run_search` after `build_params`
  and before `call_op_blocking_for_verb`.

**`crates/sidestep-cli/tests/auth_chain.rs`:**
- 3 new integration tests:
  - `list_without_owner_errors_with_chain_naming_message` — list rule
    with no owner anywhere; verifies all four sources named, asserts
    the bare SDK `missing required parameter` shape no longer leaks.
  - `list_audit_log_without_customer_errors_with_chain_naming_message` —
    same shape for customer (audit_log uses get_customer_audit_logs
    which has `{customer}` as its only path param).
  - `list_with_owner_flag_skips_chain_error` — sanity: providing the
    flag short-circuits the guard; chain message must NOT appear when
    the param is supplied.

127 tests green at this commit (was 124 before 1mgo); clippy + cargo
deny + nightly fmt clean.

## What this validates

The CLI-vs-SDK error split is right. The CLI knows what it knows
(which params are chain-tracked, where the chain layers live, what
commands set them). The SDK knows what it knows (the operation
template requires this name, no value was provided). Forcing one to
do the other's job either bloats the SDK with CLI-specific knowledge
or asks the CLI to second-guess the SDK's contract. The split is
clean: the CLI catches its own case; the SDK error remains a
fallback for everything else.

`CHAIN_PARAMS` as a closed `&[&str]` constant is the right shape for
a small enumerable set. A `HashMap` or trait would be over-engineered
at v0.1. If the set grows beyond 3-4 names, revisit; today, two.

The `format_chain_error` helper panics on unknown `param` — that's
intentional. `CHAIN_PARAMS` is the closed set; any other value
reaching the formatter is a programmer bug, not a runtime
condition. Don't gracefully degrade what should never happen.

## What this does NOT change

- The SDK's `SidestepError::MissingParam` and its display string are
  unchanged. Non-chain path params (`runid`, `repo`, `head_sha`,
  `jobid`, etc.) still produce that message. The CLI doesn't catch
  those because there's no chain to name for them.
- `--repo` is still flag-only. Repos vary per question; chain
  resolution would not help (per ticket scope and cli-philosophy.md
  "what does NOT trigger this rule").
- Audit emission shape is unchanged. `path_params_source` continues
  to record the source for chain-tracked params that DID resolve;
  the new guard prevents a request from going out at all when one
  required chain param didn't resolve, so no audit line is emitted
  for the failed call (consistent with how other validation failures
  in the CLI behave — e.g. `--since` Go-duration validation).

## Cross-references

- Finding 002: `_kos/findings/finding-002-abusive-argument-pattern.md`
- Finding 003: `_kos/findings/finding-003-owner-customer-resolution-shipped.md`
- Finding 004: `_kos/findings/finding-004-base-url-override-and-wiremock-harness.md`
- Rule: `.claude/rules/cli-philosophy.md` ("The fix — Argument Resolution Chain")
- Bedrock: `_kos/nodes/bedrock/val-resolution-chain.yaml`, B5
- Ticket: `aae-orc-1mgo` (closed at this commit)

The session-045-onward arc is now closed end-to-end: rule → bedrock
→ first instantiation (token) → second instantiation (owner/customer)
→ integration harness → ergonomic error.
