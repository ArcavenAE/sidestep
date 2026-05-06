# Finding 004 — Base-URL Override + wiremock Harness Shipped

**Date:** 2026-05-06
**Session:** 047
**Probe:** `aae-orc-if85` — SDK base-URL override + wiremock-based integration tests

## Context

Slice 5 of the v0.1 primitive layer (commit `332d420`, finding-001 /
charter B7) noted: "Live-API integration tests pending." Until this
session, every SDK + CLI test that exercised the request path either
(a) stopped at URL construction in unit tests, or (b) routed through
shell asserts in `examples/asserts/` against fixture files. Nothing
exercised the actual HTTP layer end-to-end.

That gap surfaced again immediately after y7lq shipped: the
`path_params_source` audit field (finding-003) had unit-test
coverage for the emission shape but no integration test proving the
source signal flowed through a real network call.

## What was built

**Part A — SDK base-URL override.**

- `pub const BASE_URL_ENV: &str = "SIDESTEP_BASE_URL"` in `client.rs`,
  re-exported from `lib.rs`.
- `Client::with_base_url(token, base_url)` constructor for explicit
  override (tests, library callers pointing at non-production
  endpoints deterministically).
- `Client::from_env()` and `Client::with_token()` honor
  `SIDESTEP_BASE_URL` when set — empty string treated as unset so a
  stray `export SIDESTEP_BASE_URL=` doesn't silently break production
  calls.
- Trailing-slash trimming on the override path, matching the
  spec-loader's behavior in `spec.rs:90`. Without this the URL would
  build as `<base>//<path>`.
- 3 SDK unit tests (override replaces spec default, trailing slash
  trimmed, `auth_source` records `None`).

**Part B — wiremock integration tests** in
`crates/sidestep-cli/tests/wiremock_endpoint.rs`. Pattern:
`#[tokio::test]` spins up a `MockServer`, mounts a `Mock` with
explicit method/path/query/header expectations, runs the `sidestep`
binary synchronously via `assert_cmd` with
`SIDESTEP_BASE_URL=<server.uri()>`. Mock expectations verified on
`MockServer::drop` — failure raises a panic with the actual requests
received.

Six tests, six things proven:

1. **`list_detections_routes_owner_flag_into_url_path`** — flag-source
   end-to-end: `--owner arcaven` lands at
   `/github/arcaven/actions/detections`, audit records
   `path_params_source.owner = "flag"`.
2. **`list_detections_owner_resolves_from_env`** —
   `SIDESTEP_OWNER=from-env` (no flag) routes to `/github/from-env/...`
   and the audit records `"env"`.
3. **`list_detections_owner_resolves_from_config`** — `[default]
   owner = "from-config"` in `SIDESTEP_CONFIG`-pointed file routes to
   `/github/from-config/...` and the audit records `"config"`. **The
   y7lq loop closer** — proves the source signal flows end-to-end
   through the audit JSONL.
4. **`list_detections_flag_overrides_env_and_config`** — chain
   ordering verified at the URL layer, not just in the resolver
   unit tests.
5. **`list_handles_bare_array_response_shape`** — `extract_items`
   accepts both `{key: [...]}` and bare `[...]` responses; the
   bare-array case wasn't previously covered over the wire.
6. **`get_run_routes_id_path_param`** — multi-path-param endpoint
   `/github/{owner}/{repo}/actions/runs/{runid}` exercises a kind
   with a `get_operation_id` and a non-trivial id_path_param.

124 tests green at this commit (was 115 before if85). clippy + cargo
deny + nightly fmt clean.

## What this validates

The SDK's `Client::build` was already structured around an injected
`base_url` (the constructor took it from `registry()` rather than
hardcoding) — adding the override was a parameter-threading change,
not a redesign. The pre-existing shape already anticipated this.

`tokio::test` + sync `assert_cmd Command` composes cleanly. The
wiremock server runs in the test's tokio runtime; the binary runs
synchronously inside the async test. Expectations are still
async-verified at server drop. No subprocess-vs-async bridge needed.

The y7lq audit-signal coverage is now load-bearing. Before this
session, `path_params_source` was an SDK invariant proven only by
unit tests against `Span::base_record`. After, three CLI tests prove
flag/env/config sources each flow through:

- CLI argument parsing
- `auth::resolve_owner()` chain walk
- `build_params()` source-map construction
- `CallOptions.path_params_source` threading
- `Span::with_path_params_source` builder
- HTTP request construction (URL path)
- `Span::finish()` → `base_record()` → JSONL emission
- audit JSONL file read-back

That's nine layers of dependency between the user passing a flag
(or omitting it) and the audit miner seeing the source. The
integration tests pin all nine in place at once.

## What follow-ons this enables (filed as separate tickets)

- `aae-orc-8mq8` (P2) — API-fetched auxiliary for `enrich --with
  policy-context`. Currently file-only via `--policies <FILE>`. The
  wiremock harness lets us write the integration test against a mock
  policies endpoint before wiring the live fetch.
- `aae-orc-u7hy` (P2) — Pagination support in `run_list`. The
  multi-page response path is testable against wiremock simulating
  cursor-driven responses; trace_id grouping is already plumbed in
  `CallOptions`.
- `aae-orc-1mgo` (P3) — `MissingParam` error doesn't name the
  resolution chain when the missing param is chain-tracked. Today
  it says `missing required parameter 'owner' for operation 'X'`;
  cli-philosophy.md says it should enumerate flag/env/config status
  with a concrete next step for each. CLI-side reformat is cleaner
  than SDK-side since the SDK doesn't know which params are
  chain-tracked.

## What this does NOT change

- The vendored OpenAPI spec is still the source of truth. The
  override lets you point at a different endpoint; it does not let
  you call operations the spec doesn't describe.
- Production behavior is unchanged when `SIDESTEP_BASE_URL` is
  unset. The doc-comment on `BASE_URL_ENV` calls it a
  testing-and-dev knob, not a supported production override —
  documenting intent without enforcing it (per cli-philosophy.md
  "Trust internal code and framework guarantees").

## Cross-references

- Charter F6 (distribution) — unchanged
- Charter B7 slice 5 (audit v2 emission) — wiremock now covers the
  end-to-end emission path
- Finding 003 — y7lq audit signal, now integration-tested
- Finding 001 — primitives over composites, the work this finishes
- Ticket: `aae-orc-if85` (closed at this commit)
- Follow-ons: `aae-orc-8mq8`, `aae-orc-u7hy`, `aae-orc-1mgo`
