# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions follow [SemVer](https://semver.org/). Alpha builds are cut from
every push to `main` (`alpha-YYYYMMDD-HHMMSS-<sha7>`); stable versions
are cut from `v*` tags.

## [0.1.0] — unreleased (held release-ready)

First stable line: the v0.1 **primitive algebra** over the StepSecurity
API. Composite verbs (`triage`, `inventory`, …) are v0.2, designed from
audit-trail evidence.

### Added

- Primitive verbs composing `_kind`-tagged JSON-line streams:
  `list`, `get`, `search`, `filter --where '<CEL>'`,
  `enrich --with <recipe>`, `emit --format {jsonl|md}` over nine kinds
  (`run`, `detection`, `check`, `policy`, `rule`, `incident`,
  `audit_log`, `repo`, `threat_intel`), with `--limit` and `--since`.
- `sidestep api <operationId>` spec escape hatch reaching all 130
  operations in the vendored OpenAPI spec (2026-07 upstream sync:
  developer-mdm, secure-registry, api-keys, run-policies,
  harden-runner-agent releases).
- Transparent pagination: `list`/`search` follow `next_token` to
  exhaustion — no silently truncated first page.
- Resolution chains (flag → env → config) for the bearer token
  (env → keyring → config) and for `owner`/`customer` path parameters —
  on curated verbs **and** the `api` passthrough. Four-source
  diagnostics when a chain-tracked parameter is missing.
- `auth login/status/logout`, `config show/path/set/unset`,
  `ops list/show`.
- Local audit trail (JSONL, schema v2) per call: operation, params with
  per-param resolution source, response shape hash, timing, and filter
  mining fields (`predicate_text`, `predicate_ast_shape`,
  `predicate_outcome`, `field_paths_referenced`,
  `literal_values_by_path`).
- Enrichment recipes: `policy-context`, `repo-owner`,
  `severity-roll-up`.
- Agent-harness permission guidance in `docs/permissions.md`.
- Distribution: signed + notarized macOS arm64 binary via Homebrew
  (`brew install arcavenae/tap/sidestep`) and mise, with GitHub
  artifact attestation.

### Fixed

- Response-envelope handling matches the API's real shapes
  (`workflow_runs` top-level array; collections nested in `data`
  objects) instead of collapsing to a single record.
- Malformed CEL predicates (e.g. a trailing `==`) return a parse
  diagnostic instead of aborting; upstream parser-panic fix adopted via
  the `cel` 0.13 crate, with a retained defense-in-depth guard.

[0.1.0]: https://github.com/ArcavenAE/sidestep/releases
