# sidestep Charter

> Re-introduction document for sidestep — Rust CLI for the StepSecurity API.
> Restores context for a collaborator who was present but does not persist.
> Follows the kos process: Orient → Ideate → Question → Probe → Harvest → Promote.

Last updated: 2026-04-30 (harvest — F1 → B2, sessions through alpha-on-main, charter materialized into `_kos/nodes/`).

---

## The Problem Statement

Agents working on GitHub Actions security operations need programmatic access
to StepSecurity's API. The vendor publishes an OpenAPI spec at
`https://app.stepsecurity.io/assets/shared/step-security-api-v1.yaml` (79
paths, 93 operations covering runs, detections, checks, rules, policies,
baselines, threat-intel incidents, ai-agents, mcp-servers, npm/pypi search,
audit logs, customer admin). There is no first-party CLI today — agents
either write ad-hoc curl wrappers per session, or skip API integration
entirely.

A CLI alone is not enough. To eventually create *meta-actions* — verbs that
compose primitive API calls into well-shaped agent workflows — we need a
durable record of how the API is used in practice. That record has to be
structured enough for a future LLM session to mine for patterns, and it has
to capture every call, not just the curated ones.

---

## Design Values

1. **Spec is the contract.** The vendored OpenAPI spec is the canonical
   surface. The generated `sidestep-api` crate is its faithful Rust
   projection. The CLI exposes the spec via `sidestep api <operationId>`
   and curates ergonomic verbs on top.
2. **SDK-first.** All shared logic — auth, retry, pagination, audit
   emission, redaction — lives in `sidestep-sdk`. The CLI is presentation;
   the future MCP server is a sibling consumer.
3. **Audit trail is a feature, not a log.** Every call writes a structured
   JSONL line locally. The format is designed for future LLM analysis to
   propose meta-actions. See `docs/audit-trail-format.md`.
4. **Agent-first ergonomics.** JSON output by default for non-TTY,
   predictable verb shape, stable exit codes, transparent pagination.
5. **User sovereignty.** Local-first audit trail, local config, no
   phone-home, no telemetry. Aligns with the orc platform's SOUL §1.

---

## Non-Goals

- **Not a curl replacement.** The `raw` HTTP escape hatch was considered and
  ruled out (see G1). The spec is the contract; bypassing it is a smell.
- **Not a multi-tenant service.** sidestep is a local CLI. Authentication is
  per-user. Multi-user routing of credentials is out of scope (mirrors the
  orc platform's auth boundary in SOUL §3).
- **Not a UI.** Pretty tables for TTY are nice-to-have; the LLM contract is
  `--output json`.

---

## Bedrock

*Established. Evidence-based or decided with rationale.*

### B1: SDK-Backed CLI + Future MCP

The workspace is structured as four crates: `sidestep-api` (generated),
`sidestep-sdk` (hand-written), `sidestep-cli` (consumer), `sidestep-mcp`
(placeholder consumer). All shared concerns live in the SDK. The CLI and
MCP are sibling presentation layers.

Rationale: an MCP server reasoned about as an afterthought duplicates auth,
retry, pagination, and audit logic — exactly the surface that must be
identical between human and agent invocations.

### B2: OpenAPI Codegen via progenitor

`sidestep-api` is regenerated from `spec/stepsecurity-v1.yaml` via
`cargo xtask regen`. Generator: progenitor (Oxide Computer's
spec-to-reqwest tool). Generated source is committed (not built at
compile time) so it is grep-able by humans and agents.

Evidence: progenitor is the mature option for Rust + reqwest + spec-driven
clients; alternatives (`openapi-generator`, hand-rolled) carry maintenance
or output-quality penalties. Rationale was settled in session-040 design
discussion before scaffold.

**Implemented at `4a26361`** (formerly F1). Three pre-passes against
the in-memory spec model accommodate StepSecurity's spec quirks
without modifying the vendored YAML:

1. `fill_missing_operation_ids` — 78 of 93 operations lack
   `operationId`; synthesized as `{method}_{path-with-params-stripped}`.
2. `collapse_multi_success_responses` — progenitor asserts at most one
   Rust response type in the success class. The spec has 200 + default
   + 207 with distinct schemas; we keep one bodied success per operation.
3. `collapse_multi_error_responses` — same constraint applies to the
   error class. The spec has 400 + 401 + 404 + 500 with distinct inline
   schemas; we keep one.

Output: 27,653 lines of generated client across 97 operations, one
`Client` struct, all spec operations reachable. Committed at the crate
level — `cargo xtask regen` updates it in place.

### B3: Vendored Spec, Live Source

The spec is vendored under `spec/stepsecurity-v1.yaml` with a `.sha256`
pin. `cargo xtask sync-spec` fetches from the upstream URL
(`https://app.stepsecurity.io/assets/shared/step-security-api-v1.yaml`)
and updates both files. Spec changes are reviewed in PR via
`cargo xtask diff-spec` (forthcoming) which summarizes added/removed/
changed operations.

### B5: Auth UX — Three-Layer Resolution Chain

Token resolution walks env → keyring → config file → error. Each
layer's failure mode is graceful in service of the next:

- `SIDESTEP_API_TOKEN` env var — highest precedence. Empty string
  treated as unset.
- Platform keyring (macOS Keychain, Linux Secret Service via the
  `keyring` crate's `apple-native` / `linux-native` features).
  Service `sidestep`, user `default`. Backend errors (no daemon,
  denied access) treated as "no entry" rather than fatal — so a
  missing Secret Service doesn't block env or config users.
- Config file at `~/.config/sidestep/config.toml` (override via
  `SIDESTEP_CONFIG`). Format: `[auth] token = "<value>"`. Missing
  file is silent; **malformed file is fatal** (silent failure here
  would mask a real auth misconfiguration).

CLI surface:
- `sidestep auth login --token <v>` (non-interactive)
- `sidestep auth login --stdin` (`echo $T | sidestep auth login --stdin`)
- `sidestep auth status` (reports source: env / keyring / config;
  never prints the token; non-zero exit when no token is configured)
- `sidestep auth logout` (no-op-safe keyring deletion)

The audit trail's `invocation.auth_source` records `"env"`,
`"keyring"`, or `"config"` (or `null` for `Client::with_token`). The
schema_version stays at 1 — the field is additive.

Evidence: end-to-end verified across all three sources, including
malformed-config rejection with line/column diagnostic.

### B4: Audit Trail Schema (Initial)

Every API call emits one JSONL line under `~/.local/state/sidestep/audit/`
with: `trace_id`, `span_id`, `parent_span_id`, `ts_start`, `duration_ms`,
`invocation` (argv, version, host, user, tty), `operation` (operationId,
method, url_template, path_params, query_params), `response` (status,
size_bytes, items_returned, next_cursor, shape_hash), `result`,
`redacted_fields`. See `docs/audit-trail-format.md` for the full schema.

Rationale: the schema's join keys (`operation.id` from OpenAPI, `trace_id`
clustering CLI invocations, `shape_hash` for response-shape pattern
detection) are designed to support future LLM mining for meta-action
candidates without storing PII or secrets.

---

## Frontier

*Actively open. Expected to resolve through design work or probes.*

### F1: progenitor Wire-Up [RESOLVED → B2]

Promoted into B2's content above. Single-file `generated.rs` output
chosen; the three pre-passes named there handle the spec's quirks.
No follow-on questions remain at this layer.

### F2: Curated v0.1 CLI Verb Set [partial]

Spec-aware passthrough shipped at `29ae9c7` — every operation reachable
today via `sidestep api <operationId> --param k=v`. `sidestep ops list`
discovers operations; `sidestep ops show <id>` inspects one.

Remaining: ergonomic curated verbs over the highest-value
triage-and-harden workflows: `runs list|get`, `detections
list|get|suppress`, `checks list|get|run`, `policies
list|attach|detach`, `rules list|create|delete`, `incidents list|get`,
`run-policy-evaluations list`, `audit-logs list`. Should there be a
separate `sidestep harden` namespace for StepSecurity's
harden-runner-specific verbs?

### F3: Audit-Trail Pattern-Mining Surface

Once the audit trail is emitting in production, the second-order question
is what tooling reads it. Candidates: `sidestep audit query` (local
analysis), `sidestep audit traces` (trace_id rendering),
`sidestep meta propose` (LLM-driven meta-action suggestion). Also: should
audit lines become a flyloft catalog adapter so an LLM can `fly` against
them? Out of scope for v0.1; design once the trail has weeks of data.

### F4: Auth UX [RESOLVED → B5]

Promoted to bedrock B5 — see below. Resolution chain
env → keyring → config file is implemented across the SDK MVP
(`29ae9c7`), keyring fallback (`82b8cef`), and config file fallback
(`aae-orc-tqu6` close).

### F5: Permissions Model for Agent Use

`sidestep` is intended for agent invocation. Claude Code can scope
permissions like `Sidestep(api:listWorkflowRuns)` or `Sidestep(api:*)` if
the operationId is the addressable unit. Open: is this the right
granularity? Should curated verbs use a separate axis
(`Sidestep(detections:*)`)? Documenting the recommended permission
patterns in `docs/permissions.md` is a follow-on.

### F6: Distribution [partially resolved]

Single-channel Homebrew distribution, kos pattern. One formula
`Formula/sidestep.rb` published on every push to main (alpha versions)
and on `v*` tags (stable versions, when first cut). Two workflows
write to the same formula; only one fires per push event:

- `.github/workflows/alpha.yml` — push to main. Tag format
  `alpha-YYYYMMDD-HHMMSS-<sha7>`; GitHub prerelease; old prereleases
  pruned to last 30. **Active.**
- `.github/workflows/release.yml` — `v*` tag push. Stable release.
  **Dormant** until first tag.

Both mac-arm64 only, gated by `vars.SIGNING_ENABLED`. Apple Developer
ID signing + notarytool zip submission (no `.pkg`/`.dmg`/`.app` — the
raw signed binary is consumed via URL + sha256). The `release`
environment is set on the repo.

Open follow-ons:
- **Org-level signing secrets aren't reaching sidestep**: first
  alpha run failed at "Import certificates" with
  `APPLE_CERTIFICATE_P12` empty. Org has the secret but it isn't
  shared with this repo's `release` environment. Needs admin to
  add sidestep to the secret's selected-repository list (or share
  the secret to the `release` environment directly).
- Linux + x86_64-darwin builds, if real demand emerges.
- cosign + Sigstore Rekor attestation for the binary (per orc F24's
  frozen-composition lessons).
- First `v*` tag once curated verbs are ready.

---

## Graveyard

*Ruled out. Kept for the reasoning.*

### G1: `raw` HTTP Escape Hatch

Considered shipping `sidestep raw <method> <path>` (gh-CLI-style) for
endpoints not in the spec. Ruled out: the spec is the canonical surface;
`raw` would let drift hide. If we ever need it, we update the spec and
regenerate. The `sidestep api <operationId>` command is the spec-aware
escape hatch and serves the same need without bypassing the contract.

Evidence: design discussion at scaffold time. Reopen if a real need
emerges.

---

## Session Log

| Session | Date | Outcomes |
|---------|------|----------|
| Scaffold | 2026-04-29 | Repo created at ArcavenAE/sidestep. Workspace structure (4 crates + xtask), CI, conventions, vendored spec, charter, audit-trail design. B1–B4 set, F1–F6 opened, G1 ruled. orc bd `aae-orc-icqp`. |
| Progenitor wire-up | 2026-04-29 | `cargo xtask regen` produces 27,653 lines / 97 ops via progenitor 0.14. Three pre-passes (synthesize operationIds, collapse multi-success / multi-error responses) accommodate spec quirks. reqwest 0.12 → 0.13. F1 closed → B2. orc bd `aae-orc-n91j`. |
| SDK MVP + api passthrough | 2026-04-30 | sidestep-sdk: error / auth / spec / audit / redact / client. CLI `auth login/status/logout`, `ops list/show`, `api <opId>`. Audit JSONL schema v1 emitting per call (auth_source, operation, response.shape_hash, …). End-to-end verified against live API. F4 partial; F2 partial via api passthrough. orc bd `aae-orc-il4t`. |
| Keyring fallback | 2026-04-30 | Token chain extended env → keyring. `auth status` reports source without printing the token. invocation.auth_source records `"env"` or `"keyring"` in audit. orc bd `aae-orc-2kmy`. |
| Config-file fallback | 2026-04-30 | Chain completed: env → keyring → config (`~/.config/sidestep/config.toml`, override `SIDESTEP_CONFIG`). Missing file silent; malformed file fatal with TOML line/column. F4 → B5. orc bd `aae-orc-tqu6`. |
| Release pipeline (stable) | 2026-04-30 | Tag-triggered v* workflow: check → build mac-arm64 → sign + notarize-zip → GitHub Release → tap update. `Formula/sidestep.rb`. SIGNING_ENABLED + release environment configured on the repo. Dormant until first tag. F6 partial. orc bd `aae-orc-pxai`. |
| Alpha-on-main release | 2026-04-30 | `.github/workflows/alpha.yml` ships alpha on every push to main: `alpha-YYYYMMDD-HHMMSS-<sha7>` prereleases pruned to last 30 (kos pattern). `Formula/sidestep-a.rb` installs as `sidestep-a` so alpha + stable coexist (forestage-a / threedoors-a / jr-a convention). F6 expanded with two-channel posture. orc bd `aae-orc-2jh8`. |
| Harvest | 2026-04-30 | Charter F1 → B2 (closed); B2 expanded with the three pre-pass implementation; F2 marked partial. Charter materialized into `_kos/nodes/` (5 bedrock elements, 1 graveyard, 4 frontier questions). `kos doctor` clean. |
