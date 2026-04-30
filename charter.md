# sidestep Charter

> Re-introduction document for sidestep — Rust CLI for the StepSecurity API.
> Restores context for a collaborator who was present but does not persist.
> Follows the kos process: Orient → Ideate → Question → Probe → Harvest → Promote.

Last updated: 2026-04-29 (initial scaffold).

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

### F1: progenitor Wire-Up

`cargo xtask regen` is stubbed. Wiring progenitor against the vendored
spec, deciding generator config (split into modules per resource group?
single file?), handling the additionalProperties + nullable + array-of-
heterogeneous-objects shapes the spec uses, and fitting the output into
`sidestep-api/src/`.

### F2: Curated v0.1 CLI Verb Set

The codegen will expose all 93 operations via `sidestep api <operationId>`.
The first curated verbs should cover the highest-value triage-and-harden
workflows: `runs list|get`, `detections list|get|suppress`, `checks
list|get|run`, `policies list|attach|detach`, `rules list|create|delete`,
`incidents list|get`, `run-policy-evaluations list`, `audit-logs list`.
Open: should there be a separate `sidestep harden` namespace for
StepSecurity's harden-runner-specific verbs?

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

Release pipeline shipped at `aae-orc-pxai` close, mirroring forestage's
shape (Apple Developer ID signing + notarytool + GitHub Releases +
ArcavenAE/homebrew-tap update) trimmed to mac-arm64-only and
binary-only. Tag-triggered on `v*`; gated by `vars.SIGNING_ENABLED`
so push-without-signing is a no-op until the variable is set on the
repo. The signed binary is consumed by Homebrew via raw URL +
sha256 — no `.pkg`/`.dmg` (kos's pattern), since brew is the
canonical install path. Notarization is via zip submission so
direct downloads pass Gatekeeper online check.

Open follow-ons:
- Set `SIGNING_ENABLED=true` on `ArcavenAE/sidestep` repo variables.
- Confirm the `release` GitHub environment + signing/notarization/tap
  secrets are inherited from the org (forestage already uses them).
- Cut the first tag (`v0.1.0`) once a curated verb set lands.
- Linux + x86_64-darwin builds, if real demand emerges.
- cosign + Sigstore Rekor attestation for the binary (per orc F24's
  frozen-composition lessons).

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
| Scaffold | 2026-04-29 | Repo created at ArcavenAE/sidestep. Workspace structure (4 crates + xtask), CI, conventions, vendored spec, charter, audit-trail design. B1–B4 set, F1–F6 opened, G1 ruled. Tracked as orc bd `aae-orc-icqp`. |
