# sidestep Charter

> Re-introduction document for sidestep — Rust CLI for the StepSecurity API.
> Restores context for a collaborator who was present but does not persist.
> Follows the kos process: Orient → Ideate → Question → Probe → Harvest → Promote.

Last updated: 2026-05-03 (session-045 — abusive-argument pattern named, `val-resolution-chain` promoted to bedrock as the generalization of B5; `aae-orc-y7lq` filed for owner/customer chain; `.claude/rules/cli-philosophy.md` shipped).

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

### B6: Primitives over Composites

v0.1 ships the **primitive algebra**, not opinionated composite verbs.
Six primitives compose JSON-line streams of typed records into
exported, actionable plans — the WebUI's gap. Composite verbs
(`triage`, `inventory`, `plan`, `orient`, `verify`) emerge as v0.2
recipe sugar designed from accumulated audit-trail evidence, not from
intuition.

**Primitives:** `list <noun>`, `get <noun> <id>`, `search <noun> <name>`,
`enrich --with <kind>`, `filter --where '<CEL>'`, `emit --format <fmt>`.
Plus `api <opId>` peer escape hatch (B2).

**Stream contract:** JSON-lines, `_kind`-tagged, primitives
compose stdin → stdout. 9 v0.1 kinds: `run`, `detection`, `check`,
`policy`, `rule`, `incident`, `audit_log`, `repo`, `threat_intel`.

**Predicate language:** raw CEL (`cel-rust`) with strict canonical
adapter rules (timestamps parsed at ingest, absent fields omit keys,
list collections always `Value::List<T>` with concrete `T`, missing
fields error not null, `now` bound per query). Two trivial sugar
freebies: `--limit N`, `--since <duration>`. Schema-aware tooling —
`filter --explain` and column-accurate, schema-suggesting error
messages — collapses friction better than per-flag sugar would.

**Enrichment recipes (3):** `policy-context`, `repo-owner`,
`severity-roll-up`.

**Audit instrumentation:** `verb_phase`, `synthesis_keys`,
`recipe_id`, `step_index`, `predicate_text`, `predicate_ast_shape`,
`field_paths_referenced`, `literal_values_by_path`,
`predicate_outcome`, `retry_chain_id`, `time_to_next_invocation`. The
trail is the v0.2 sugar-design dataset.

Evidence: 5 party-mode rounds (10 BMAD agents, 4 lenses), 9-agent
rescue-poll convergence (K-2 threat_intel 78%, E-3 severity-roll-up
44%), CEL stress test against 5 real predicates (Sally + Amelia)
showing 3 of 5 predicates expose un-presugarable shapes. Quinn's
TRIZ reframe: schema-aware tooling collapses the
ergonomics/completeness contradiction without baking opinions in.

See `_kos/findings/finding-001-primitives-over-composites.md` and
`_kos/probes/brief-primitive-layer-v01.md`.

### B7: v0.1 Primitive Layer Shipped

The v0.1 verb surface from B6 is implemented and on `main`. Five
slices, each its own commit, each green at all gates (clippy +
deny + 98 tests + Track B shell asserts):

- Slice 1 (`da6d220`) — stream contract + 9-kind table + `list` +
  `emit` (jsonl, md). End-to-end: `cat fixture | sidestep emit
  --format jsonl` round-trips byte-identically.
- Slice 2 (`b8d62fe`) — `filter --where '<CEL>'` + `--explain`,
  raw CEL via `cel-interpreter` 0.10 with the canonical adapter
  from finding-001. Track C's `triage.sh` predicate runs verbatim.
- Slice 3 (`d0f4db1`) — `get`, `search`, `--limit`, `--since`.
  `--since` is a CEL post-filter (`<ts_field> > now -
  duration("...")`) with hand-rolled Go-duration validator that
  fail-fasts before any network call.
- Slice 4 (`0e7c6d8`) — `enrich --with <recipe>`. Three recipes:
  `policy-context` (rule → parent policy join), `severity-roll-up`
  (max(rule, parent) when both present, else copy-rename),
  `repo-owner` (hoist `repo.owner` to top-level for filter
  convenience). Auxiliary records via `--policies <FILE>`;
  API-fetched aux is follow-up (`aae-orc-if85`).
- Slice 5 (`332d420`) — audit `schema_version` 1 → 2. Adds
  `verb_phase`, `synthesis_keys`, `recipe_id`, `predicate_text`,
  `predicate_ast_shape` (literal-stripped sha256 of parsed
  Program), `predicate_outcome`. Stream-transform verbs (filter,
  enrich) emit verb-shape audit lines via
  `Span::finish_as_verb`; API-shape lines (list/get/search/api)
  ride along with `verb_phase` + `synthesis_keys`.

Caveats captured: cel-interpreter 0.10's antlr4rust parser
panics on some malformed predicates rather than returning Err
(`aae-orc-qvk9`); `paste 1.0.15` advisory ignored in deny.toml
(unmaintained per RUSTSEC-2024-0436, no known vulnerability).

Deferred to v0.2 per finding-001 + this slice's notes:
field_paths_referenced + literal_values_by_path audit fields
(`aae-orc-deux`, AST-walk work); rank, replay, act primitives
(aae-orc-emap/jsai/7nhb); diff primitive (aae-orc-08gd); CEL
sugar layer (vjc6); 5 deferred kinds + 2 deferred enrichments
(t3mc); SDK base-URL override + wiremock integration tests
(`aae-orc-if85`).

Evidence: bd `aae-orc-lyeh` closed with full slice provenance
(2026-05-02). 98 tests green at close (45 SDK unit + 33 CLI
integration + 14 sub-test groups + 3 MCP + Track B shell
asserts + 3 doc tests).

---

## Frontier

*Actively open. Expected to resolve through design work or probes.*

### F1: progenitor Wire-Up [RESOLVED → B2]

Promoted into B2's content above. Single-file `generated.rs` output
chosen; the three pre-passes named there handle the spec's quirks.
No follow-on questions remain at this layer.

### F2: Curated v0.1 CLI Verb Set [RESOLVED → B6]

Resolved by finding-001 (session-041). The framing changed: not "what
curated verbs," but "what primitive algebra composes into the verbs
users will reach for." See B6. Composite verbs (`triage`, `inventory`,
`plan`, `orient`, `verify`) deferred to v0.2 as recipe sugar designed
from audit-trail evidence.

### F3: Audit-Trail Pattern-Mining Surface [now active per B7]

Once the audit trail is emitting in production, the second-order question
is what tooling reads it. Candidates: `sidestep audit query` (local
analysis), `sidestep audit traces` (trace_id rendering),
`sidestep meta propose` (LLM-driven meta-action suggestion). Also: should
audit lines become a flyloft catalog adapter so an LLM can `fly` against
them?

**Status as of session-044:** the v2 audit schema is emitting (B7,
slice 5). Every CLI invocation produces a JSONL line with
`verb_phase`, `synthesis_keys`, and verb-specific fields
(`predicate_text` + `predicate_ast_shape` + `predicate_outcome`
for filter; `recipe_id` + `transform_outcome` + auxiliary for
enrich). The dataset that justifies v0.2 sugar design is now
flowing — the question shifts from "design the schema" (resolved)
to "what readers do we want, and what's the threshold of data
volume before sugar candidates become statistically defensible."
Murat's threshold of 8–12 weeks at 5–10 invocations/day
(finding-001) is the bar.

Pre-v0.2-design follow-up: `aae-orc-deux` adds the AST-walk
audit fields (field_paths_referenced, literal_values_by_path)
that complete Murat's set.

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

First end-to-end alpha shipped 2026-04-30 as
`alpha-20260430-215941-40b3708`. `Formula/sidestep.rb` lives in
`ArcavenAE/homebrew-tap`; `brew install ArcavenAE/tap/sidestep`
works.

Org-level signing/notary/tap secrets (`APPLE_CERTIFICATE_*`,
`APPLE_SIGNING_IDENTITY`, `APPLE_NOTARIZATION_*`,
`HOMEBREW_TAP_TOKEN`) are `visibility: selected`; sidestep is now
on each allowlist. Empirically the fleet uses the same org-level
mechanism (no env-scoped or repo-scoped secrets on
kos/forestage/sideshow/marvel/switchboard/BetterDials).

Open follow-ons:
- **Restore `.pkg` build path** if non-Homebrew installs become
  important. The fleet (kos, forestage, marvel) builds .pkg/.dmg
  alongside the binary; sidestep dropped them to keep the alpha
  pipeline minimal. Would need the 3 `APPLE_INSTALLER_*` secrets
  added to sidestep's allowlist.
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
| Single-channel revert + first publish | 2026-04-30 | Reverted `sidestep-a` channel after user correction (kos/sideshow use a single formula; I had drawn from forestage/jr/ThreeDoors). One `Formula/sidestep.rb` written by both alpha-on-main and tag-on-tag workflows. Added sidestep to org-secret selected-repos allowlist for the 7 secrets the workflow uses. First green alpha shipped: `alpha-20260430-215941-40b3708`, signed + notarized + in `ArcavenAE/homebrew-tap`. `brew install ArcavenAE/tap/sidestep` works. `.pkg` build path remains dropped (could be restored later). |
| Primitives convergence (041) | 2026-05-01 | F2 → B6 via 5 party-mode rounds (10 BMAD agents) + value-prop research + 9-agent rescue poll. v0.1 surface locked: 6 primitives (`list`, `get`, `search`, `enrich`, `filter`, `emit`) + `api` peer, 9 `_kind`s (run, detection, check, policy, rule, incident, audit_log, repo, threat_intel), 3 enrichments (policy-context, repo-owner, severity-roll-up), raw CEL with canonical adapter, 2 sugar freebies (`--limit`, `--since`), `filter --explain`, rich audit instrumentation. Composite verbs deferred to v0.2 as recipes designed from audit-trail evidence. Two research artifacts: `docs/research/{noun-inventory,value-propositions}.md`. Brief replaced: `_kos/probes/brief-primitive-layer-v01.md`. Finding: `_kos/findings/finding-001-primitives-over-composites.md`. |
| v0.1 Track A — ActionItem schema (041) | 2026-05-01 | 5-field bridge artifact (id content-addressed, kind closed enum 6 values, target discriminated union per kind, severity 5-level, evidence list min cardinality 1) shipped to `docs/research/action-item-schema.md`. Promoted to bedrock `elem-action-item-schema` (replaces frontier `question-action-item-schema`). Back-propagation surfaced concrete field requirements for the 9 input kinds (Track B spec). bd `aae-orc-0t43`. |
| v0.1 Track B — spine fixtures + 3 asserts (041) | 2026-05-01 | 23 fixture records across 4 spine kinds (detection, run, policy, audit-log) + rule.jsonl as join target, in `examples/fixtures/`. 3 jq+shell asserts implemented and green: round-trip (parse+filter+emit byte-identical), cross-kind-enrich (3 policy join cases + orphan-rule detection), rank-stability (deterministic across runs + explicit severity-int mapping + ts-desc tiebreak). `make -C examples assert` runs all. Becomes regression contract for the Rust impl. bd `aae-orc-kdz1`. |
| v0.1 Track C — recipe sketches + diff surfaced (041) | 2026-05-01 | 5 recipes shipped to `examples/recipes/`. `inventory.sh` + `triage.sh` work cleanly (4-pipe primitive composition). `orient.sh` bends (multi-source rollup uses shell-level count; aggregation isn't a v0.1 primitive — v0.2 design question deferred to audit-trail evidence). `verify.sh` + `changed-pinning.sh` (Winston's deliberate failing recipe) both demand set difference over two streams — strongest single missing-primitive signal. Filed bd `aae-orc-08gd` for the `diff` primitive (v0.2). v0.1 primitive set sufficient for inventory + triage flows; verify/time-travel flows gate on `diff` (08gd) + `replay` (jsai). bd `aae-orc-ldq1`. |
| Abusive-argument pattern + cli-philosophy rule (045) | 2026-05-03 | Orient on sidestep surfaced a UX question that turned into an epistemic one: `--owner` is required on every v0.1 list/get/search even though the StepSecurity token is bound to one GitHub org for the credential's life. Investigation confirmed the spec has no `/me` endpoint, so auto-discovery is unavailable; the gap was scaffold-level, treating path params uniformly when `{owner}`/`{customer}` are categorically bookkeeping while `{runid}`/`{head_sha}` are content. Filed `aae-orc-y7lq` (P2) — flag > env > config chain captured at `auth login` time, mirrored by `path_params_source.owner` in audit (additive — schema_version stays at 2). The deeper finding: B5 (auth UX three-layer chain) is **one instance** of a broader pattern, not auth-specific. Promoted `val-resolution-chain` to bedrock as the generalization; B5 now `instantiates` it. Added downward edge from `question-audit-mining` (F3) — chain reduces noise floor on the constant-valued fields that would otherwise dominate the dataset and push Murat's sugar-design threshold further out. Codified the broader CLI design rule in `.claude/rules/cli-philosophy.md` (167 lines, behavior-trigger shape matching orc tooling-friction): four-box Abusive Argument test (near-constant + not-derivable + no-chain + required), the resolution chain as the canonical fix, plus operative-form principles drawn from McIlroy 1978 / Gancarz 1995 / Raymond 2003 / Pike / POSIX XBD §12 / XDG / 12-factor §III, with two new constraints not in the canonical Unix philosophy (the LLM-in-pipe token tax, the audit-mining noise floor). Finding: `_kos/findings/finding-002-abusive-argument-pattern.md`. Charter `Last updated` rolled to 2026-05-03. bd: 1 filed (y7lq). 2 commits this session: `a101e3d` (rule), pending harvest commit. |
| v0.1 primitive layer ship (044) | 2026-05-02 | Five-slice ship of the v0.1 verb surface from B6 → B7. Each slice its own commit, each green at every gate. Slice 1 (`da6d220`) — sidestep-sdk gains `stream` (Record + SourceRef + JSONL read/write helpers) and `kinds` (9-kind static table with id_field, severity_field, primary_timestamp_field, id_path_param, search_field). CLI gains `list` + `emit` (jsonl, md). End-to-end byte-identical round-trip against detection fixture verified. Slice 2 (`b8d62fe`) — sdk `cel` module wraps cel-interpreter 0.10 with the canonical adapter from finding-001 (timestamp promotion of `*_at`/`ts`, `record` map for `has()`, top-level + record bindings, now per query, non-bool error, missing-field error). CLI `filter --where '<CEL>' [--explain]`. Track C's triage predicate runs verbatim. Caveat captured: cel-rust antlr4rust panics on some malformed input (`aae-orc-qvk9`, P4); paste 1.0.15 RUSTSEC-2024-0436 ignored in deny.toml with rationale. Slice 3 (`d0f4db1`) — `get`/`search`/`--limit`/`--since`. KindSpec gains `id_path_param` (runid/head_sha/incidentId per kind) and `search_field`. `--since` is a CEL post-filter `<ts_field> > now - duration("...")` reusing the cel adapter. Hand-rolled `is_valid_go_duration` validates Go-duration syntax (ns/us/µs/ms/s/m/h, no `d` for days) before any network call so a typo doesn't burn a YubiKey tap. Slice 4 (`0e7c6d8`) — sdk `enrich` module + 3 recipes. policy-context attaches parent policy as `policy: {id, name, severity, attached_repos}` for rule records (orphans get null); severity-roll-up takes max(rule, parent) when both severities are present, falls back to copy-rename when only one is; repo-owner hoists `repo.owner` to a top-level `_repo_owner`. Auxiliary records via `--policies <FILE>`; API-fetched aux is follow-up `aae-orc-if85` (P2). Cross-kind-enrich semantic from Track B's shell assert is now also enforced through the Rust binary against the same fixtures. Slice 5 (`332d420`) — audit `schema_version` 1→2. Span gains `verb_phase` + `synthesis_keys` + `Span::start_fresh()` + `Span::finish_as_verb(extra)`. CallOptions gains verb_phase + synthesis_keys to thread through Client::call_op. CLI run_filter creates a Span, tracks kept/dropped/error counts, emits with `predicate_text` + `predicate_ast_shape` (literal-stripped sha256 of Debug-formatted Program — value-independent: `severity == "critical"` and `severity == "high"` hash identically; structurally different: `==` vs `in` flips the hash) + `predicate_outcome`. CLI run_enrich similarly emits with `recipe_id` + `transform_outcome` + auxiliary.policies_loaded. AST-walk audit fields (field_paths_referenced, literal_values_by_path) deferred to `aae-orc-deux` (P3). Charter F2 → B6 (resolved session-041) extended with B7 (shipped); F3 (audit-mining surface) updated from "design once data flows" to "data is now flowing, threshold gating v0.2 sugar design." Final: 98 tests green (45 SDK unit + 33 CLI integration + 6 sub-test groups + 3 MCP + Track B shell asserts + 3 doc tests); clippy + cargo deny + nightly fmt clean; lyeh closed with provenance; sidestep main pushed `b00a441..332d420`. bd: closed `aae-orc-lyeh`; filed `aae-orc-qvk9` (upstream cel-rust panic, P4), `aae-orc-if85` (SDK base-URL override + wiremock tests, P2), `aae-orc-deux` (AST-walk audit fields, P3). The v0.1 surface from finding-001 is on disk and signing alpha-on-main on next push to the formula. |
