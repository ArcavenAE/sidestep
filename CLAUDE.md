# CLAUDE.md — sidestep

Rust CLI for the StepSecurity API. Codegen from a vendored OpenAPI spec,
audit-trail-as-feature, agent-first ergonomics. Backed by an SDK that also
serves a future MCP surface.

@charter.md
@.claude/rules/_index.md

## Build / Run / Test

Requires: Rust 1.85+ (Edition 2024), `just`, nightly rustfmt.

```sh
just build              # cargo build --workspace
just test               # cargo test --workspace
just check              # fmt-check + clippy + cargo-deny
just run -- --version   # invoke the CLI
just sync-spec          # cargo xtask sync-spec — refresh vendored OpenAPI
```

## Architecture

```
crates/
  sidestep-api/         Generated reqwest client (regenerable from spec/)
  sidestep-sdk/         Hand-written: auth, retry, pagination, audit, redaction
  sidestep-cli/         clap CLI: curated verbs + `sidestep api <op-id>` escape
  sidestep-mcp/         Placeholder — MCP server backed by sidestep-sdk

xtask/                  cargo xtask sync-spec | regen | diff-spec
spec/                   Vendored OpenAPI spec (+ sha256 pin)
docs/                   Audit-trail format, design notes
```

Three-layer call graph: `cli/mcp → sdk → api`. Audit emission, retries,
pagination, and redaction live in the SDK so both consumers inherit them.

## Conventions

- **Language:** Rust, edition 2024, MSRV 1.85.
- **No unsafe:** `#![forbid(unsafe_code)]` everywhere.
- **Generated code:** `sidestep-api` is rebuilt from `spec/`; do not hand-edit.
- **Auth:** delegate via env (`SIDESTEP_API_TOKEN`) → keyring → config file.
- **Audit trail:** every API call emits a JSONL line under
  `~/.local/state/sidestep/audit/`. See `docs/audit-trail-format.md`.
- **No file deletion:** never delete user files. Overwrite only with explicit intent.
- **Git workflow:** trunk-based on `main` until distribution channel exists.

## How to Work Here (kos Process)

### Re-introduction
Read charter.md before any substantive work.

### Session Protocol
1. Read charter.md (orient)
2. Identify the highest-value open question — or capture ideas in `_kos/ideas/`
3. Write an Exploration Brief in `_kos/probes/`
4. Do the probe work
5. Write a finding in `_kos/findings/`
6. Harvest: update affected NODES (`_kos/nodes/{bedrock,frontier,graveyard}/*.yaml`),
   move files if confidence changed. Charter is renderer output (per orc F22,
   `kos charter render`); do NOT hand-edit charter prose outside
   `<!-- backdrop -->` blocks. Subrepo charter renderer extension tracked
   in aae-orc-gezz.

Cross-repo questions belong in the orchestrator's `_kos/`.
