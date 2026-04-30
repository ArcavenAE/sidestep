# sidestep

Rust CLI for the [StepSecurity](https://www.stepsecurity.io/) API. Built
from a vendored OpenAPI spec, designed for LLM-driven workflows, with a
local audit trail intended to be mined for meta-action patterns.

> Status: scaffold. The CLI compiles and reports its version. Curated
> verbs and `sidestep api <operationId>` are wired in follow-on work.

## Why sidestep

- **Spec-driven.** `sidestep-api` is generated from
  `spec/stepsecurity-v1.yaml`. Update the spec, regenerate, ship.
- **SDK-backed.** The same SDK that powers the CLI will power a future
  MCP server. Auth, retries, pagination, audit, and redaction live in
  one place.
- **Agent-first.** JSON output for non-TTY, predictable verb shape,
  stable operation IDs, structured audit trail.
- **Audit as feature.** Every API call emits a JSONL line locally; a
  future tooling pass can mine those traces to propose meta-actions
  that compose multiple primitive calls.

## Install

Pre-built binaries are not yet published. Build from source:

```sh
git clone https://github.com/ArcavenAE/sidestep.git
cd sidestep
cargo build --release
./target/release/sidestep --version
```

## Configure

Authentication resolves in this order:

1. `SIDESTEP_API_TOKEN` environment variable
2. Platform keyring (macOS Keychain, Linux Secret Service) — managed via
   `sidestep auth login`, `auth status`, `auth logout`
3. Config file at `~/.config/sidestep/config.toml` (override path with
   `SIDESTEP_CONFIG`):
   ```toml
   [auth]
   token = "your-bearer-token"
   ```

A missing config file is silent. A malformed config file fails fast
with a line/column diagnostic — by design, so a typo doesn't quietly
fall through to "no token configured." Every API call records its
`auth_source` in the audit trail.

## Usage

```sh
sidestep --version                       # works today
sidestep <resource> <verb> [args]        # curated verbs (forthcoming)
sidestep api <operationId> --param k=v   # call any spec operation (forthcoming)
```

The `sidestep api` form lets agents reach all 93 operations the spec
exposes. Curated verbs are for the highest-value workflows.

## Development

```sh
just build           # cargo build --workspace
just test            # cargo test --workspace
just check           # fmt + clippy + cargo-deny
just sync-spec       # cargo xtask sync-spec
```

See [CLAUDE.md](CLAUDE.md) and [charter.md](charter.md) for design context.

## License

MIT — see [LICENSE](LICENSE).
