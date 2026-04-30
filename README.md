# sidestep

Rust CLI for the [StepSecurity](https://www.stepsecurity.io/) API. Built
from a vendored OpenAPI spec, designed for LLM-driven workflows, with a
local audit trail intended to be mined for meta-action patterns.

> Status: usable. Auth (env / keyring / config), spec-aware operation
> dispatch, and the audit trail are all wired. Curated CLI verbs are
> follow-on work; today every operation is reachable via
> `sidestep api <operationId>`.

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

### Homebrew (recommended)

```sh
brew tap arcavenae/tap                        # one-time
brew install arcavenae/tap/sidestep
```

### Upgrade

```sh
brew update
brew upgrade arcavenae/tap/sidestep
```

### Uninstall

```sh
brew uninstall arcavenae/tap/sidestep
brew untap arcavenae/tap                      # optional, removes the tap
```

### Build from source

```sh
git clone https://github.com/ArcavenAE/sidestep.git
cd sidestep
cargo build --release
./target/release/sidestep --version
```

macOS arm64 only for v0.1. Other platforms can build from source.

## Getting started

Recommended path — store your StepSecurity API token in the macOS Keychain
once, and let sidestep find it on every call:

```sh
# Interactively (token never appears in argv or shell history):
echo "$YOUR_TOKEN" | sidestep auth login --stdin

# Or from a .env-style file:
( . ~/path/to/.env && printf '%s' "$STEP_SECURITY_API_KEY" ) | sidestep auth login --stdin

# Verify (prints source + length, never the token itself):
sidestep auth status
```

If you'd rather use an environment variable, `SIDESTEP_API_TOKEN` takes
precedence over the keychain:

```sh
export SIDESTEP_API_TOKEN="<bearer-token>"
sidestep auth status
```

A config file at `~/.config/sidestep/config.toml` (override path with
`SIDESTEP_CONFIG`) is the third fallback:

```toml
[auth]
token = "<bearer-token>"
```

Resolution order is **env → keychain → config file → error**. A missing
config file is silent; a malformed config file fails fast with a TOML
parser diagnostic so a typo doesn't quietly fall through.

## Quick verification

After `sidestep auth status` reports `authenticated`, confirm the wiring
end-to-end with a few read-only commands. Replace `your-org` with your
GitHub organization name as it appears in StepSecurity.

```sh
# 1. Discover what operations are available.
sidestep ops list | head
sidestep ops list --filter detection

# 2. Inspect one operation's path, params, and which are required.
sidestep ops show getRunsDetails

# 3. Make a real read-only call. --param values are JSON-parsed first,
#    so `limit=1` becomes the integer 1, not the string "1".
sidestep api getRunsDetails --param owner=your-org --param limit=1
```

You should see a JSON response with workflow runs and security data. If
you get `HTTP 401`, double-check the token; if you get `HTTP 404`,
double-check the org name.

Every API call writes an audit line under `~/.sidestep/audit/` (macOS) or
`~/.local/state/sidestep/audit/` (Linux). The line records
`operation.id`, path/query params, response shape hash, status, duration,
and where the token was resolved from — never the token itself.

## Usage

```sh
sidestep --version
sidestep --help

sidestep auth login --token <v>            # store in keychain
sidestep auth login --stdin                # read token from stdin
sidestep auth status                       # report source + length
sidestep auth logout                       # remove from keychain

sidestep ops list [--filter <substring>]   # list operationIds
sidestep ops show <operationId>            # path, params, body shape

sidestep api <operationId> \                # invoke any spec operation
    [--param key=value ...]
    [--body '<json>']
    [--no-audit]
```

The `sidestep api` command reaches every operation in the StepSecurity
OpenAPI spec. Curated verbs (`sidestep runs list`, `detections suppress`,
etc.) are follow-on work; for now any operation is one `--param` away.

## Development

```sh
just build           # cargo build --workspace
just test            # cargo test --workspace --all-targets
just check           # fmt + clippy + cargo-deny
just sync-spec       # cargo xtask sync-spec — refresh vendored OpenAPI
just regen           # cargo xtask regen — rebuild sidestep-api
```

See [CLAUDE.md](CLAUDE.md) and [charter.md](charter.md) for design context,
and [docs/audit-trail-format.md](docs/audit-trail-format.md) for the
audit-trail JSONL schema.

## License

MIT — see [LICENSE](LICENSE).
