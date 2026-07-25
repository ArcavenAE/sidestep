# sidestep

Rust CLI for the [StepSecurity](https://www.stepsecurity.io/) API. Built
from a vendored OpenAPI spec, designed for LLM-driven workflows, with a
local audit trail intended to be mined for meta-action patterns.

> Status: usable. Auth (env / keyring / config), the v0.1 primitive verb
> set (`list` / `get` / `search` / `filter` / `enrich` / `emit`) with
> transparent pagination, spec-aware operation dispatch
> (`sidestep api <operationId>` reaches all 130 spec operations), and
> the audit trail are all wired.

## Why sidestep

- **Spec-driven.** `sidestep-api` is generated from
  `spec/stepsecurity-v1.yaml`. Update the spec, regenerate, ship.
- **SDK-backed.** The same SDK that powers the CLI will power a future
  MCP server. Auth, retries, pagination, audit, and redaction live in
  one place.
- **Agent-first.** JSON-lines output, predictable verb shape, stable
  operation IDs, structured audit trail, and a documented permission
  model for agent harnesses ([docs/permissions.md](docs/permissions.md)).
- **Audit as feature.** Every API call emits a JSONL line locally; a
  future tooling pass can mine those traces to propose meta-actions
  that compose multiple primitive calls.

## Install

sidestep publishes three Homebrew channels. They install as different
binary names and coexist side by side:

| Formula | Binary | Moves on | Version shape |
|---|---|---|---|
| `sidestep` | `sidestep` | tagged releases only | `0.1.0` |
| `sidestep-rc` | `sidestep-rc` | every merge to `main` | `0.1.0-rc.N` |
| `sidestep-a` | `sidestep-a` | every push to `develop` | `alpha-20260725-…` |

`brew upgrade sidestep` only ever takes you tag-to-tag; nothing lands on
the stable channel from a branch push.

```sh
brew tap arcavenae/tap                        # one-time
brew install arcavenae/tap/sidestep           # stable
brew install arcavenae/tap/sidestep-rc        # release candidates
brew install arcavenae/tap/sidestep-a         # bleeding edge
```

### Upgrade

```sh
brew update
brew upgrade arcavenae/tap/sidestep           # (or sidestep-rc / sidestep-a)
```

### Uninstall

```sh
brew uninstall arcavenae/tap/sidestep
brew untap arcavenae/tap                      # optional, removes the tap
```

### Install with mise

[mise](https://mise.jdx.dev/) is a polyglot version manager. It reads a per-project `mise.toml`, pulls the exact signed binary from GitHub Releases, and verifies GitHub Artifact Attestations natively — no Homebrew tap required.

**Stable:**

```bash
mise use github:ArcavenAE/sidestep@latest
sidestep --version
```

*(First stable `v*` release pending — until it's cut, `latest` resolves to the current alpha even without the prerelease opt-in below.)*

**Prerelease channels** — add `prerelease = true` to opt in per-tool.
Caveat: mise cannot distinguish the alpha channel from the rc channel —
`prerelease = true` resolves to the newest prerelease of either kind
(`alpha-…` from develop or `v…-rc.N` from main). For channel-accurate
installs use Homebrew; mise is best for stable-or-newest-prerelease:

```toml
# mise.toml
[tools]
"github:ArcavenAE/sidestep" = { version = "latest", prerelease = true }
```

```bash
mise install
sidestep --version
```

**macOS troubleshooting** — mise downloads over HTTP libraries that do not set `com.apple.quarantine`, so notarized binaries launch without a Gatekeeper prompt in the common case. If a quarantine-aware host (some IDEs, launchers, or file-manager copies) propagates the xattr into the mise install, clear it once:

```bash
xattr -d com.apple.quarantine "$(mise which sidestep)"
```

macOS arm64 only for now, matching the Homebrew formula.

### Build from source

```sh
git clone https://github.com/ArcavenAE/sidestep.git
cd sidestep
cargo build --release
./target/release/sidestep --version
```

macOS arm64 only for now. Other platforms can build from source.

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

### Set your org once

Most StepSecurity endpoints take an `{owner}` (GitHub org) or
`{customer}` path parameter, and both are constant for the lifetime of
a token. Set them once instead of passing a flag on every call:

```sh
sidestep auth login --owner your-org          # persisted in config
# or per-shell:
export SIDESTEP_OWNER=your-org
```

Every verb (including `sidestep api`) then resolves them through
**flag → `SIDESTEP_OWNER`/`SIDESTEP_CUSTOMER` env → config**, and the
audit trail records which source supplied the value. `sidestep config
show` reports the current defaults.

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

### Primitives — compose by stream

The v0.1 surface is a primitive algebra: each verb reads or writes
`_kind`-tagged JSON-lines, so verbs compose with `|`. Nine kinds:
`run`, `detection`, `check`, `policy`, `rule`, `incident`, `audit_log`,
`repo`, `threat_intel`.

```sh
sidestep list <kind> [--limit N] [--since 24h]   # fetch → JSONL stream
sidestep get <kind> <id>                         # one record by id
sidestep search <kind> <text>                    # substring match on name field
sidestep filter --where '<CEL>' [--explain]      # predicate over stdin stream
sidestep enrich --with <recipe> [--policies f]   # join/derive fields
sidestep emit --format {jsonl|md}                # sink / render
```

`list` and `search` follow the API's pagination transparently — you get
the full result set (or stop early with `--limit N`), never a silently
truncated first page.

Real composition, from the triage recipe:

```sh
sidestep list detection --since 168h \
  | sidestep filter --where 'severity in ["critical", "high"] && status == "open"' \
  | sidestep emit --format md
```

Predicates are [CEL](https://cel.dev/): fields bind at the top level
(`severity == "critical"`), `*_at` fields compare as timestamps
(`created_at > now - duration("24h")`), and `filter --explain` shows the
available columns for a kind when a predicate doesn't parse.

### Spec escape hatch — every operation, by id

```sh
sidestep ops list [--filter <substring>]   # list operationIds
sidestep ops show <operationId>            # path, params, body shape

sidestep api <operationId> \               # invoke any spec operation
    [--param key=value ...]
    [--body '<json>']
    [--no-audit]
```

`sidestep api` reaches all 130 operations in the vendored spec —
including surfaces the curated kinds don't cover yet (developer-mdm,
secure-registry, api-keys, run-policies). It resolves `owner`/`customer`
through the same chain as the curated verbs. Composite verbs (`triage`,
`inventory`, …) are v0.2 work, designed from audit-trail evidence
rather than intuition — see `docs/research/`.

### Auth & config

```sh
sidestep auth login --token <v>            # store token in keychain
sidestep auth login --stdin                # read token from stdin
sidestep auth login --owner <slug>         # persist org default
sidestep auth status                       # token + owner/customer + sources
sidestep auth logout                       # remove from keychain
sidestep config show|path|set|unset        # manage config.toml
```

### Agent harnesses

Running sidestep under Claude Code or another agent harness? See
[docs/permissions.md](docs/permissions.md) for recommended permission
patterns (read-only allowlist vs. gated mutations).

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
