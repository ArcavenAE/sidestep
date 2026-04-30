# sidestep — Rust CLI for the StepSecurity API

default:
    @just --list

# ─── Build & Run ───────────────────────────────────────

build:
    cargo build --workspace

build-release:
    cargo build --workspace --release

run *args:
    cargo run --bin sidestep -- {{args}}

# ─── Test ──────────────────────────────────────────────

test:
    cargo test --workspace --all-targets

# Doctests, skipping the generated sidestep-api crate (its doctests come
# from the OpenAPI spec and are illustrative, not verified).
test-doc:
    cargo test --workspace --doc --exclude sidestep-api

# ─── Quality Checks ────────────────────────────────────

check: check-fmt check-clippy check-deny

check-fmt:
    cargo +nightly fmt --all -- --check

check-clippy:
    cargo clippy --workspace --all-targets --all-features -- -D warnings

check-deny:
    cargo deny check advisories licenses bans

lint: check

# ─── Formatting ────────────────────────────────────────

fmt:
    cargo +nightly fmt --all

# ─── CI Mirror ─────────────────────────────────────────

ci: check-fmt check-clippy build check-deny test test-doc

# ─── Spec / Codegen ────────────────────────────────────

# Fetch the upstream OpenAPI spec and update the vendored copy.
sync-spec:
    cargo xtask sync-spec

# Regenerate sidestep-api from the vendored spec (not yet wired).
regen:
    cargo xtask regen

# Diff the vendored spec against upstream (not yet wired).
diff-spec:
    cargo xtask diff-spec

# ─── Setup ─────────────────────────────────────────────

setup:
    rustup component add clippy
    rustup toolchain install nightly --component rustfmt
    cargo install cargo-deny
    @echo "Optional: brew install lefthook && just install-hooks"

install-hooks:
    lefthook install

# ─── Maintenance ───────────────────────────────────────

clean:
    cargo clean
