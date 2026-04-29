# Contributing

## Quick start

```sh
just setup           # install nightly rustfmt + cargo-deny
just install-hooks   # lefthook pre-commit + pre-push
just check           # mirror CI quality gates locally
```

## Workflow

- Branch from `main`. Trunk-based until distribution lands.
- Commits follow Conventional Commits. See `.claude/rules/git-commits.md`.
- All commits SSH-signed. CI rejects unsigned commits.
- Open a PR; CI runs fmt, clippy, build, test, cargo-deny, and dependency
  review.

## Spec changes

If the StepSecurity OpenAPI spec changes upstream:

```sh
cargo xtask sync-spec         # fetch and update spec/ + sha256
cargo xtask diff-spec         # (forthcoming) summarize the diff
cargo xtask regen             # (forthcoming) regenerate sidestep-api
```

Open a PR with the spec bump separate from any CLI changes that depend
on it, where reasonable.

## Generated code

`crates/sidestep-api/` is regenerated from `spec/`. Do not hand-edit
generated source files; modify the spec or the generator config and
regenerate.

## Tests

- Unit tests: `#[cfg(test)] mod tests {}` alongside source.
- HTTP-level tests: `wiremock` against the SDK.
- Snapshot tests: `insta` for stable response renderings.
- CLI smoke tests: `assert_cmd` with a built binary.
