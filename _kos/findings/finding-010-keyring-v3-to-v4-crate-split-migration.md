# finding-010: keyring v3 to v4 is a crate split, not a feature rename

Status: reference finding. sidestep is the first of three CLIs (sidestep,
bloomctl, stave) to move keyring v3 to v4; bloomctl and stave replay this
finding rather than rediscover it.

Date: 2026-09-18. bd: `aae-orc-zb5ar`. Plan of record:
`director/_bmad-output/keyring-v3-v4-migration-plan-2026-09-18.md`.

## Why this matters

The three CLIs pinned `keyring = "3"` with an explicit
`features = ["apple-native", "linux-native"]` list. The dependency-currency
task read as "v4 renamed those features, find the new names." That premise is
wrong and the remedy it implies (hunt for replacement feature names) does not
exist. Getting the real shape recorded once saves the other two repos from the
same false start.

## What v4 actually changed

keyring v4 did not rename the platform features. It split the crate:

- The library and API moved into a new crate, `keyring-core` (v1.0.0).
- Each platform backend became its own store crate: `apple-native-keyring-store`
  (macOS), `zbus-secret-service-keyring-store` (Linux D-Bus secret service),
  `windows-native-keyring-store`.
- The `keyring` crate is now, in the maintainer's words, "just a sample app."
  Its default `v1` feature re-exposes a v1-compatible `Entry` facade over
  `keyring-core`, so a caller that uses only the simple surface keeps working
  with no code change.

There is no 1:1 feature substitution. The correct move is to enable the `v1`
facade (the default) or depend on `keyring-core` plus store crates directly.

## The remedy (Path A, the v1 facade)

One line in the workspace-root `Cargo.toml`:

```
-keyring = { version = "3", features = ["apple-native", "linux-native"] }
+keyring = "4"
```

Drop the explicit feature list; keyring 4's default `v1` feature supplies the
macOS Keychain backend via `apple-native-keyring-store`. The SDK crate's
`keyring.workspace = true` line needs no edit. Then `cargo update -p keyring`.

Path B (depend on `keyring-core` plus explicit store crates and call
`keyring_core::set_default_store`) buys per-entry credentials and non-default
stores. None of the three CLIs need that today. Path A is the choice.

## Result for sidestep: no auth-module code change

Our keyring surface is fully covered by the v1 facade. sidestep uses only
`keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER)`, `set_password`,
`get_password`, `delete_credential`, and the single `Err(keyring::Error::NoEntry)`
arm (`crates/sidestep-sdk/src/auth.rs`). All are present and unchanged in v4's
v1 facade; `NoEntry` is unchanged. No method the v4 facade dropped is used, and
there is no exhaustive `match` on `keyring::Error` (which would break on v4's new
variants); the one `NoEntry` arm has a fallback, so new variants land safely.

The migration compiled with zero source edits. Green on this host (macOS,
Apple Silicon), all from a Cargo.toml + Cargo.lock change only:

- `cargo build --workspace` clean
- `cargo clippy --workspace --all-targets -- -D warnings` clean
- `cargo test --workspace`: 160 passed, 0 failed
- `cargo deny check`: advisories, bans, licenses, sources all ok

## Resolved dependency shape (host: macOS)

```
keyring v4.2.0
  apple-native-keyring-store v1.0.2
    keyring-core v1.0.0
    security-framework v3.7.0
  keyring-core v1.0.0
```

`cargo update -p keyring` moved v3.6.3 to v4.2.0, added keyring-core v1.0.0,
and (macOS) moved security-framework 2.11.1 to 3.7.0 under the store crate.
The `cargo update` add/remove summary lists the Linux and Windows store crates
too, because Cargo.lock records every platform; `cargo tree -p keyring` on the
host confirms `apple-native-keyring-store` is the active macOS backend.

## Local Keychain round-trip: verified

keyring v4, under a throwaway service (`sidestep-keyring-migration-test`) so the
real `sidestep`/`default` entry is untouched, in a single process:
`Entry::new` -> `set_password` -> `get_password` (read-back equal) ->
`delete_credential` -> `Entry::new` again -> `get_password` returns
`Err(NoEntry)`. Passed; no leftover keychain item; no GUI prompt (a single
process is trusted for the item it just created).

## The one thing the docs cannot answer: cross-major read-back

Primary sources confirm the v1 facade keeps the API identical. They do NOT
state that a Keychain item written by v3's `apple-native` reads back under v4's
`apple-native-keyring-store` (same service/account attribute mapping). This is
the only place the upgrade could surprise an existing user, and it is settled by
measurement, not assertion:

- With env isolated (`SIDESTEP_API_TOKEN` unset, `SIDESTEP_CONFIG` pointed at a
  nonexistent file, so only keyring can satisfy the chain), run v4 `auth status`
  against the existing v3-written entry.
- Reads back and reports `source: keyring`: the upgrade is transparent; existing
  users keep their stored token.
- Returns "no token configured": users re-authenticate once after upgrade. That
  is acceptable for a credential CLI but must be documented as a one-line upgrade
  note.

RESULT: transparent upgrade (measured 2026-09-18). The director ran a read-only
`auth status` on the built v4 binary with env isolated (`SIDESTEP_API_TOKEN`
unset, `SIDESTEP_CONFIG` nonexistent). It reported `source: keyring` (token
length only, secret never surfaced). The v3-written Keychain entry reads back
under v4 with no re-authentication and no macOS Keychain prompt. No upgrade note
is needed. bloomctl and stave carry the same measurement step; each holds a
different vendor credential, so each is measured on its own.

## Linux caveat (recorded, not chased)

Under Path A the Linux backend changes from `linux-keyutils` (kernel session
keyring, v3's `linux-native`) to `zbus-secret-service-keyring-store` (D-Bus
secret service, v4's v1 default). Different backend, different persistence
semantics. Moot for a macOS fleet with Linux compile-only validation. If Linux
keyutils parity is ever required, that is a keyring-core plus
`linux-keyutils-keyring-store` dependency and a separate Linux-host task.

## Replay checklist for bloomctl and stave

1. Root Cargo.toml: `keyring = "4"` (drop the feature list). SDK crate
   `keyring.workspace = true` unchanged. (bloomctl root:45, stave root:49.)
2. `cargo update -p keyring`.
3. Expect no auth-module change; if clippy or tests surface a delta, apply it
   against the v1 facade, not keyring-core.
4. Green: build, clippy `-D warnings`, workspace tests, cargo-deny.
5. Local Keychain round-trip under a throwaway service.
6. Cross-major read-back measurement (operator/director step; do not touch the
   live tenant).
7. Dispose of the Renovate bare-bump PR (comment linking this work, then close;
   the bare bump renames nothing and cannot merge as filed).
8. Branch targets: bloomctl and stave have `main` only (no develop), PR into
   main. stave follows `aae-orc-ydto` (named profiles, same auth file), does not
   race it.

## Sources

Primary, byte-verified in the plan of record: keyring v4.0.0 release notes
("just a sample app," use keyring-core), v4.2.0 Cargo.toml (`default = ["v1"]`),
v3.6.2 Cargo.toml (`apple-native`/`linux-native`, no default), v4 `src/v1.rs`
(the facade Entry surface), keyring-core `lib.rs`/`error.rs`. Repo moved
`hwchen/keyring-rs` to `open-source-cooperative/keyring-rs`.
