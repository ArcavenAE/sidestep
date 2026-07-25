# finding-009 — Build identity stamping (channel + commit in --version and audit)

Date: 2026-07-25 · bd: aae-orc-c714 (closed) · commit: 30922da (on develop,
released as alpha-20260725-055851-f78041e)

## What was learned

1. **CARGO_PKG_VERSION is channel-blind.** After the three-channel
   gitflow restructure, `sidestep`, `sidestep-rc`, and `sidestep-a` all
   compiled with workspace version `0.1.0` and were indistinguishable in
   `--version` output and audit lines — while `brew list --versions`
   correctly knew each channel's tag. The binary was the only party that
   couldn't say what it was. Any repo adopting multi-channel distribution
   from one Cargo/Go version field will hit this.

2. **Cost of per-line identity is noise-level, measured.** Real corpus:
   1,328 lines / ~2.5 months, avg 875 bytes/line. A
   `build_id: "v0.1.0-rc.1+g337e358"` field ≈ 32 bytes ≈ 3.6%/line
   (~40 KB/yr). Each line already spends 72+ chars on two UUIDv7s.
   Compression at rest reduces repeated constants to ~nothing — compress,
   don't strip semantics.

3. **Per-line beats per-file header for mineable JSONL.** The daily-file
   rotation offered a natural "emit rarely" spot, but a header breaks line
   independence (any `grep | jq` loses it), and two binaries can append to
   the same daily file (alpha at 9am, stable at 3pm — one header would
   misattribute half the lines). Line-level self-description is the price
   of a composable stream (cli-philosophy: compose by stream).

4. **No chicken-and-egg for the CI path.** All three workflows compute
   their tag BEFORE `cargo build`, so the tag is injectable as env at
   build time. The classic trap (a commit can't contain its own hash)
   doesn't apply — we stamp the *binary*, not the source. Real edge
   cases are mundane: dirty local trees (`-dirty` suffix), gitless
   builds (fallback `unknown`).

5. **Implementation gotchas** (Rust/clap specifics):
   - `build.rs` in the SDK crate + `cargo:rustc-env` makes the id a
     compile-time const consumable by both SDK (audit) and CLI
     (`--version`) — one build script, exported as
     `sidestep_sdk::{BUILD_ID, FULL_VERSION}`.
   - clap 4 without its `string` feature needs `&'static str` for
     `.name()`; `Box::leak` of argv0 at startup is the cheap fix.
   - Displaying the argv[0] basename means each channel binary (and any
     symlink) introduces itself by its installed name; the stamped
     build id stays authoritative underneath.
   - `cargo:rerun-if-changed=../../.git/HEAD` keeps local dev stamps
     fresh across commits.

## Resolution chain (what was stamped where)

| Build | build_id |
|---|---|
| CI (any channel) | the channel tag: `alpha-YYYYMMDD-HHMMSS-<sha7>` / `v<ver>-rc.N+g<sha7>` / `v<ver>+g<sha7>` via `SIDESTEP_BUILD_ID` env |
| local dev | `dev+g<sha7>[-dirty]` via git in build.rs |
| gitless (tarball) | `unknown` |

Emitted as additive schema-v2 field `invocation.build_id` (docs/
audit-trail-format.md updated); printed by `--version` and the bare
no-subcommand banner.

## Verification (B12 scope qualifier: distribution-verified)

Alpha run 30146683689's Verify step printed
`sidestep-darwin-arm64 0.1.0 (alpha-20260725-055851-f78041e)` — stamped
id + argv0 naming confirmed in the released, signed, notarized artifact,
same session. Tests: +1 `--version` smoke (tests/version.rs), +1 audit
assertion; 173 total pass.

## Follow-on

The F3 mining surface can now stratify the corpus by channel/commit —
which the audit-stream-sharing design (see
`_kos/ideas/audit-stream-sharing.md`) lists in its bundle whitelist.
The channel-preference resolver idea (~/.config/skills/tools.yaml,
discussed same session, unimplemented) can be validated after the fact
from audit build_id once shipped.
