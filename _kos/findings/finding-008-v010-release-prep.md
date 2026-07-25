# Finding 008: v0.1.0 release prep — pagination, envelopes, panic guard, api-chain, docs

**Date:** 2026-07-24
**Context:** pre-release hardening pass (session directive: "do everything,
hold release-ready; composites gate on verb evidence"). Companion to
finding-007 (same session, spec sync).

## What shipped (5 commits, `2e4f89d..d4f20d9`)

1. **Transparent pagination** (`aae-orc-u7hy`): `list`/`search` follow
   `next_token` to exhaustion via a `Pager` gated on the spec declaring
   the param (runs + detections paginate; the other list ops are
   single-shot). Repeated-token and 500-page guards. `--limit` breaks
   the loop early — verified a satisfied limit never fetches the next
   page (wiremock `expect(0)`).
2. **Envelope corrections** — the release-blocking surprise: v0.1's
   `extract_items` did not match the spec's actual list envelopes for
   the two highest-traffic kinds. `getRunsDetails` wraps items in
   `workflow_runs` (not in the helper's key list) and detections nests
   the collection inside a `data` **object** (`data.detections[]`,
   where the helper only handled `data` as an array). Both fell through
   to "whole envelope as one record." `list run` / `list detection`
   were structurally broken against the live API and nobody noticed —
   consistent with the mining corpus showing curated verbs at near-zero
   real usage. `extract_cursor` similarly never matched the API's real
   `next_token` key, so audit `response.next_cursor` was always null.
3. **CEL panic guard** (`aae-orc-qvk9` mitigated): compile + evaluate
   run under `catch_unwind` with a thread-local-gated silent panic
   hook; a trailing `==` now yields the standard InvalidParam error
   instead of an abort + backtrace. Upstream issue still unfiled
   (ticket stays open for that).
4. **Chain on `api` passthrough** (F3 mining proposal #1):
   owner/customer resolve flag→env→config on the escape hatch, exactly
   like curated verbs; explicit `--param` records as `flag` source.
   The 17%-of-corpus constant-owner noise floor ends here.
5. **Docs + version**: README rewritten around the primitive surface
   (it predated the verb layer); `docs/permissions.md` ships the F5
   recommended patterns (read-only allowlist, gated `api`, never-
   allowlist set, GET-prefix caveat); workspace version 0.0.1 → 0.1.0.

Tests 127 → 139 (wiremock 6 → 12).

## Release pipeline dry-run

`release.yml` had zero run history since 2026-04-30 — first stable tag
should not be its maiden voyage. Dry-run via signed throwaway tag
`v0.0.1-rc1` (deleted after verification; formula overwrite self-heals
on next alpha). Result recorded in the session log / bd `na9z` sibling
notes.

## The release decision (user-ratified this session)

**v0.1.0 is held release-ready, not cut.** Raw materials for composite
verbs were assessed against the F3 mining doc: proposals #1/#6 are
surface completions (shipped / ticketed now); true composites (#2
harden-status n=9, #3 actions-inspect n=12, #5 detections-resolve n=3
template-exact) rest on one operator's 251-record corpus — below the
finding-001 threshold. The tag waits for the verb evidence; everything
else is done. Charter F6's "first v* tag once curated verbs are ready"
stands as written.

## Lessons

- **Zero-usage features hide structural breakage.** The envelope
  mismatches survived 12 weeks because nothing real exercised
  `list run`/`list detection` end-to-end; the wiremock harness tested
  the shapes we *assumed*. Fixtures must mirror the spec's response
  schemas, not invented envelopes. (The new tests now encode the
  spec-true shapes.)
- **A dormant release workflow is a liability, not an asset.** Exercise
  it before you need it.

## Affected artifacts

- nodes: `question-permissions-model` (patterns documented, granularity
  open), `question-audit-mining` (proposal #1 shipped; noise floor
  removed), `elem-primitives-over-composites` (envelope fix evidence).
- bd: `u7hy` closed, `qvk9` upstream-filing remains, new tickets for
  mining proposals #2/#5/#6/#7 + the release-cut anchor.
