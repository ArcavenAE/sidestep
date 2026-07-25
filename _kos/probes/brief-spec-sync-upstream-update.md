# Probe Brief: Does the B3 spec-sync pipeline absorb a real upstream API update?

**Date opened:** 2026-07-24
**Status:** COMPLETE — see `_kos/findings/finding-007-first-upstream-spec-sync.md`.
Hypothesis confirmed: pipeline absorbed the update; one new spec quirk
(same-name path/query param collision) handled by a fourth pre-pass.

## Question

StepSecurity has updated their published OpenAPI spec. sidestep was built
(B2 + B3) with the explicit intent that upstream spec changes are absorbed
mechanically: `cargo xtask sync-spec` re-vendors + re-pins, `cargo xtask
regen` reprojects the client through progenitor's three pre-passes, and the
existing test surface (127 tests incl. the B8 wiremock harness) catches
breakage. This is the first real upstream update since scaffold — does the
pipeline hold?

## Hypothesis

The pipeline absorbs the update with no manual spec surgery: sync-spec +
regen complete, the workspace builds, clippy + tests stay green. Where the
spec adds/removes/renames operations, `diff-spec` reports them and the
generated client tracks them; hand-written SDK/CLI code only breaks if an
operation the curated verbs depend on (runs/detections/policies/rules/…)
changed shape.

## Method

1. `cargo xtask sync-spec` — fetch upstream, update `spec/stepsecurity-v1.yaml`
   + `.sha256`.
2. `cargo xtask diff-spec` (first real use) + git diff — characterize the
   upstream change: added / removed / changed operations.
3. `cargo xtask regen` — reproject `sidestep-api`.
4. Build + clippy + full test suite.
5. Assess blast radius on curated verbs (9-kind table, enrich recipes,
   chain-tracked params owner/customer).

## Success signal

Green build + tests with only generated-code churn, OR a precise list of
hand-written call sites that need updating (which itself validates the
pipeline's design: breakage surfaces at compile time, not runtime).

## Timebox

~1 session. If progenitor's pre-passes fail on a new spec quirk, capture the
quirk as a finding and stop rather than patching blind.
