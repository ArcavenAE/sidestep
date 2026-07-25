# Finding 007: First real upstream spec sync — B3 pipeline holds, with one new pre-pass

**Date:** 2026-07-24
**Brief:** `_kos/probes/brief-spec-sync-upstream-update.md`
**Question:** StepSecurity updated their published API. Can sidestep absorb
the update through the mechanical sync-spec → regen → test pipeline it was
built around?

## Answer

**Yes.** One session, one small xtask change, all gates green. The
sync-spec → regen → build → test path absorbed a 34% growth in the API
surface with zero hand-edits to the vendored spec and zero changes to
hand-written SDK/CLI code.

## What the upstream update contained

- 97 → 130 operations (83 → 107 paths). **Purely additive** — zero
  operations removed or renamed; existing curated-verb surface untouched.
- New feature families: `developer-mdm` (devices, policies, profiles,
  compliance, agent-skills, ai-agents, brew-packages), `secure-registry`
  (controls, audit-logs), API-key management (`/{customer}/api-keys`,
  `/github/{owner}/actions/api-keys`), run-policies CRUD, harden-runner-agent
  release listings, threat-intel `compromised-components`.
- Vendored spec: +4874/−1669 lines; sha re-pinned; sanitizer caught 2
  secret-shaped examples; 100 operationIds synthesized (was 78).

## What broke, and the fix

Progenitor 0.14 panicked: `missing path name mapping skill_key`.

Root cause: `GET /{customer}/developer-mdm/agent-skills/{skill_key}`
declares **two parameters named `skill_key`** — a required path param and
an optional query param (upstream's escape hatch for composite keys
containing `/` that URL-encode poorly in paths; the query variant takes
precedence server-side). Progenitor cannot map the colliding names.

Fix: **pre-pass 4**, `drop_shadowing_non_path_params`, in `xtask regen` —
same philosophy as pre-passes 1–3 (accommodate the quirk in the in-memory
model; never modify the vendored YAML; keep the canonical form). We keep
the required path param and drop the colliding query duplicate. Renaming
was rejected because the parameter `name` is the on-wire query key — a
rename would silently send a wrong parameter. Exactly 1 collision existed
across all 130 operations.

**Recorded limitation:** the generated client loses the query-string
escape hatch for `skill_key`. If a real composite key defeats
percent-encoded path transmission, revisit (progenitor-side ident rename,
or a curated-verb workaround).

## Verification

- `cargo build --workspace` clean; clippy clean; **127/127 tests green**
  (unchanged count — the update is additive, so no existing test moved);
  `cargo deny` ok; nightly fmt clean after formatting the regenerated file.
- `sidestep ops list` reports 130 operations; new families reachable via
  `sidestep api <opId>` (B2's escape hatch) with no further work.
- Generated client: 27.6k → ~38.9k lines, committed per B2.

## Process notes

1. **fmt gotcha:** prettyplease output ≠ nightly rustfmt style. Post-regen,
   `cargo +nightly fmt` must run before the fmt gate passes. Candidate for
   folding into `xtask regen` itself.
2. **`diff-spec` gap is real:** B3 designed spec-change review around
   `cargo xtask diff-spec`; it is still a stub (`not yet implemented`).
   This probe hand-rolled the operation-set diff in Python. First real
   sync = first real demand signal. bd ticket filed.
3. **Charter drift observed, handled per charter-light-touch:** B2/B3 prose
   says "three pre-passes" and "97 operations" — now stale. Nodes updated;
   charter prose left for the renderer (F22 / aae-orc-gptl).

## Strategic note

The new `developer-mdm/agent-skills` surface (skill inventory across
devices with provenance, SKILL.md content-hash divergence, and
shell-injection/risk flags) is directly relevant to the orc's own skill
distribution work (sideshow, F24) and to agent-fleet governance — a
vendor-side complement to the known-defects registry idea. Worth a look
when F24's doctor layers come back around.

## Affected nodes

- `elem-vendored-spec` — evidence: first real sync exercised end-to-end.
- `elem-codegen-via-progenitor` — three pre-passes → four; op count updated.
