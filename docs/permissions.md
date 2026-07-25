# Permission Patterns for Agent Use

sidestep is designed to be invoked by agents (Claude Code, other
harnesses that gate shell commands by prefix). This page documents the
recommended permission grants. The organizing principle: **read-only
verbs are safe to allowlist broadly; mutations go through the spec
escape hatch and stay gated.**

## The risk model

- Every curated primitive (`list`, `get`, `search`, `filter`, `enrich`,
  `emit`) and the discovery surface (`ops list`, `ops show`,
  `auth status`, `config show`) is **read-only** against the API — GET
  requests or purely local stream transforms.
- The only way to mutate anything (resolve a detection, create a
  policy, rotate an API key, delete an MDM profile) is
  `sidestep api <operationId>` with a POST/PUT/DELETE operation.
- `auth login`, `auth logout`, `config set`, `config unset` mutate
  **local** state (keychain + config file), not the API.

This split is deliberate: an agent doing triage needs the whole
read-only surface fluidly, while anything that changes your security
posture deserves a human in the loop.

## Recommended Claude Code settings

Add to `.claude/settings.json` (project) or your user settings:

```json
{
  "permissions": {
    "allow": [
      "Bash(sidestep list:*)",
      "Bash(sidestep get:*)",
      "Bash(sidestep search:*)",
      "Bash(sidestep filter:*)",
      "Bash(sidestep enrich:*)",
      "Bash(sidestep emit:*)",
      "Bash(sidestep ops:*)",
      "Bash(sidestep auth status)",
      "Bash(sidestep config show)",
      "Bash(sidestep config path)"
    ]
  }
}
```

This allows the full triage surface without prompts. `sidestep api …`
deliberately stays un-allowlisted: each invocation prompts, and the
operator sees the operationId before it runs.

## If you want `api` reads without prompts

The spec's GET operations are read-only, but Claude Code prefix rules
cannot distinguish HTTP methods — `Bash(sidestep api:*)` would also
allow `api delete_customer_developer_mdm_profiles_profile_id`. Two
workable positions:

1. **Keep `api` gated** (recommended default, the settings above).
   Cost: one prompt per passthrough call.
2. **Allowlist specific read operations** you use routinely:

   ```json
   "Bash(sidestep api getRunsDetails:*)",
   "Bash(sidestep api getSecuritySummary:*)",
   "Bash(sidestep api get_github_owner_actions_baseline:*)"
   ```

   The synthesized operationId convention helps here: spec operations
   without a hand-written id are named `{method}_{path}`, so
   `sidestep api get_*` prefixes are GETs. Hand-named ids
   (`getRunsDetails`, `getSecuritySummary`) don't follow the
   convention mechanically — check `sidestep ops show <id>` before
   allowlisting.

## Never allowlist

- `Bash(sidestep api:*)` — see above; it spans every mutation in the
  spec.
- `Bash(sidestep auth login:*)` — writes credentials; a prompted,
  human-typed operation by design.

## Deny-list hardening (optional)

For defense in depth in shared or long-running environments:

```json
{
  "permissions": {
    "deny": [
      "Bash(sidestep api post_*)",
      "Bash(sidestep api put_*)",
      "Bash(sidestep api delete_*)"
    ]
  }
}
```

Deny rules win over allow rules, so this stays safe even if a broad
`api` allow lands later by accident.

## Open questions (charter F5)

Whether the operationId is the right long-term permission axis — vs. a
curated-verb axis (`detections:*`) or an HTTP-method axis — is an open
frontier question. If sidestep grows first-class mutating verbs in
v0.2 (e.g. `detections resolve`), each will be its own prefix and this
page will document its blast radius before anything is allowlisted.

## Cross-references

- `charter.md` F5 — permissions model frontier question
- `.claude/rules/cli-philosophy.md` — agent-first CLI design rules
- `docs/audit-trail-format.md` — every call (allowed or prompted) is
  audited locally either way
