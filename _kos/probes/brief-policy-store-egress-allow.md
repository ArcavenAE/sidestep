# Probe Brief: Can sidestep let a blocked run reach an endpoint without a workflow edit?

**Date opened:** 2026-10-30
**Status:** desk phase COMPLETE, see `_kos/findings/finding-sidestep-0a17-policy-store-egress-without-workflow-edit.md`. The live phase (section 5) is not run; it needs a test tenant and an operator's go-ahead for writes there.

## Question

When Harden-Runner blocks a run's egress to an endpoint the run legitimately needs, the usual fix is a workflow edit: add the endpoint to `allowed-endpoints` and push. Could sidestep make the same change without touching the workflow file, for one run's workflow, a repository, or a runner cluster?

Three sub-questions:

1. Does the StepSecurity API offer any surface that changes enforced egress for a workflow, repository or cluster without a workflow change?
2. Does a stored policy apply when a workflow sets neither `use-policy-store` nor a `policy` input, on GitHub-hosted runners (the action) and on ARC runners (the daemonset)?
3. If a surface exists, what sidestep verb would wrap it, gated as a mutation and recorded in the audit trail, and what undoes it?

## Hypothesis

The Policy Store is the surface. A policy attached at workflow scope overrides broader scopes, so a dedicated workflow-scope policy can add one endpoint for one workflow and be undone by detaching it. Whether it takes effect without a workflow change depends on the runner type.

## Method

Desk phase, read-only, no tenant contact:

1. Read the vendored OpenAPI spec (`spec/stepsecurity-v1.yaml`; first read as vendored 2026-07-24 at ba3779b, re-read after the 2026-10-30 re-vendor at b103042, which added the policy read, delete and history operations) for every operation whose path names policies, baselines or endpoints.
2. Read the vendored vendor docs (`docs/research/stepsecurity-llms-full.txt`, vendored 2026-05-01 at ffe1427), sections "Policy Store", "Self-Hosted Runners" and the changelog entries for the Policy Store.
3. Compare each answer against sidestep's bedrock: primitives over composites, the ActionItem schema (`attach_policy` is already a kind), the audit trail schema, and the permissions doc's gating of `api post_*`.

Live phase, for later (section 5): on a test tenant only, with the operator's go-ahead.

## Success criteria

- Each sub-question answered from a named source, with what the source says and what it leaves open kept apart.
- A verb design that names its undo and its blast radius, or a statement that no safe verb exists.

## 5. Live phase (not run)

Read-only against any production tenant throughout. On a test tenant, with a throwaway repository and workflow:

1. A GitHub-hosted job with inline `egress-policy: block` and no `use-policy-store`. Attach a workflow-scope policy that allows one more endpoint. Expected from the docs: no effect.
2. The same job with `use-policy-store: true` and an API key, and no inline endpoints. Attach, re-run. Expected: the endpoint is reachable.
3. The same as 2 with inline `allowed-endpoints` as well as `use-policy-store: true`. Which wins is not documented.
4. An ARC job with no Harden-Runner step, cluster-scope policy in block mode, then a workflow-scope policy adding an endpoint. Expected: the workflow-scope policy wins (documented precedence).
5. An ARC job that carries the Harden-Runner step with inline block settings, under a workflow-scope store policy. Which wins is not documented.
6. Detach the workflow-scope policy after each case and re-run, to show the undo.
7. Attach a throwaway policy to the throwaway workflow and delete it without detaching. Record what the attachment list and the workflow's next run show, and confirm the history endpoint returns 404 after the delete.

Each case records the policy YAML, the attach and detach responses, the run's egress verdicts, and the audit trail lines sidestep wrote.
