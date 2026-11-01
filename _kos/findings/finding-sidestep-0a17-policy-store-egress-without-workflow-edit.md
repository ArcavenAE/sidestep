# finding-sidestep-0a17: the Policy Store can widen a workflow's egress without a workflow edit, on runners that fetch it

Status: desk finding. Sources are the vendored spec (re-read at develop ca2a767, the spec as re-vendored in b103042 on 2026-10-30) and the vendored vendor docs (2026-05-01); nothing was run against a tenant. Brief: `_kos/probes/brief-policy-store-egress-allow.md`.

Date: 2026-10-30. Revised 2026-11-01: the first draft read the spec vendored on 2026-07-24, which had four Policy Store operations and no delete. The 2026-10-30 re-vendor has seven, including a delete and a history read, and sections 1, 3 and 5 are rewritten against it.

## Why this matters

A blocked egress call usually costs a workflow edit, a review and a push before the job can run again. Where the runner fetches its policy from the Policy Store, the same change can be made centrally and undone centrally, and sidestep already reaches the operations that do it. Where the runner does not fetch, nothing in the API helps, and saying so early keeps a verb from promising what it cannot deliver.

## 1. The surface exists: the Policy Store

The vendored spec (re-vendored 2026-10-30, b103042) has seven Harden-Runner Policy Store operations:

| operation | operationId | what it does |
|---|---|---|
| `GET /github/{owner}/actions/policies` | `get_github_owner_actions_policies` | lists policies with their attachments, `allowed_endpoints` and `egress_policy` |
| `GET /github/{owner}/actions/policies/{policy_name}` | `get_github_owner_actions_policies_policy_name` | reads one policy |
| `POST /github/{owner}/actions/policies/{policy_name}` | `post_github_owner_actions_policies_policy_name` | creates a policy or partially updates an existing one |
| `DELETE /github/{owner}/actions/policies/{policy_name}` | `delete_github_owner_actions_policies_policy_name` | deletes a policy: idempotent (an absent name returns 200), and it removes the policy even while it is attached |
| `POST /github/{owner}/actions/policies/{policy_name}/attach` | `post_github_owner_actions_policies_policy_name_attach` | attaches a policy to workflows, repositories, the organization, or ARC clusters |
| `DELETE /github/{owner}/actions/policies/{policy_name}/attach` | `delete_github_owner_actions_policies_policy_name_attach` | removes the policy's attachments, keeping the policy; idempotent |
| `GET /github/{owner}/actions/policies/{policy_name}/history` | `get_github_owner_actions_policies_policy_name_history` | the changes to a policy and its attachments, newest first; 404 once the policy is deleted |

Five properties decide any design built on them:

- **One policy per scope.** Attaching a policy to a scope that already holds one returns 409 ("already has policy ... attached"). The vendor docs describe the UI as replacing the current attachment; the API, as specified, refuses.
- **Detach takes no target.** The DELETE carries only the policy name, and the docs say it removes all attachments. A policy attached to several scopes cannot be detached from one of them through this operation.
- **Delete does not detach, and it ends the history read.** The spec says the delete removes a policy "even while it is still attached" and tells the caller to "detach it first if you do not want to leave the attachment behind". The vendored docs (2026-05-01) describe the UI's delete as removing all attachments first; the two may disagree, and the spec is newer. The history is kept after a delete, but its endpoint returns 404 once the policy is gone, so a caller that wants it reads it first.
- **The most specific policy wins, whole.** Precedence is workflow, then repository, then organization, then cluster, and Harden-Runner picks the most specific one (docs, "Precedence"). Policies are not merged, so a workflow-scope policy must carry every endpoint the workflow needs, not only the new one.

Baselines (`.../baseline`, `.../jobs/baseline`, `.../clusters/{cluster}/baseline`) are read-only and carry the endpoints a job or scope has been seen to call. They are the input a new policy can be built from.

## 2. Whether a stored policy applies without a workflow change depends on the runner

- **GitHub-hosted runners, the action.** No. The docs say attaching is not enough: "the runner also needs to know to fetch policies from the Policy Store." On hosted runners that means the Harden-Runner step sets `use-policy-store: true` with an `api-key` (action 2.17.0 and later), or the older `policy` input, which needs `id-token: write`. A workflow that sets neither never reads the store, so no attachment changes what it enforces. Making such a workflow store-driven is a one-time workflow edit; after it, endpoint changes need none. With `use-policy-store: true` and no policy found, the action falls back to audit mode.
- **Custom VM images and self-hosted VM runners.** Yes, once the runner is set up: policy fetching is configured on the runner by a pre-job hook, "so no workflow changes are needed".
- **ARC runners, the daemonset.** Yes for jobs that carry no Harden-Runner step: the docs list attaching a policy as one of the two ways to block on ARC, and cluster is a store scope. Open: whether a job that does carry the step, with inline `egress-policy` and `allowed-endpoints`, follows a store policy or its own inline settings. The docs say only that a job-level block policy overrides the cluster-level Helm allowlist, which is a different mechanism from the store.
- **Also open, on every runner type:** whether inline `allowed-endpoints` and `use-policy-store: true` in one step combine, or one wins.

A policy is fetched at job start ("applied on the next workflow run that fetches the policy"), so a run already blocked is not unblocked. Its re-run is.

## 3. A verb, and its undo

The narrowest change that touches one workflow and nothing else is a dedicated workflow-scope policy:

1. Read the workflow's effective policy: list policies, find the most specific attachment that covers the workflow, and read that policy (GET) for its endpoints and mode. If none covers it, start from the job's baseline.
2. If a policy is already attached at workflow scope, stop. Editing it widens every scope it is attached to, and attaching a second returns 409. Report it as an ActionItem for a person instead.
3. Create a new policy, named for the workflow and the change, holding the effective endpoints plus the new one, with the same mode.
4. Attach it to that one workflow.

**Undo: detach, then optionally delete.**

- **Detach is the undo.** The new policy is attached nowhere else, so detach removes exactly the attachment step 4 made, and the workflow falls back to the policy that covered it before. Detach is idempotent, so an undo that is retried does no harm.
- **Delete is cleanup, never the undo.** Deleting first would remove the policy and may leave its attachment behind (the spec's warning), so the workflow could be left pointing at a policy that no longer exists. A cleanup step therefore runs only after the detach, and in this order: read the policy (GET) and confirm it has no attachments; read its history and write it to sidestep's audit trail, since the endpoint returns 404 afterwards; then delete.
- Leaving a detached policy in the store is also safe: its name says what it was, and its history stays readable. Whether cleanup runs is the operator's choice, not a default.

Changes that are not narrow, and why the verb should refuse them:

- **Editing an existing policy** widens every workflow, repository and cluster it is attached to.
- **Repository, organization or cluster scope** is a legitimate operator choice, but its blast radius is the scope. It belongs to a person's explicit flag, never a default.
- **A hosted workflow without `use-policy-store`.** Steps 1 to 4 succeed and change nothing at runtime. The verb should read the workflow file and refuse, saying a one-time workflow edit is needed first.

Fit with sidestep's bedrock:

- **Primitives over composites.** This is a composite (list, create, attach). By that rule it waits for audit-trail evidence. Today it is reachable as three `sidestep api` calls, which the permissions doc already gates as mutations.
- **ActionItem.** `attach_policy` is already a kind. `plan` can emit the steps above as an ActionItem with its undo, for a person to run.
- **Audit trail.** Each call already writes one JSONL line with its operationId. A verb adds nothing there, except that the undo should name the `trace_id` of the change it reverses.
- **Permissions.** There is no write-guard yet (`question-permissions-model` is open). A mutating verb would be the first one, so the guard is part of building it.

## 4. What was not established

- The two open precedence questions in section 2.
- Whether the API, unlike the UI, really refuses a second attach rather than replacing it. The 409 is in the spec. It was not observed.
- Whether a partial update can remove an endpoint, or only add and replace.
- What a delete of an attached policy leaves behind: no attachment (the UI's documented behavior) or a dangling one (the spec's warning), and what a job under a dangling attachment then enforces.

Each is a case in the brief's live phase, which needs a test tenant and an operator's go-ahead for writes there.

## 5. Side note: inventory drift

`docs/research/noun-inventory.md` counts 12 Policy Store operations (5 GET, 4 POST, 3 DELETE), and it has not changed since 2026-05-01. Its Policy Store family is wider than the Harden-Runner policy operations in section 1: its table also counts rules, run policies, policy-driven PR configs and policy evaluations. So the two counts do not measure the same set, and the 2026-10-30 re-vendor, which took the spec from 130 to 243 operations, will have moved the inventory's own numbers too. Worth a recount against the current spec when it is next used.
