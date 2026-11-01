# finding-sidestep-0a17: the Policy Store can widen a workflow's egress without a workflow edit, on runners that fetch it

Status: desk finding. Sources are the vendored spec and the vendored vendor docs; nothing was run against a tenant. Brief: `_kos/probes/brief-policy-store-egress-allow.md`.

Date: 2026-10-30.

## Why this matters

A blocked egress call usually costs a workflow edit, a review and a push before the job can run again. Where the runner fetches its policy from the Policy Store, the same change can be made centrally and undone centrally, and sidestep already reaches the operations that do it. Where the runner does not fetch, nothing in the API helps, and saying so early keeps a verb from promising what it cannot deliver.

## 1. The surface exists: the Policy Store

The vendored spec (1.0.0, vendored 2026-07-24) has four Harden-Runner Policy Store operations:

| operation | operationId | what it does |
|---|---|---|
| `GET /github/{owner}/actions/policies` | `get_github_owner_actions_policies` | lists policies with their attachments, `allowed_endpoints` and `egress_policy` |
| `POST /github/{owner}/actions/policies/{policy_name}` | `post_github_owner_actions_policies_policy_name` | creates a policy or partially updates an existing one |
| `POST /github/{owner}/actions/policies/{policy_name}/attach` | `post_github_owner_actions_policies_policy_name_attach` | attaches a policy to workflows, repositories, the organization, or ARC clusters |
| `DELETE /github/{owner}/actions/policies/{policy_name}/attach` | `delete_github_owner_actions_policies_policy_name_attach` | removes the policy's attachments, keeping the policy |

Four properties decide any design built on them:

- **One policy per scope.** Attaching a policy to a scope that already holds one returns 409 ("already has policy ... attached"). The vendor docs describe the UI as replacing the current attachment; the API, as specified, refuses.
- **Detach takes no target.** The DELETE carries only the policy name, and the docs say it removes all attachments. A policy attached to several scopes cannot be detached from one of them through this operation.
- **No delete.** The spec has no operation that deletes a policy. The UI has one. A policy created through the API stays in the store after it is detached.
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

1. Read the workflow's effective policy: list policies, find the most specific attachment that covers the workflow, and take its endpoints and mode. If none covers it, start from the job's baseline.
2. If a policy is already attached at workflow scope, stop. Editing it widens every scope it is attached to, and attaching a second returns 409. Report it as an ActionItem for a person instead.
3. Create a new policy, named for the workflow and the change, holding the effective endpoints plus the new one, with the same mode.
4. Attach it to that one workflow.

**Undo:** detach the new policy. It is attached nowhere else, so detach removes exactly the attachment step 4 made, and the workflow falls back to the policy that covered it before. The detached policy remains in the store (no delete in the spec); its name says what it was.

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

Each is a case in the brief's live phase, which needs a test tenant and an operator's go-ahead for writes there.

## 5. Side note: inventory drift

`docs/research/noun-inventory.md` counts 12 Policy Store operations (5 GET, 4 POST, 3 DELETE). The vendored spec has the 4 in section 1 for Harden-Runner policies. The rest of that count appears to come from neighboring families: run policies, policy-driven PR configs and baselines. The inventory may predate a spec sync. Worth a recount when it is next used.
