# StepSecurity Value Propositions — Map

Source: `docs/research/stepsecurity-llms-full.txt` (711KB) including
the changelog (40+ entries since 2022), product-area docs, and
Harden-Runner feature matrix. Captured session-041, 2026-05-01.

The thesis: **before designing curated CLI verbs, the verb set has to
serve the actual customer-felt value propositions, not just the API
surface.** This document enumerates what StepSecurity sells, then
maps each value prop to (a) the API operations that expose it, (b)
the CLI shape sidestep needs to deliver it, and (c) the v0.1 priority.

---

## Ten value-proposition families

### A. Visibility / Inventory of CI/CD assets

What the customer is buying: **"I can finally see what's running in my GitHub
Actions, who has access, what tokens exist, and what I'm depending on."**

| Capability | Evidence | API ops |
|---|---|---|
| Inventory of GitHub Actions in use | docs §"GitHub Actions In Use", changelog Jan 2024 (Advisor) | `get_github_owner_actions_workflow_actions(_action)`, `get_github_actions_maintained_actions` |
| Inventory of reusable workflows | docs §"Reusable Workflows" | `get_github_owner_actions_reusable_workflows` |
| Inventory of GitHub Apps & PATs | changelog Jan 29, 2026 (named feature) | `getAppsForOrganization`, `getAppsForCustomer` |
| Inventory of Actions Secrets | docs §"Actions Secret" | `get_github_owner_actions_secrets` |
| Inventory of artifacts | changelog May 22, 2025 (Artifact Monitor) | `get_github_owner_actions_artifacts` |
| Tenant-level security summary (rollup) | docs §"Reports" | `getSecuritySummary` |
| Action governance metrics (rollup) | docs §"Actions Governance" | `get_github_owner_actions_actions_governance_metrics`, `get_customer_github_actions_actions_governance_metrics` |
| Harden-Runner deployment coverage | docs §"Coverage" | `getHardenRunnerCoverage`, `getGitHubOwnerHardenRunnerCoverage` |

**Sidestep verb fit:** `orient` (the rollup) + `inventory <noun>` (the deep dive).
**v0.1 priority:** TIER-1. This is the WebUI's biggest export gap.

### B. Runtime protection (the Harden-Runner pillar)

What the customer is buying: **"My CI/CD jobs can't be quietly compromised
because Harden-Runner watches every outbound call, file write, and process
spawn — and blocks the bad ones."**

| Capability | Evidence | API ops |
|---|---|---|
| Outbound network monitoring (DNS + network layers) | feature matrix; changelog Feb 2024 | runs/file/process events ops |
| Anomaly detection vs. ML baseline | feature matrix; blog post | `get_github_owner_actions_baseline`, `get_github_owner_actions_clusters` |
| Egress filtering (block mode) | feature matrix; changelog Sep 2024 | `actions_aggregate_endpoints` |
| Source-code tampering detection | feature matrix; changelog Aug 2022 | runs ops |
| Process-event observation (Enterprise tier) | feature matrix | `..._processevents` op |
| File-event observation (Enterprise tier) | feature matrix | `..._fileevents` op |
| Run-by-PR/branch filtering (Enterprise) | feature matrix | runs ops + filters |
| Detections of all the above | docs §"Detections" | `get_github_owner_actions_detections` |
| Detection suppression (false positives) | docs §"Suppression Rules" | `post_github_owner_actions_detections` (creates rule) |
| Multi-platform support (Linux + Windows + macOS) | changelog Feb 2026 | runtime-side; API is the same |
| Self-hosted (VM, ARC, third-party) support | changelog Apr 20 + Apr 2023 | runtime-side |

**Sidestep verb fit:** `inventory detections`, `inventory runs`, `triage detections`,
`verify detections-fixed`. WRITE side: `improve` to suppress.
**v0.1 priority:** TIER-1. Runtime detections are the defining pillar.

### C. PR-time gates (GitHub Checks pillar)

What the customer is buying: **"Risky workflow changes are blocked before
merge, and developers get a check status they can act on without leaving GitHub."**

| Capability | Evidence | API ops |
|---|---|---|
| GitHub Checks per-PR status | docs §"GitHub Checks" | `get_github_owner_repo_checks(_head_sha)` |
| Owner-level check rollup | docs §"Configuration" | `get_github_owner_checks` |
| Control checks (rollup) | docs §"Control Evaluation" | `getControlChecksData` |
| Configurable check enablement | docs §"GitHub Checks/Configuration" | `getGithubChecksConfig`, `updateGithubChecksConfig` |
| Re-run / cancel / approve a failed check (developer surface) | docs §"GitHub Checks (Developer)" | `post_github_owner_repo_checks_head_sha` |

**Sidestep verb fit:** `inventory checks` (failures), `triage failed-checks`.
WRITE side (re-run, override) probably doesn't belong in CLI — that's a
developer-in-PR action.
**v0.1 priority:** TIER-2. Useful but not what the user named.

### D. Automated remediation (StepSecurity PRs pillar)

What the customer is buying: **"When the platform finds a problem, it
files a PR with the fix. I review and merge."**

| Capability | Evidence | API ops |
|---|---|---|
| Auto-PRs to pin third-party actions to commit SHAs | changelog Mar 2025 (Policy-Driven PRs) | `get_github_owner_pull_requests`, `repo_policy_driven_pr_configs` |
| Auto-PRs to replace risky actions with maintained alternatives | changelog Jun 2025 + Apr 22 2026 | `actions_maintained`, `post_app_securerepo_analyze` |
| Policy-driven PR configs (per-repo) | docs §"Policy Driven PRs" | `_repo_policy_driven_pr_configs` (full CRUD) |
| Secure Workflow / Secure Repo analysis | docs §"Secure Workflow", §"Secure Repo" | `post_app_securerepo_analyze` |
| Action Requests (request a maintained action) | docs §"Action Requests" | `post_github_owner_actions_maintained_actions` |

**Sidestep verb fit:** READ — `inventory pull-requests` (status of SS PRs in flight),
`triage stale-prs`. WRITE — `improve` to trigger Secure Repo analysis or to
configure policy-driven PRs.
**v0.1 priority:** TIER-2. Visibility into PRs in flight is useful; configuration
is admin work.

### E. Curated, hardened action library (StepSecurity Maintained Actions)

What the customer is buying: **"I don't have to trust 50 unknown
GitHub Action authors — StepSecurity ships verified, supply-chain-controlled
versions of the common ones."**

| Capability | Evidence | API ops |
|---|---|---|
| Browse maintained action catalog | changelog Jan 2024; docs §"StepSecurity Maintained Actions" | `get_github_actions_maintained_actions`, `get_github_owner_actions_maintained(_actions)` |
| Replace upstream with maintained | changelog Apr 22 2026 | `post_github_owner_actions_maintained_actions` |
| Per-action details / risk lookup | implicit | `post_github_actions_action_details` |
| Internal Actions Marketplace | changelog Oct 2024 | implicit |

**Sidestep verb fit:** This is **enrichment**, not a separate noun. `inventory actions`
should annotate every action with its maintained-replacement availability.
**v0.1 priority:** TIER-1 (as enrichment to actions inventory).

### F. Policy-as-Code Governance (Policy Store pillar)

What the customer is buying: **"My security posture is declared in code,
versioned, auditable, and consistently enforced."**

| Capability | Evidence | API ops |
|---|---|---|
| Policies (declarative rules) | docs §"Policy Store", §"Policies" | `get_github_owner_actions_policies` |
| Rules within policies | docs §"Policy Store" | `actions_rules` (full CRUD) |
| Policy attach/detach to scope | docs §"Attaching a policy to a scope" | `_actions_policies_policy_name_attach` (POST/DELETE) |
| Policy evaluations (read what passed/failed) | docs §"Policy Evaluations" | `getRunPolicyEvaluations` |
| Policy History and Audit Trail | changelog Apr 21 2026 | implicit in policies API |
| Workflow Run Policies (gates) | changelog Apr 15 2026 + May 2025 | `actions_run_policies` (GET + POST) |
| Lockdown Mode | docs §"Policy Store" | implicit |
| Terraform Provider for IaC management | changelog (Terraform Provider) | external; not CLI surface |

**Sidestep verb fit:** `inventory policies`, `inventory rules`, `inventory policy-evaluations`,
`triage stale-policies`, `verify policy-effective`. WRITE — `improve` for attach/detach.
**v0.1 priority:** TIER-2. The user named "manage CI/CD pipeline issues"; policy state
matters but is admin-domain.

### G. Threat Intelligence

What the customer is buying: **"StepSecurity actively hunts supply-chain
attacks and feeds the findings into my pipeline as detections."**

| Capability | Evidence | API ops |
|---|---|---|
| Real incident feed (tj-actions, nx, axios, etc.) | "Recent supply chain attacks" docs section | `getThreatIntelIncidents`, `getThreatIntelIncidentById` |
| Global Block List (auto-block known-bad endpoints) | changelog Apr 15 2026 | implicit (block list is runtime data) |
| NPM Package Cooldown Check | changelog Sep 5 2025 | implicit (in OSS Package Search behavior) |
| OSS Security Feed | docs §"OSS Security Feed" | implicit |
| LLM-driven analysis on demand | implicit | `post_owner_github_actions_llm_analysis_requests` |

**Sidestep verb fit:** `inventory incidents`. CROSS-CUTTING: every other inventory
should be threat-intel-aware — `inventory actions --threat-intel` annotates each
action with "is this in any incident?"
**v0.1 priority:** TIER-2 as standalone; **TIER-1 as enrichment** to actions/packages.

### H. Supply-chain visibility (OSS package side)

What the customer is buying: **"When axios gets compromised on a Friday
afternoon, I can answer 'where do we use it' in 30 seconds."**

| Capability | Evidence | API ops |
|---|---|---|
| OSS Package Search (npm) | changelog Nov 11, 2025 | `searchTenantNpmPackages`, `searchGhOrgNpmPackages` |
| OSS Package Search (pypi) | implicit | `searchTenantPypiPackages`, `searchGhOrgPypiPackages` |
| Artifact Monitor | changelog May 22 2025 | `get_github_owner_actions_artifacts` |

**Sidestep verb fit:** `search packages <name>` — this is **NOT** an inventory
verb; it's a search-by-name. Special verb shape: input is a package name,
output is "where it's used."
**v0.1 priority:** TIER-1. Blast-radius queries are *the* incident-response
moment. Snyk/trivy/semgrep all have an analog.

### I. Dev Machine Guard (separate product, MDM API)

What the customer is buying: **"I have visibility into what my developers
are running on their workstations: IDE extensions, AI agents, packages,
all with risk assessment."**

| Capability | Evidence | API ops |
|---|---|---|
| Device inventory | changelog Jan 13 + Mar 12 + Apr 17 2026 | `get_customer_developer_mdm_devices` (full) |
| Per-device executions + logs | docs §"Devices" | `..._devices_device_id_executions(_logs)` |
| IDE extension governance | changelog Jan 2026 (DMG launch) | `get_customer_developer_mdm_ide_extensions(_ide_type_extension_id)`, `_extension_metadata` |
| AI coding agent visibility (Claude/Copilot/Cursor on dev machines) | DMG product description | `get_customer_developer_mdm_ai_agents(_agent_key)` |
| MCP server visibility | recent | `get_customer_developer_mdm_mcp_servers(_server_key)` |
| Dev-machine package inventory (npm/pypi/brew/system) | changelog Apr 17 2026 (Expanded Coverage) | `..._mdm_npm_packages`, `..._python_packages`, `..._brew_packages`, `..._system_packages` |
| Cross-device package search | implicit | `post_customer_developer_mdm_npm_packages_search`, `..._python_packages_search` |
| Install scripts visibility | implicit | `_install_scripts` |
| MDM config management | implicit | `_mdm_config` |

**Sidestep verb fit:** `inventory devices`, `inventory extensions`, `inventory mdm-packages`,
`inventory ai-agents`. `search packages --mdm` for cross-device.
**v0.1 priority:** TIER-1 for `extensions` and `mdm-packages` (user named these
explicitly: "remove high risk packages, OSS, extensions"). Devices/AI agents/MCP
servers are TIER-2 noun candidates.

### J. Compliance, Audit, and Integrations

What the customer is buying: **"My security operations integrate with
the rest of my SOC tooling — SIEM, Slack, S3, Terraform — and I have
an audit trail of who did what when."**

| Capability | Evidence | API ops |
|---|---|---|
| Customer audit logs | docs §"Audit Logs" | `get_customer_audit_logs` |
| Notification settings | docs §"Notifications" | `getNotificationSettings`, `updateNotificationSettings` |
| Reports + Export to PDF | docs §"Reports", §"Export to PDF" | `_actions_report(_id)` |
| S3 Integration (export Harden-Runner insights) | changelog Apr 23 2025 | external; configured in admin console |
| Webhook Integration (SIEM) | docs §"Webhook Integration" | external |
| Slack OAuth Integration | docs §"Slack OAuth" | external |
| Terraform Provider | docs §"Terraform Provider" | external; not CLI scope |

**Sidestep verb fit:** `inventory audit-logs` (read-only). The integrations
themselves are external — they're configured in the admin console, not via CLI.
**v0.1 priority:** TIER-3. Audit log read is nice-to-have; integrations are
out of CLI scope.

---

## Cross-cutting themes the value-prop map reveals

Three patterns the bare API surface didn't make obvious:

### 1. Threat-intelligence is an enrichment axis, not a noun

Every inventory noun (actions, packages, extensions) has the question:
"is this thing in a known incident?" That's an enrichment, not a separate
walk through the API. The audit trail (B4) should record threat-intel
joins as a `verb_phase: enrich` with `synthesis_keys: [incidents, <noun>]`.

### 2. Maintained-action availability is enrichment for actions

Same pattern: `inventory actions` should annotate each row with its
maintained-replacement availability and the migration path. Without that
annotation, the inventory is just a list. With it, it's an action plan.

### 3. There are two "search" use cases, distinct from inventory

OSS Package Search (`searchGhOrgNpmPackages`) takes a package name and
returns where it's used. That's the **blast-radius** primitive. It's
not an inventory walk — it's a targeted lookup. Curated verb: `search packages <name>`.

The other "search" is the MDM cross-device package search (`post_customer_developer_mdm_npm_packages_search`).
Same shape, different scope.

These belong to a `search` verb, **not** `inventory`. Different cardinality,
different audit-trail signature, different user mental model.

---

## How this sharpens the v0.1 verb cut

The value-prop map argues for **six v0.1 verbs**, not five:

| Verb | Job | Value props served | Cardinality |
|---|---|---|---|
| **`orient`** | "where do I stand on security right now" | A (summary), B (coverage), G (incidents), F (policy state) | many ops, one screen |
| **`inventory <noun>`** | "give me the deep enumeration of this surface" | A, B, E (enrichment), F, G (enrichment), I | many ops, one cluster |
| **`search <noun> <name>`** | "where is this thing used / who has it / blast radius" | H, I (cross-device package), G (cross-ref to incidents) | typically 1-2 ops, targeted |
| **`triage <noun>`** | "filter+rank inventory output into ActionItems" | local | no API |
| **`plan`** | "render ActionItems into deliverable" | local | no API |
| **`verify <plan-file>`** | "confirm prior plan items are remediated" | re-runs A/B/F nouns | many ops |

`improve` (writes) deferred to v0.2.
`api <opId>` peer escape hatch always.

**The discovery:** `search` was missing from prior rounds. The value-prop map
named it. Without `search`, sidestep cannot answer the Friday-afternoon
"where do we use axios" question — which is **the** moment customers
reach for a CLI over the WebUI.

---

## v0.1 noun inventory, prioritized

By value-prop weight × user-felt remediation pain:

**Tier 1 (must ship):**
- `actions` — value prop A + E + G (huge enrichment value)
- `detections` — value prop B
- `extensions` — value prop I (user named explicitly)
- `mdm-packages` — value prop I (user named explicitly)

**Tier 2 (likely v0.1, low budget):**
- `apps-pats` — value prop A (Jan 2026 named feature)
- `policies` — value prop F

**Tier 3 (v0.2 unless user pushes):**
- `runs`, `checks`, `pull-requests`, `incidents`, `audit-logs`, `devices`, `ai-agents`

**Search targets (Tier 1 for `search`):**
- `packages` (npm, pypi) — both org and tenant scope, with `--mdm` flag for cross-device
