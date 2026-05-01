# StepSecurity Noun Inventory

Source: `docs/research/stepsecurity-llms-full.txt` cross-referenced with the
97 operations in `spec/stepsecurity-v1.yaml` (as of 2026-04-29 sync).
Captured session-041, 2026-05-01.

This is the structured noun map sidestep's curated verbs (`inventory`,
`triage`, `plan`) act on. Each cluster names the service area, the
nouns inside it, the read/write coverage in the API, and the v0.1
priority ranking.

---

## The two-axis map

```
                     CI/CD Security             Dev Machine Guard
                     (GitHub-org scoped)        (Customer/MDM scoped)
                     ─────────────────────      ─────────────────────
RUNTIME              Harden-Runner              MDM Devices
                     • runs                     • devices
                     • detections               • device executions
                     • baseline                 • IDE extensions
                     • clusters                 • AI agents
                                                • MCP servers

INVENTORY            Actions Inventory          MDM Packages
                     • workflow actions         • npm
                     • reusable workflows       • pypi/python
                     • maintained actions       • brew
                     • secrets                  • system packages
                     • artifacts                • install scripts
                     • aggregate endpoints
                     • apps & PATs

GOVERNANCE           Policy Store               (n/a — MDM is read-only)
                     • policies
                     • rules
                     • run policies
                     • policy-driven PR configs
                     • workflow run policies

GATES                GitHub Checks              (n/a)
                     • check configurations
                     • per-PR check results
                     • control checks (rollup)

INTELLIGENCE         Threat Intel               OSS Package Search
                     • incidents                • npm/pypi search
                                                  (tenant + org scope)

OBSERVABILITY        Reports + Summary          Audit Logs
                     • security summary         • notification settings
                     • action governance        • customer audit logs
                       metrics
                     • generated reports

REMEDIATION          Pull Requests              (n/a — workflow is
                     • SS-generated PRs           remove/replace)
                     • Secure Repo analyze
                     • Action LLM analysis

ADMIN                Customer / Users           MDM Config
                     • organizations            • mdm config
                     • users
                     • GHE servers
```

---

## Per-cluster noun + op coverage

### 1. Harden-Runner (16 ops: 14 GET, 2 POST)

The runtime-security pillar. Where most `inventory detections` and
`inventory runs` live.

| Noun | List | Get | Create | Update | Delete |
|------|------|-----|--------|--------|--------|
| **detections** | ✅ | — | ✅ POST | — | — |
| **runs** | ✅ (RunsDetails, RepoRunsDetails, runid) | ✅ | — | — | — |
| **run jobs (file events)** | ✅ | — | — | — | — |
| **run jobs (process events)** | ✅ | — | — | — | — |
| **baseline** (org + repo + jobs) | ✅ ✅ ✅ | — | — | — | — |
| **clusters** + cluster baseline | ✅ ✅ | — | — | — | — |
| **run policies** | ✅ | — | ✅ POST | — | — |
| **harden-runner coverage** (rollup) | ✅ ✅ | — | — | — | — |

**v0.1 inventory targets:** `detections`, `runs` (with severity + status enrichment).

### 2. Policy Store (12 ops: 5 GET, 4 POST, 3 DELETE)

The governance pillar. The most-CRUD-rich cluster — full lifecycle
ops because policies are operator-managed.

| Noun | List | Get | Create | Update | Delete |
|------|------|-----|--------|--------|--------|
| **policies** (with attach/detach) | ✅ | — | ✅ POST attach | — | ✅ DELETE attach |
| **rules** | ✅ | — | ✅ POST | — | ✅ DELETE |
| **run policies** (workflow gates) | ✅ | — | ✅ POST | — | — |
| **policy-driven PR configs** | ✅ | — | ✅ POST | — | ✅ DELETE |
| **policy evaluations** (read-only) | ✅ | — | — | — | — |

**v0.1 inventory targets:** `policies` (with evaluation cross-ref),
`rules`. `triage` will surface stale/orphaned policies; `plan` emits
attach/detach action items.

### 3. GitHub Checks (6 ops: 4 GET, 1 POST, 1 PUT)

PR-time gates. Both repo-scoped and owner-scoped read paths exist.

| Noun | List | Get | Create | Update | Delete |
|------|------|-----|--------|--------|--------|
| **checks** (repo, owner) | ✅ ✅ | — | — | — | — |
| **check by head_sha** | ✅ | — | ✅ POST (re-run?) | — | — |
| **GitHub Checks config** | — | ✅ | — | ✅ PUT | — |
| **control checks data** (rollup) | ✅ | — | — | — | — |

**v0.1 inventory targets:** `checks` failures across owner.

### 4. Actions Inventory + Governance (14 ops: 11 GET, 2 POST, 1 DELETE)

The "what third-party stuff am I running" pillar. **The cluster the
user explicitly named** as a top remediation target ("remove high
risk packages, OSS, extensions").

| Noun | List | Get | Create | Update | Delete |
|------|------|-----|--------|--------|--------|
| **workflow actions** (used in workflows) | ✅ | ✅ | — | — | — |
| **reusable workflows** | ✅ | — | — | — | — |
| **maintained actions** (SS-curated replacements) | ✅ ✅ ✅ | — | ✅ POST request | — | — |
| **secrets** | ✅ | — | — | — | — |
| **artifacts** | ✅ | — | — | — | — |
| **aggregate endpoints** | — | — | — | — | ✅ DELETE |
| **action governance metrics** (org + customer) | ✅ ✅ | — | — | — | — |
| **action report** | — | ✅ id | ✅ POST | — | — |

**v0.1 inventory targets:** `actions in use` (with risk score + maintained-replacement
cross-ref). This is the **most user-recognizable inventory** — it's
the "what risky Actions does my org use, with what alternatives" report.

### 5. Reports + Summary (3 ops: 2 GET, 1 POST)

Tenant-level rollup reads. Cheap entry points for inventory.

| Noun | List | Get | Create |
|------|------|-----|--------|
| **security summary** | ✅ | — | — |
| **action report** | — | ✅ | ✅ |

### 6. Apps & PATs (2 ops: 2 GET)

GitHub Apps + Personal Access Tokens governance — tenant- and org-level
lists only. Read-only inventory target.

| Noun | List (tenant) | List (org) |
|------|---------------|------------|
| **apps & PATs** | ✅ | ✅ |

**v0.1 inventory target:** `apps-pats` — what tokens/apps have access,
their scopes, who installed them.

### 7. Threat Intel (2 ops: 2 GET)

Supply-chain incident feed. Tied to a specific GitHub owner.

| Noun | List | Get |
|------|------|-----|
| **incidents** | ✅ | ✅ id |

### 8. Audit + Notifications (3 ops: 2 GET, 1 PUT)

| Noun | List/Get | Update |
|------|----------|--------|
| **audit logs** | ✅ | — |
| **notification settings** | ✅ | ✅ PUT |

### 9. Pull Requests (1 op: 1 GET)

Auto-generated SS PRs. Read-only feed of remediation work in flight.

| Noun | List |
|------|------|
| **pull requests** | ✅ |

**v0.1 inventory target:** PR queue per owner — what remediation
SS has already proposed, status, age.

### 10. OSS Package Search (4 ops: 4 search/POST)

The **blast-radius** primitive. Find where a specific package is
used (npm/pypi, tenant-wide or org-scoped).

| Noun | Search (tenant) | Search (org) |
|------|-----------------|--------------|
| **npm packages** | ✅ | ✅ |
| **pypi packages** | ✅ | ✅ |

**v0.1 inventory target:** `package-uses <name>` — answers "where is
`colors@1.4.44-liberty-2` used across our repos?" This is **not a
list**; it's a search-by-name. Special verb shape.

### 11. Dev Machine Guard / MDM (27 ops: 22 GET, 4 POST, 1 DELETE)

Separate product surface. Heavy on read endpoints because the agent
on the device emits, the API consumes. POSTs are package-search
endpoints (cross-device).

| Noun | List | Get | Create | Delete |
|------|------|-----|--------|--------|
| **devices** | ✅ | ✅ | — | ✅ |
| **device executions** | ✅ | — | — | — |
| **execution logs** (timestamp-keyed) | ✅ | — | — | — |
| **IDE extensions** (per-device + global) | ✅ ✅ | ✅ ide_type+id | — | — |
| **extension metadata** | ✅ | — | — | — |
| **AI agents** (Claude, Copilot, etc.) | ✅ | ✅ key | — | — |
| **MCP servers** | ✅ | ✅ key | — | — |
| **npm packages** (per-device + cross-device + search) | ✅ ✅ | — | ✅ search | — |
| **python packages** (per-device + cross-device + search) | ✅ ✅ | — | ✅ search | — |
| **brew packages** | ✅ | ✅ name | — | — |
| **system packages** | ✅ | ✅ name | — | — |
| **install scripts** | ✅ | — | — | — |
| **MDM config** | ✅ | — | — | — |

**v0.1 inventory targets:** `devices`, `ide-extensions` (with publisher
trust + permissions), `mdm packages` (cross-device risk).

### 12. Customer / Users / Admin (6 ops: 2 GET, 2 POST, 1 PUT, 1 DELETE)

Tenant-scope user management. Full CRUD on users.

| Noun | List | Get | Create | Update | Delete |
|------|------|-----|--------|--------|--------|
| **users** | ✅ | ✅ | ✅ POST | ✅ PUT | ✅ |
| **organizations** (registered) | ✅ | — | — | — | — |
| **GHE servers** | — | — | ✅ POST | — | — |

Operator/admin domain. Probably not a v0.1 inventory target.

### Unmatched / scaffolding (5 ops)

These are workflow-support ops, not primary nouns:

- `get_customer_github_organizations` — admin/setup helper
- `get_github_owner_checks` — owner-level checks roll-up
- `post_app_securerepo_analyze` — Secure Repo remediation generator
- `post_github_actions_action_details` — action-detail lookup
- `post_owner_github_actions_llm_analysis_requests` — LLM analysis on demand

---

## v0.1 ranked noun candidates

By "highest user-felt remediation pain → easiest exportable plan" the
top six noun targets for the inaugural `inventory` verb:

1. **`actions`** — third-party Actions in use across an owner, with
   risk score, maintained-action replacements, usage count. Direct hit
   on the user's "remove high-risk packages, OSS, extensions" framing.
   Cluster: Actions Inventory + Maintained Actions.
2. **`detections`** — open Harden-Runner detections, severity, age,
   suppression status, recommended response. Cluster: Harden-Runner.
3. **`extensions`** — IDE extensions across MDM devices, publisher
   trust, permissions, flagged status. Cluster: MDM.
4. **`packages`** — npm/pypi/brew/system packages across MDM devices,
   with detection cross-ref. Cluster: MDM Packages + (optionally)
   OSS Package Search for blast-radius enrichment.
5. **`policies`** — policies + rules + evaluations, surfacing
   stale/orphaned/never-attached items. Cluster: Policy Store.
6. **`apps-pats`** — GitHub Apps + PATs with org scope and risk
   posture. Cluster: Apps & PATs.

`runs`, `checks`, `pull-requests`, `incidents`, `audit-logs` are v0.2
candidates — they're observation surfaces that orbit the v0.1 six.

---

## What this argues for the verb shape

- **`inventory <noun>`** — the `<noun>` slot is the six above (and
  growing). Each noun has its own synthesis recipe (which list
  endpoints to call, which join keys, which enrichments).
- **`triage <noun>`** — same noun slot, takes inventory output, applies
  risk/severity/owner/blast-radius filters, ranks into ActionItems.
- **`plan`** — noun-agnostic. Renders ActionItems from any noun
  through a template per `--output` format.
- **The ActionItem schema must be noun-portable** — if `inventory
  actions` and `inventory extensions` produce ActionItems whose
  shape diverges, `plan` becomes N templates and Murat's contract
  test (`inventory_output_consumable_by_plan`) collapses.

This is the structural test for the schema Winston proposed. Take
all six v0.1 nouns, sketch the ActionItem each one produces, render
through one Markdown template. If it doesn't fit, the schema is wrong.
