# ActionItem Schema (sidestep v0.1)

Status: draft, Track A deliverable (bd `aae-orc-0t43`).
Resolves: frontier `question-action-item-schema`.
Promotes to: bedrock element `elem-action-item-schema` on user accept.

This document defines the canonical ActionItem record — the *bridge
artifact* between StepSecurity's observation surface and the
engineer's action surface (Quinn, finding-001). Every primitive in
v0.1 either produces, transforms, or consumes ActionItems. The schema
is bedrock-grade because changing it breaks every recipe and every
downstream tool that joins on the audit trail.

---

## The five fields

```
ActionItem {
  id        : string       // stable content hash; primary key
  kind      : Kind         // closed enum (v0.1); 6 values
  target    : Target       // discriminated by kind
  severity  : Severity     // critical | high | medium | low | info
  evidence  : Evidence[]   // 1+ audit-trail join keys
}
```

`_kind: "action-item"` is added by the stream contract (the ActionItem
record above is what fills the rest of the JSON-line).

### Field 1: `id` — stable content-addressed string

```
id : string  // 16-hex-char prefix of sha256(canonical_form)
```

**Engineer-action ladder:** "is this still open since last week?" /
"have I already filed a ticket for this?" / "did the fix work?" —
all require `verify` to find the same item across two different
runs.

**Stability rule:** id is `sha256(kind || target_canonical || root_cause)[:16]`.

- `kind` is the action category (closed enum, stable).
- `target_canonical` is the deterministic JSON-canonical encoding
  of `target` (sorted keys, no whitespace).
- `root_cause` is *what makes this problem distinct*, not the
  observation that surfaced it. For "harden workflow X in repo Y
  because action Z is unmaintained," root_cause is `action-z@v3`
  (the unmaintained dependency), NOT the detection_id that fired
  this morning.

**Why content-addressed, not source-addressed:** StepSecurity rotates
detection IDs (we know this from the noun inventory: detections have
their own lifecycle separate from the underlying problem). A
source-addressed id (`detection_id`) would make the same engineer
problem appear as two different ActionItems across two runs —
breaking `verify`. A content-addressed id treats "same kind +
same target + same root cause" as one item, regardless of which
detection batch surfaced it.

**Limit:** the hash function for `root_cause` is per-kind. Each kind
specifies what fields go into `root_cause`. Get the per-kind set
wrong and id stability suffers. Document each kind's `root_cause`
inputs explicitly (see §Kinds below).

### Field 2: `kind` — closed enum, 6 values for v0.1

```
Kind : enum {
  harden_workflow      // pin actions, add concurrency limits, restrict permissions
  suppress_detection   // a detection is a known-good false positive
  replace_action       // unmaintained third-party action → maintained alternative
  attach_policy        // workflow/repo lacks required policy attachment
  update_rule          // existing policy rule is misconfigured or stale
  acknowledge_incident // threat-intel incident matches our usage
}
```

**Engineer-action ladder:** "what category of fix is this?" The kind
determines who acts (developer vs. admin vs. security engineer), how
they act (PR vs. policy edit vs. dashboard click), and what
deliverable format makes sense (Jira ticket vs. PR body vs. SOC alert).

**Why closed for v0.1:** type safety on `target` (discriminated
union per kind below); audit-trail miners get clean clusters; render
templates know which fields exist. Open-set would defer all
type-checking to runtime.

**v0.2 extension is additive:** new kinds can be added without
breaking existing audit-trail data or recipes — just append. Removing
a kind is the breaking change to avoid.

**Mapping to v0.1 enrichment recipes:**

| Kind | Produced from |
|---|---|
| `harden_workflow` | `list workflows + enrich repo-owner + enrich severity-roll-up` |
| `suppress_detection` | `list detections + enrich policy-context` (rule says safe) |
| `replace_action` | `list workflows + enrich maintained-actions` (deferred to v0.2 enrichment) |
| `attach_policy` | `list policies + enrich policy-context` (gap detection) |
| `update_rule` | `list rules + enrich severity-roll-up` (stale-or-misconfigured) |
| `acknowledge_incident` | `list incidents + enrich repo-owner` |

`replace_action` is in the v0.1 kind set even though
`maintained-actions` enrichment is deferred to v0.2. Reason: the
*kind* is stable (the engineer action — replace an unmaintained
action — is a real category whether or not v0.1 ships the enrichment
that auto-detects it). Users in v0.1 can construct
`replace_action` ActionItems by hand from `list workflows +
enrich repo-owner + filter` if they want.

### Field 3: `target` — discriminated by `kind`

Each kind specifies its target shape:

```
Target = HardenWorkflowTarget    // when kind = harden_workflow
       | SuppressDetectionTarget // when kind = suppress_detection
       | ReplaceActionTarget     // when kind = replace_action
       | AttachPolicyTarget      // when kind = attach_policy
       | UpdateRuleTarget        // when kind = update_rule
       | AcknowledgeIncidentTarget // when kind = acknowledge_incident

HardenWorkflowTarget {
  repo: { owner, name },
  workflow_path: string,         // ".github/workflows/release.yml"
}
// root_cause inputs: repo + workflow_path + (specific concern, e.g., unpinned-actions)

SuppressDetectionTarget {
  repo: { owner, name },
  detection_pattern: string,     // canonicalized signature, NOT detection.id
                                 // e.g., "egress:api.example.com:443"
}
// root_cause inputs: repo + detection_pattern

ReplaceActionTarget {
  action_ref: string,            // "actions/checkout@v3"
  repos_affected: string[],      // for fan-out tracking; not in root_cause
}
// root_cause inputs: action_ref only (one ActionItem per action; affects N repos)

AttachPolicyTarget {
  policy_name: string,
  scope: { type: "org"|"repo"|"workflow", id: string },
}
// root_cause inputs: policy_name + scope

UpdateRuleTarget {
  rule_id: string,
  policy_name: string,
}
// root_cause inputs: policy_name + rule_id

AcknowledgeIncidentTarget {
  incident_id: string,           // upstream stable
  affected_resources: string[],  // for fan-out; not in root_cause
}
// root_cause inputs: incident_id only
```

**Engineer-action ladder:** "where do I go to fix this?" Every
target points to a specific addressable resource — a workflow file,
a repo, a policy, an action ref. The engineer (or a downstream agent)
takes the target and acts on it.

**Why per-kind shapes vs. one polymorphic blob:** type safety again.
A `plan --format markdown` template for `harden_workflow` knows it
gets `{owner, name, workflow_path}`; it never has to write
`if target.workflow_path defined` defensive code. The cost is
maintaining N target schemas; the benefit is templates that don't
check.

**Why `detection_pattern` not `detection_id`:** see id-stability
above. The pattern is what the engineer recognizes ("traffic to
api.example.com on port 443"); the id is what changes.

### Field 4: `severity` — closed 5-level enum

```
Severity : enum { critical, high, medium, low, info }
```

**Engineer-action ladder:** "in what order should I work these?" The
severity is the rank-by default for `triage` recipes and the visual
sort for `plan --format markdown`.

**Source:** by default, severity is propagated from the highest-
severity field on the source records (detection.severity,
incident.severity, etc.). Triage recipes can override (e.g., "items
in repos owned by critical-team are minimum 'high'") — when they do,
the ActionItem's severity is the *post-triage* value.

**v0.2 candidate:** `severity_source: "raw" | "triage_override"` so
the audit trail can distinguish. Not in v0.1 — keeps schema minimal.

### Field 5: `evidence` — list of audit-trail join keys

```
Evidence {
  operation_id: string  // OpenAPI operationId from the API call
  trace_ref: string     // <trace_id>:<span_id> — points to audit JSONL
  ts: timestamp         // when the underlying observation was made
}

evidence: Evidence[]    // 1+; ActionItem requires at least one observation
```

**Engineer-action ladder:** "where did you find this?" / "is the data
fresh?" / "show me the underlying API response so I can verify or
push back."

**Why `trace_ref` not the full response:** ActionItem must stay
portable (one JSON-line per item; bundleable into a Markdown table or
Jira ticket; cheap to transmit). The full API response can be huge.
The audit trail (B4 + finding-001 metadata) holds the full response
indexed by `<trace_id>:<span_id>`. ActionItem holds the pointer.

**Why a list:** one ActionItem can be supported by multiple
observations. `harden_workflow` for a given target might be supported
by:
- the detection that fired (operation_id: `get_github_owner_actions_detections`)
- the policy that demands hardening (operation_id: `get_github_owner_actions_policies`)
- the maintained-actions catalog (operation_id: `get_github_actions_maintained_actions`)

Three Evidence entries, one ActionItem.

**Minimum cardinality 1:** an ActionItem with no evidence is a
hallucination. The engineer cannot verify. The audit-mining tools
cannot join.

---

## What's deliberately NOT on ActionItem

These belong on a sibling **RenderContext** object (designed in v0.2
when format-specific needs emerge), not on ActionItem itself:

- `assignee` — Jira-specific concept; markdown reports don't have one
- `status` — workflow-system concept (open, in-progress, done); not
  intrinsic to the action being recommended
- `recommended_text` — natural-language prose for humans; per-format
  (Jira description vs. PR body vs. Slack message), so per-render
- `due_date` — operator-set, not derived from data
- `labels` / `tags` — Jira-specific, GitHub-issue-specific
- `cost_estimate` — useful for triage but not in scope for v0.1
- `dependencies` — "this ActionItem blocked by another" is graph data,
  not item data; v0.2 question

**Why this keeps ActionItem portable:** the same record flows through
`emit --format markdown`, `emit --format jira`, `emit --format sarif`
without changing. Render context is per-emit-call.

---

## What back-propagates to the 9 v0.1 `_kind` schemas

Quinn's reframe was: write ActionItem first, then the input kinds
derive their fields from "what does ActionItem need." Working
through it:

| ActionItem field | Required from input kinds |
|---|---|
| `id` (root_cause inputs) | varies per kind (see §Kinds); each input kind must provide stable identifiers (action_ref, detection_pattern, policy_name, rule_id, incident_id) |
| `target` | input kind must include enough to construct the target — for `harden_workflow`: detection records must carry `repo + workflow_path` (✓ already in detection schema sketch from session-041); for `replace_action`: workflow records must carry `action_refs` and the maintained-actions catalog must carry `replacement_for[]` |
| `severity` | every input kind must have a severity field (or the enrichment that produces severity-roll-up); `audit_log` and `repo` don't natively have severity — they enrich into ActionItems via other kinds, never produce ActionItems directly |
| `evidence` | every input kind's records must carry `_source.operation_id` and a span_id (already in stream contract); `ts` must be present (most have `created_at`/`triggered_at`/`first_seen` — needs to be normalized to one timestamp per record) |

**Concrete back-propagated requirements for v0.1 input kinds:**

- `detection` must include: id, severity, status, created_at, repo, workflow_path (the workflow that triggered the run that produced the detection — required for `harden_workflow.target`)
- `run` must include: id, repo, branch, triggered_at, status, workflow_path, detection_count
- `policy` must include: id, name, attached_repos[], last_evaluated_at, severity (default if no rules)
- `rule` must include: id, policy_id, kind, severity
- `incident` must include: id, severity, first_seen, action_refs[], package_refs[]
- `audit_log` must include: id, ts, actor, operation, target — does NOT produce ActionItems directly, only supports them via evidence
- `repo` must include: owner, name, primary_branch, owner_team — supports targets but does not produce ActionItems
- `threat_intel` must include: id, severity, action_ref or package_name, source — supports `acknowledge_incident.target`
- `check` must include: id, repo, head_sha, status, pr_number — supports `harden_workflow.evidence`

This list is the spec for Track B (spine fixtures + 3 asserts).

---

## Open questions resolved by this draft

1. **Is `id` stable when finding-refs rotate?** Yes — content-addressed,
   not source-addressed. Detection IDs rotate; root_cause inputs don't.
2. **Closed enum or open set for `kind`?** Closed for v0.1 (6 values).
   v0.2 extensions are additive.
3. **Does evidence carry response shape or just a pointer?** Pointer
   (`trace_ref`). Full response lives in the audit trail.
4. **Render context fields (assignee, status, etc.)?** Not on
   ActionItem. v0.2 sibling RenderContext object.

## Open questions punted to v0.2

- `severity_source` field (raw vs. triage_override) — useful for audit
  mining; not v0.1
- `RenderContext` design — emerges from `plan --format` real usage
- `dependencies` — ActionItem-A blocks ActionItem-B graph data
- `confidence` — how sure are we this is a real problem? (Today
  implicit in severity)

## Bedrock-promotion checklist

Before this graduates from `_kos/probes` (this doc) to
`_kos/nodes/bedrock/elem-action-item-schema.yaml`:

- [ ] User accepts the 5-field shape and the per-kind target shapes
- [ ] Track B writes the spine fixtures and round-trips ActionItem
      records through filter/rank/emit without special-casing
- [ ] Track C writes the four composite recipes and they all produce
      coherent ActionItem streams
- [ ] One Markdown template renders all 6 kinds without per-kind
      special cases
