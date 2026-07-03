# Audit-Mined Meta-Command Candidates — draft

**Status:** draft. One operator's corpus, 60-day window, n=251 records. Below the
8–12 week × 5–10/day threshold finding-001 set for general-sugar design,
strong enough to support the specific workflows called out here. Refresh after
team-wide collection (see [Reproduction prompt](#reproduction-prompt) below).

**Owner:** _Michael Pursifull, 2026-06-30_

Charter context: this artifact feeds [F3 (audit-trail pattern-mining
surface)](../../charter.md). The thesis is that v0.2 composite verbs should
be designed *from audit-trail evidence of actual workflow clustering*, not
intuition.

---

## What this document is

An end-to-end pass against one operator's `~/.sidestep/audit/` corpus —
inventorying which operations cluster in time, which arguments are
constant, which retry loops the API is producing, and what concrete
composite verbs the evidence supports. Each proposal cites the n-count
that justifies it.

## What is incomplete

- **n is small.** 251 records over 60 calendar days, 12 active days. Murat's
  finding-001 threshold for general sugar-design (5–10 invocations/day × 8–12
  weeks) sits above this. The corpus is rich enough to support strong-signal
  proposals (#1, #2, #5) and to surface weak-signal hypotheses (#3, #4, #6);
  it is not enough to enumerate the full v0.2 surface.
- **One operator.** No cross-operator validation. The reproduction prompt
  below exists to fix this — running it across the team's machines and
  merging the per-operator summaries produces a corpus on the order of
  1k–2k records, comfortably across the threshold.
- **Trace size 1.** Every CLI invocation is a single span. Composite verbs
  do not yet fan out, so co-occurrence is detected by time-adjacency, not
  `trace_id` clustering. Once #2–#4 ship and emit `parent_span_id`, the
  next mining pass sees real trace trees and can refine the design.
- **Filter-predicate noise.** Seven CEL predicates each appear exactly 21
  times — a fixture sweep, not real triage. Stripped before drawing
  workflow conclusions, but it means filter-usage proposals need a
  cleaner dataset.
- **Curated verbs barely used.** `get`/`search`/`enrich` show zero
  invocations in the corpus. Proposals here are derived from raw
  `api <opId>` patterns; once curated verbs see real use, the mining
  surface needs to learn their argv shapes too.

---

## Corpus stats

```
Source:    ~/.sidestep/audit/*.jsonl  (XDG fallback path; XDG_STATE_HOME unset)
Window:    2026-04-30 → 2026-06-29  (60 days calendar, 12 active days)
Records:   251  |  Total size: 200KB  |  Schema: v2

By verb_phase     filter:147 (58.6%)  api:80 (31.9%)  list:22 (8.8%)
By result         ok:26  http_error:26  network_error:8  redacted_block:44  filter-no-http:147
By status         200:52  400:13  500:4
By owner          acme-corp:40 (83%)   arcaven:8 (17%)
Operations        23 of 97 exercised
```

Caveat on filter: 147 looks dominant but 7 predicates × 21 identical invocations
each is a fixture sweep. Real triage is in the low tens.

---

## Proposals — ranked by evidence strength

### 1. Extend the resolution chain to `sidestep api <opId>`

Empirically confirmed during this analysis pass — `sidestep api
getSecuritySummary` (with `owner=acme-corp` in config) still errors with
`missing required parameter 'owner'`. The chain (B5,
[`aae-orc-y7lq`](../../../.beads/issues.jsonl)) shipped through
`list/get/search` but the `api` passthrough never received it.

| Signal | n |
|---|---:|
| `owner=acme-corp` typed as a literal | **74** |
| `--param` typed | 139 |
| `-p` typed | 37 |
| % of audit lines carrying owner as a literal | **17%** |
| Records routed through `api <opId>` | 80 (31.9% of corpus) |

**Mechanics.** `run_api_passthrough` should consult `CHAIN_PARAMS` exactly like
`run_list` does — when the operation declares `{owner}` in path_params and
no `--param owner=...` is passed, fall back through env → config →
chain-naming error (finding-005 four-source diagnostic). Audit-trail entry
gets `path_params_source.owner = "config"` instead of `"flag"`.

**Cost saved.** ~440 tokens against the existing corpus; growing per session.
Removes the constant-value noise floor from F3's mining surface so v0.2
candidates become statistically visible sooner.

**Where the rule lives.** `.claude/rules/cli-philosophy.md` Abusive-Argument
test — owner satisfies all four boxes on the `api` path specifically because
the chain wiring stops at the curated verbs.

---

### 2. `sidestep harden status` — harden-runner posture composite

| Pair (5-min co-occurrence) | n |
|---|---:|
| `get_github_owner_actions_baseline` + `get_github_owner_actions_detections` | **9** |
| Avg `…_baseline` duration | 1284ms (slowest endpoint, 3× the median) |
| Avg `…_detections` duration | 389ms |

Nine close-time pairings is the strongest workflow signal in the corpus.
Maps directly onto the `stepsecurity-egress-sweep` skill operators have
installed.

**Shape.** One verb issues both calls in parallel and emits a joined
`_kind:"workflow"` stream — `{workflow_id, baseline_state,
open_detections[], severity_roll_up}`. Honors "compose by stream"
(`cli-philosophy.md`). Reuses the `severity-roll-up` enrichment recipe
already in the SDK (B6).

**Cost saved.** Sequential today ≈ 1673ms wall + two argv invocations
(~110 tokens). Parallel ≈ 1284ms (the slower call) + one argv (~25
tokens). At 9 observed pairs that is ~750 tokens already, plus ~3.5
seconds wall.

---

### 3. `sidestep actions inspect <action>` — action-detail synthesis

| Pair (5-min co-occurrence) | n |
|---|---:|
| `get_github_owner_actions_workflow_actions` + `…_workflow_actions_action` | **12** |
| `…_workflow_actions_action` co-occurring with governance/baseline/clusters | 3–4 each |

`workflow_actions_action` is the hub: every governance/posture endpoint
cross-references it within 5 minutes. The latent verb is "show me
everything about this action" — list-then-detail today, one call
tomorrow.

**Bonus.** Three HTTP 500s on this endpoint in the corpus suggest the API
itself is fragile here; a curated verb is the place to centralize retry
policy (the SDK already has the retry layer per B1).

**Cost saved.** ~50 tokens of argv per invocation × 12 observed = ~600
tokens. Plus retry-handling consolidation.

---

### 4. `sidestep actions analyze <action>` — action-vetting flow

| Pair (60-sec co-occurrence) | n |
|---|---:|
| `get_github_owner_actions_maintained` + `post_app_securerepo_analyze` | **5** |
| 60-sec retry loop on `post_app_securerepo_analyze` | 4 |
| HTTP 400 on `post_app_securerepo_analyze` | **5 (100%)** |

5/5 co-occurring within 60 seconds and **every analyze attempt in the
corpus returned HTTP 400.** The strongest "API rejected my shape" signal
in the dataset. A curated verb validates body shape client-side before
the round-trip.

**Cost saved.** 5 × 393ms ≈ 2 seconds of failed round-trips, every one
of which an LLM had to read, parse, and retry-shape. Plus the prompt
cost on retry.

---

### 5. `sidestep detections resolve --workflow <id> --jira MSSCI-XXXXX [--reason …]`

All 3 `post_github_owner_actions_detections` resolves in the corpus
share the **exact** template:

```
"Endpoint already in <workflow>.yml allowed-endpoints (MSSCI-XXXXX);
 detection predates the fix merge."
```

Body keys identical across the 3: `{workflow_id, detection, resolve,
resolve_reason}`. The `stepsecurity-egress-sweep` skill description
confirms this is the durable resolve shape — every sweep produces N of
these.

**Cost saved.** Body JSON today ≈ 250 chars / ~80 tokens; proposed flag
set ≈ 80 chars / ~25 tokens. **~55 tokens per resolve.** At an
expected 20 resolves/sweep that is ~1100 tokens per sweep saved, plus
shape-validation in the SDK instead of JSON-parsing roundtrips.

---

### 6. First-class `--type` / `--status` filters on `list detection`

| Signal | n |
|---|---:|
| Total `get_github_owner_actions_detections` calls | 25 |
| HTTP 400 returned | 8 |
| Same-op retries within 60s | **7** |
| `detection_id=Domain-Blocked` typed as a query param | 10 |

32% of detection list calls fail with 400, and 7 of those are
time-adjacent retries — the operator (or LLM) is param-tuning at the
API. `sidestep list detection` already exists in v0.1 but currently
routes through CEL post-filter. Adding first-class `--type` / `--status`
filters that map to the API's query schema lets the SDK reject bad
shapes before the round-trip, with finding-005-style "expected vs
received" diagnostics.

**Cost saved.** 7 retries × 389ms ≈ 2.7 seconds wall + a prompt rewrite
per retry.

---

### 7. `sidestep audit query --since <dur> --group-by <field> [--cooccur <window>]`

[Charter F3](../../charter.md) currently sits in *data-flowing, threshold-gating
v0.2-sugar-design* status. The analysis in this document is the
prototype. Without a built-in reader, every v0.2 design session
reinvents the `python3 < jq < grep` pipeline.

This is also the verb the reproduction prompt below should eventually
delegate to. Today the prompt embeds a Python script; once #7 ships,
the prompt becomes one shell line.

---

## Summary table

| # | Proposal | Evidence (corpus n) | Tokens saved (corpus) | Latency saved |
|---|---|---|---:|---:|
| 1 | Chain reaches `api <opId>` | 74 owner literals; 17% noise | ~440 + ongoing | — |
| 2 | `harden status` | 9 baseline+detections pairs | ~750 | 389ms/call (parallel) |
| 3 | `actions inspect <action>` | 12 list+detail pairs | ~600 | retry consolidation |
| 4 | `actions analyze <action>` | 5/5 co-occur, 5/5 HTTP 400 | ~125 | ~2s (kill retry loop) |
| 5 | `detections resolve --jira <id>` | 3/3 identical-shape resolves | ~55/call, ~1100/sweep | — |
| 6 | First-class detection filters | 7 of 25 calls are 400-retries | ~350 | ~2.7s |
| 7 | `audit query` (F3 reader) | enables F3 design itself | recurring | recurring |

---

## Reproduction prompt

> **Goal:** Mine your own `sidestep` audit trail and produce a comparable
> per-operator summary so we can merge across the team and design v0.2
> composites from real workflow evidence rather than intuition.

Copy the block below into a Claude Code session (or any agent with
shell + Python). It is self-contained: no inputs other than your own
audit-log directory.

````markdown
You are mining my local `sidestep` audit trail to surface candidate
meta-commands for the v0.2 composite-verb design. Charter F3 in
`~/work/aae-orc/sidestep/charter.md` is the destination.

## Step 1 — Locate the corpus

The audit logs live in one of (first that exists wins):

  1. `$SIDESTEP_AUDIT_DIR`               (if set)
  2. `$XDG_STATE_HOME/sidestep/audit/`   (canonical XDG)
  3. `~/.local/state/sidestep/audit/`    (XDG default)
  4. `~/.sidestep/audit/`                (legacy fallback)

Each file is `YYYY-MM-DD.jsonl`, one JSON object per line. Schema is
documented at `~/work/aae-orc/sidestep/docs/audit-trail-format.md`
(schema_version 2). If you find nothing, report `corpus: empty` and stop
— that itself is a useful data point.

## Step 2 — Run this Python against the corpus

```python
import json, glob, collections, os, sys
from datetime import datetime, timedelta

candidates = [
    os.environ.get("SIDESTEP_AUDIT_DIR"),
    os.environ.get("XDG_STATE_HOME") and f"{os.environ['XDG_STATE_HOME']}/sidestep/audit",
    os.path.expanduser("~/.local/state/sidestep/audit"),
    os.path.expanduser("~/.sidestep/audit"),
]
audit_dir = next((c for c in candidates if c and os.path.isdir(c)), None)
if not audit_dir:
    print("corpus: empty"); sys.exit(0)

records = []
for f in sorted(glob.glob(f"{audit_dir}/*.jsonl")):
    for ln in open(f):
        ln = ln.strip()
        if not ln: continue
        try: records.append(json.loads(ln))
        except json.JSONDecodeError: pass

for r in records:
    r["_ts"] = datetime.fromisoformat(r["ts_start"].replace("Z", "+00:00"))
records.sort(key=lambda r: r["_ts"])

print(f"## Corpus")
print(f"records: {len(records)}")
if records:
    print(f"window:  {records[0]['ts_start'][:10]} → {records[-1]['ts_start'][:10]}")
days = collections.Counter(r['ts_start'][:10] for r in records)
print(f"active days: {len(days)}")
print(f"avg/active-day: {len(records)/max(len(days),1):.1f}")

print(f"\n## By verb_phase")
for k, n in collections.Counter(r.get('verb_phase', '<none>') for r in records).most_common():
    print(f"  {n:4d}  {k}")

print(f"\n## By operation.id (top 20)")
ops = collections.Counter(
    (r.get('operation') or {}).get('id', '<none>') for r in records)
for k, n in ops.most_common(20):
    print(f"  {n:4d}  {k}")

print(f"\n## Results")
for k, n in collections.Counter(r.get('result', '<none>') for r in records).most_common():
    print(f"  {n:4d}  {k}")

print(f"\n## HTTP status")
st = collections.Counter()
for r in records:
    s = (r.get('response') or {}).get('status')
    if s is not None: st[s] += 1
for s, n in sorted(st.items()):
    print(f"  {n:4d}  {s}")

print(f"\n## Constant-value typing tax (argv tokens appearing >= 3 times)")
toks = collections.Counter()
SKIP = {'sidestep', 'filter', 'api', 'list', 'get', 'search', 'enrich', 'emit',
        '--where', '--param', '--body', '--owner', '--customer', '--limit',
        '--since', '--output', '--policies', '--explain', '-p', '--no-audit'}
for r in records:
    for tok in r['invocation']['argv']:
        if tok in SKIP or tok.endswith('/sidestep'): continue
        toks[tok] += 1
for t, n in [(t, n) for t, n in toks.most_common() if n >= 3][:20]:
    print(f"  {n:4d}  {t!r}")

print(f"\n## Time-adjacent co-occurrence (api calls within 5min, distinct ops)")
api = [r for r in records
       if r.get('verb_phase') == 'api' and (r.get('operation') or {}).get('id')]
pairs = collections.Counter()
W = timedelta(minutes=5)
for i, a in enumerate(api):
    for b in api[i+1:]:
        if b['_ts'] - a['_ts'] > W: break
        ka, kb = a['operation']['id'], b['operation']['id']
        if ka == kb: continue
        pairs[tuple(sorted([ka, kb]))] += 1
for (a, b), n in pairs.most_common(15):
    print(f"  {n:3d}  {a}  +  {b}")

print(f"\n## Retry/arg-tuning loops (same op within 60s)")
loops = collections.Counter()
for i, a in enumerate(api):
    for b in api[i+1:]:
        if b['_ts'] - a['_ts'] > timedelta(seconds=60): break
        if a['operation']['id'] == b['operation']['id']:
            loops[a['operation']['id']] += 1
            break
for op, n in loops.most_common(10):
    print(f"  {n:3d}  {op}")

print(f"\n## Errors by operation (top 10 by failure count)")
fails = collections.Counter()
for r in records:
    if r.get('result') == 'http_error':
        op = (r.get('operation') or {}).get('id', '<none>')
        st = (r.get('response') or {}).get('status', '?')
        fails[(op, st)] += 1
for (op, s), n in fails.most_common(10):
    print(f"  {n:3d}  {s}  {op}")
```

## Step 3 — Produce the summary

Using the script output, write a Markdown summary in this exact shape
(so summaries from different operators merge cleanly):

````
# sidestep audit-mining — <your-name> — <today>

## Corpus
- Records: <n>
- Window: <YYYY-MM-DD> → <YYYY-MM-DD>
- Active days: <n>
- Average per active day: <float>

## Top 5 operations (by call count)

| operation.id | n | result mix (ok/http_error/network_error) |
|---|---:|---|
| ... | ... | ... |

## Top 5 time-adjacent co-occurrence pairs (5-min window)

| op A | op B | n |
|---|---|---:|
| ... | ... | ... |

## Top retry loops (same op within 60s)

| operation.id | retry-head count |
|---|---:|
| ... | ... |

## Failure clusters (operations with >= 2 http_errors)

| operation.id | http status | n |
|---|---|---:|
| ... | ... | ... |

## Constant-value typing (tokens appearing >= 3x, excluding flags/verbs)

| token | n |
|---|---:|
| ... | ... |

## Workflow narratives — your shape, not template

Spend 3-5 sentences each on the top 3 recurring workflows the data
reveals. What were you actually trying to accomplish? Which API calls
were "real" content vs. ceremony? Where did the ceremony bite (typing,
retries, joining results in your head)? Be specific — name the
detections, the workflows, the repos. The narrative is what merges
into a v0.2 composite-verb proposal; the table is just the evidence.

## Composite-verb candidates you'd commit to

For each candidate, name:
- Proposed verb form (e.g. `sidestep harden status`)
- Constituent operations it would fold together
- Audit-trail evidence (n) from your corpus
- One real recent task it would have helped with
````

## Step 4 — Send the summary

Paste the Markdown summary into the Slack thread or share the file
back to me. Do **not** paste raw audit-log contents — those are local
data with redaction policy applied only on write. The summary above
is the right shape to share.

## Notes

- The audit log never contains tokens or other secrets; redaction
  happens at write-time (see `docs/audit-trail-format.md` §Redaction).
- If you have `--no-audit` lines (`result: "redacted_block"`), those
  count toward the corpus but carry no operation detail — that is by
  design. Note them in the corpus section.
- If your corpus is below 30 records, say so up front; small-n
  summaries still aggregate, they just carry a confidence note.
- Schema is v2; if you see `schema_version: 1` lines, the corpus
  predates B7 (slice 5) and lacks `verb_phase`/`synthesis_keys`. The
  script tolerates this — `verb_phase` becomes `<none>` for those
  records.

Optional but useful: if you have a sense of how often you reach for
sidestep but stop because the verb shape is missing, write a short
"unwritten workflows" section at the bottom — counterfactual evidence
the audit trail cannot capture but the design needs.
````

---

## Merging across operators (followup)

Once 3+ summaries are in, the next pass is:

1. Concatenate the per-operator summary tables into one ranking sheet.
2. For each composite-verb candidate, count operator-distinct support
   (a workflow that exists in 1 operator's corpus is weak; in 3 is
   strong). Operator-distinct support matters more than raw n.
3. Cross-reference each candidate against `docs/research/value-propositions.md`
   — does it serve a named StepSecurity value family, or is it a
   personal-workflow shortcut?
4. File the strongest 3–5 candidates as `aae-orc` bd tickets against
   sidestep, gated on charter F3 promotion to bedrock.

That step is the v0.2 design session this document is groundwork for.

---

## Cross-references

- [`charter.md`](../../charter.md) — F3 (audit-mining surface), B7 (v0.1 layer shipped)
- [`docs/audit-trail-format.md`](../audit-trail-format.md) — schema, redaction policy
- [`docs/research/value-propositions.md`](value-propositions.md) — what StepSecurity sells (constrains which composites earn their weight)
- [`docs/research/noun-inventory.md`](noun-inventory.md) — the 9 `_kind`s
- [`.claude/rules/cli-philosophy.md`](../../.claude/rules/cli-philosophy.md) — the design rules each composite must honor
- [`_kos/findings/finding-001-primitives-over-composites.md`](../../_kos/findings/finding-001-primitives-over-composites.md) — why v0.2 is deferred to evidence-driven design
