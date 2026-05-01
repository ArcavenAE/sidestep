# sidestep examples

Track B deliverable (bd `aae-orc-kdz1`) — **spine fixtures + 3 asserts**.

The fixtures + asserts simulate the v0.1 primitive flows in `jq` + shell
so they run today, pre-Rust. Once the Rust implementation lands
(`aae-orc-lyeh`), its output of `list | filter | emit` etc. on the same
fixtures should match these simulations byte-for-byte. That is the
regression contract.

## Layout

```
examples/
├── fixtures/
│   ├── detection.jsonl    5 records covering severity range
│   ├── run.jsonl          5 records covering status lifecycle
│   ├── policy.jsonl       3 records (attached, partial, orphan)
│   ├── rule.jsonl         5 records (3 in pol_001, 1 in pol_002, 1 orphan)
│   └── audit-log.jsonl    5 records covering operation types
├── asserts/
│   ├── 01-round-trip.sh        list → filter(_kind=X) → emit(json) is byte-identical
│   ├── 02-cross-kind-enrich.sh foreign-key joins (policy ↔ rules) work
│   └── 03-rank-stability.sh    rank --by severity desc, ts desc is deterministic
├── Makefile               make assert runs all three
└── README.md              you are here
```

## Run

```sh
make -C examples assert
```

## Spine kinds covered

Per Murat's design (finding-001), the four spine kinds with the most
distinct schema shapes are:

| Kind | Why it's spine |
|---|---|
| `detection` | nested findings, severity enum, suppression state — exercises filter + rank |
| `run` | time-series, status lifecycle — exercises list pagination + get |
| `policy` | relational (attaches to repos, contains rules) — exercises search + cross-kind enrich |
| `audit_log` | high-volume flat records, structured actor — exercises emit + stream back-pressure |

`rule` is included as the join target for the cross-kind-enrich assert
but isn't a spine kind itself; it's a rib that exercises the
`policy.attached_repos[]` / `rule.policy_id` foreign-key shape that
both `enrich --with policy-context` and `update_rule` ActionItems
will rely on.

## What the asserts catch

**01 round-trip** — schema bugs that survive parse but fail on emit:
missing fields, accidental field renames, wrong types, `_kind`
contamination across files. JSON-key ordering is normalized via
`jq -cS` so comparison isn't fragile.

**02 cross-kind enrich** — the foreign-key shape problem (Murat: "the
place schemas usually fail silently"). Tests that the
`policy.id ↔ rule.policy_id` join actually finds rules, that orphan
policies (no rules) return empty cleanly, and that orphan rules
(parent doesn't exist) are detectable rather than silently dropped.

**03 rank-stability** — under-specified sort keys produce
non-deterministic order on ties, which is the worst kind of audit-trail
noise (same logical state hashes differently across runs). The assert
uses an explicit severity-enum-to-int mapping (no lexical sort), then
ts desc as the tiebreak, and verifies two runs produce byte-identical
output.

## What the asserts don't catch (yet)

Track B is fixture-and-assert work. Real Rust primitive behavior —
canonical adapter rules from finding-001 (timestamps at ingest, absent
fields omit keys, `Value::List<T>` with concrete `T`, missing fields
error not null, `now` per query) — is the umbrella's job
(`aae-orc-lyeh`). When the Rust impl lands, these asserts become the
spec for its conformance tests.

## Severity ordering

Closed enum, explicit integer mapping for sort:

```
critical = 4
high     = 3
medium   = 2
low      = 1
info     = 0
```

Same mapping must be used in the Rust impl. Lexical sort is wrong:
"critical" < "high" < "info" < "low" < "medium" alphabetically.

## ActionItem produced from these fixtures

Per `docs/research/action-item-schema.md`, the four spine kinds
produce:

| Source kind | ActionItem kind | Notes |
|---|---|---|
| detection | `suppress_detection` (when status=open + low severity + matches policy) | needs `enrich --with policy-context` |
| detection | `harden_workflow` (when status=open + has workflow_path) | direct |
| run | (none — run is evidence, not action) | `_source` field on detection cites the run |
| policy | `attach_policy` (when attached_repos is empty/sparse) | direct |
| policy | `update_rule` (when last_evaluated_at is null/stale) | needs `enrich --with severity-roll-up` |
| rule | `update_rule` (when policy_id orphan) | direct |
| audit_log | (none — audit_log is evidence) | supports `evidence[]` on others |

Track C (`aae-orc-ldq1`) is the validation that these compositions
actually produce coherent ActionItem streams.
