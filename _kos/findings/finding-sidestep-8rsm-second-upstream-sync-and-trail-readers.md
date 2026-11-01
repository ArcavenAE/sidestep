# finding-sidestep-8rsm: the second upstream sync moved and changed operations, and the audit trail got its first readers

Date: 2026-10-30
Status: final
Subject: sidestep (the vendored spec, the stream primitives and the audit-trail readers)
Refs: sidestep#48, #49, #50, #51, #52, #53, #55; follows finding-007 (the first sync) and finding-006 (the v0.1 primitive layer)

## Why it matters

The first upstream sync (finding-007) was purely additive. This one was not, so the claim that the sync pipeline absorbs an upstream update without hand edits now has a second data point that moved and changed existing operations. The same week gave `diff-spec` its implementation and the audit trail its first readers, which is what `question-audit-mining` was waiting for.

## The second sync (#50)

- The vendored spec went from 130 to 243 operations by method and path: 114 added and 1 removed, the removed one reappearing at a new path (the reusable-workflows read lost its `actions` path segment; no curated kind uses it), so 130 - 1 + 114 = 243. The sync PR (#50) worded this as "114 new, one moved", which counts the moved operation twice; `diff-spec` (#52) reports 114 added and 1 removed.
- A method-and-path comparison of parameter lists found 12 shared operations whose parameters changed (#50). `diff-spec` (#52), which also compares request bodies and responses, reports 36 changed operations for the same sync, so the two counts measure different things and neither is wrong.
- The sanitizer replaced 3 secret-shaped examples, and 158 operations got a synthesized operationId.
- The generated client now depends on `regress`, because the spec carries its first string types with a `pattern`. Without it the regenerated crate does not compile.

## diff-spec is built (#52)

It was a stub when finding-007 was written, and the operation-set diff was hand-rolled then. It now prints added and removed operations (method, path, operationId), changed operations with one line per difference, a count of component-schema changes by name, and a summary. Operations are keyed on path and method; summaries, descriptions, titles and examples are ignored. Limit: a `$ref` is compared as a reference, so a change inside a component schema shows in the `schemas:` line and not under each operation that uses it.

## Three more stream primitives

- `rank` (#48): deterministic, stable ordering by typed fields, with the keys and outcome counts in the verb's audit line.
- `diff` (#49): set difference over two keyed record streams. It exists because two example recipes could not be written in the v0.1 primitives without splitting the audit trail through `comm` and `jq`. A record with a missing key field fails the run, since skipping it would read as unchanged when the truth is not comparable.
- `replay` (#51): one trace's audit spans read back as a stream. It returns what was called and the shape of each response, not the records, because the trail stores no payloads.

## The trail's first reader (#53)

`audit query` summarizes the corpus, groups by a field, and counts operations called together inside a window. It reads the trail even when writing is off, appends its own audit line after it has read so a run does not count itself, and reads the whole trail into memory, which is fine at the corpus size in the research notes (about 250 spans in 60 days).

## A defect class in --since (#55)

`list detection --since` failed on every window. The kind table named time fields the live records do not carry: detection records carry `timestamp`, epoch seconds as a string, not `created_at`. The fix names each kind's real field (run, rule, incident and threat_intel changed as well), reads epoch seconds and milliseconds, and holds records until the listing finishes, because a filter that failed mid-listing had left earlier records on stdout before exiting 1. Tests now serve the shapes the live API returns. Not verified: `audit_log`'s field, which needs a customer that was not configured.

## What this does not settle

The mining question stays open: what to build from weeks of trail. Two of its candidates now exist, and the corpus is still small. No confidence moves.
