# sidestep Audit Trail Format

> Status: design (v1). Implementation lands with the SDK wire-up. The
> schema below is the contract future code must honor; deviations require
> bumping `schema_version`.

## Goals

1. Capture every API call sidestep makes — curated verb or `sidestep api`
   passthrough — without exception.
2. Make the trail mineable by a future LLM session for *patterns* (which
   operations cluster, which fail together, which sequences hint at a
   meta-action) without that session needing to read raw payloads.
3. Never write secrets. Authentication headers and known sensitive
   response fields are redacted before write.
4. Stay local. The trail is one user's record on one machine. OTEL export
   is a future opt-in, not a requirement.

## Location

- Default: `~/.local/state/sidestep/audit/YYYY-MM-DD.jsonl` (XDG state).
- Fallback when XDG is unset: `~/.sidestep/audit/YYYY-MM-DD.jsonl`.
- Override: `SIDESTEP_AUDIT_DIR` environment variable.
- Disable per-call: `--no-audit` flag (writes a stub line — see below).
- Disable globally: `SIDESTEP_AUDIT=off`.

Files roll at UTC midnight. Old files are not pruned by sidestep — that
is intentional: the trail is the corpus; pruning is the user's call.

## Schema (v1)

One JSON object per line. Every key below is required unless marked
optional.

```json
{
  "schema_version": 1,
  "trace_id": "01HXY...",
  "span_id": "01HXY...",
  "parent_span_id": null,
  "ts_start": "2026-04-29T18:42:11.234Z",
  "duration_ms": 187,
  "invocation": {
    "argv": ["sidestep", "runs", "list", "--owner", "1898andCo", "--all"],
    "binary_version": "0.1.0",
    "host": "kinu",
    "user": "mike",
    "tty": false,
    "auth_source": "keyring"
  },
  "operation": {
    "id": "listWorkflowRuns",
    "method": "GET",
    "url_template": "/github/{owner}/actions/runs",
    "path_params": {"owner": "1898andCo"},
    "query_params": {"limit": 50, "cursor": "abc"}
  },
  "response": {
    "status": 200,
    "size_bytes": 14823,
    "items_returned": 50,
    "next_cursor": "def",
    "shape_hash": "sha256:..."
  },
  "result": "ok",
  "redacted_fields": ["authorization"]
}
```

### Field semantics

| Field | Purpose |
|-------|---------|
| `schema_version` | Integer. Bump on incompatible schema change. v1 is current. |
| `trace_id` | ULID. Shared across one CLI invocation; all HTTP calls in a `--all` paginated list share one. |
| `span_id` | ULID. Unique per HTTP call. |
| `parent_span_id` | ULID or null. For nested operations (a curated verb that fans out to multiple ops). |
| `ts_start` | RFC 3339 UTC timestamp of when the HTTP request was sent. |
| `duration_ms` | Integer milliseconds, request-send to response-fully-read. |
| `invocation.argv` | Full argv with secret values redacted (e.g. `--token=...` → `--token=***`). |
| `invocation.binary_version` | `CARGO_PKG_VERSION` of the running sidestep. |
| `invocation.host` | `gethostname`. |
| `invocation.user` | `$USER` (best-effort). |
| `invocation.tty` | `true` if stdout is a tty. |
| `invocation.auth_source` | Where the bearer token was resolved from: `"env"` \| `"keyring"` \| `"config"` \| `null`. `null` means an explicit `with_token` constructor was used; nothing was resolved. |
| `operation.id` | OpenAPI `operationId`. The stable join key for pattern mining. |
| `operation.method` | HTTP method. |
| `operation.url_template` | OpenAPI path template (`/github/{owner}/actions/runs`), not the concrete path. Aggregates cleanly across owners/repos. |
| `operation.path_params` | Map of path-param name to value. |
| `operation.query_params` | Map of query-param name to value (redacted per policy). |
| `response.status` | HTTP status. |
| `response.size_bytes` | Bytes received (compressed-on-wire if applicable; SDK reports decompressed length). |
| `response.items_returned` | Integer if the response is a paginated list. Omitted otherwise. |
| `response.next_cursor` | Opaque cursor string for paginated responses. Omitted if absent. |
| `response.shape_hash` | sha256 of the redacted response *shape* (keys + types, not values). Lets pattern detection see "this op returned a different schema today" without storing payloads. |
| `result` | Enum: `ok` \| `http_error` \| `network_error` \| `auth_error` \| `redacted_block`. The last is for `--no-audit` calls where the SDK still records *that* a call happened. |
| `redacted_fields` | List of field paths the redaction policy stripped. Useful for verifying the policy worked. |

## Redaction Policy (initial)

- **Always redacted:** `authorization`, `x-api-key`, any header named like a
  token. Authentication never lands in the trail.
- **Default-deny field names** in payloads: `secret`, `token`, `key` (when
  in a credential-shaped context, not e.g. `key` as a map key in a
  generic JSON shape — heuristic, refined as we hit real cases),
  `password`, `client_secret`.
- **OpenAPI-flagged sensitive fields:** when the spec marks a field as
  containing secrets (e.g. `Detection.secret`), the redaction policy
  honors that automatically. The generator emits a list of redaction
  paths the SDK loads at startup.
- **User-defined extra paths:** `~/.config/sidestep/redaction.toml` adds
  paths beyond the defaults. Never *removes* defaults.

When a field is redacted, its path appears in `redacted_fields` and its
value never reaches disk.

## `--no-audit` and stub lines

`sidestep --no-audit <op>` skips the operation-level detail but still
writes:

```json
{
  "schema_version": 1,
  "trace_id": "01HXY...",
  "span_id": "01HXY...",
  "ts_start": "...",
  "duration_ms": 187,
  "invocation": { "argv": ["sidestep", "--no-audit", "..."], "binary_version": "0.1.0" },
  "result": "redacted_block"
}
```

This preserves a usage signal (an operation happened, took ~187ms, for
this user, at this time) without recording the operation's content. A
later analyzer can see *that* opted-out calls occur even if it cannot
see *what* they were.

`SIDESTEP_AUDIT=off` writes nothing at all.

## Future analysis surface

Out of scope for v0.1. Charter F3 tracks this. Likely shapes:

- `sidestep audit query --since 7d --group-by operation.id` — local
  aggregation.
- `sidestep audit traces` — render trace_id trees.
- `sidestep meta propose` — LLM call against a window of trail to
  suggest curated verbs.
- flyloft catalog adapter — battens that index audit lines so an LLM can
  `fly` against them.

## Why this schema, specifically

- `operation.id` (OpenAPI `operationId`) is the stable join key. Path
  templates aggregate by *operation*, not by *concrete URL*; that keeps
  patterns visible across owners, repos, and customers.
- `trace_id` lets a future analyzer cluster "what does a triage session
  look like?" — a workflow is a tree of related calls, not a flat list.
- `shape_hash` over the redacted response shape (keys + types, not
  values) detects spec drift and unexpected response shapes without
  storing payloads. It's cheap and surprisingly informative.
- `result` taxonomy lets a future analyzer find "operations that
  frequently fail and need a meta-verb wrapper" without parsing prose
  error messages.
- `--no-audit` produces stub lines (not silence) so that opt-out is
  observable. Privacy-preserving, but not invisibility-preserving.
