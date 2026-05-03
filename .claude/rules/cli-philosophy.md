# CLI Philosophy — Unix-Native, Agent-First

`sidestep` is a CLI for two callers at once: a human at a terminal, and
an LLM in a pipe. They pull the same direction more than they conflict.
This file is the design-time rule that pulls them together — and the
brake we pull when an interface starts taxing the caller.

Behavior-trigger shape (same as orc `tooling-friction.md`). Names the
*behavior*, not the concept, because concepts are easy to rationalize
past at the keystroke.

## The trigger

You are about to do one of:

- Type `arg(required = true)` (or `clap` equivalent) for anything other
  than a unique-per-call identity (the run ID for `get run`, the
  predicate text for `filter`, a file path).
- Add a flag that the next recipe in `examples/` will pass through
  unchanged.
- Write a code comment that says "user must supply X."
- Write an integration test that always sets `--X foo` and never varies it.
- Write a doc that says "remember to include `--X` on every call."

Stop. Apply the test below before the keystroke.

## The Abusive Argument test

A flag is **abusive** if it satisfies all four:

1. **Near-constant.** The value rarely or never changes for a given
   user, credential, or environment.
2. **Not derivable on this call.** No upstream — env, token
   introspection, sibling record, adjacent tool's config — exposes it
   automatically.
3. **No resolution chain.** The flag is the only way to provide it.
4. **Required.** The tool errors when it's omitted.

If all four are true, the flag is abusive. The user pays a tax on every
invocation. The audit trail records the constant on every line. Each
`|` in a pipeline pays again. An LLM caller pays it in tokens.

Worked example: `--owner` on `sidestep list rules`. Owner is the GitHub
org slug, fixed for the lifetime of a StepSecurity token, present on
every v0.1 endpoint. All four boxes check. Captured at `auth login`,
resolved through a chain, the abuse goes away. See `aae-orc-y7lq`.

## The fix — Argument Resolution Chain

For any near-constant value, walk:

1. **Flag** (`--owner <slug>`) — explicit per-call override.
2. **Env** (`SIDESTEP_OWNER=<slug>`) — per-shell or per-process default.
3. **Config** (`~/.config/sidestep/config.toml [default] owner = ...`)
   — persisted per-machine, set at `auth login` time or by `config set`.
4. **Derivation** — token introspection, sibling-record join, adjacent
   tool's config — only if the upstream actually exposes it. Never
   invent. Never guess.
5. **Error**, with a message naming all four sources that failed and
   one concrete next step for each (`set SIDESTEP_OWNER=…`,
   `sidestep config set owner …`).

Mirror the chain on the audit trail: the resolved value records a
`<param>_source` field (`flag|env|config|derived`) so the F3 mining
surface separates constant defaults from per-call intent.

Same chain for tokens (B5), for owner/customer (`aae-orc-y7lq`), for
any future field that meets the abusive-argument test. **One chain, not
one per field.**

## CLI principles, codified

Drawn from McIlroy (1978), Gancarz (1995), Raymond (2003), Pike's
"data dominates," POSIX Utility Conventions (XBD §12), XDG Base
Directory Specification, 12-factor §III. Operative form below.

- **Rule of silence.** No banners, no `[INFO]` chatter, no progress
  bars on stdout. A useful tool shuts up unless it has something to
  say. Decorative output goes to stderr, gated on `isatty(stderr)`.
- **stdout is the contract.** What goes to stdout is structured for
  the next consumer (JSONL by default). Prose, diagnostics, progress
  → stderr.
- **Exit codes are part of the contract.** `0` success, `1` operation
  failure, `2` argv/usage error. Reserve higher codes for semantically
  distinct failures (`sysexits.h` 64–78 if it fits).
- **TTY auto-detection, never auto-coercion.** If stdout is a TTY, the
  tool may pretty-print; otherwise JSONL. `--output {jsonl|md|...}`
  always overrides. There is no `--pretty`; that is the default of a
  TTY-attached output.
- **No captive UI.** No interactive prompts when stdin is not a TTY.
  Explicit non-interactive feeds are named (`auth login --stdin`).
- **Schema stability.** JSONL output shape is part of the public API.
  `schema_version` bumps are release events. Adding fields is additive
  within a major; removing or renaming is breaking.
- **Determinism.** Same argv + same stdin + same config → same stdout
  + same exit code. No hidden RNG. Time is bound at call time (`now`
  per query) and recorded in the audit line.
- **Repair-friendly errors.** Errors carry: what was expected, what
  was received, where (line/column/path), at least one concrete next
  step. No stack traces in release builds.
- **One thing well.** Primitives transform a stream once. Composites
  are recipes (shell, makefile, future v0.2 sugar) until evidence
  justifies promotion. See finding-001.
- **Compose by stream.** The `_kind`-tagged JSONL stream is the text
  that primitives compose over. New verbs respect the contract or
  state explicitly that they are a sink (`emit`) or source (`list`).
- **XDG-correct paths.** Config under `$XDG_CONFIG_HOME` (default
  `~/.config/sidestep/`), state under `$XDG_STATE_HOME` (default
  `~/.local/state/sidestep/`), cache under `$XDG_CACHE_HOME`. Never
  scatter dotfiles in `$HOME`.
- **Env over flags for invariants.** Anything a deployment would set
  once (token, owner, customer, base URL) is reachable via env. Flags
  are for per-call intent.

## Smells (sub-tests for the abusive-argument lens)

- A flag whose value you've typed verbatim more than three times in a
  shell session.
- A flag that appears with the same value on every line of the audit
  trail.
- A flag that recipes pass through unchanged.
- A flag whose value lives in another tool's config (token, org, repo,
  branch) and could be borrowed.
- A flag that an integration test always sets and never varies.
- A flag whose absence produces "missing required parameter" rather
  than a useful default-source diagnostic.

Any one smell is a yellow flag. Two or more is the abusive-argument
test in disguise — apply it.

## What does NOT trigger this rule

- **Per-call identity.** `runid`, predicate text (`--where`), file
  paths, search queries — these are the call's actual content, not
  bookkeeping.
- **Genuinely-varying knobs.** `--limit`, `--since`, `--output` — the
  value is per-question; no constant default makes sense.
- **Safety flags.** `--force`, `--no-confirm`, `--yes` — silence-by-
  default is correct; defaulting to "yes" is a footgun.
- **One-off scaffolding** in `xtask` or internal tooling that is never
  invoked from a recipe or an agent. Apply taste, not the test.

## Why this rule exists

`sidestep` v0.1 shipped `--owner` as a required flag on `list`, `get`,
and `search`, threaded through `build_params`, on every endpoint, even
though every StepSecurity token is bound to a single GitHub org for the
lifetime of the credential. The CLI scaffold treated path params
uniformly and missed that one of them was constant. The audit trail —
designed in finding-001 to mine usage patterns — was about to record
`path_params.owner = "1898andCo"` on every line of the F3 dataset.

Each missed default is small. The agent caller pays it in tokens; the
mining surface pays it in noise; the human pays it in keystrokes. They
compound. The rule moves the test in front of the keystroke: before
typing `required = true`, run the four-box check. If it fails, build
the chain instead of the requirement.

## Cross-references

- B5 (token resolution chain) — `charter.md`
- B7 (v0.1 primitive layer + audit v2) — `charter.md`
- F3 (audit-mining surface) — `charter.md`
- `aae-orc-y7lq` — owner/customer resolution chain (the rule's first
  concrete application)
- finding-001 — primitives over composites (the rule's compositional half)
- orc `.claude/rules/tooling-friction.md` — same behavior-trigger shape
