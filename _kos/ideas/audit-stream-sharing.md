# Audit-stream sharing as a first-class action

Status: idea (pre-hypothesis). Raised 2026-07-25 while the qkb9
verb-evidence corpus ask was being drafted — teammates need to hand us
their audit streams, and today the instructions are manual ("tar up
`~/.sidestep/audit/`"), which ships raw lines that violate the
data-hygiene forbidden classes (org slug, repo names, usernames,
hostnames, predicate literals).

## The shape

`sidestep audit share` (or `audit export --shareable`): a verb that
produces a **whitelist projection** of the local trail and delivers it
over a private, authenticated channel. Safe by construction — the
teammate runs one command instead of following redaction instructions.

### Whitelist, never blacklist

The v2 line already separates shape from values by design: `shape_hash`
(keys+types, no payloads), `predicate_ast_shape` (sha256), field
*sources* (`path_params_source`), `field_paths_referenced`. The
dangerous residue is enumerable: `argv`, `path_params`/`query_params`
values, `literal_values_by_path` (predicate literals = real repo/org
names), `host`, `user`, `next_cursor`.

Projection emits ONLY declared-safe fields: schema_version, bucketed
timestamp, duration_ms, verb_phase, operation.id/method, outcome,
status, items_returned, shape_hash, predicate_ast_shape,
field_paths_referenced, param sources, synthesis_keys, build_id
(stamped as of aae-orc-c714 — corpus stratification by channel).

### Pseudonymization where joins matter

Values that must correlate across lines (owner, repo, customer) get
deterministic pseudonyms: HMAC-SHA256 with a per-corpus random salt →
`org_1`, `repo_3`. Joins survive, identities don't, and the salt never
leaves the contributor's machine. `literal_values_by_path` keeps paths
+ pseudonymized values (or counts only, strictest profile).

### Gates before the bundle leaves

- `scripts/check-org-leaks.sh` + `.leak-patterns.local` run over the
  bundle (reuse of the existing pre-commit backstop).
- Manifest: date range, line count, redaction-profile version,
  build_id set, TLP marking (TLP:AMBER default).
- Show the human the bundle (or a sample) before send — Homebrew
  `brew analytics` / ubuntu-report precedent: display what leaves.

### Transport candidates

CORRECTED 2026-07-25 (same session): the repo-first framing assumed
senders have (1) a GitHub account, (2) signing set up if the repo
enforces required_signatures, (3) write access someone must grant and
manage. Wrong baseline. The load-bearing security lives in bundle
construction (whitelist + pseudonymization + gate + manifest), which
is transport-agnostic; **age-encrypt the bundle to the collector's
public key** (a 62-char string embeddable in the ask itself) and the
transport needs zero trust properties — requirement becomes "can
deliver an opaque file."

- **Tier 0 — any channel the sender already has.** Slack DM (the
  qkb9 ask is already a Slack message), email. No GitHub, no
  signing, no access grants. Debian popcon precedent (HTTP *or
  email* submission).
- **Tier 1 — HTTPS collector.** Cloudflare Worker + R2 accepting
  POSTs — the dl.betterdials.com pattern pointed inbound. Upload
  tokens optional (payloads encrypted, size-capped).
- **Tier 2 — private GitHub repo drop-box** for contributors who
  already have access and want history/review semantics. A
  convenience, not the baseline. (mss-status pattern.)
- Authenticity without ceremony, if ever needed: `ssh-keygen -Y
  sign` with the SSH key every GitHub user already has, verified
  against `github.com/<user>.keys`. Optional — never the price of
  admission; manifest-claimed contributor ID suffices for a mining
  corpus.
- GitHub private vulnerability reporting / draft advisories:
  investigated, **off-label** — right shape (private channel +
  temporary private forks), wrong scope (vulnerabilities, not data
  streams). Prior art only; do not abuse.
- Actions artifacts on a private repo — viable, clunkier than the
  above.

## Prior art surveyed

- **Mozilla Glean** — strongest governance: every metric declared in
  metrics.yaml with a data-sensitivity category (1 technical → 4
  highly sensitive), mandatory data review, expiry. "Whitelist by
  declaration" is the stance our projection copies.
- **Homebrew analytics** — opt-out, anonymous UUID, event names only
  (never argv), public aggregate dashboards; moved off Google
  Analytics to self-hosted for privacy.
- **.NET SDK telemetry** — publishes the collected corpus itself
  (sanitized, delayed) — precedent for sharing data, not just
  aggregates.
- **Debian popcon / ubuntu-report** — opt-in, random ID, show-before-
  send.
- **Sentry** — beforeSend client-side scrub hooks + server scrubbers;
  org-scoped private sharing.
- **OpenTelemetry Collector** — redaction/attributes processors:
  "emit rich locally, redact at the export boundary." Our trail is
  already OTel-shaped (trace_id/span_id); an OTLP export path with a
  collector-side redaction profile is a plausible alternative
  architecture.
- **Threat-intel sharing** — MISP sharing groups, STIX/TAXII, CISA
  AIS (submitter identity stripped by default), TLP markings. The
  "private community + explicit sensitivity marking" pattern.
- **HIBP k-anonymity range queries** — share an indicator without
  revealing it; relevant if we ever share detection indicators.
- **Apple local DP / Google RAPPOR** — differential privacy for
  aggregates; heavy machinery, overkill for v1, the canonical answer
  if corpus contributors ever exceed a trusted circle.
- **rustup telemetry (canceled)** — cautionary: consent posture
  decides adoption.

## Mail-slot inbox design (session addendum 2)

User direction: combine expiry/encryption with a write-only drop-box —
uploads swept out of the inbox to an undisclosed location; attackers
can read sidestep's code so they know where data is *sent*, but not
where it *went*; perms in the spirit of `rw-----w-`. Prior art: Unix
spool dirs (mode 733 — droppers need traverse `-wx`, no list) and
SecureDrop (source-facing server ASSUMED compromised, never holds
keys, submissions encrypted on arrival, swept to an airgapped
station).

Cloud rendering of the mail slot:
- **IAM as mode bits** — inbox bucket exposes PutObject only (no
  Get/List). Object-store policy is the honest modern spelling.
- **Content-addressed, unguessable names** — upload path = hash of
  ciphertext; without List, objects are undiscoverable even if Get
  leaks (128-bit-URL entropy as read-permission).
- **Sweep** — scheduled Worker moves objects to a second bucket whose
  binding exists only server-side, in no client-visible code (the
  user's core mechanic). dl.betterdials.com stack, pointed inbound.
- **TTL on inbox residue** — lifecycle expiry (~72h) bounds exposure
  and garbage accumulation for unswept objects.

Additions beyond the sweep:
1. **Quarantine, not just relocation** — a world-writable slot
   accepts attacker writes; the inbox is untrusted input. Sweep =
   validation: manifest shape, size caps, redaction-profile version,
   server-side re-run of the leak-gate (never trust the client's
   gate). Rejects → review hold, not corpus. (MISP/AIS submission-
   validation precedent.)
2. **Collector age key on YubiKey** (`age-plugin-yubikey`) — bulk
   decryption of the corpus requires a physical touch per bundle;
   total infra compromise yields ciphertext only. SecureDrop's
   airgap, worn on a keychain. Fits the existing hardware posture.
3. **Per-campaign recipient keys** — the qkb9-style ask embeds a
   campaign key; window closes, key retires; blast radius of key
   compromise = one campaign.

Protection ranking (each cheap — stack all, but don't let the sweep
substitute for the first two): whitelist projection (data never
collected) > age-to-YubiKey (unreadable anywhere) > quarantine
validation > sweep-to-unknown > inbox TTL.

## Open questions

- Is the projection a redaction *profile* (versioned, declared in the
  manifest) so the mining side knows exactly what it can rely on?
- Does `literal_values_by_path` survive pseudonymization usefully, or
  do verb-evidence miners only need path+cardinality?
- Where does the corpus repo live and who holds read access?
- Opt-in UX: one-shot share vs. standing `audit share --follow`?
- Relationship to F3 (mining surface) and F5 (permissions): a
  `share` verb is a new privilege class — never allowlisted for
  agents without the human-gated review step?
