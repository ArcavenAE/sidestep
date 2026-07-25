# Audit-stream sharing as a first-class action

Status: idea (pre-hypothesis), v2 — restructured 2026-07-25 after five
same-session design rounds (history at bottom). Raised while drafting
the qkb9 verb-evidence corpus ask: teammates need to hand over audit
streams, and manual instructions ("tar up `~/.sidestep/audit/`") ship
raw lines violating every data-hygiene forbidden class.

**Scope note:** v2 spans sidestep, bloomctl, jira-cli, and future
vendor CLIs — outgrowing sidestep. Candidate for promotion to
`aae-orc/_kos/ideas/` (cross-cutting knowledge belongs at the
composition layer). Kept here until an orc session promotes it.

## Threat model (governs everything below)

**Harvest-now-decrypt-later is the design assumption.** Standing
doctrine (NIST PQ-migration rationale; CISA/NSA store-now-decrypt-
later advisories), concrete in our tooling: age recipient encryption
is X25519 → broken by Shor; TLS key exchange likewise. AI-scaled
attack economics make bulk ciphertext collection rational with no
immediate monetization path. AES-256/SHA-256 survive known quantum
attack (Grover halves effective strength), so symmetric constructions
outlive the envelopes. **Design as if the corpus eventually becomes
plaintext.**

Layer ranking, by what survives:

1. **Minimization** (whitelist projection) — the only durable layer.
   Strictest profile is the DEFAULT: shapes, hashes, sources,
   timings; path+cardinality, no literals.
2. **Pseudonymization** — HMAC-SHA256, per-machine salts that never
   leave contributors. Symmetric-strength: survives envelope breaks.
   A future-decrypted bundle still doesn't map `org_1` to anyone.
3. **Ciphertext non-availability** — write-only inboxes, sweep to
   undisclosed storage, TTL, never publicly-reachable ciphertext
   (rules out pastebin-class and secret-gist transports). What was
   never collected, no future break unlocks.
4. **Scheduled deletion** — raw bundles destroyed after mining; only
   derived aggregates persist (Glean expiry made mandatory).
5. **Encryption** — time-boxed confidentiality. Harden cheaply:
   PQ-hybrid age plugin (sntrup761x25519) or scrypt-passphrase age
   (symmetric, PQ-resistant), passphrase out-of-band.

## The bundle contract (transport-agnostic core)

A **whitelist projection** of the local trail — only declared-safe
fields: schema_version, bucketed timestamp, duration_ms, verb_phase,
operation id/method, outcome, status, items_returned, shape_hash,
predicate_ast_shape, field_paths_referenced, param *sources*,
synthesis_keys, build_id (aae-orc-c714 — corpus stratification by
channel). Dangerous residue is enumerable and excluded: argv, param
values, literal_values_by_path, host, user, cursors.

Plus: manifest (date range, line count, redaction-profile version,
build_id set, claimed contributor id, TLP marking), leak-gate pass
(`check-org-leaks.sh` + `.leak-patterns.local`), show-a-sample-
before-send (brew/ubuntu-report precedent), then age-encrypt to the
campaign recipient set. After encryption the transport needs zero
trust properties.

**Redaction profiles are versioned declarations** (the Glean
metrics.yaml stance: whitelist by declaration, never blacklist by
scrubbing). Manifest pins the profile version; miners declare which
versions they accept; contributors' config records the version they
consented to and the tool refuses to share under a newer one without
re-consent.

## Cross-tool architecture: sharing as a TOOL, not a feature

sidestep, bloomctl (iru/Kandji), jr/jira-cli, and future vendor CLIs
are all "CLI against a SaaS API with a local audit trail" — and they
span languages (Rust, Go). So the share machinery must not be a
per-tool reimplementation:

- **Spec-first:** the bundle format + profile schema is the contract
  (like `docs/audit-trail-format.md`), owned at platform level.
- **A standalone `dropbundle`-style CLI** does projection-by-profile,
  pseudonymization, gating, sealing, sending. Tools compose by
  stream: `sidestep audit export | dropbundle seal --campaign X |
  dropbundle send`. A Go tool adopts by shelling out — no port
  needed. Fits SOUL composability; each tool only needs (a) an audit
  trail, (b) a published redaction profile.
- Per-tool sugar (`sidestep audit share`) wraps the composition.

**Casual build path (gradual elaboration):** v0 lives inside sidestep
(qkb9 campaign, manual transport). Extract the standalone CLI when
the second tool (bloomctl is nearest — tenant-data-hygiene sibling
rule already exists) wants it — the fleet's second-instance rule.
Profiles registry and transport plugins evolve behind the stable
bundle contract.

## SecureDrop, transferred

SecureDrop's stance: the submission server is ASSUMED compromised —
it never holds decryption keys; submissions are encrypted on arrival;
plaintext exists only on an airgapped Secure Viewing Station.

Transfers to us:
- **Two-plane separation**: submission surface (write-only, publicly
  reachable, holds no secrets) vs retrieval plane (authenticated,
  different infrastructure entirely).
- **Encrypt-on-arrival as backstop**: sweep re-wraps objects to the
  current escrow set — a stale-campaign-key or misconfigured-client
  bundle still ends up sealed to the roster.
- **The SVS maps to hardware keys**: decryption only ever on operator
  machines with YubiKey-resident age identities
  (age-plugin-yubikey) — touch-per-decrypt; infra compromise yields
  ciphertext only (time-boxed per threat model, still the best
  available). "The airgap, worn on a keychain."
- **Codenames map to stable contributor pseudonyms**: longitudinal
  joins across campaigns without identity.
- **Reply channel maps to receipts**: content-hash receipt so a
  contributor can verify inclusion; team context = Slack ack.

Does NOT transfer: Tor/anonymity (contributors are known teammates),
Tails/dedicated-hardware operational burden.

## Mail-slot inbox (write-only drop)

Prior art: Unix spool dirs (mode 733 — droppers get write+traverse,
no list). Cloud rendering:

- **IAM as mode bits** — inbox bucket exposes PutObject only (no
  Get/List). Presigned PUT URLs add time-bounding per upload.
- **Content-addressed unguessable names** — path = hash of
  ciphertext; without List, objects are undiscoverable even if Get
  leaks.
- **Sweep = quarantine + relocation** — scheduled function validates
  (manifest shape, size caps, profile version, server-side leak-gate
  re-run — never trust the client's gate; MISP/AIS precedent), then
  moves survivors to a second bucket whose binding exists only
  server-side, in no client-visible code. Attackers reading tool
  source know where data is SENT, not where it WENT. Rejects → review
  hold, never corpus.
- **Inbox TTL** (~72h lifecycle) — unswept residue vanishes; bounds
  exposure and garbage-fill.
- Rate limits + size caps on the submission surface.

## Storage/transport suitability survey

| Option | Verdict | Notes |
|---|---|---|
| **R2 + Workers** | Best default | Presigned PUT, lifecycle TTL, sweep Worker, no egress fees; dl.betterdials.com stack pointed inbound |
| **S3 + Lambda** | Best for AWS-native teams | Same shape + IAM maturity, Object Lock for retention; natural where team infra is AWS (1898 case) |
| B2 / GCS / any S3-compatible | Fine | Contract is presigned-PUT + lifecycle + sweep fn |
| **Pastebin-class / gists** | REJECTED | Publicly-reachable ciphertext violates layer 3; no deletion control, no write-only semantics |
| **Magic Wormhole / croc** | Strong tier-0 | PAKE-encrypted direct transfer, NO at-rest ciphertext anywhere — maximal HNDL resistance for transit; synchronous/human-paced |
| **Taildrop** | Good if shared tailnet | Machine-to-machine, no cloud at rest |
| Slack DM / email | v0 baseline | Bundle is sealed; channel needs only delivery. popcon precedent (HTTP or email) |
| GitHub private repo | Convenience tier | Only for contributors already having access; never the baseline (assumes account + access + possibly signing) |
| GitHub PVR/advisories | Off-label, rejected | Right shape, wrong scope; prior art only |

## Deployment modes

- **Solo-maintainer mode (default posture):** an individual supporting
  a tool locks data to themselves — recipient set = their own key(s)
  only; bundles may never leave their machines (local corpus dir).
  The drop infrastructure is optional; the projection/profile
  discipline is not.
- **Team mode:** a named collection campaign — recipient roster,
  campaign window, drop endpoint, retention schedule — announced in
  the ask (Slack), everything needed embedded (campaign key, upload
  URL or "DM me").

## Multi-maintainer escrow (the "PGP approach", modernized)

age natively encrypts to N recipients — any single roster key
decrypts. With age-plugin-yubikey each maintainer's identity is
hardware-resident: "any of the team members might decrypt" is the
default behavior of a recipient list, no PGP needed.

What PGP's web-of-trust actually provided — **how contributors know
the recipient set is legitimate** — is rebuilt as a signed roster:

- **Recipient roster file**: age recipients + owner identities,
  versioned, in the campaign/tool repo.
- **Enrollment ceremony**: new maintainer generates a YubiKey age
  recipient → roster PR → **M existing members countersign**
  (`ssh-keygen -Y sign` with keys verifiable at
  `github.com/<user>.keys` — zero new key material; or minisign;
  or cosign + GitHub attestation, matching F24 practice).
- **Clients verify the signature chain** against pinned genesis keys
  (pinned in the tool/profile at first install).
- **True escrow (recovery)**: optionally an offline org recovery
  recipient — key split Shamir-style among officers or held in a
  safe — so the corpus survives all YubiKeys lost.
- **HNDL tension, stated:** every added recipient widens the
  future-decryption surface, and one compromised roster key opens
  everything sealed to that roster. Bounds: per-campaign rosters
  (small, operational-need-only), campaign key retirement, and layer
  4 deletion. Roster size is a security parameter, not a convenience.

OpenPGP proper (YubiKey OpenPGP applet) remains possible for teams
with existing PGP infra; age+plugins is the fewer-footguns default.

## Evolution path

- **v0 (qkb9, now):** sidestep-only export + strictest profile +
  scrypt-passphrase age + Slack DM. Manual collection, manual
  deletion promise in the ask.
- **v1:** extract `dropbundle` CLI; campaign keys; R2/S3 mail-slot +
  quarantine sweep; receipts.
- **v2:** signed recipient rosters + enrollment ceremony; retention
  automation; bloomctl + jr adopt via profiles.
- **v3:** profile registry at platform level; aggregate-stats
  reciprocity to contributors (Homebrew-style dashboards); possible
  standing `--follow` streams; possible MCP surface.
- Every stage: bundle contract stable, additive-only within major;
  profile versions pinned in manifests.

## Open questions

- Where does the bundle/profile spec live once promoted — orc docs,
  spectacle template, or the dropbundle repo?
- Pseudonym stability across campaigns: per-campaign salts (max
  privacy) vs per-machine salts (longitudinal joins)? Likely
  per-tool default with campaign override.
- Quarantine review UX: who clears the hold queue, with what view?
- Does the sweep re-wrap (encrypt-on-arrival backstop) require the
  roster public keys at the edge — and is that acceptable exposure?
- F5 tie-in: `share`/`send` is a privilege class never allowlisted
  for agents without the human review step. How does the permission
  doc encode "may build bundle, may never send"?
- Consent versioning UX: what does re-consent look like when a
  profile version bumps?
- Escrow recovery drill: how is the Shamir/safe path tested without
  exposing it?

## Design history (same-session arc, 2026-07-25)

1. v1: private-repo drop-box first → corrected: assumed GitHub +
   signing + repo access; encrypted bundle became the contract,
   transport tiers (Slack/HTTPS/repo).
2. Mail-slot addendum: write-only inbox, sweep-to-unknown, quarantine,
   YubiKey-resident collector key (user direction).
3. HNDL correction (user pushback, accepted): encryption is
   time-boxed; minimization + non-availability + deletion are the
   durable layers.
4. v2 (this rewrite): cross-tool architecture, SecureDrop transfer
   analysis, deployment modes, storage survey, escrow rosters,
   evolution path.
