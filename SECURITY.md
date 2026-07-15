# Security Policy

## Reporting a Vulnerability

If you believe you've found a security vulnerability in sidestep, please
report it privately via [GitHub Security
Advisories](https://github.com/ArcavenAE/sidestep/security/advisories/new).

We aim to acknowledge reports within 72 hours and to coordinate disclosure
once a fix is available.

## Scope

sidestep is a local CLI that talks to the StepSecurity API. Vulnerabilities
in StepSecurity's service itself should be reported to StepSecurity
directly, not here.

In-scope examples:

- Credential mishandling (token leakage to logs, audit trail, error output)
- Audit-trail redaction failures (sensitive fields not stripped)
- Supply-chain issues in sidestep's dependency graph

## Org Data Hygiene

sidestep is a PUBLIC repo operating against a real StepSecurity org.
Payloads and metadata identify it. Treat ALL of the following as
confidential — never paste into issues, PRs, commits, discussions, or
public logs:

- **Org / customer identity** — the real GitHub org or customer slug,
  internal team names.
- **Internal repo names** — they map the product and infrastructure.
- **PII** — user names, emails, team memberships from audit actors.
- **Org security posture** — which repos carry which detections /
  policies / suppressions / threat-intel incidents.
- **Credentials** — API tokens, bearer/key material.
- **Raw audit-trail lines** — real path/query params (owner, customer,
  repo), local hostname/username, predicate text.

Defenses in this repo:

- `scripts/check-org-leaks.sh` — pre-commit (lefthook) + CI. Generic
  patterns in-repo; org literals in a gitignored `.leak-patterns.local`.
- GitHub secret scanning + push protection enabled on the repo.
- Fixtures are synthetic by policy (see `examples/`).

Full behavior rule: `.claude/rules/data-hygiene.md`. Report a leaking
field via the security advisory channel above.

## Audit Trail Privacy

sidestep writes a local JSONL audit trail of every API call. By design
this trail strips authentication tokens and known sensitive payload
fields before writing. See `docs/audit-trail-format.md` for the
redaction policy. Report any field that leaks via the channel above.
