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

## Audit Trail Privacy

sidestep writes a local JSONL audit trail of every API call. By design
this trail strips authentication tokens and known sensitive payload
fields before writing. See `docs/audit-trail-format.md` for the
redaction policy. Report any field that leaks via the channel above.
