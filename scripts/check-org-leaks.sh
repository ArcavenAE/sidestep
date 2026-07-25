#!/usr/bin/env bash
# check-org-leaks.sh — block org/customer-identifying data from entering git.
#
# sidestep operates against a StepSecurity org bound to a real company.
# Payloads, audit lines, and fixtures can name the org, its repos, and
# its people. This check runs generic patterns that are safe to publish,
# plus optional org-specific literals from a GITIGNORED local file — so
# the check itself never names the org.
#
# Usage:
#   scripts/check-org-leaks.sh --staged   # pre-commit (staged files)
#   scripts/check-org-leaks.sh --all      # CI / full-tree scan
#
# Local extension: create `.leak-patterns.local` (gitignored) with one
# fixed string per line — your GitHub org / customer name, real repo
# names, internal user emails. Lines starting with # are comments.
# Every developer working against a real org should create one.

set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

MODE="${1:---staged}"

# Generic patterns (ERE). Safe to publish — they describe *shapes*.
GENERIC_PATTERNS=(
  # StepSecurity API bearer tokens (adjust if the real shape differs)
  'Bearer [A-Za-z0-9_-]{24,}'
  # sk_live / sk_test style keys, if any dependency uses them
  'sk_(live|test):[A-Za-z0-9]{16,}'
)

files() {
  case "$MODE" in
    --staged) git diff --cached --name-only --diff-filter=ACM ;;
    --all)    git ls-files ;;
    *) echo "usage: $0 [--staged|--all]" >&2; exit 2 ;;
  esac
}

# Text files only; skip the vendored spec and this script.
scan_list() {
  files | grep -vE '^(spec/|target/|scripts/check-org-leaks\.sh$)' || true
}

fail=0
matches() {
  local pattern="$1"; shift
  [ "$#" -eq 0 ] && return 0
  grep -nE "$pattern" -- "$@" 2>/dev/null || true
}

mapfile -t FILE_LIST < <(scan_list)
[ "${#FILE_LIST[@]}" -eq 0 ] && exit 0

for p in "${GENERIC_PATTERNS[@]}"; do
  hits="$(matches "$p" "${FILE_LIST[@]}")"
  if [ -n "$hits" ]; then
    echo "org-leak check: pattern '$p' matched:" >&2
    echo "$hits" >&2
    fail=1
  fi
done

# Org-specific literals (gitignored local file — fixed strings).
if [ -f .leak-patterns.local ]; then
  while IFS= read -r needle; do
    case "$needle" in ''|'#'*) continue ;; esac
    hits="$(grep -nF -- "$needle" "${FILE_LIST[@]}" 2>/dev/null || true)"
    if [ -n "$hits" ]; then
      echo "org-leak check: local pattern matched (value not echoed):" >&2
      echo "$hits" | cut -d: -f1,2 | sed 's/$/: <redacted match>/' >&2
      fail=1
    fi
  done < .leak-patterns.local
fi

if [ "$fail" -ne 0 ]; then
  cat >&2 <<'EOF'

Org/customer-identifying data must not enter git. Sanitize before committing:
  - replace real org/customer names with synthetic values (acme-corp)
  - replace real repo names with generic ones (web-api, auth-svc)
  - replace real user emails with example values
  - never commit audit-trail lines or raw API payloads
See SECURITY.md "Org Data Hygiene" and CONTRIBUTING.md.
EOF
  exit 1
fi
exit 0
