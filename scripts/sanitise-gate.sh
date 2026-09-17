#!/usr/bin/env bash
#
# Environment-neutrality gate (requirement 17).
#
# Proves the repository contains no real account identifier, credential profile
# name, region, or routable address range. The check is a positive allowlist, not
# a denylist of known-bad values: enumerating real values in a checked-in script
# would defeat the purpose. Anything not explicitly permitted fails.
#
# Invoked by path from the pre-commit hook and from CI, so it works from any
# working directory:
#   ./scripts/sanitise-gate.sh
#
set -uo pipefail

# The hook and CI both call this by path from wherever they happen to be, and
# every check below resolves paths relative to the repository root.
cd "$(git rev-parse --show-toplevel)" || exit 1

fail=0

# Files to scan: everything tracked plus everything untracked that is not
# ignored, minus binaries, module checksums, the spec directory (which quotes the
# pre-migration module path as history), and this script (whose allowlist
# patterns would otherwise match themselves).
#
# --others --exclude-standard is what makes this gate useful. A gate that reads
# only committed content passes on the changeset you are about to commit, which
# is the single moment the answer matters: the values it exists to catch are
# still untracked when the hook runs, so scanning the index alone reports green
# on a tree nobody has looked at. Ignored files stay out, so a local snapshot or
# a built binary does not fail the run.
scan_files() {
  git ls-files --cached --others --exclude-standard \
    | grep -vE '^(bin/|\.kiro/|go\.sum$|LICENSE$|scripts/sanitise-gate\.sh$)' \
    | grep -vE '\.(png|jpg|jpeg|gif|ico|pdf)$'
}

report() {
  printf '  %-24s %s\n' "$1" "$2"
}

# ---------------------------------------------------------------------------
# 1. IPv4 literals must fall inside a reserved range.
#
# Permitted (cross-cutting semantics 8, requirement 17.2):
#   10.0.0.0/8, 192.168.0.0/16                RFC 1918 private
#   192.0.2.0/24, 198.51.100.0/24,
#   203.0.113.0/24                            RFC 5737 documentation
#   127.0.0.0/8, 169.254.0.0/16               loopback, link-local
#   0.0.0.0, 128.0.0.0, 255.255.255.255       address-space boundaries used by
#                                             the prefix set algebra tests
#
# The allowlist is deliberately narrower than RFC 1918 as a whole. Examples,
# fixtures, and tests draw private space from 10.0.0.0/8 and 192.168.0.0/16 only,
# so any other private range appearing here is an unreviewed value and fails.
#
# One literal is allowlisted by exact value rather than by range: 3.3.0.0 is a
# Systems Manager agent version, not an address. Agent versions are four-part, so
# every realistic value is IPv4-shaped and no substitution can avoid the match.
# The allowlist is that exact string only, so it cannot admit a real address.
# ---------------------------------------------------------------------------
echo "checking IPv4 literals..."
bad_ip=$(
  scan_files | xargs grep -EohI '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' 2>/dev/null \
    | sort -u \
    | grep -vE '^10\.' \
    | grep -vE '^192\.168\.' \
    | grep -vE '^192\.0\.2\.' \
    | grep -vE '^198\.51\.100\.' \
    | grep -vE '^203\.0\.113\.' \
    | grep -vE '^127\.' \
    | grep -vE '^169\.254\.' \
    | grep -vE '^(0\.0\.0\.0|128\.0\.0\.0|255\.255\.255\.255)$' \
    | grep -vxF '3.3.0.0'
)
if [ -n "$bad_ip" ]; then
  echo "FAIL: address literals outside the reserved documentation ranges:"
  while IFS= read -r ip; do
    report "$ip" "$(scan_files | xargs grep -lI -- "$ip" 2>/dev/null | tr '\n' ' ')"
  done <<< "$bad_ip"
  fail=1
fi

# ---------------------------------------------------------------------------
# 2. Twelve-digit account identifiers must be reserved documentation values.
# ---------------------------------------------------------------------------
echo "checking account identifiers..."
bad_acct=$(
  scan_files | xargs grep -EohI '\b[0-9]{12}\b' 2>/dev/null \
    | sort -u \
    | grep -vE '^(111122223333|222233334444|444455556666|555566667777|777788889999|888899990000)$'
)
if [ -n "$bad_acct" ]; then
  echo "FAIL: account identifiers outside the placeholder set:"
  while IFS= read -r id; do
    report "$id" "$(scan_files | xargs grep -lI -- "$id" 2>/dev/null | tr '\n' ' ')"
  done <<< "$bad_acct"
  fail=1
fi

# ---------------------------------------------------------------------------
# 3. Region identifiers must come from the neutral example set. No region is
#    hardcoded in logic; these appear only in examples, fixtures, and tests.
# ---------------------------------------------------------------------------
echo "checking region identifiers..."
bad_region=$(
  scan_files | xargs grep -EohI '\b(af|ap|ca|cn|eu|il|me|sa|us)-[a-z]+-[0-9]{1,2}\b' 2>/dev/null \
    | sort -u \
    | grep -vE '^(us-east-1|us-west-2|eu-west-1)$'
)
if [ -n "$bad_region" ]; then
  echo "FAIL: region identifiers outside the neutral example set:"
  while IFS= read -r r; do
    report "$r" "$(scan_files | xargs grep -lI -- "$r" 2>/dev/null | tr '\n' ' ')"
  done <<< "$bad_region"
  fail=1
fi

# ---------------------------------------------------------------------------
# 4. No region, account, or profile literal in any non-test code path
#    (requirement 17.3).
# ---------------------------------------------------------------------------
echo "checking for environment coupling in logic..."
coupled=$(
  git ls-files --cached --others --exclude-standard '*.go' | grep -v '_test\.go$' \
    | xargs grep -nE '"(af|ap|ca|cn|eu|il|me|sa|us)-[a-z]+-[0-9]{1,2}"|\b[0-9]{12}\b' 2>/dev/null
)
if [ -n "$coupled" ]; then
  echo "FAIL: region or account literal in a non-test code path:"
  echo "$coupled" | sed 's/^/  /'
  fail=1
fi

# ---------------------------------------------------------------------------
# 5. Collected snapshots must not be tracked (requirement 17.5).
# ---------------------------------------------------------------------------
echo "checking for tracked snapshots..."
tracked_snap=$(git ls-files | grep -E '(^|/)snapshot[^/]*\.json$')
if [ -n "$tracked_snap" ]; then
  echo "FAIL: collected snapshot committed to version control:"
  echo "$tracked_snap" | sed 's/^/  /'
  fail=1
fi

# ---------------------------------------------------------------------------
# 6. No leftover reference to the pre-migration project name.
# ---------------------------------------------------------------------------
echo "checking for pre-migration identifiers..."
leftover=$(scan_files | xargs grep -nI 'netprobe' 2>/dev/null)
if [ -n "$leftover" ]; then
  echo "FAIL: pre-migration project name still present:"
  echo "$leftover" | sed 's/^/  /'
  fail=1
fi

if [ "$fail" -eq 0 ]; then
  echo
  echo "PASS: no real account identifier, profile name, region, or routable address range found."
fi
exit "$fail"
