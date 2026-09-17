#!/usr/bin/env bash
#
# Lint CI workflow and lint-config files at save time.
#
# Called by workflow-lint-on-save.json (trigger PostFileSave).
#
# Why this exists: a malformed workflow, a dependabot config with a bad key, or a
# .golangci.yml that no longer parses is invisible locally — the failure surfaces
# on push, after a round trip. actionlint and yamllint catch all three in under a
# second.
#
# Target resolution is delegated to hook-target.sh: explicit argument, then the
# STDIN payload, then the git-dirty set. v1 hooks do not substitute ${file}, so
# the payload and the dirty set are what a real save has to work from — see the
# comment block in hook-target.sh.
#
# Advisory only, same reasoning as go-check.sh: exits 0 even with findings, and
# skips cleanly when a tool is not installed.
#
# Usage:
#   bash .kiro/hooks/workflow-lint.sh .github/workflows/release.yml
#   echo '{"filePath":".github/workflows/release.yml"}' | bash .kiro/hooks/workflow-lint.sh
#   bash .kiro/hooks/workflow-lint.sh       # falls back to the dirty set
set -uo pipefail

# actionlint installs to GOPATH/bin.
if command -v go >/dev/null 2>&1; then
  PATH="$PATH:$(go env GOPATH)/bin"
  export PATH
fi

hook_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=.kiro/hooks/hook-target.sh
source "$hook_dir/hook-target.sh"

repo_root="$(cd "$hook_dir/../.." && pwd)"
cd "$repo_root" || exit 0

note() {
  echo "workflow-lint: $*"
}

# The same set the hook's matcher regex selects, kept identical on purpose: the
# matcher decides whether the hook fires, this decides what it looks at, and the
# two disagreeing would be a silent no-op.
TARGET_REGEX='(^|/)(\.github/(workflows/[^/]+\.ya?ml|dependabot\.ya?ml)|\.yamllint|\.golangci\.ya?ml)$'

readarray -t resolved < <(hook_resolve "$TARGET_REGEX" "${1:-}")
target_source="${resolved[0]#source=}"
files=("${resolved[@]:1}")

if (( ${#files[@]} == 0 )); then
  note "no workflow or lint config resolved from argument, payload, or dirty set — nothing to do"
  exit 0
fi

# Cap before doing work; only ever engages on the dirty fallback.
found_count=${#files[@]}
readarray -t files < <(hook_cap 10 "${files[@]}")
if (( found_count > ${#files[@]} )); then
  note "capped  $(( found_count - ${#files[@]} )) further dirty file(s) skipped to keep the save fast"
fi

note "source $target_source  ${#files[@]} file(s)"

findings=0

# 1. actionlint, only for workflow files. It understands the Actions schema,
#    expression syntax, and shell inside `run:` blocks — none of which yamllint
#    can see. Run against the resolved workflows, not the whole directory.
readarray -t workflows < <(printf '%s\n' "${files[@]}" | grep -E '^\.github/workflows/.*\.ya?ml$' || true)
if (( ${#workflows[@]} == 0 )) || [[ -z "${workflows[0]}" ]]; then
  note "actionlint n/a       no workflow file among the targets"
elif ! command -v actionlint >/dev/null 2>&1; then
  note "actionlint skipped   not on PATH"
elif al_out="$(actionlint "${workflows[@]}" 2>&1)"; then
  note "actionlint ok        ${#workflows[@]} workflow(s)"
else
  note "actionlint findings"
  printf '%s\n' "$al_out" | sed 's/^/             /' | head -25
  findings=$((findings + 1))
fi

# 2. yamllint against the repo's own .yamllint, so the hook enforces exactly what
#    the yaml-lint workflow enforces and cannot drift from it.
if ! command -v yamllint >/dev/null 2>&1; then
  note "yamllint   skipped   not on PATH"
elif [[ ! -f .yamllint ]]; then
  note "yamllint   skipped   no .yamllint config at repo root"
elif yl_out="$(yamllint -c .yamllint "${files[@]}" 2>&1)"; then
  note "yamllint   ok        ${#files[@]} file(s)"
else
  note "yamllint   findings"
  printf '%s\n' "$yl_out" | sed 's/^/             /' | head -25
  findings=$((findings + 1))
fi

if (( findings > 0 )); then
  note "$findings gate(s) reported findings (advisory — not failing the save)"
fi

exit 0
