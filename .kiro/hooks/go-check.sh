#!/usr/bin/env bash
#
# Fast Go gates for the edited file's package.
#
# Called by go-check-on-save.json (trigger PostFileSave). Scoped to package
# directories rather than ./... so a save stays under a second or two: linting the
# whole module on every keystroke-adjacent save is the difference between a hook
# that gets left enabled and one that gets turned off.
#
# Target resolution is delegated to hook-target.sh: explicit argument, then the
# STDIN payload, then the git-dirty set. v1 hooks do not substitute ${file}, so
# the payload and the dirty set are what a real save has to work from — see the
# comment block in hook-target.sh.
#
# Advisory only: findings are printed but the script exits 0 regardless. A
# save-time hook fires while code is half-written — an unused variable in a
# function you are still typing is not a failure, it is the normal state of
# work in progress. The blocking gate is verify.sh on Stop, and CI.
#
# Usage:
#   bash .kiro/hooks/go-check.sh internal/cli/collect.go
#   echo '{"filePath":"internal/cli/collect.go"}' | bash .kiro/hooks/go-check.sh
#   bash .kiro/hooks/go-check.sh            # falls back to the dirty set
set -uo pipefail

# golangci-lint and the other Go tools install to GOPATH/bin, which is not
# necessarily on the hook process's PATH.
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
  echo "go-check: $*"
}

readarray -t resolved < <(hook_resolve '\.go$' "${1:-}")
target_source="${resolved[0]#source=}"
files=("${resolved[@]:1}")

if (( ${#files[@]} == 0 )); then
  note "no Go file resolved from argument, payload, or dirty set — nothing to do"
  exit 0
fi

# Cap the file list before doing any work. Only ever engages on the dirty
# fallback; an argument or payload resolves to one file.
found_count=${#files[@]}
readarray -t files < <(hook_cap 10 "${files[@]}")
capped_files=$(( found_count - ${#files[@]} ))

# Package directories are the unit of work for vet and lint, so collapse the file
# list to unique directories. Ten dirty files in one package cost one vet run.
readarray -t pkg_dirs < <(printf '%s\n' "${files[@]}" | xargs -r -n1 dirname | sort -u)

note "source $target_source  ${#files[@]} file(s), ${#pkg_dirs[@]} package(s)"
if (( capped_files > 0 )); then
  note "capped  $capped_files further dirty file(s) skipped to keep the save fast"
fi

findings=0

# 1. gofmt across the resolved files. Cheapest gate, catches the most common diff
#    noise. A missing tool is a skip, not a finding: reporting "needs formatting"
#    when gofmt could not run would be a false accusation.
if ! command -v gofmt >/dev/null 2>&1; then
  note "gofmt   skipped   gofmt not on PATH"
elif fmt_out="$(gofmt -l "${files[@]}" 2>&1)" && [[ -z "$fmt_out" ]]; then
  note "gofmt   ok        ${#files[@]} file(s)"
else
  note "gofmt   needs formatting:"
  printf '%s\n' "$fmt_out" | sed 's/^/          /' | head -10
  note "        fix with: gofmt -w <file>"
  findings=$((findings + 1))
fi

# 2. go vet per package. Type-checks, so it also surfaces compile errors in the
#    package the edit belongs to.
if ! command -v go >/dev/null 2>&1; then
  note "vet     skipped   go not on PATH"
else
  for pkg_dir in "${pkg_dirs[@]}"; do
    if vet_out="$(go vet "./$pkg_dir" 2>&1)"; then
      note "vet     ok        ./$pkg_dir"
    else
      note "vet     findings  ./$pkg_dir"
      printf '%s\n' "$vet_out" | sed 's/^/          /' | head -20
      findings=$((findings + 1))
    fi
  done
fi

# 3. golangci-lint per package. Skip cleanly when absent: a contributor without
#    the linter installed should still get gofmt and vet, not a hook that fails
#    on every save.
if ! command -v golangci-lint >/dev/null 2>&1; then
  note "lint    skipped   golangci-lint not on PATH"
else
  for pkg_dir in "${pkg_dirs[@]}"; do
    if lint_out="$(golangci-lint run "./$pkg_dir" 2>&1)"; then
      note "lint    ok        ./$pkg_dir"
    else
      note "lint    findings  ./$pkg_dir"
      printf '%s\n' "$lint_out" | sed 's/^/          /' | head -25
      findings=$((findings + 1))
    fi
  done
fi

if (( findings > 0 )); then
  note "$findings gate(s) reported findings (advisory — not failing the save)"
fi

exit 0
