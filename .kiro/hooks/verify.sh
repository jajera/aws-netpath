#!/usr/bin/env bash
#
# Full repository gate, run once when the agent finishes a turn.
#
# Called by verify-on-stop.kiro.hook. This is the blocking counterpart to the
# advisory save-time hooks: it runs the same gates CI runs, so a turn does not
# end with the repo in a state that would fail on push.
#
# Output is deliberately terse — one line per gate plus a summary — because it
# lands in the transcript on every single turn. Failure detail is printed only
# for the gates that failed, and truncated.
#
# Exits non-zero when a gate genuinely failed, so the agent notices.
#
# Usage:
#   bash .kiro/hooks/verify.sh
set -uo pipefail

if command -v go >/dev/null 2>&1; then
  PATH="$PATH:$(go env GOPATH)/bin"
  export PATH
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root" || exit 1

failed=()
skipped=()

# report NAME STATUS [detail...]
line() {
  printf 'verify: %-10s %s\n' "$1" "$2"
}

# run NAME COMMAND...
# Records a failure and prints the tail of its output.
run() {
  local name="$1"
  shift
  local out
  if out="$("$@" 2>&1)"; then
    line "$name" "PASS"
  else
    line "$name" "FAIL"
    printf '%s\n' "$out" | tail -15 | sed 's/^/          /'
    failed+=("$name")
  fi
}

# 1. Environment neutrality. Cheapest and the one whose failure matters most:
#    it is the gate standing between a real account id or CIDR and a push.
if [[ -x ./scripts/sanitise-gate.sh ]]; then
  run sanitise ./scripts/sanitise-gate.sh
else
  line sanitise "SKIP" && skipped+=(sanitise)
fi

have_go=0
command -v go >/dev/null 2>&1 && have_go=1

# 2. Compile. Everything after this is meaningless if the module does not build.
if (( have_go )); then
  run build go build ./...
else
  line build "SKIP" && skipped+=(build)
fi

# 3. vet.
if (( have_go )); then
  run vet go vet ./...
else
  line vet "SKIP" && skipped+=(vet)
fi

# 4. gofmt must report nothing. gofmt exits 0 even when it lists files, so the
#    check is on the output being empty, not on the exit code.
if ! command -v gofmt >/dev/null 2>&1; then
  line gofmt "SKIP"
  skipped+=(gofmt)
elif fmt_out="$(gofmt -l . 2>&1)" && [[ -z "$fmt_out" ]]; then
  line gofmt "PASS"
else
  line gofmt "FAIL"
  printf '%s\n' "$fmt_out" | head -15 | sed 's/^/          /'
  failed+=(gofmt)
fi

# 5. golangci-lint. Skipped rather than failed when absent — a missing local tool
#    is not a defect in the tree, and CI runs it unconditionally.
if command -v golangci-lint >/dev/null 2>&1; then
  run lint golangci-lint run
else
  line lint "SKIP"
  skipped+=(lint)
fi

# 6. Tests last: slowest gate, and the least useful signal if the build is broken.
#    `go test ./...` prints an ok line per package, which is 20-odd lines of noise
#    around the one that failed, so the passing lines are dropped before the tail.
if ! (( have_go )); then
  line test "SKIP"
  skipped+=(test)
elif test_out="$(go test ./... 2>&1)"; then
  line test "PASS"
else
  line test "FAIL"
  printf '%s\n' "$test_out" | grep -vE '^(ok|\?)[[:space:]]' | tail -15 | sed 's/^/          /'
  failed+=(test)
fi

summary="verify: ${#failed[@]} failed"
if (( ${#skipped[@]} > 0 )); then
  summary="$summary, ${#skipped[@]} skipped (${skipped[*]})"
fi
if (( ${#failed[@]} > 0 )); then
  echo "$summary — ${failed[*]}"
  exit 1
fi
# A skipped gate is not a pass, so do not claim the tree is green when one was
# unrunnable — the same distinction the tool itself draws between a pass and an
# abstention.
if (( ${#skipped[@]} > 0 )); then
  echo "$summary — no failures, but not every gate ran"
  exit 0
fi
echo "$summary — all gates green"
exit 0
