#!/usr/bin/env bash
#
# Capture the CLI surface — stdout, stderr, and exit code for every command and
# error path — into a single text file. Used to prove that refactoring the
# command bodies out of internal/cli leaves observable behaviour unchanged:
#
#   ./scripts/cli-golden.sh > /tmp/before.txt   # then refactor
#   ./scripts/cli-golden.sh > /tmp/after.txt
#   diff /tmp/before.txt /tmp/after.txt
#
# Only offline paths are covered. Anything needing AWS credentials is invoked
# only far enough to exercise argument handling.
#
set -uo pipefail

BIN=${BIN:-./bin/aws-netpath}
EX=examples/double-inspection.json
TD=internal/query/testdata

run() {
  echo "############################################################"
  echo "\$ aws-netpath $*"
  echo "--- stdout+stderr:"
  "$BIN" "$@" 2>&1
  echo "--- exit: $?"
  echo
}

# Exit codes, per cross-cutting 7:
#
#   0  permitted with every layer evaluated, or the command succeeded
#   1  a finding to act on, or an answer established only in part
#   2  the command could not produce an answer at all
#
# Two consequences to watch for in the capture. Requested help is exit 0, at the
# top level and under every subcommand. And a verdict resting on an abstention is
# exit 1 even when nothing was shown to block the flow: an abstention is not a
# pass, so it does not get the code that means permitted.

CLI=internal/cli/testdata

# --- dispatch and help -----------------------------------------------------
run
run -h
run --help
run help
run version
run not-a-command

# --- query -----------------------------------------------------------------
run query -h
run query
run query --snapshot "$TD/double-inspection.json"
run query --snapshot "$TD/double-inspection.json" --from 10.30.32.10
run query --snapshot /nope.json --from 10.30.32.10 --to 10.30.192.10 --proto tcp --port 443
run query --snapshot "$TD/double-inspection.json" --from nonsense --to 10.30.192.10 --proto tcp --port 443
run query --snapshot "$TD/double-inspection.json" --from 10.30.32.10 --to nonsense --proto tcp --port 443
run query --snapshot "$TD/double-inspection.json" --from 10.30.32.10 --to 10.30.192.10 --proto sctp --port 443
run query --snapshot "$TD/double-inspection.json" --from 10.30.32.10 --to 10.30.192.10 --proto tcp
run query --snapshot "$TD/double-inspection.json" --from 10.30.32.10 --to 10.30.192.10 --proto tcp --port 99999
run query --snapshot "$TD/double-inspection.json" --from 10.30.32.10 --to 10.30.192.10 --proto tcp --port 443
run query --snapshot "$TD/double-inspection.json" --from 10.30.32.10 --to 10.30.192.10 --proto tcp --port 443 --json
run query --snapshot "$TD/double-inspection.json" --from 10.30.32.10 --to 10.30.192.10 --proto tcp --port 443 --skip-firewall
run query --snapshot "$TD/double-inspection.json" --from 10.30.32.10 --to 10.30.192.10 --proto icmp
run query --snapshot "$TD/default-action-pass.json" --from 10.30.32.10 --to 10.30.192.10 --proto tcp --port 443
run query --snapshot "$TD/default-action-pass.json" --from 10.30.32.10 --to 10.30.192.10 --proto icmp
run query --snapshot "$TD/double-inspection.json" --from 192.168.99.1 --to 10.30.192.10 --proto tcp --port 443
# the exit-0 case: both endpoints resolve to collected interfaces, every layer is
# evaluated, nothing abstains. Contrast with default-action-pass.json above, which
# reports PERMITTED on three abstentions and exits 1.
run query --snapshot "$CLI/same-vpc-permitted.json" --from 10.0.1.10 --to 10.0.2.20 --proto tcp --port 443

# --- firewall --------------------------------------------------------------
run firewall -h
run firewall
run firewall --snapshot "$EX"
run firewall --snapshot /nope.json --from 10.30.32.0/19 --to 10.30.192.0/20
run firewall --snapshot "$EX" --from garbage --to 10.30.192.0/20
run firewall --snapshot "$EX" --from 10.30.32.0/19 --to garbage
run firewall --snapshot "$EX" --from 10.30.32.0/19 --to 10.30.192.0/20 --proto sctp
run firewall --snapshot "$EX" --from 10.30.32.0/19 --to 10.30.192.0/20 --port garbage
run firewall --snapshot "$EX" --from 10.30.32.0/19 --to 10.30.192.0/20 --proto tcp --port 443
run firewall --snapshot "$EX" --from 10.30.32.0/19 --to 10.30.192.0/20 --proto tcp --port 443 --json
run firewall --snapshot "$EX" --from 10.30.32.0/19 --to 10.30.192.0/20 --proto tcp --port 443,8080
run firewall --snapshot "$EX" --from 10.30.32.0/19 --to 10.30.192.0/20 --proto tcp --port 443,8080 --firewall use1
run firewall --snapshot "$EX" --from 10.30.32.0/19 --to 10.30.192.0/20 --proto tcp --port 443 --firewall no-such-firewall
run firewall --snapshot "$EX" --from 10.30.32.0/19 --to 10.30.192.0/20 --proto icmp
run firewall --snapshot "$EX" --from 10.30.32.0/19 --to 10.30.192.0/20 --proto any --port any
run firewall --snapshot "$TD/default-action-pass.json" --from 10.30.32.0/19 --to 10.30.192.0/20 --proto tcp --port 443

# --- diagnose --------------------------------------------------------------
run diagnose -h
run diagnose
run diagnose --snapshot "$TD/double-inspection.json"
run diagnose --snapshot /nope.json --from 10.30.32.10 --to 10.30.192.10 --proto tcp --port 443
run diagnose --snapshot "$TD/double-inspection.json" --from 10.30.32.10 --to 10.30.192.10 --proto sctp --port 443
run diagnose --snapshot "$TD/double-inspection.json" --from 10.30.32.10 --to 10.30.192.10 --proto tcp
run diagnose --snapshot "$TD/double-inspection.json" --from 10.30.32.10 --to 10.30.192.10 --proto tcp --port 443
run diagnose --snapshot "$TD/double-inspection.json" --from 10.30.32.10 --to 10.30.192.10 --proto tcp --port 443 --skip-firewall
run diagnose --snapshot "$TD/double-inspection.json" --from 10.30.32.10 --to 10.30.192.10 --proto icmp
# cloud layers clear, host layers unverified: NO BLOCKER FOUND, not authoritative,
# exit 1. The same snapshot exits 0 under query, which does not probe a host.
run diagnose --snapshot "$CLI/same-vpc-permitted.json" --from 10.0.1.10 --to 10.0.2.20 --proto tcp --port 443
# renderers: text is the default, --json and --markdown are the same report, and
# both together is a usage error rather than a precedence rule
run diagnose --snapshot "$TD/double-inspection.json" --from 10.30.32.10 --to 10.30.192.10 --proto tcp --port 443 --json
run diagnose --snapshot "$TD/double-inspection.json" --from 10.30.32.10 --to 10.30.192.10 --proto tcp --port 443 --markdown
run diagnose --snapshot "$TD/double-inspection.json" --from 10.30.32.10 --to 10.30.192.10 --proto tcp --port 443 --json --markdown
# symptom: each recognised value, then one that is not
run diagnose --snapshot "$TD/double-inspection.json" --from 10.30.32.10 --to 10.30.192.10 --proto tcp --port 443 --symptom connection-refused
run diagnose --snapshot "$TD/double-inspection.json" --from 10.30.32.10 --to 10.30.192.10 --proto tcp --port 443 --symptom no-route-to-host
run diagnose --snapshot "$TD/double-inspection.json" --from 10.30.32.10 --to 10.30.192.10 --proto tcp --port 443 --symptom timeout
run diagnose --snapshot "$TD/double-inspection.json" --from 10.30.32.10 --to 10.30.192.10 --proto tcp --port 443 --symptom connect-then-stall
run diagnose --snapshot "$TD/double-inspection.json" --from 10.30.32.10 --to 10.30.192.10 --proto tcp --port 443 --symptom icmp-ok-tcp-fails
run diagnose --snapshot "$TD/double-inspection.json" --from 10.30.32.10 --to 10.30.192.10 --proto tcp --port 443 --symptom not-a-symptom

# --- compare ---------------------------------------------------------------
run compare -h
run compare
run compare --snapshot "$TD/double-inspection.json" --from 10.30.32.10 --to 10.30.192.10
run compare --snapshot /nope.json --from 10.30.32.10 --to 10.30.192.10 --ref-from 10.30.32.11 --proto tcp --port 443
run compare --snapshot "$TD/double-inspection.json" --from 10.30.32.10 --to 10.30.192.10 --ref-from 10.30.32.11 --proto tcp --port 443
run compare --snapshot "$TD/double-inspection.json" --from 10.30.32.10 --to 10.30.192.10 --ref-from 10.30.32.11 --ref-to 10.30.192.11 --proto tcp --port 443
run compare --snapshot "$TD/double-inspection.json" --from 10.30.32.10 --to 10.30.192.10 --ref-from 10.30.32.11 --proto tcp --port 443 --json
run compare --snapshot "$TD/double-inspection.json" --from 10.30.32.10 --to 10.30.192.10 --ref-from 10.30.32.11 --proto tcp --port 443 --markdown
run compare --snapshot "$TD/double-inspection.json" --from 10.30.32.10 --to 10.30.192.10 --ref-from 10.30.32.11 --proto tcp --port 443 --json --markdown
# the symptom describes the failing path only
run compare --snapshot "$TD/double-inspection.json" --from 10.30.32.10 --to 10.30.192.10 --ref-from 10.30.32.11 --proto tcp --port 443 --symptom connection-refused
run compare --snapshot "$TD/double-inspection.json" --from 10.30.32.10 --to 10.30.192.10 --ref-from 10.30.32.11 --proto tcp --port 443 --symptom not-a-symptom

# --- diff ------------------------------------------------------------------
run diff -h
run diff
run diff --from "$EX"
run diff --from /nope.json --to "$EX"
run diff --from "$EX" --to /nope.json
run diff --from "$EX" --to "$EX"
run diff --from "$EX" --to "$TD/default-action-pass.json"
run diff --from "$EX" --to "$TD/default-action-pass.json" --json
run diff --from "$EX" --to "$TD/default-action-pass.json" --markdown
run diff --from "$EX" --to "$TD/default-action-pass.json" --json --markdown

# --- test ------------------------------------------------------------------
run test -h
run test
run test --snapshot "$TD/double-inspection.json"
run test --flows examples/flows.yaml
run test --snapshot /nope.json --flows examples/flows.yaml
run test --snapshot "$TD/double-inspection.json" --flows /nope.yaml
run test --snapshot "$TD/double-inspection.json" --flows examples/flows.yaml
run test --snapshot "$TD/double-inspection.json" --flows examples/flows.yaml --skip-firewall
run test --snapshot "$TD/double-inspection.json" --flows examples/flows.yaml --json
run test --snapshot "$TD/double-inspection.json" --flows examples/flows.yaml --markdown
run test --snapshot "$TD/double-inspection.json" --flows examples/flows.yaml --json --markdown

# --- verify (offline paths only) -------------------------------------------
run verify -h
run verify
run verify --snapshot "$TD/double-inspection.json"
run verify --snapshot /nope.json --from 10.30.32.10 --to 10.30.33.10 --skip-aws
run verify --snapshot "$TD/double-inspection.json" --from bad --to 10.30.33.10 --skip-aws
run verify --snapshot "$TD/double-inspection.json" --from 10.30.32.10 --to bad --skip-aws
run verify --snapshot "$TD/double-inspection.json" --from 10.30.32.10 --to 10.30.33.10 --proto sctp --skip-aws
run verify --snapshot "$TD/double-inspection.json" --from 10.30.32.10 --to 10.30.33.10 --proto tcp --skip-aws
run verify --snapshot "$TD/double-inspection.json" --from 10.30.32.10 --to 10.30.192.10 --proto tcp --port 443 --skip-aws
run verify --snapshot "$TD/double-inspection.json" --from 10.30.32.10 --to 10.30.192.10 --proto tcp --port 443 --skip-aws --json
run verify --snapshot "$TD/double-inspection.json" --from 10.30.32.10 --to 10.30.192.10 --proto tcp --port 443 --skip-aws --markdown
run verify --snapshot "$TD/double-inspection.json" --from 10.30.32.10 --to 10.30.192.10 --proto tcp --port 443 --skip-aws --json --markdown
run verify --snapshot "$TD/double-inspection.json" --from 10.30.32.10 --to 10.30.192.10 --proto icmp --skip-aws
# no --profile and no --config: must fail before any AWS call
run verify --snapshot "$TD/double-inspection.json" --from 10.30.32.10 --to 10.30.192.10 --proto tcp --port 443
# --config present but no account for the region: must fail before any AWS call.
# eu-west-1 is deliberately absent from examples/aws-netpath.yaml.
run verify --snapshot "$TD/double-inspection.json" --config examples/aws-netpath.yaml --region eu-west-1 --from 10.30.32.10 --to 10.30.192.10 --proto tcp --port 443

# --- collect (argument handling only; no AWS call) --------------------------
run collect -h
run collect
run collect --profiles a,b
run collect --profile p --profiles a,b --regions us-east-1
run collect --config /nope.yaml

# --- mcp (help only) -------------------------------------------------------
#
# Bare `mcp` is not captured: it hands stdin and stdout to the MCP transport and
# waits for a client, so it would block this script rather than print anything.
# Help is the only path that returns.
run mcp -h
