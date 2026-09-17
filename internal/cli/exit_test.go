package cli

// The exit-code contract.
//
// A pipeline reads the exit code and nothing else, so these are the assertions
// that matter most to a caller who never sees the report. Two levels are covered:
// the mapping functions in isolation, and whole invocations through Run, because a
// correct mapping wired to the wrong fact is still the wrong code.
//
// Every invocation here is offline. The snapshots are fixtures, no AWS client is
// constructed, and the paths that would need credentials are exercised only as far
// as argument handling.

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"testing"
)

// Fixtures. same-vpc-permitted is the case exit 0 exists for: both endpoints
// resolve to collected interfaces, every layer is evaluated, nothing abstains.
// The two inherited fixtures supply a blocked flow and a permitted-but-unverified
// one.
const (
	permittedSnapshot  = "testdata/same-vpc-permitted.json"
	blockedSnapshot    = "../query/testdata/double-inspection.json"
	unverifiedSnapshot = "../query/testdata/default-action-pass.json"
	permittedSrc       = "10.0.1.10"
	permittedDst       = "10.0.2.20"
)

func TestExitParse(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		// Requested help is a command succeeding, not a usage error. Every
		// command parses with flag.ContinueOnError, so -h and --help arrive here
		// as flag.ErrHelp and must not be confused with a bad flag.
		{"help requested", flag.ErrHelp, ExitOK},
		{"help requested through a wrapped error", fmt.Errorf("diagnose: %w", flag.ErrHelp), ExitOK},
		{"parsing succeeded", nil, ExitOK},
		{"unrecognised flag", errors.New("flag provided but not defined: -nope"), ExitError},
		{"unparseable value", errors.New(`invalid value "x" for flag -port`), ExitError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := exitParse(tt.err); got != tt.want {
				t.Errorf("exitParse(%v) = %d, want %d", tt.err, got, tt.want)
			}
		})
	}
}

// The whole of cross-cutting 7's 0-versus-1 line, in four rows.
//
// The third row is the one the tool exists for: nothing was shown to block the
// flow, and a layer went unread, so "permitted" was not established. Cross-cutting
// 1 forbids aggregating that Abstention into a pass, and exit 0 is a pass.
func TestExitFinding(t *testing.T) {
	tests := []struct {
		name        string
		finding     bool
		established bool
		want        int
	}{
		{"permitted with every layer evaluated", false, true, ExitOK},
		{"blocked, and shown to be", true, true, ExitBlocked},
		{"no finding, but a layer could not be read", false, false, ExitBlocked},
		{"a finding on an incomplete run is still a finding", true, false, ExitBlocked},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := exitFinding(tt.finding, tt.established)
			if got != tt.want {
				t.Errorf("exitFinding(finding=%t, established=%t) = %d, want %d",
					tt.finding, tt.established, got, tt.want)
			}
		})
	}
}

// Dispatch: nothing ran, so there is nothing to read and the code says so.
func TestDispatchExitCodes(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want int
	}{
		{"no subcommand", nil, ExitError},
		{"unknown subcommand", []string{"not-a-command"}, ExitError},
		{"unknown subcommand with flags", []string{"not-a-command", "--json"}, ExitError},
		{"help", []string{"help"}, ExitOK},
		{"-h", []string{"-h"}, ExitOK},
		{"--help", []string{"--help"}, ExitOK},
		{"version", []string{"version"}, ExitOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := run(t, tt.args...); got != tt.want {
				t.Errorf("aws-netpath %s exited %d, want %d", strings.Join(tt.args, " "), got, tt.want)
			}
		})
	}
}

// Help is exit 0 for every subcommand, not just the top level. Read from
// commands() so a command added later cannot quietly opt out.
func TestRequestedHelpSucceedsForEverySubcommand(t *testing.T) {
	for _, c := range commands() {
		for _, flagName := range []string{"-h", "--help"} {
			t.Run(c.name+" "+flagName, func(t *testing.T) {
				if got := run(t, c.name, flagName); got != ExitOK {
					t.Errorf("aws-netpath %s %s exited %d, want %d: requested help is a command succeeding",
						c.name, flagName, got, ExitOK)
				}
			})
		}
	}
}

// A usage error is exit 2 for every subcommand: a missing required flag, an
// unrecognised flag, and two renderers at once all mean the command was never told
// what to answer.
func TestUsageErrorsExitTwo(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"no flags at all", []string{"diagnose"}},
		{"missing endpoints", []string{"diagnose", "--snapshot", permittedSnapshot}},
		{"unrecognised flag", []string{"diagnose", "--not-a-flag"}},
		{"unreadable snapshot", []string{
			"diagnose", "--snapshot", "testdata/no-such-snapshot.json",
			"--from", permittedSrc, "--to", permittedDst, "--proto", "tcp", "--port", "443",
		}},
		{"unrecognised symptom", []string{
			"diagnose", "--snapshot", permittedSnapshot,
			"--from", permittedSrc, "--to", permittedDst, "--proto", "tcp", "--port", "443",
			"--symptom", "not-a-symptom",
		}},
		{"two renderers", []string{
			"diagnose", "--snapshot", permittedSnapshot,
			"--from", permittedSrc, "--to", permittedDst, "--proto", "tcp", "--port", "443",
			"--json", "--markdown",
		}},
		{"query with an address the snapshot does not cover", []string{
			"query", "--snapshot", blockedSnapshot,
			"--from", "192.168.99.1", "--to", "10.30.192.10", "--proto", "tcp", "--port", "443",
		}},
		{"diff with one snapshot", []string{"diff", "--from", permittedSnapshot}},
		{"test with no flow file", []string{"test", "--snapshot", permittedSnapshot}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := run(t, tt.args...); got != ExitError {
				t.Errorf("aws-netpath %s exited %d, want %d", strings.Join(tt.args, " "), got, ExitError)
			}
		})
	}
}

// The three codes over whole invocations, against real fixtures.
func TestCommandExitCodes(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want int
		why  string
	}{
		{
			name: "a permitted flow with nothing abstaining",
			args: []string{
				"query", "--snapshot", permittedSnapshot,
				"--from", permittedSrc, "--to", permittedDst, "--proto", "tcp", "--port", "443",
			},
			want: ExitOK,
			why:  "every layer was evaluated and none blocked",
		},
		{
			name: "a blocked flow",
			args: []string{
				"query", "--snapshot", blockedSnapshot,
				"--from", "10.30.32.10", "--to", "10.30.192.10", "--proto", "tcp", "--port", "443",
			},
			want: ExitBlocked,
			why:  "a firewall dropped the flow",
		},
		{
			// The decision this test exists to pin: PERMITTED resting on
			// abstentions is not exit 0. Cross-cutting 1.
			name: "a permitted flow resting on abstentions",
			args: []string{
				"query", "--snapshot", unverifiedSnapshot,
				"--from", "10.30.32.10", "--to", "10.30.192.10", "--proto", "tcp", "--port", "443",
			},
			want: ExitBlocked,
			why:  "three layers abstained, so permitted was not established",
		},
		{
			// Same fixture as the exit-0 case above, through diagnose, which
			// probes no host without a Systems Manager client. Cloud clear and
			// host unverified is not the same answer as all clear.
			name: "no blocker found with the host layers unverified",
			args: []string{
				"diagnose", "--snapshot", permittedSnapshot,
				"--from", permittedSrc, "--to", permittedDst, "--proto", "tcp", "--port", "443",
			},
			want: ExitBlocked,
			why:  "both host layers abstained, so no blocker found is not permitted",
		},
		{
			name: "two identical snapshots",
			args: []string{"diff", "--from", permittedSnapshot, "--to", permittedSnapshot},
			want: ExitOK,
			why:  "nothing changed and both were read at the same schema version",
		},
		{
			name: "two different snapshots",
			args: []string{"diff", "--from", permittedSnapshot, "--to", blockedSnapshot},
			want: ExitBlocked,
			why:  "a change is the finding this command exists to produce",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := run(t, tt.args...); got != tt.want {
				t.Errorf("aws-netpath %s exited %d, want %d: %s",
					strings.Join(tt.args, " "), got, tt.want, tt.why)
			}
		})
	}
}

// The exit code changed and the report did not. A diagnosis that exits 1 because
// its host layers went unread still reports that no layer was shown to block —
// downgrading the finding to match the code would be the wrong fix.
func TestUnestablishedDiagnosisStillReportsWhatItFound(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{
		"diagnose", "--snapshot", permittedSnapshot,
		"--from", permittedSrc, "--to", permittedDst, "--proto", "tcp", "--port", "443",
	}, &stdout, &stderr)

	if code != ExitBlocked {
		t.Fatalf("exited %d, want %d (stderr: %s)", code, ExitBlocked, stderr.String())
	}
	got := stdout.String()
	for _, want := range []string{
		"NO BLOCKER FOUND",
		"not authoritative",
		"host_firewall",
		"host_listener",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the report no longer mentions %q:\n%s", want, got)
		}
	}
}

// run dispatches through Run with the output discarded, which is how a caller
// reading only the exit code sees the tool.
func run(t *testing.T, args ...string) int {
	t.Helper()
	return Run(args, io.Discard, io.Discard)
}
