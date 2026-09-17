package cli

// The mcp subcommand: what it parses, what it hands the server, and what it tells
// a pipeline afterwards.
//
// The command is thin, which is exactly why it is worth testing: everything it
// does is decide whether the session ending was a failure. Being asked to stop is
// not — a client shutting the server down, or an operator interrupting it, is the
// command succeeding at the last thing it was asked to do — and a command that
// reported exit 2 for an ordinary shutdown would put a failure in a supervisor's
// log every time a client closed.
//
// The server itself is substituted, so nothing here opens a session or touches the
// process's stdin. internal/mcpserver covers the session; this covers the mapping.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

// withServer substitutes the MCP server for the duration of a test and returns a
// pointer to the arguments it was called with, or nil if it was never called.
func withServer(t *testing.T, result error) *struct {
	called  bool
	version string
} {
	t.Helper()

	got := &struct {
		called  bool
		version string
	}{}

	original := serve
	serve = func(_ context.Context, version string) error {
		got.called = true
		got.version = version
		return result
	}
	t.Cleanup(func() { serve = original })

	return got
}

// The exit code a session's end maps to.
//
// The first three rows are the same outcome reached three ways: the client closed
// the pipe, the operator interrupted, or the cancellation arrived wrapped by the
// SDK. All three are a session that ended when it was asked to.
func TestMCPExitCodes(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
		why  string
	}{
		{
			name: "the client disconnected",
			err:  nil,
			want: ExitOK,
			why:  "a client closing the pipe is the ordinary end of a session",
		},
		{
			name: "the session was cancelled",
			err:  context.Canceled,
			want: ExitOK,
			why:  "the context is cancelled only by the signal handler, so this is an operator or client asking it to stop",
		},
		{
			name: "the cancellation arrived wrapped",
			err:  fmt.Errorf("session ended: %w", context.Canceled),
			want: ExitOK,
			why:  "the reason is the cancellation however deeply the transport wrapped it",
		},
		{
			name: "the transport failed",
			err:  errors.New("read stdin: file already closed"),
			want: ExitError,
			why:  "a session that ended because it broke produced no answer",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := withServer(t, tt.err)

			var stdout, stderr bytes.Buffer
			code := Run([]string{"mcp"}, &stdout, &stderr)

			if !server.called {
				t.Fatal("aws-netpath mcp did not start the server")
			}
			if code != tt.want {
				t.Errorf("aws-netpath mcp exited %d, want %d: %s", code, tt.want, tt.why)
			}
			// Under stdio transport stdout is the protocol channel, so this
			// command has to leave it alone whatever happened — a diagnostic
			// written there is a framing error rather than a message.
			if stdout.Len() != 0 {
				t.Errorf("aws-netpath mcp wrote to stdout, which carries the protocol:\n%s", stdout.String())
			}
			if tt.want == ExitError && stderr.Len() == 0 {
				t.Error("aws-netpath mcp failed without reporting why on stderr")
			}
			if tt.want == ExitOK && stderr.Len() != 0 {
				t.Errorf("aws-netpath mcp reported a complaint for a clean shutdown:\n%s", stderr.String())
			}
		})
	}
}

// A bad flag is a usage error, and the server is never started. The order matters:
// a command that opened a session and then discovered it could not parse its own
// arguments would have taken over the process's stdin to say so.
func TestMCPRefusesAnUnrecognisedFlagWithoutStartingTheServer(t *testing.T) {
	server := withServer(t, nil)

	var stdout, stderr bytes.Buffer
	if code := Run([]string{"mcp", "--not-a-flag"}, &stdout, &stderr); code != ExitError {
		t.Errorf("aws-netpath mcp --not-a-flag exited %d, want %d", code, ExitError)
	}
	if server.called {
		t.Error("aws-netpath mcp --not-a-flag started the server despite not parsing")
	}
	if stdout.Len() != 0 {
		t.Errorf("aws-netpath mcp --not-a-flag wrote to stdout, which carries the protocol:\n%s", stdout.String())
	}
	if stderr.Len() == 0 {
		t.Error("aws-netpath mcp --not-a-flag refused the flag without saying so on stderr")
	}
}

// Requested help is the command succeeding, and it is written to stderr rather
// than stdout for the same reason everything else here is.
//
// TestRequestedHelpSucceedsForEverySubcommand already asserts the code across the
// whole set; what is added here is that asking for help does not start a session,
// and that the usage text says how a client is meant to reach this command.
func TestMCPHelpDoesNotStartTheServer(t *testing.T) {
	for _, flagName := range []string{"-h", "--help"} {
		t.Run(flagName, func(t *testing.T) {
			server := withServer(t, nil)

			var stdout, stderr bytes.Buffer
			if code := Run([]string{"mcp", flagName}, &stdout, &stderr); code != ExitOK {
				t.Errorf("aws-netpath mcp %s exited %d, want %d", flagName, code, ExitOK)
			}
			if server.called {
				t.Errorf("aws-netpath mcp %s started the server", flagName)
			}
			if stdout.Len() != 0 {
				t.Errorf("aws-netpath mcp %s wrote usage to stdout, which carries the protocol:\n%s",
					flagName, stdout.String())
			}
			// A command started by a client rather than typed at a prompt has to
			// say how it is registered, or the help is addressed to nobody.
			if !strings.Contains(stderr.String(), `["mcp"]`) {
				t.Errorf("aws-netpath mcp %s does not show how to register it with a client:\n%s",
					flagName, stderr.String())
			}
		})
	}
}

// The server reports the binary's version, not one of its own. A client compares
// what it is talking to against what it expected, and two version numbers in one
// process is two answers to that question.
func TestMCPServesTheBinaryVersion(t *testing.T) {
	server := withServer(t, nil)

	original := Version
	Version = "v9.9.9-test"
	t.Cleanup(func() { Version = original })

	if code := Run([]string{"mcp"}, io.Discard, io.Discard); code != ExitOK {
		t.Fatalf("aws-netpath mcp exited %d, want %d", code, ExitOK)
	}
	if server.version != Version {
		t.Errorf("the server was started with version %q, want the binary's %q", server.version, Version)
	}
}
