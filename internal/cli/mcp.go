package cli

// The MCP subcommand.
//
// This command is thinner than the others because there is no report to render
// and no verdict to map: it hands the process's stdin and stdout to the MCP
// transport and waits. Note that it is the only command that does not write to
// the stdout passed to Run — under stdio transport stdout is the protocol
// channel, and internal/mcpserver reads and writes it directly. Diagnostics stay
// on stderr, which is safe to write to and is where a client shows a server's
// complaints.

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/jajera/aws-netpath/internal/mcpserver"
)

// serve runs the MCP server over the process's own stdin and stdout.
//
// It is a variable for one reason: the exit-code mapping below is this command's
// entire contribution, and the alternative way to assert it is a real stdio
// session, whose outcome depends on whatever the caller attached to the process's
// stdin. Substituted in tests and nowhere else.
var serve = mcpserver.Serve

func runMCP(args []string, _, stderr io.Writer) int {
	fs := flag.NewFlagSet("mcp", flag.ContinueOnError)
	fs.SetOutput(stderr)

	fs.Usage = func() {
		fmt.Fprint(stderr, `Serve the same operations to an agent over MCP on stdio.

Every subcommand is also an MCP tool, running the same code: the CLI and this
server share one set of operations, so an agent and an operator cannot be told
different things about the same network.

This command speaks the Model Context Protocol on stdin and stdout, so it is
started by an MCP client rather than typed at a prompt. It prints nothing to
stdout of its own — stdout carries the protocol — and reports its own failures
on stderr. It runs until the client disconnects, or until interrupted.

Register it with a client by pointing that client at this binary:

  {"command": "aws-netpath", "args": ["mcp"]}

Usage:
  aws-netpath mcp

Flags:
`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return exitParse(err)
	}

	// A client shutting the server down sends a signal rather than closing the
	// pipe, so the signal is what ends the session cleanly: in-flight calls see a
	// cancelled context instead of a truncated write.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := serve(ctx, Version); err != nil {
		// Being asked to stop is not a failure. The context is cancelled only by
		// the signal handler above, so its error means the operator or the client
		// ended the session, which is the command succeeding at the last thing it
		// was asked to do.
		if errors.Is(err, context.Canceled) {
			return ExitOK
		}
		fmt.Fprintf(stderr, "aws-netpath mcp: %v\n", err)
		return ExitError
	}

	return ExitOK
}
