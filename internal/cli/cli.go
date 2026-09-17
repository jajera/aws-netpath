// Package cli implements aws-netpath's command line.
//
// This package parses flags, renders results, and maps outcomes to exit codes.
// The capabilities themselves live in internal/ops, so the CLI and the MCP
// server run the same code rather than two implementations that drift.
package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
)

// writeJSON emits a result as indented JSON. The shape is the operation's
// result type, so it stays stable enough to assert against in tests.
func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// Version is overridden at build time with -ldflags.
var Version = "dev"

type command struct {
	name    string
	summary string
	run     func(args []string, stdout, stderr io.Writer) int
}

func commands() []command {
	return []command{
		{"verify", "Compare model query vs AWS Reachability Analyzer", runVerify},
		{"query", "End-to-end reachability query (routes, NACL, firewall)", runQuery},
		{"collect", "Collect AWS network state into a snapshot (multi-profile)", runCollect},
		{"firewall", "Evaluate a flow against firewall policies in a snapshot", runFirewall},
		{"diagnose", "Diagnose a failing flow across cloud and host layers", runDiagnose},
		{"compare", "Diff a failing path against a reference path that works", runCompare},
		{"diff", "Report what changed between two snapshots", runDiff},
		{"test", "Assert a file of declared flows against a snapshot", runTestFlows},
		{"mcp", "Serve the same operations to an agent over MCP on stdio", runMCP},
		{"version", "Print the aws-netpath version", runVersion},
	}
}

// Run dispatches a command and returns the process exit code.
//
// No subcommand and an unrecognised subcommand are both exit 2: nothing ran, so
// there is no answer to read. Requested help is exit 0, here and in every
// subcommand — the operator asked a question and got it answered.
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stdout)
		return ExitError
	}

	switch args[0] {
	case "-h", "--help", "help":
		usage(stdout)
		return ExitOK
	}

	for _, c := range commands() {
		if c.name == args[0] {
			return c.run(args[1:], stdout, stderr)
		}
	}

	fmt.Fprintf(stderr, "aws-netpath: unknown command %q\n\n", args[0])
	usage(stderr)
	return ExitError
}

func usage(w io.Writer) {
	fmt.Fprint(w, `aws-netpath models a network and answers reachability questions offline.

Usage:
  aws-netpath <command> [flags]

Commands:
`)
	cs := commands()
	sort.Slice(cs, func(i, j int) bool { return cs[i].name < cs[j].name })
	for _, c := range cs {
		fmt.Fprintf(w, "  %-10s %s\n", c.name, c.summary)
	}
	fmt.Fprint(w, `
Run "aws-netpath <command> -h" for the flags a command accepts.

Exit codes:
  0  traffic permitted with every layer evaluated, or command succeeded
  1  traffic blocked, a difference or change found, or the answer established
     only in part because a layer could not be read — usable output either way
  2  usage error, unknown address in snapshot, or failure
`)
}

func runVersion(_ []string, stdout, _ io.Writer) int {
	fmt.Fprintln(stdout, Version)
	return ExitOK
}
