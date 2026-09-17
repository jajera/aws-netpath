package cli

import (
	"flag"
	"fmt"
	"io"

	"github.com/jajera/aws-netpath/internal/format"
	"github.com/jajera/aws-netpath/internal/ops"
)

func runTestFlows(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var (
		snapPath     = fs.String("snapshot", "", "path to a snapshot file (required)")
		flowsPath    = fs.String("flows", "", "path to a declared flow file (required)")
		skipFirewall = fs.Bool("skip-firewall", false, "evaluate routing and NACLs only, on every flow")
		out          = addOutputFlags(fs)
	)

	fs.Usage = func() {
		fmt.Fprint(stderr, `Assert a file of declared flows against a snapshot.

Each declared flow is resolved, walked, and correlated exactly as a query is, so
a flow this reports as blocked is a flow "aws-netpath query" reports as blocked.
Evaluation is offline and makes no API call, which is what lets this run on every
commit.

A flow whose endpoints cannot be resolved is recorded as inconclusive and the
remaining flows are still asserted. A flow that abstains is reported as
inconclusive too, never as a pass. A malformed flow file is refused whole.

Text by default, --json or --markdown on request. There is no --symptom here: a
declared flow states what it expects rather than what an operator observed.

The declared flow file is YAML, and JSON parses unchanged:

  flows:
    - name: app to database
      from: 10.0.1.10
      to: 10.1.2.20
      proto: tcp
      port: 5432
      expect: permitted
    - name: workload must not reach the management subnet
      from: 10.0.1.10
      to: 192.0.2.10
      proto: tcp
      port: 22
      expect: blocked

Usage:
  aws-netpath test --snapshot snapshots/snapshot.json --flows flows.yaml

Flags:
`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return exitParse(err)
	}

	opts, err := out.options()
	if err != nil {
		fmt.Fprintf(stderr, "aws-netpath test: %v\n", err)
		return ExitError
	}

	result, err := ops.TestFlows(ops.TestFlowsRequest{
		SnapshotPath: *snapPath,
		FlowsPath:    *flowsPath,
		SkipFirewall: *skipFirewall,
	})
	if err != nil {
		fmt.Fprintf(stderr, "aws-netpath test: %v\n", err)
		return ExitError
	}

	if err := format.Write(stdout, result.Report(), opts); err != nil {
		fmt.Fprintf(stderr, "aws-netpath test: %v\n", err)
		return ExitError
	}

	// Requirement 12.3: a declared flow that did not hold is the finding, and
	// exit 1 is what fails the build. An inconclusive flow is not a failure and
	// is not a pass either — requirement 12.4 — so it is kept out of exit 0
	// rather than being aggregated into one or the other.
	return exitFinding(result.Failed(), result.Established())
}
