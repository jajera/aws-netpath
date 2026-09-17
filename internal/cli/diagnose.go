package cli

import (
	"context"
	"flag"
	"fmt"
	"io"

	"github.com/jajera/aws-netpath/internal/format"
	"github.com/jajera/aws-netpath/internal/ops"
)

func runDiagnose(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("diagnose", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var (
		snapPath     = fs.String("snapshot", "", "path to a snapshot file (required)")
		from         = fs.String("from", "", "source: address, CIDR, instance ID, or Name tag (required)")
		to           = fs.String("to", "", "destination: address, CIDR, instance ID, or Name tag (required)")
		proto        = fs.String("proto", "tcp", "protocol: tcp, udp, icmp")
		port         = fs.Int("port", 0, "destination port (required for tcp/udp)")
		symptom      = addSymptomFlag(fs)
		skipFirewall = fs.Bool("skip-firewall", false, "evaluate routing and NACLs only")
		out          = addOutputFlags(fs)
	)

	fs.Usage = func() {
		fmt.Fprint(stderr, `Diagnose why a flow fails, across every layer between the two endpoints.

Runs the full pipeline against a collected snapshot: classify, resolve both
endpoints, walk routes, NACLs, security groups, and firewall policy, evaluate
the return direction, probe the host layers, then correlate. The earliest
blocking layer in flow order is reported as primary and the rest are listed
after it. A layer that cannot be established abstains with its reason and is
never reported as a pass.

Endpoints accept an address, a CIDR, an instance ID, or a Name tag. An input
matching more than one resource halts with every candidate listed rather than
answering for the wrong one.

With --symptom the layers that failure implicates are checked first, which is
usually the shortest route to the answer: a refused connection came from a host
that answered, so the host layers lead. Without one the layers are evaluated in
flow order. A symptom narrows the search rather than limiting it — every layer is
still reported.

Text by default, --json or --markdown on request. The three render one report, so
they cannot disagree about what was found.

Usage:
  aws-netpath diagnose --snapshot snapshots/snapshot.json --from 10.0.1.10 --to 10.1.2.20 --proto tcp --port 443
  aws-netpath diagnose --snapshot snapshots/snapshot.json --from bastion --to app-server --proto tcp --port 22
  aws-netpath diagnose --snapshot snapshots/snapshot.json --from 10.0.1.10 --to 10.1.2.20 --proto tcp --port 22 --symptom connection-refused

Host layers are probed over Systems Manager, which this command does not yet
open a client for, so they abstain and the report states that the host is
unverified.

Flags:
`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return exitParse(err)
	}

	// Resolved before the operation runs, so a conflicting pair of renderer flags
	// is refused without a snapshot having been read.
	opts, err := out.options()
	if err != nil {
		fmt.Fprintf(stderr, "aws-netpath diagnose: %v\n", err)
		return ExitError
	}

	result, err := ops.Diagnose(context.Background(), ops.DiagnoseRequest{
		SnapshotPath: *snapPath,
		From:         *from,
		To:           *to,
		Proto:        *proto,
		Port:         *port,
		Symptom:      *symptom,
		SkipFirewall: *skipFirewall,
	})
	if err != nil {
		fmt.Fprintf(stderr, "aws-netpath diagnose: %v\n", err)
		return ExitError
	}

	if err := format.Write(stdout, result.Report(), opts); err != nil {
		fmt.Fprintf(stderr, "aws-netpath diagnose: %v\n", err)
		return ExitError
	}

	// A blocker is the finding. Authority is the other half, and it is the half
	// worth being explicit about: "no blocker found" while a host layer went
	// unread is not "permitted", so it does not get the code that means
	// permitted. The report already says the verdict is not authoritative; this
	// is the same statement in the only form a pipeline reads.
	return exitFinding(result.Blocked(), result.Established())
}
