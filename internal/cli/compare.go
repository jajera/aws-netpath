package cli

import (
	"context"
	"flag"
	"fmt"
	"io"

	"github.com/jajera/aws-netpath/internal/format"
	"github.com/jajera/aws-netpath/internal/ops"
)

func runCompare(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("compare", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var (
		snapPath     = fs.String("snapshot", "", "path to a snapshot file (required)")
		from         = fs.String("from", "", "failing path source (required)")
		to           = fs.String("to", "", "failing path destination (required)")
		refFrom      = fs.String("ref-from", "", "reference path source, the one that works (required)")
		refTo        = fs.String("ref-to", "", "reference path destination (default: --to)")
		proto        = fs.String("proto", "tcp", "protocol: tcp, udp, icmp")
		port         = fs.Int("port", 0, "destination port (required for tcp/udp)")
		symptom      = addSymptomFlag(fs)
		skipFirewall = fs.Bool("skip-firewall", false, "evaluate routing and NACLs only, on both paths")
		out          = addOutputFlags(fs)
	)

	fs.Usage = func() {
		fmt.Fprint(stderr, `Compare a failing path against a reference path that works.

Both paths are diagnosed through the same pipeline against one snapshot, so a
difference is a configuration difference rather than an artefact of two
evaluations or two collections. Only the differences are reported.

Where every cloud layer matches but the behaviour does not, the report names the
layers that remain as an explanation. Where a layer abstains on one side, that
comparison is reported as incomplete rather than as a match.

The reference path defaults to the same destination as the failing path, which is
the ordinary shape: two sources, one service, one of them working.

--symptom describes the failing path only. The reference path is the one that
works, so there is no observed failure on it to classify.

Text by default, --json or --markdown on request.

Usage:
  aws-netpath compare --snapshot snapshots/snapshot.json \
    --from 10.0.1.10 --to 10.1.2.20 --ref-from 10.0.1.11 --proto tcp --port 443

Flags:
`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return exitParse(err)
	}

	opts, err := out.options()
	if err != nil {
		fmt.Fprintf(stderr, "aws-netpath compare: %v\n", err)
		return ExitError
	}

	result, err := ops.Compare(context.Background(), ops.CompareRequest{
		SnapshotPath: *snapPath,
		From:         *from,
		To:           *to,
		RefFrom:      *refFrom,
		RefTo:        *refTo,
		Proto:        *proto,
		Port:         *port,
		Symptom:      *symptom,
		SkipFirewall: *skipFirewall,
	})
	if err != nil {
		fmt.Fprintf(stderr, "aws-netpath compare: %v\n", err)
		return ExitError
	}

	if err := format.Write(stdout, result.Report(), opts); err != nil {
		fmt.Fprintf(stderr, "aws-netpath compare: %v\n", err)
		return ExitError
	}

	// A difference is the finding this command exists to produce, so it is
	// signalled the way a blocked flow is: usable output, something to act on.
	// An incomplete comparison joins it, because "identical everywhere" was not
	// established while a layer abstained on one side.
	return exitFinding(result.Differs(), result.Established())
}
