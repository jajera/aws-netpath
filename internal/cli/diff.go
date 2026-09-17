package cli

import (
	"flag"
	"fmt"
	"io"

	"github.com/jajera/aws-netpath/internal/format"
	"github.com/jajera/aws-netpath/internal/ops"
)

func runDiff(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var (
		fromPath = fs.String("from", "", "path to the earlier snapshot (required)")
		toPath   = fs.String("to", "", "path to the later snapshot (required)")
		out      = addOutputFlags(fs)
	)

	fs.Usage = func() {
		fmt.Fprint(stderr, `Compare two snapshots and report what changed.

Resources added, removed, and modified, grouped by type and by account and
region. No path is walked and no policy is evaluated, which makes this the
cheapest way to tie a breakage to a change: the operator usually knows what
broke and needs to find out what moved.

Both snapshots are read even when their schema versions differ, because a
collection from before a change and one from after it may have been written by
different builds. Where the versions differ the report states that the
comparison may be incomplete.

Text by default, --json or --markdown on request.

Usage:
  aws-netpath diff --from snapshot-before.json --to snapshot-after.json

Flags:
`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return exitParse(err)
	}

	opts, err := out.options()
	if err != nil {
		fmt.Fprintf(stderr, "aws-netpath diff: %v\n", err)
		return ExitError
	}

	result, err := ops.DiffSnapshot(ops.DiffSnapshotRequest{
		FromPath: *fromPath,
		ToPath:   *toPath,
	})
	if err != nil {
		fmt.Fprintf(stderr, "aws-netpath diff: %v\n", err)
		return ExitError
	}

	if err := format.Write(stdout, result.Report(), opts); err != nil {
		fmt.Fprintf(stderr, "aws-netpath diff: %v\n", err)
		return ExitError
	}

	// A change is the finding, so it is reported the way a blocked flow is
	// rather than as success with something buried in the output. A caveat that
	// makes the comparison incomplete counts too: "nothing changed" across two
	// schema versions is a weaker claim than "nothing changed".
	return exitFinding(result.Changed(), result.Established())
}
