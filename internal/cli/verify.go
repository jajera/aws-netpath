package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/jajera/aws-netpath/internal/format"
	"github.com/jajera/aws-netpath/internal/ops"
	"github.com/jajera/aws-netpath/internal/verify"
)

func runVerify(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var (
		snapPath   = fs.String("snapshot", "", "path to a snapshot file (required)")
		configPath = fs.String("config", "", "aws-netpath.yaml for profile lookup")
		profile    = fs.String("profile", "", "AWS profile for Reachability Analyzer")
		region     = fs.String("region", "", "AWS region for analyzer (default: source subnet region)")
		fromIP     = fs.String("from", "", "source IP address (required)")
		toIP       = fs.String("to", "", "destination IP address (required)")
		proto      = fs.String("proto", "tcp", "protocol: tcp or udp")
		port       = fs.Int("port", 0, "destination port (required for tcp/udp)")
		timeout    = fs.Duration("timeout", 2*time.Minute, "AWS analysis timeout")
		skipAWS    = fs.Bool("skip-aws", false, "evaluate model only, skip AWS comparison")
		out        = addOutputFlags(fs)
	)

	fs.Usage = func() {
		fmt.Fprint(stderr, `Compare offline model query vs AWS Reachability Analyzer.

Runs aws-netpath query against the snapshot, then (when possible) asks AWS
Reachability Analyzer in one region. Cross-region and ICMP flows skip the
AWS call and report INCONCLUSIVE for the comparison.

Text by default, --json or --markdown on request. All three carry both verdicts
and both citations, because a disagreement is not settled by preferring one.

Usage:
  aws-netpath verify --snapshot snapshots/snapshot.json --config aws-netpath.yaml \
    --from 10.30.32.10 --to 10.30.33.10 --proto tcp --port 443

Flags:
`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return exitParse(err)
	}

	opts, err := out.options()
	if err != nil {
		fmt.Fprintf(stderr, "aws-netpath verify: %v\n", err)
		return ExitError
	}

	result, err := ops.Verify(context.Background(), ops.VerifyRequest{
		SnapshotPath: *snapPath,
		ConfigPath:   *configPath,
		Profile:      *profile,
		Region:       *region,
		From:         *fromIP,
		To:           *toIP,
		Proto:        *proto,
		Port:         *port,
		Timeout:      *timeout,
		SkipAWS:      *skipAWS,
	})
	if err != nil {
		var awsErr *ops.AWSError
		if errors.As(err, &awsErr) {
			fmt.Fprintf(stderr, "aws-netpath verify: aws: %v\n", awsErr)
		} else {
			fmt.Fprintf(stderr, "aws-netpath verify: %v\n", err)
		}
		return ExitError
	}

	// Every rendering goes through the Formatter, --json included: the report is
	// the stable schema, and a JSON mode that dumped the operation's own result
	// instead would be a second shape to keep stable.
	if err := format.Write(stdout, ops.VerifyReport(result), opts); err != nil {
		fmt.Fprintf(stderr, "aws-netpath verify: %v\n", err)
		return ExitError
	}

	// A disagreement is the finding. Anything else short of agreement — the
	// analyser skipped, the analysis returned nothing, a cross-region flow no
	// single run covers — leaves the model uncorroborated, which is an answer
	// established only in part rather than a success.
	return exitFinding(
		result.Agreement == verify.AgreementMismatch,
		result.Agreement == verify.AgreementMatch,
	)
}
