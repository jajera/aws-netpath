package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/jajera/aws-netpath/internal/ops"
)

func runCollect(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("collect", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var (
		cfgPath = fs.String("config", "", "path to aws-netpath.yaml")
		// The default writes into snapshots/, which .gitignore excludes as a
		// directory. A snapshot is an unsanitised model of a real network, and the
		// name-based ignore patterns that used to cover it are defeated by the first
		// person who passes --output prod-net.json. Defaulting into an ignored
		// directory makes the safe path the path of least resistance rather than a
		// convention to remember.
		outPath  = fs.String("output", "snapshots/snapshot.json", "write snapshot here (parent directory is created)")
		profile  = fs.String("profile", "", "single-account mode: AWS profile")
		profiles = fs.String("profiles", "", "multi-profile shortcut: comma-separated profiles (each uses all --regions)")
		regions  = fs.String("regions", "", "comma-separated regions")
		account  = fs.String("account", "", "optional account ID check (single --profile only)")
		assume   = fs.String("assume-role", "", "optional role ARN to assume after profile auth")
		timeout  = fs.Int("timeout", 120, "per-target timeout in seconds (0 = no limit)")
	)

	fs.Usage = func() {
		fmt.Fprint(stderr, `Collect AWS network state into a snapshot using one profile per account.

Multi-account (recommended when regions differ per account):
  aws-netpath collect --config aws-netpath.yaml

Multi-profile shortcut (each profile × each region):
  aws-netpath collect --profiles network-hub,workload-prod --regions us-east-1,us-west-2

Single account:
  aws-netpath collect --profile network-hub --regions us-east-1,us-west-2 --output snapshots/prod.json

Each account in the config uses its own SSO profile. Collection runs in parallel.
Partial failures are recorded in the snapshot; other accounts still collect.

A snapshot is an unsanitised model of a real network, so the default output path
lands in snapshots/, which is gitignored as a directory. Missing directories in
--output are created.

Flags:
`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return exitParse(err)
	}

	result, err := ops.Collect(context.Background(), ops.CollectRequest{
		ConfigPath: *cfgPath,
		Profile:    *profile,
		Profiles:   *profiles,
		Regions:    *regions,
		Account:    *account,
		AssumeRole: *assume,
		Timeout:    *timeout,
		OutputPath: *outPath,
	})
	if err != nil {
		fmt.Fprintf(stderr, "aws-netpath collect: %v\n", err)
		// A scope error means the invocation could not say what to collect, so
		// the flags are the useful thing to show next.
		var scopeErr *ops.ScopeError
		if errors.As(err, &scopeErr) {
			fmt.Fprintln(stderr)
			fs.Usage()
		}
		return ExitError
	}

	renderCollect(stdout, result)

	// Requirement 2.5: a collection that recorded errors wrote a usable snapshot
	// covering less than was asked for. There is no finding to report — nothing
	// was evaluated — so it lands on exit 1 through the incompleteness half of
	// the mapping.
	return exitFinding(false, !result.Partial())
}

func renderCollect(w io.Writer, r *ops.CollectResult) {
	snap := r.Snapshot
	fmt.Fprintf(w, "wrote %s\n", r.OutputPath)
	fmt.Fprintf(w, "  targets:  %d account+region pairs\n", r.Targets)
	fmt.Fprintf(w, "  accounts: %d\n", len(snap.Accounts))
	fmt.Fprintf(w, "  regions:  %d\n", len(snap.Regions))
	fmt.Fprintf(w, "  vpcs:           %d\n", len(snap.VPCs))
	fmt.Fprintf(w, "  subnets:        %d\n", len(snap.Subnets))
	fmt.Fprintf(w, "  route tables:   %d\n", len(snap.RouteTables))
	fmt.Fprintf(w, "  security groups:%d\n", len(snap.SecurityGroups))
	fmt.Fprintf(w, "  enis:           %d\n", len(snap.NetworkIfaces))
	fmt.Fprintf(w, "  tgw:            %d\n", len(snap.TransitGateways))
	fmt.Fprintf(w, "  tgw attach:     %d\n", len(snap.TGWAttachments))
	fmt.Fprintf(w, "  firewalls:      %d\n", len(snap.Firewalls))
	fmt.Fprintf(w, "  rule groups:    %d\n", len(snap.RuleGroups))
	if r.Errors > 0 {
		fmt.Fprintf(w, "  errors:         %d (see collection_errors in snapshot)\n", r.Errors)
	}
}
