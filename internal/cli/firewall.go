package cli

import (
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/jajera/aws-netpath/internal/flow"
	"github.com/jajera/aws-netpath/internal/nfw"
	"github.com/jajera/aws-netpath/internal/ops"
)

func runFirewall(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("firewall", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var (
		snapPath = fs.String("snapshot", "", "path to a snapshot file (required)")
		from     = fs.String("from", "", "source CIDR or address (required)")
		to       = fs.String("to", "", "destination CIDR or address (required)")
		proto    = fs.String("proto", "tcp", "protocol: tcp, udp, icmp, any")
		ports    = fs.String("port", "any", "destination ports, e.g. 443 or 80-443 or 22,443")
		only     = fs.String("firewall", "", "evaluate only firewalls whose name or ID contains this string")
		asJSON   = fs.Bool("json", false, "emit machine-readable JSON")
	)

	fs.Usage = func() {
		fmt.Fprint(stderr, `Evaluate a flow against every firewall policy in a snapshot.

Rule groups are walked in priority order and each verdict cites the rule that
produced it. Constructs outside the 5-tuple model, such as domain allowlists or
raw Suricata rules, are reported as abstentions rather than guessed at.

Usage:
  aws-netpath firewall --snapshot snap.json --from 10.30.32.0/19 --to 10.30.192.0/20 --proto tcp --port 443

Flags:
`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return exitParse(err)
	}

	result, err := ops.Firewall(ops.FirewallRequest{
		SnapshotPath: *snapPath,
		From:         *from,
		To:           *to,
		Proto:        *proto,
		Ports:        *ports,
		Only:         *only,
	})
	if err != nil {
		fmt.Fprintf(stderr, "aws-netpath firewall: %v\n", err)
		return ExitError
	}

	if *asJSON {
		if err := writeJSON(stdout, result.Results); err != nil {
			fmt.Fprintf(stderr, "aws-netpath firewall: %v\n", err)
			return ExitError
		}
	} else {
		renderFirewall(stdout, result.Flow, result.Results)
	}

	// A rule group that could not be evaluated might have been the one that
	// decided the flow, which is what the rendered note already says. PERMITTED
	// on that basis does not get the code that means permitted.
	return exitFinding(result.Blocked(), result.Authoritative())
}

func renderFirewall(w io.Writer, traffic flow.Slice, results []nfw.Result) {
	fmt.Fprintf(w, "flow: %s\n\n", traffic)

	blocked := false
	uncertain := false

	for _, r := range results {
		header := r.Firewall
		if r.Region != "" {
			header = fmt.Sprintf("%s (%s)", header, r.Region)
		}
		fmt.Fprintf(w, "%s\n", header)

		for _, d := range r.Decisions {
			verdict := strings.ToUpper(string(d.Verdict))
			reason := d.Rule.String()
			if d.ByDefault {
				reason = fmt.Sprintf("default action %s", d.Rule.Action)
			}
			fmt.Fprintf(w, "  %-5s %s\n", verdict, d.Slice)
			fmt.Fprintf(w, "        via %s\n", reason)
			if d.Verdict == nfw.Drop {
				blocked = true
			}
		}

		for _, a := range r.Abstentions {
			uncertain = true
			name := ops.DisplayName(a.GroupName, a.GroupARN)
			fmt.Fprintf(w, "  ?     cannot evaluate %s: %s\n", name, a.Reason)
		}
		fmt.Fprintln(w)
	}

	switch {
	case blocked:
		fmt.Fprintln(w, "verdict: BLOCKED")
	default:
		fmt.Fprintln(w, "verdict: PERMITTED")
	}
	if uncertain {
		fmt.Fprintln(w, "note: some rule groups could not be evaluated, so this verdict is not authoritative")
	}
}
