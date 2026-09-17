package cli

import (
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/jajera/aws-netpath/internal/ops"
	"github.com/jajera/aws-netpath/internal/query"
)

func runQuery(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("query", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var (
		snapPath     = fs.String("snapshot", "", "path to a snapshot file (required)")
		fromIP       = fs.String("from", "", "source IP address (required)")
		toIP         = fs.String("to", "", "destination IP address (required)")
		proto        = fs.String("proto", "tcp", "protocol: tcp, udp, icmp")
		port         = fs.Int("port", 0, "destination port (required for tcp/udp)")
		skipFirewall = fs.Bool("skip-firewall", false, "evaluate routing/NACL only")
		asJSON       = fs.Bool("json", false, "JSON output")
	)

	fs.Usage = func() {
		fmt.Fprint(stderr, `End-to-end reachability query against a collected snapshot.

Checks subnet routing, transit gateway routes, NACLs, security groups on both
endpoints, and network firewalls in every region on the path. A layer the
snapshot cannot answer for is reported as an abstention, never as a pass.

Usage:
  aws-netpath query --snapshot snapshots/snapshot.json --from 10.0.1.5 --to 10.1.2.3 --proto tcp --port 443

Flags:
`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return exitParse(err)
	}

	result, err := ops.Query(ops.QueryRequest{
		SnapshotPath: *snapPath,
		From:         *fromIP,
		To:           *toIP,
		Proto:        *proto,
		Port:         *port,
		SkipFirewall: *skipFirewall,
	})
	if err != nil {
		fmt.Fprintf(stderr, "aws-netpath query: %v\n", err)
		return ExitError
	}

	if *asJSON {
		if err := writeJSON(stdout, result); err != nil {
			fmt.Fprintf(stderr, "aws-netpath query: %v\n", err)
			return ExitError
		}
	} else {
		renderQuery(stdout, result)
	}

	// UNKNOWN is not a network verdict: the address is not in the snapshot, so no
	// path was walked and there is nothing to act on but a re-collection. That
	// makes it exit 2 rather than exit 1, on the same grounds as an endpoint
	// matching nothing.
	if result.Verdict == query.VerdictUnknown {
		return ExitError
	}
	return exitFinding(result.Verdict == query.VerdictBlocked, result.Authoritative())
}

func renderQuery(w io.Writer, r *query.Result) {
	fmt.Fprintf(w, "flow: %s\n\n", r.Flow)
	for _, h := range r.Hops {
		status := "ALLOW"
		if !h.Allowed {
			status = "DENY "
		}
		loc := h.Resource
		if loc == "" {
			loc = h.Layer
		}
		if h.Region != "" {
			loc = fmt.Sprintf("%s (%s)", loc, h.Region)
		}
		fmt.Fprintf(w, "  [%s] %s\n", status, loc)
		if h.Detail != "" {
			fmt.Fprintf(w, "         %s\n", h.Detail)
		}
	}

	// Abstentions are listed apart from the cleared layers above, so a layer
	// that could not be checked never reads as one that passed.
	if len(r.Abstentions) > 0 {
		fmt.Fprintf(w, "\nabstentions:\n")
		for _, a := range r.Abstentions {
			fmt.Fprintf(w, "  [ABSTAIN] %s\n", a.Layer)
			fmt.Fprintf(w, "         %s\n", a.Reason)
			for _, c := range a.Citations {
				fmt.Fprintf(w, "         cited: %s %s\n", c.Identifier, c.Detail)
			}
		}
	}

	// The return direction is its own Flow, so it gets its own section rather
	// than being mixed into the forward hops.
	if rp := r.ReturnPath; rp != nil {
		fmt.Fprintf(w, "\nreturn path [%s]: %s\n", strings.ToUpper(string(rp.Result.Verdict)), rp.Flow)
		for _, h := range rp.Path() {
			status := "ALLOW"
			if !h.Allowed {
				status = "DENY "
			}
			loc := h.Resource
			if loc == "" {
				loc = h.Layer
			}
			if h.Region != "" {
				loc = fmt.Sprintf("%s (%s)", loc, h.Region)
			}
			fmt.Fprintf(w, "  [%s] %s\n", status, loc)
			if h.Detail != "" {
				fmt.Fprintf(w, "         %s\n", h.Detail)
			}
		}
	}

	fmt.Fprintf(w, "\nverdict: %s\n", r.Verdict)
	for _, n := range r.Notes {
		fmt.Fprintf(w, "note: %s\n", n)
	}
}
