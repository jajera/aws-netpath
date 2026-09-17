package verify

// What a Reachability Analyzer cross-check does not tell you.
//
// A cross-check is the strongest evidence this tool can offer — an independent
// evaluation by the provider whose network it is — and that is exactly why its
// limits have to travel with its result. Requirements 13.4 and 13.5 name three of
// them: the analyses are billable, TCP over a transit gateway route table is
// evaluated in the forward direction only, and no single run crosses a region
// boundary.
//
// Two of those are stated whether or not an analysis ran. The cost belongs beside
// the answer for an operator deciding whether to ask again, and the forward-only
// limit belongs beside an agreement, because an agreement that covered one
// direction of a flow whose failure is in the other direction is a true statement
// that answers the wrong question.
//
// A Caveat never becomes a verdict and never changes one, on the same terms as an
// Abstention: the honest failure mode is a narrower claim, not a confident one.

import (
	"fmt"

	"github.com/jajera/aws-netpath/internal/flow"
	"github.com/jajera/aws-netpath/internal/query"
)

// Caveat is something a reader has to know before relying on a cross-check.
type Caveat struct {
	Subject string `json:"subject"`
	Summary string `json:"summary"`
	// Coverage marks a Caveat that narrows what the comparison established, as
	// distinct from one a reader needs before deciding to run it again. A
	// per-analysis charge is worth stating and weakens no conclusion; a direction
	// the analyser did not evaluate does.
	Coverage bool `json:"coverage,omitempty"`
}

// Caveat subjects. They are short because they are headings: the Summary carries
// what the caveat means.
const (
	CaveatBilling     = "analysis cost"
	CaveatForwardOnly = "forward direction only"
	CaveatCrossRegion = "cross-region path"
	CaveatNotRun      = "no analysis"
)

// Covers reports whether the comparison covered the whole flow. It is false when
// any Caveat narrows coverage, which is what stops an agreement over one
// direction from reading as an agreement over the flow.
func (r *Result) Covers() bool {
	for _, c := range r.Caveats {
		if c.Coverage {
			return false
		}
	}
	return true
}

// caveats states what this cross-check does not cover.
//
// The billing caveat is unconditional. The rest are decided from the flow: the
// forward-only limit applies to the analyser's transit gateway behaviour and so
// depends on the path the engine walked, and the region caveat replaces the
// generic "no analysis ran" one, because "single-region" is the reason and
// repeating it as two findings would read as two problems.
func caveats(opts Options, res *Result) []Caveat {
	out := []Caveat{{
		Subject: CaveatBilling,
		Summary: "Reachability Analyzer analyses are billable: each run creates a network insights path and an analysis and is charged per analysis, where the offline query over the snapshot costs nothing",
	}}

	if forwardOnly(opts, res) {
		out = append(out, Caveat{
			Subject:  CaveatForwardOnly,
			Summary:  "for TCP over a transit gateway route table, Reachability Analyzer evaluates forward traffic only: this comparison says nothing about the return direction, which is where an asymmetric path fails",
			Coverage: true,
		})
	}

	switch span := spanFor(opts); {
	case span.Crosses():
		out = append(out, Caveat{
			Subject:  CaveatCrossRegion,
			Summary:  span.caveatSummary(),
			Coverage: true,
		})
	case res.AWS != nil && res.AWS.Skipped:
		out = append(out, Caveat{
			Subject:  CaveatNotRun,
			Summary:  fmt.Sprintf("no analysis ran, so nothing independent corroborates the engine here: %s", res.AWS.SkipReason),
			Coverage: true,
		})
	}
	return out
}

// forwardOnly reports whether the analyser's transit gateway limit bears on this
// flow: TCP, and a path the engine resolved through a transit gateway route
// table.
//
// It is read from the path the engine walked rather than from the snapshot,
// because a transit gateway present in an account and a transit gateway this flow
// actually traverses are different facts, and stating the caveat on the first
// would attach it to flows it does not constrain.
func forwardOnly(opts Options, res *Result) bool {
	if opts.Proto != flow.ProtoTCP || res.Model == nil {
		return false
	}
	for _, h := range res.Model.Path() {
		if h.Layer == query.LayerTGWRoute {
			return true
		}
	}
	return false
}
