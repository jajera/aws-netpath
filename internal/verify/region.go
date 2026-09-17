package verify

// Which regions one analysis would have to reach across.
//
// A Reachability Analyzer analysis is scoped to a single region, so requirement
// 13.5 is really a question about counting: how many regions does this flow put
// in play, and is that more than one run can cover? Two facts decide it — the
// region each endpoint sits in, and the one region the analysis would be scoped
// to — and neither is always known. An endpoint can sit outside every collected
// subnet, and the scope can be supplied on the command line rather than inferred
// from the snapshot.
//
// Both of those are why the count lives here rather than as an inline comparison
// of two subnet regions. That comparison answers the question only when both
// endpoints resolve and the caller named no region: a flow whose endpoints are
// both in us-east-1, analysed under a scope of us-west-2, crosses a boundary the
// comparison cannot see, and the run it would let through is a billable analysis
// covering none of the path while reporting on it.
//
// The span is computed once and read twice: the Verifier consults it before
// spending an analysis, and the Caveat that states the limit is derived from the
// same value, so the reason no analysis ran and the reason the result is narrower
// than asked for cannot drift apart.

import (
	"fmt"
	"slices"
	"strings"
)

// regionSpan is the regions a cross-check would have to span.
type regionSpan struct {
	// Src and Dst are the regions the endpoints sit in, empty when an endpoint is
	// in no collected subnet — unknown rather than absent, which is why nothing
	// here treats an empty region as a region.
	Src string
	Dst string
	// Scope is the single region an analysis would run in: what the caller asked
	// for, or the source's region when they asked for nothing.
	Scope string
}

// spanFor reads the span from the run's options.
func spanFor(opts Options) regionSpan {
	_, srcRegion, srcOK := SubnetForAddr(opts.Snapshot, opts.SrcIP)
	_, dstRegion, dstOK := SubnetForAddr(opts.Snapshot, opts.DstIP)

	s := regionSpan{Scope: opts.Region}
	if srcOK {
		s.Src = srcRegion
	}
	if dstOK {
		s.Dst = dstRegion
	}
	if s.Scope == "" {
		s.Scope = s.Src
	}
	return s
}

// pathRegions are the regions the path is known to run through, in flow order and
// without repeats.
func (s regionSpan) pathRegions() []string {
	var out []string
	for _, r := range []string{s.Src, s.Dst} {
		if r != "" && !slices.Contains(out, r) {
			out = append(out, r)
		}
	}
	return out
}

// Crosses reports whether more than one region is in play, which is exactly when
// no single analysis covers the path.
//
// Two shapes qualify. The endpoints can sit in different regions, and the scope
// can be a region the known part of the path is not in — the second catching the
// case an endpoint that resolved to nothing would otherwise hide, since a run
// scoped away from the path covers no more of it than a run that never happened.
func (s regionSpan) Crosses() bool {
	path := s.pathRegions()
	if len(path) > 1 {
		return true
	}
	if s.Scope == "" {
		return false
	}
	for _, r := range path {
		if r != s.Scope {
			return true
		}
	}
	return false
}

// caveatSummary states that no single run covers this path, and why. Requirement
// 13.5.
//
// Both regions are named where both are known, because an operator who has to
// fall back on two analyses needs to know which two, and which hop neither of
// them would evaluate.
func (s regionSpan) caveatSummary() string {
	if s.crossesBetweenEndpoints() {
		return fmt.Sprintf(
			"no single Reachability Analyzer run covers %s to %s: an analysis is scoped to one region, so no run evaluates this path end to end and two runs cannot be joined into one verdict",
			s.Src, s.Dst)
	}
	return fmt.Sprintf(
		"no single Reachability Analyzer run covers this path: an analysis is scoped to one region, and a run in %s does not evaluate a path through %s",
		s.Scope, joinRegions(s.pathRegions()))
}

// detail is the same fact in one clause, for the outcome line and the banner
// above it.
//
// It replaces the generic "the analyser returned no result" a skipped comparison
// would otherwise lead with, because that sentence is true of a login that
// expired, an endpoint outside the snapshot, and a path no run can cover, and
// only the last one is a fact about the network. A reader who stops after two
// lines should already know which one they have.
func (s regionSpan) detail() string {
	if s.crossesBetweenEndpoints() {
		return fmt.Sprintf("no single Reachability Analyzer run covers %s to %s", s.Src, s.Dst)
	}
	return fmt.Sprintf("no single Reachability Analyzer run covers this path: an analysis in %s does not evaluate a path through %s",
		s.Scope, joinRegions(s.pathRegions()))
}

// skipReason is the same fact where an operator meets it first: on the analyser's
// outcome, as the reason it reached no verdict.
func (s regionSpan) skipReason() string {
	if s.crossesBetweenEndpoints() {
		return fmt.Sprintf("cross-region (%s → %s): Reachability Analyzer is single-region", s.Src, s.Dst)
	}
	return fmt.Sprintf("cross-region (analysis in %s, path through %s): Reachability Analyzer is single-region",
		s.Scope, joinRegions(s.pathRegions()))
}

// crossesBetweenEndpoints reports whether the boundary lies between the two
// endpoints, as distinct from between the path and the region it would be
// analysed in. The distinction is worth keeping because the two send an operator
// somewhere different: the first to two analyses, the second to the scope they
// asked for.
func (s regionSpan) crossesBetweenEndpoints() bool {
	return s.Src != "" && s.Dst != "" && s.Src != s.Dst
}

func joinRegions(regions []string) string {
	switch len(regions) {
	case 0:
		return "an unknown region"
	case 1:
		return regions[0]
	default:
		return strings.Join(regions[:len(regions)-1], ", ") + " and " + regions[len(regions)-1]
	}
}
