package verify

// What a cross-check says about its own limits.
//
// The billing caveat is asserted on every branch, including the one that made no
// AWS call at all, because requirement 13.4 states a property of the analyser
// rather than a property of one run — and an operator reading a skipped comparison
// is exactly the one deciding whether to spend a run.
//
// The forward-only caveat is asserted on the flow it constrains and denied on one
// it does not, since a caveat attached to everything carries no information.
//
// Every address is RFC 1918 space from the inherited fixtures.

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/jajera/aws-netpath/internal/model"
)

// A pair of endpoints the inherited fixtures place in two different regions, both
// inside collected subnets — so the run reaches the region comparison rather than
// stopping at an endpoint it could not scope.
const (
	crossRegionSrc = "10.30.32.10" // subnet-prod-east-a, us-east-1
	crossRegionDst = "10.29.48.10" // subnet-inspection-west-fw, us-west-2
)

func caveatFor(t *testing.T, res *Result, subject string) Caveat {
	t.Helper()
	for _, c := range res.Caveats {
		if c.Subject == subject {
			return c
		}
	}
	t.Fatalf("no %q caveat; got %+v", subject, res.Caveats)
	return Caveat{}
}

func hasCaveat(res *Result, subject string) bool {
	for _, c := range res.Caveats {
		if c.Subject == subject {
			return true
		}
	}
	return false
}

// Requirement 13.4, first half: the analyses are billable, and the run says so
// whether or not it made one.
func TestRunAlwaysStatesTheAnalysesAreBillable(t *testing.T) {
	snap := loadFixture(t, "../query/testdata/double-inspection.json")

	cases := []struct {
		name string
		opts Options
	}{
		{"analysis ran", Options{
			SrcIP: mustAddr(t, "10.30.32.10"), DstIP: mustAddr(t, "10.29.17.10"),
			Proto: mustProto(t, "tcp"), Port: 8080,
			Analyzer: &mockAnalyzer{reachable: false}, Region: "us-east-1",
		}},
		{"skipped by request", Options{
			SrcIP: mustAddr(t, "10.30.32.10"), DstIP: mustAddr(t, "10.29.17.10"),
			Proto: mustProto(t, "tcp"), Port: 8080, SkipAWS: true,
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.opts.Snapshot = snap
			res, err := Run(t.Context(), tc.opts)
			if err != nil {
				t.Fatal(err)
			}

			c := caveatFor(t, res, CaveatBilling)
			for _, want := range []string{"billable", "per analysis"} {
				if !strings.Contains(c.Summary, want) {
					t.Errorf("the billing caveat omits %q: %s", want, c.Summary)
				}
			}
			// A cost is worth stating and narrows nothing, so it must not on its own
			// weaken what the comparison established.
			if c.Coverage {
				t.Error("the billing caveat is marked as narrowing coverage; a charge is not a gap in evidence")
			}
		})
	}
}

// Requirement 13.4, second half: TCP over a transit gateway route table is
// evaluated in the forward direction only, and that is a limit on what the
// comparison established.
func TestRunStatesTCPOverATransitGatewayIsForwardOnly(t *testing.T) {
	snap := loadFixture(t, "../query/testdata/double-inspection.json")
	res, err := Run(t.Context(), Options{
		Snapshot: snap,
		SrcIP:    mustAddr(t, "10.30.32.10"),
		DstIP:    mustAddr(t, "10.29.17.10"),
		Proto:    mustProto(t, "tcp"),
		Port:     8080,
		Analyzer: &mockAnalyzer{reachable: false},
		Region:   "us-east-1",
	})
	if err != nil {
		t.Fatal(err)
	}

	c := caveatFor(t, res, CaveatForwardOnly)
	for _, want := range []string{"TCP", "transit gateway route table", "forward", "return direction"} {
		if !strings.Contains(c.Summary, want) {
			t.Errorf("the forward-only caveat omits %q: %s", want, c.Summary)
		}
	}
	if !c.Coverage {
		t.Error("the forward-only caveat does not narrow coverage; a direction the analyser never evaluated is a gap")
	}
	if res.Covers() {
		t.Error("Covers() = true with a forward-only caveat, so an agreement over one direction would read as an agreement over the flow")
	}
}

// The caveat is stated for the flows it constrains and not for the others: the
// analyser's transit gateway limit is specific to TCP.
func TestRunOmitsTheForwardOnlyCaveatForUDP(t *testing.T) {
	snap := loadFixture(t, "../query/testdata/double-inspection.json")
	res, err := Run(t.Context(), Options{
		Snapshot: snap,
		SrcIP:    mustAddr(t, "10.30.32.10"),
		DstIP:    mustAddr(t, "10.29.17.10"),
		Proto:    mustProto(t, "udp"),
		Port:     8080,
		Analyzer: &mockAnalyzer{reachable: false},
		Region:   "us-east-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if hasCaveat(res, CaveatForwardOnly) {
		t.Errorf("a UDP flow carries the TCP forward-only caveat: %+v", res.Caveats)
	}
	if !hasCaveat(res, CaveatBilling) {
		t.Errorf("the billing caveat is missing: %+v", res.Caveats)
	}
}

// Requirement 13.5: a flow crossing a region boundary reports that no single
// analyzer run covers the path, naming both regions.
func TestRunReportsThatNoSingleRunCoversACrossRegionFlow(t *testing.T) {
	snap := loadFixture(t, "../query/testdata/default-action-pass.json")
	res, err := Run(t.Context(), Options{
		Snapshot: snap,
		SrcIP:    mustAddr(t, crossRegionSrc),
		DstIP:    mustAddr(t, crossRegionDst),
		Proto:    mustProto(t, "tcp"),
		Port:     443,
		// Supplied and expected to go unused: the caveat is the report of a limit,
		// and an analysis run anyway would make it the report of a limit the run had
		// already ignored.
		Analyzer: &refusingAnalyzer{t: t},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.AWS == nil || !res.AWS.Skipped {
		t.Fatalf("an analysis was reported for a cross-region flow: %+v", res.AWS)
	}

	c := caveatFor(t, res, CaveatCrossRegion)
	for _, want := range []string{"no single Reachability Analyzer run covers", "one region"} {
		if !strings.Contains(c.Summary, want) {
			t.Errorf("the cross-region caveat omits %q: %s", want, c.Summary)
		}
	}

	// Both regions are named, so an operator knows which two analyses would be
	// needed and which hop neither of them would cover.
	srcRegion := regionFor(t, snap, crossRegionSrc)
	dstRegion := regionFor(t, snap, crossRegionDst)
	if srcRegion == dstRegion {
		t.Fatalf("fixture is not cross-region: both endpoints are in %s", srcRegion)
	}
	for _, region := range []string{srcRegion, dstRegion} {
		if !strings.Contains(c.Summary, region) {
			t.Errorf("the cross-region caveat does not name %s: %s", region, c.Summary)
		}
	}

	if res.Covers() {
		t.Error("Covers() = true for a cross-region flow no single analysis reaches across")
	}
	// The region boundary is the reason, so it is reported once rather than
	// alongside a generic "no analysis ran".
	if hasCaveat(res, CaveatNotRun) {
		t.Errorf("the cross-region flow also carries a generic no-analysis caveat: %+v", res.Caveats)
	}
}

// Requirement 13.5, the cases a comparison of two subnet regions does not see: an
// endpoint in no collected subnet, and a scope the caller named rather than one
// inferred from the snapshot.
//
// Each of these puts more than one region in play, so each has to report that no
// single run covers the path. Reporting it only for the two-resolved-endpoints
// case would leave the requirement satisfied for the flows that are easy to
// detect and silent for the ones an operator is most likely to get wrong.
func TestRunReportsNoSingleRunCoversWhenTheRegionsAreNotBothInferred(t *testing.T) {
	snap := loadFixture(t, "../query/testdata/default-action-pass.json")

	cases := []struct {
		name        string
		src, dst    string
		region      string
		wantRegions []string
	}{
		{
			// Both endpoints in one region, analysed under a scope in another: the
			// run would be billable, would evaluate a path in us-west-2, and would
			// report on a flow that lives in us-east-1.
			name: "scope excludes the whole path",
			src:  "10.30.32.10", dst: "10.29.17.10", region: "us-west-2",
			wantRegions: []string{"us-east-1", "us-west-2"},
		},
		{
			// The destination is in no collected subnet, so the snapshot cannot say
			// which region it is in. What it can say is that the scope is not the
			// region the known half of the path runs through.
			name: "destination outside the snapshot with a scope elsewhere",
			src:  "10.30.32.10", dst: "10.30.192.10", region: "us-west-2",
			wantRegions: []string{"us-east-1", "us-west-2"},
		},
		{
			// And the same with the unknown endpoint on the other side.
			name: "source outside the snapshot with a scope elsewhere",
			src:  "192.168.99.10", dst: "10.29.48.10", region: "us-east-1",
			wantRegions: []string{"us-west-2", "us-east-1"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// An analyser that fails the test if it is called: a run covering part of
			// the path is the failure this branch exists to prevent, and a charge for
			// it is the part an operator notices.
			analyzer := &refusingAnalyzer{t: t}
			res, err := Run(t.Context(), Options{
				Snapshot: snap,
				SrcIP:    mustAddr(t, tc.src),
				DstIP:    mustAddr(t, tc.dst),
				Proto:    mustProto(t, "tcp"),
				Port:     443,
				Region:   tc.region,
				Analyzer: analyzer,
			})
			if err != nil {
				t.Fatal(err)
			}

			c := caveatFor(t, res, CaveatCrossRegion)
			for _, want := range append([]string{"no single Reachability Analyzer run covers", "one region"}, tc.wantRegions...) {
				if !strings.Contains(c.Summary, want) {
					t.Errorf("the cross-region caveat omits %q: %s", want, c.Summary)
				}
			}
			if !c.Coverage {
				t.Error("the cross-region caveat does not narrow coverage; a path no run reaches across is a gap")
			}
			if res.Covers() {
				t.Error("Covers() = true for a path no single analysis covers")
			}
			if res.AWS == nil || !res.AWS.Skipped {
				t.Fatalf("an analysis was reported for a path no single run covers: %+v", res.AWS)
			}
			if !strings.Contains(res.AWS.SkipReason, "single-region") {
				t.Errorf("SkipReason = %q, want the region boundary as the reason", res.AWS.SkipReason)
			}
		})
	}
}

// A flow inside one region, analysed under the scope it sits in, carries no
// cross-region caveat: a limit stated on every flow tells a reader nothing about
// the one in front of them.
func TestRunOmitsTheCrossRegionCaveatWithinOneRegion(t *testing.T) {
	snap := loadFixture(t, "../query/testdata/double-inspection.json")
	res, err := Run(t.Context(), Options{
		Snapshot: snap,
		SrcIP:    mustAddr(t, "10.30.32.10"),
		DstIP:    mustAddr(t, "10.29.17.10"),
		Proto:    mustProto(t, "tcp"),
		Port:     8080,
		Analyzer: &mockAnalyzer{reachable: false},
		Region:   "us-east-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if hasCaveat(res, CaveatCrossRegion) {
		t.Errorf("a single-region flow carries the cross-region caveat: %+v", res.Caveats)
	}
	if res.AWS == nil || res.AWS.Skipped {
		t.Errorf("the analysis was skipped for a flow one run does cover: %+v", res.AWS)
	}
}

// refusingAnalyzer fails the test if the Verifier asks it for an analysis.
type refusingAnalyzer struct{ t *testing.T }

func (a *refusingAnalyzer) Analyze(_ context.Context, req AnalysisRequest) (*AnalysisResponse, error) {
	a.t.Helper()
	a.t.Errorf("a billable analysis was requested for a path no single run covers: %s to %s", req.Source, req.Destination)
	return nil, fmt.Errorf("no analysis should have been requested")
}

func regionFor(t *testing.T, snap *model.Snapshot, addr string) string {
	t.Helper()
	_, region, ok := SubnetForAddr(snap, mustAddr(t, addr))
	if !ok {
		t.Fatalf("%s is not in any collected subnet", addr)
	}
	return region
}
