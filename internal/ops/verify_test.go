package ops

// The verify operation, from a snapshot on disk to a rendered cross-check.
//
// The Verifier's own tests assert that the caveats are computed and the
// renderer's assert that a caveat it is handed comes out in every mode. Neither
// can catch the projection in between dropping them, which is the failure that
// would leave requirement 13.4 true in the code and absent from the output an
// operator actually reads. These run the real operation and read what it printed.

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jajera/aws-netpath/internal/format"
	"github.com/jajera/aws-netpath/internal/verify"
)

// The inherited fixture, and a pair of endpoints in one region whose path the
// engine walks over a transit gateway route table — the flow the analyser's
// forward-only limit actually constrains.
const (
	verifyFixture = "../query/testdata/double-inspection.json"
	verifySrc     = "10.30.32.10"
	verifyDst     = "10.29.17.10"
	verifyRegion  = "us-east-1"
)

// A pair of endpoints the same fixtures place either side of a region boundary,
// both inside collected subnets — so the run reaches the boundary rather than
// stopping at an endpoint it could not scope.
const (
	crossRegionFixture = "../query/testdata/default-action-pass.json"
	crossRegionSrc     = "10.30.32.10" // subnet-prod-east-a, us-east-1
	crossRegionDst     = "10.29.48.10" // subnet-inspection-west-fw, us-west-2
)

// stubAnalyzer answers without calling AWS, so the operation can be driven end to
// end without credentials or a billable analysis.
type stubAnalyzer struct{ reachable bool }

func (s *stubAnalyzer) Analyze(_ context.Context, _ verify.AnalysisRequest) (*verify.AnalysisResponse, error) {
	v := s.reachable
	return &verify.AnalysisResponse{Reachable: &v}, nil
}

// Requirement 13.4 through the operation: the rendered cross-check states that
// the analyses are billable and that TCP over a transit gateway route table is
// evaluated in the forward direction only.
func TestVerifyRendersTheAnalyserCaveats(t *testing.T) {
	res, err := Verify(context.Background(), VerifyRequest{
		SnapshotPath: verifyFixture,
		From:         verifySrc,
		To:           verifyDst,
		Proto:        "tcp",
		Port:         8080,
		Region:       verifyRegion,
		Analyzer:     &stubAnalyzer{reachable: false},
	})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if res.AWS == nil || res.AWS.Skipped {
		t.Fatalf("the analysis did not run, so this is not the branch under test: %+v", res.AWS)
	}

	report := VerifyReport(res)
	if report.Kind != format.KindVerification {
		t.Fatalf("report kind = %q, want %q", report.Kind, format.KindVerification)
	}

	got := renderReport(t, report, format.ModeText)
	for _, want := range []string{
		"caveats:",
		"analysis cost",
		"billable",
		"per analysis",
		"forward direction only",
		"transit gateway route table",
		"return direction",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the rendering omits %q:\n%s", want, got)
		}
	}

	// The same statements survive the other two modes, since an operator reading
	// markdown in a ticket or JSON in a pipeline is owed the same limits.
	if md := renderReport(t, report, format.ModeMarkdown); !strings.Contains(md, "## caveats") {
		t.Errorf("the markdown rendering has no caveats section:\n%s", md)
	}
	if js := renderReport(t, report, format.ModeJSON); !strings.Contains(js, "forward direction only") {
		t.Errorf("the json rendering omits the forward-only caveat:\n%s", js)
	}

	// A direction the analyser never evaluated is a gap, so this comparison does
	// not get to present itself as settled.
	if res.Covers() {
		t.Error("Covers() = true for a flow the analyser evaluated in one direction only")
	}
	if report.Authoritative {
		t.Error("the report claims to cover the whole flow despite the forward-only caveat")
	}
}

// The cost is stated to the operator who has not spent it yet: a run that made no
// AWS call still says what a call would cost, and says nothing about a direction
// no analysis evaluated.
func TestVerifyWithoutAnAnalysisStillStatesTheCost(t *testing.T) {
	res, err := Verify(context.Background(), VerifyRequest{
		SnapshotPath: verifyFixture,
		From:         verifySrc,
		To:           verifyDst,
		Proto:        "tcp",
		Port:         8080,
		SkipAWS:      true,
	})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if res.AWS == nil || !res.AWS.Skipped {
		t.Fatalf("the analysis ran despite SkipAWS: %+v", res.AWS)
	}

	got := renderReport(t, VerifyReport(res), format.ModeText)
	for _, want := range []string{"analysis cost", "billable"} {
		if !strings.Contains(got, want) {
			t.Errorf("a skipped comparison omits %q:\n%s", want, got)
		}
	}
}

// Requirement 13.5 through the operation: a flow crossing a region boundary
// reports that no single analyser run covers the path, in every rendering, and
// does not present itself as corroborated.
//
// Validates: Requirements 13.5
func TestVerifyReportsNoSingleRunCoversACrossRegionFlow(t *testing.T) {
	res, err := Verify(context.Background(), VerifyRequest{
		SnapshotPath: crossRegionFixture,
		From:         crossRegionSrc,
		To:           crossRegionDst,
		Proto:        "tcp",
		Port:         443,
		// An analyser is available and must still go unasked: no single run covers
		// this path, and one run of it would be a charge for a partial answer.
		Analyzer: &refusingAnalyzer{t: t},
	})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if res.AWS == nil || !res.AWS.Skipped {
		t.Fatalf("an analysis was reported for a cross-region flow: %+v", res.AWS)
	}
	if res.Covers() {
		t.Error("Covers() = true for a path no single analysis reaches across")
	}

	report := VerifyReport(res)
	if report.Authoritative {
		t.Errorf("the report claims to cover a path no single run covers: %s", report.Notice)
	}

	for _, mode := range []format.Mode{format.ModeText, format.ModeMarkdown, format.ModeJSON} {
		got := renderReport(t, report, mode)
		for _, want := range []string{
			"cross-region path",
			"no single Reachability Analyzer run covers us-east-1 to us-west-2",
			"scoped to one region",
		} {
			if !strings.Contains(got, want) {
				t.Errorf("the %s rendering omits %q:\n%s", mode, want, got)
			}
		}
	}

	// And the machine-readable rendering says the same thing in the field a
	// pipeline gates on, rather than only in prose a human would have to read.
	if js := renderReport(t, report, format.ModeJSON); !strings.Contains(js, `"authoritative": false`) {
		t.Errorf("the json rendering reports a cross-region flow as settled:\n%s", js)
	}
}

// refusingAnalyzer fails the test if the operation asks it for an analysis.
type refusingAnalyzer struct{ t *testing.T }

func (a *refusingAnalyzer) Analyze(_ context.Context, req verify.AnalysisRequest) (*verify.AnalysisResponse, error) {
	a.t.Helper()
	a.t.Errorf("a billable analysis was requested for a path no single run covers: %s to %s", req.Source, req.Destination)
	return nil, errors.New("no analysis should have been requested")
}

// A nil cross-check renders rather than panicking, as the other operations' do.
func TestNilVerifyResultRenders(t *testing.T) {
	if got := VerifyReport(nil).Kind; got != format.KindVerification {
		t.Errorf("nil verification report kind = %q, want %q", got, format.KindVerification)
	}
}
