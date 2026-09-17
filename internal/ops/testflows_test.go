package ops

// TestFlows is tested against the snapshot the diagnose tests use, where every
// cloud layer permits tcp/22 between the two interfaces.
//
// Three flows, three outcomes. One that is declared permitted and is; one that is
// declared permitted and is blocked, which has to arrive with both verdicts and
// the rule that decided it; and one whose destination no collected interface
// holds, which abstains and has to be reported as inconclusive rather than as
// either.

import (
	"strings"
	"testing"

	"github.com/jajera/aws-netpath/internal/flowtest"
	"github.com/jajera/aws-netpath/internal/format"
	"github.com/jajera/aws-netpath/internal/model"
)

func declaredFile(flows ...flowtest.Declared) *flowtest.File {
	return &flowtest.File{Flows: flows}
}

func declared(name, to string, port int, expect flowtest.Reachability) flowtest.Declared {
	return flowtest.Declared{
		Name: name, From: testSrcAddr.String(), To: to,
		Proto: "tcp", Port: port, Expect: expect,
	}
}

// A declared flow the engine agrees with passes, and the run reports no failure
// for the caller to map onto an exit code.
//
// Validates: Requirements 12.1, 12.3
func TestTestFlowsPassesAFlowTheEngineAgreesWith(t *testing.T) {
	got, err := TestFlows(TestFlowsRequest{
		Snapshot: diagnoseSnapshot(),
		Flows:    declaredFile(declared("app to db ssh", testDstAddr.String(), 22, flowtest.Permitted)),
	})
	if err != nil {
		t.Fatalf("TestFlows() error = %v", err)
	}

	want := flowtest.Counts{Total: 1, Passed: 1}
	if got.Result.Counts != want {
		t.Fatalf("counts = %+v, want %+v (%+v)", got.Result.Counts, want, got.Result.Cases)
	}
	if got.Failed() {
		t.Errorf("Failed() = true, want false")
	}
	if got.Inconclusive() {
		t.Errorf("Inconclusive() = true, want false: every cloud layer was evaluated")
	}
	if !got.Result.Authoritative {
		t.Errorf("authoritative = false, want true (%+v)", got.Result.Notes)
	}
}

// A declared flow the engine contradicts fails, reporting the flow, both verdicts,
// and the deciding Citation.
//
// Validates: Requirements 12.2, 12.3
func TestTestFlowsReportsAMismatchWithTheDecidingCitation(t *testing.T) {
	got, err := TestFlows(TestFlowsRequest{
		Snapshot: diagnoseSnapshot(),
		// The security groups permit tcp/22 and nothing else, so a declaration
		// about tcp/443 is contradicted by a rule the report can name.
		Flows: declaredFile(declared("app to db mysql", testDstAddr.String(), 443, flowtest.Permitted)),
	})
	if err != nil {
		t.Fatalf("TestFlows() error = %v", err)
	}

	if !got.Failed() {
		t.Fatalf("Failed() = false, want true (%+v)", got.Result.Cases)
	}
	failures := got.Result.Failures()
	if len(failures) != 1 {
		t.Fatalf("failures = %d, want 1", len(failures))
	}

	c := failures[0]
	if c.Expected != flowtest.Permitted || c.Actual != flowtest.Blocked {
		t.Fatalf("verdicts = expected %q actual %q, want %q and %q",
			c.Expected, c.Actual, flowtest.Permitted, flowtest.Blocked)
	}
	if c.DecidingLayer != model.LayerSecurityGroup {
		t.Fatalf("deciding layer = %q, want %q (%s)", c.DecidingLayer, model.LayerSecurityGroup, c.Summary)
	}
	if len(c.Deciding) == 0 {
		t.Fatalf("no deciding citation for a failed flow")
	}
	// The flow the report names is the one the engine evaluated, ports and all.
	if !strings.Contains(c.Flow, "443") {
		t.Errorf("flow = %q, want the declared port", c.Flow)
	}

	// The rendered report leads with the failure and carries the evidence.
	report := got.Report()
	if report.Kind != format.KindFlowTest {
		t.Errorf("report kind = %q, want %q", report.Kind, format.KindFlowTest)
	}
	if !strings.Contains(report.Outcome, "FAILED") {
		t.Errorf("outcome = %q, want a failed run", report.Outcome)
	}
	var citedGroup bool
	for _, row := range report.Finding.Rows {
		if strings.HasPrefix(row.Subject, "sg-") {
			citedGroup = true
		}
	}
	if !citedGroup {
		t.Errorf("failure section cites no security group: %+v", report.Finding.Rows)
	}
}

// A declared flow whose evaluation abstains is inconclusive: not a pass, not a
// failure, and reported in its own section with the layer that could not be read.
//
// Validates: Requirements 12.4
func TestTestFlowsReportsAnAbstentionAsInconclusive(t *testing.T) {
	got, err := TestFlows(TestFlowsRequest{
		Snapshot: diagnoseSnapshot(),
		// An address inside a collected subnet that no collected interface holds:
		// routing is evaluable and the destination's security groups are not.
		Flows: declaredFile(declared("app to unattributed address", "10.30.1.50", 22, flowtest.Permitted)),
	})
	if err != nil {
		t.Fatalf("TestFlows() error = %v", err)
	}

	want := flowtest.Counts{Total: 1, Inconclusive: 1}
	if got.Result.Counts != want {
		t.Fatalf("counts = %+v, want %+v (%+v)", got.Result.Counts, want, got.Result.Cases)
	}
	if got.Failed() {
		t.Errorf("Failed() = true, want false: nothing contradicted the declaration")
	}
	if got.Result.Counts.Passed != 0 {
		t.Errorf("passed = %d, want 0: an abstention is never counted as a pass", got.Result.Counts.Passed)
	}

	c := got.Result.Unresolved()[0]
	if !strings.Contains(c.Reason, string(model.LayerSecurityGroup)) {
		t.Errorf("reason = %q, want the layer that could not be evaluated", c.Reason)
	}

	// The report keeps it out of both other sections and says why the run cannot
	// be relied on.
	report := got.Report()
	if report.Authoritative {
		t.Errorf("authoritative = true, want false")
	}
	if report.Notice == "" {
		t.Errorf("no notice; a run resting on an abstention has to say so")
	}
	if len(report.Unresolved.Rows) == 0 {
		t.Fatalf("inconclusive section is empty")
	}
	if len(report.Cleared.Rows) != 0 {
		t.Errorf("cleared section = %+v, want empty", report.Cleared.Rows)
	}
	if len(report.Finding.Rows) != 0 {
		t.Errorf("failure section = %+v, want empty", report.Finding.Rows)
	}
}

// One unusable flow does not stop the run: it is inconclusive and the rest are
// still asserted.
//
// Validates: Requirements 12.4
func TestTestFlowsAssertsTheRemainingFlowsWhenOneCannotBeEvaluated(t *testing.T) {
	got, err := TestFlows(TestFlowsRequest{
		Snapshot: diagnoseSnapshot(),
		Flows: declaredFile(
			declared("unknown endpoint", "db-does-not-exist", 22, flowtest.Permitted),
			declared("app to db ssh", testDstAddr.String(), 22, flowtest.Permitted),
		),
	})
	if err != nil {
		t.Fatalf("TestFlows() error = %v", err)
	}

	want := flowtest.Counts{Total: 2, Passed: 1, Inconclusive: 1}
	if got.Result.Counts != want {
		t.Fatalf("counts = %+v, want %+v (%+v)", got.Result.Counts, want, got.Result.Cases)
	}
	if reason := got.Result.Unresolved()[0].Reason; !strings.Contains(reason, "matches no collected") {
		t.Errorf("reason = %q, want the resolution failure", reason)
	}
}

// A malformed declaration is refused whole, before any flow is walked: a run that
// asserted most of a file reports a pass count that means nothing.
//
// Validates: Requirements 12.1
func TestTestFlowsRefusesAnUnusableDeclaration(t *testing.T) {
	cases := []struct {
		name string
		req  TestFlowsRequest
		want string
	}{
		{
			name: "no declared flows supplied",
			req:  TestFlowsRequest{Snapshot: diagnoseSnapshot()},
			want: "--flows is required",
		},
		{
			name: "an empty declaration asserts nothing",
			req: TestFlowsRequest{
				Snapshot: diagnoseSnapshot(),
				Flows:    &flowtest.File{},
			},
			want: "at least one flow is required",
		},
		{
			name: "a flow supplied in memory is validated too",
			req: TestFlowsRequest{
				Snapshot: diagnoseSnapshot(),
				Flows: declaredFile(flowtest.Declared{
					From: testSrcAddr.String(), To: testDstAddr.String(), Proto: "tcp", Port: 22,
				}),
			},
			want: "expect is required",
		},
		{
			name: "the snapshot is required",
			req: TestFlowsRequest{
				Flows: declaredFile(declared("app to db ssh", testDstAddr.String(), 22, flowtest.Permitted)),
			},
			want: "--snapshot is required",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := TestFlows(tc.req)
			if err == nil {
				t.Fatalf("TestFlows() = %+v, want an error", got)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}
