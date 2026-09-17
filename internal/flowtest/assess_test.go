package flowtest

// Judging is tested on the three outcomes and on the boundary between them.
//
// A mismatch has to arrive with both verdicts and the Citation that decided the
// actual one, because a gate that reports "app-to-db ssh failed" has told the
// operator what a monitoring alert would have.
//
// An Abstention has to arrive as inconclusive. That is the case worth the most
// care: a flow declared permitted, nothing shown to block it, and a Layer that
// could not be read is the exact shape a green build would be wrong about, and
// requirement 12.4 says it is not a pass.

import (
	"errors"
	"strings"
	"testing"

	"github.com/jajera/aws-netpath/internal/model"
)

func declaredFlow(expect Reachability) Declared {
	d := Declared{
		Name: "app to db ssh", From: "192.0.2.10", To: "198.51.100.20",
		Proto: "tcp", Port: 22, Expect: expect,
	}
	return d
}

func layer(l model.Layer, v model.LayerVerdict, identifier, detail string) model.LayerResult {
	return model.LayerResult{
		Layer:     l,
		Verdict:   v,
		Citations: []model.Citation{{Kind: "security_group", Identifier: identifier, Detail: detail}},
	}
}

func abstained(l model.Layer, reason string) model.LayerResult {
	return model.LayerResult{Layer: l, Verdict: model.VerdictAbstain, Reason: reason}
}

// permittedVerdict is a fully evaluated path nothing blocks.
func permittedVerdict() model.Verdict {
	v := model.Verdict{Results: []model.LayerResult{
		layer(model.LayerRoute, model.VerdictPass, "rtb-0a1b2c3d", "local route for 198.51.100.0/24"),
		layer(model.LayerSecurityGroup, model.VerdictPass, "sg-0a1b2c3d", "ingress tcp/22 from 192.0.2.0/24"),
	}}
	v.ComputeAuthoritative()
	return v
}

// blockedVerdict is a path a security group drops, with the rule cited.
func blockedVerdict() model.Verdict {
	blocker := model.LayerSecurityGroup
	v := model.Verdict{
		PrimaryBlocker: &blocker,
		Results: []model.LayerResult{
			layer(model.LayerRoute, model.VerdictPass, "rtb-0a1b2c3d", "local route for 198.51.100.0/24"),
			layer(model.LayerSecurityGroup, model.VerdictBlocked, "sg-0a1b2c3d", "no ingress rule permits tcp/22 from 192.0.2.10"),
		},
	}
	v.ComputeAuthoritative()
	return v
}

// A declared flow whose actual verdict matches passes, and cites the last gate the
// traffic cleared.
//
// Validates: Requirements 12.2
func TestJudgePassesAMatchingVerdict(t *testing.T) {
	got := Judge(declaredFlow(Permitted), Evaluation{
		Flow: "192.0.2.10 -> 198.51.100.20 tcp/22", Verdict: permittedVerdict(),
	})

	if got.Outcome != OutcomePass {
		t.Fatalf("outcome = %q, want %q (%s)", got.Outcome, OutcomePass, got.Summary)
	}
	if got.Actual != Permitted || got.Expected != Permitted {
		t.Errorf("verdicts = expected %q actual %q, want both %q", got.Expected, got.Actual, Permitted)
	}
	if !got.Established {
		t.Errorf("established = false, want true: nothing abstained")
	}
	if got.DecidingLayer != model.LayerSecurityGroup {
		t.Errorf("deciding layer = %q, want %q (the last gate cleared)", got.DecidingLayer, model.LayerSecurityGroup)
	}
	if len(got.Deciding) == 0 {
		t.Errorf("no deciding citation; a verdict without one is not emittable")
	}

	// And a matching blocked flow is a pass on the same terms.
	blocked := Judge(declaredFlow(Blocked), Evaluation{Verdict: blockedVerdict()})
	if blocked.Outcome != OutcomePass {
		t.Errorf("blocked flow outcome = %q, want %q (%s)", blocked.Outcome, OutcomePass, blocked.Summary)
	}
}

// A declared flow whose actual verdict differs fails, reporting the flow, both
// verdicts, and the Citation that decided the actual one.
//
// Validates: Requirements 12.2
func TestJudgeReportsAMismatchWithBothVerdictsAndTheDecidingCitation(t *testing.T) {
	const rendered = "192.0.2.10 -> 198.51.100.20 tcp/22"

	got := Judge(declaredFlow(Permitted), Evaluation{Flow: rendered, Verdict: blockedVerdict()})

	if got.Outcome != OutcomeFail {
		t.Fatalf("outcome = %q, want %q (%s)", got.Outcome, OutcomeFail, got.Summary)
	}
	if got.Flow != rendered {
		t.Errorf("flow = %q, want %q", got.Flow, rendered)
	}
	if got.Expected != Permitted || got.Actual != Blocked {
		t.Fatalf("verdicts = expected %q actual %q, want %q and %q",
			got.Expected, got.Actual, Permitted, Blocked)
	}

	// Both verdicts in the summary, so a one-line CI log is actionable.
	for _, want := range []string{string(Permitted), string(Blocked), string(model.LayerSecurityGroup)} {
		if !strings.Contains(got.Summary, want) {
			t.Errorf("summary %q does not mention %q", got.Summary, want)
		}
	}

	if got.DecidingLayer != model.LayerSecurityGroup {
		t.Fatalf("deciding layer = %q, want %q", got.DecidingLayer, model.LayerSecurityGroup)
	}
	var cited bool
	for _, c := range got.Deciding {
		if c.Identifier == "sg-0a1b2c3d" {
			cited = true
		}
	}
	if !cited {
		t.Errorf("deciding citations = %+v, want the blocking security group", got.Deciding)
	}
}

// An abstaining evaluation is inconclusive and is never counted as a pass,
// whichever verdict was declared.
//
// Validates: Requirements 12.4
func TestJudgeReportsAnAbstentionAsInconclusive(t *testing.T) {
	const reason = "destination 198.51.100.20 lies outside the snapshot, so its security groups were not evaluated"

	verdict := model.Verdict{Results: []model.LayerResult{
		layer(model.LayerRoute, model.VerdictPass, "rtb-0a1b2c3d", "local route for 198.51.100.0/24"),
		abstained(model.LayerSecurityGroup, reason),
	}}
	verdict.ComputeAuthoritative()
	if verdict.Authoritative {
		t.Fatalf("fixture is authoritative; the abstention should have removed that")
	}

	for _, expect := range []Reachability{Permitted, Blocked} {
		got := Judge(declaredFlow(expect), Evaluation{Verdict: verdict})

		if got.Outcome != OutcomeInconclusive {
			t.Fatalf("declared %s: outcome = %q, want %q (%s)",
				expect, got.Outcome, OutcomeInconclusive, got.Summary)
		}
		if got.Outcome == OutcomePass {
			t.Fatalf("declared %s: an abstention was counted as a pass", expect)
		}
		if got.Established {
			t.Errorf("declared %s: established = true, want false", expect)
		}
		// The Layer that could not be read is named, because that is where the
		// operator has to go next.
		for _, want := range []string{string(model.LayerSecurityGroup), reason} {
			if !strings.Contains(got.Reason, want) {
				t.Errorf("declared %s: reason %q does not mention %q", expect, got.Reason, want)
			}
		}
	}
}

// An Abstention after the blocking Layer does not make a blocked flow
// inconclusive: an unevaluated Layer cannot un-block traffic another Layer was
// shown to drop.
//
// Validates: Requirements 12.4
func TestJudgeKeepsABlockedFlowEstablishedWhenALaterLayerAbstains(t *testing.T) {
	blocker := model.LayerRoute
	verdict := model.Verdict{
		PrimaryBlocker: &blocker,
		Results: []model.LayerResult{
			layer(model.LayerRoute, model.VerdictBlocked, "rtb-0a1b2c3d", "no route to 198.51.100.20"),
			abstained(model.LayerFirewall, "the policy references a rule group absent from the snapshot"),
		},
	}
	verdict.ComputeAuthoritative()

	got := Judge(declaredFlow(Blocked), Evaluation{Verdict: verdict})
	if got.Outcome != OutcomePass {
		t.Fatalf("outcome = %q, want %q (%s)", got.Outcome, OutcomePass, got.Summary)
	}
	if got.DecidingLayer != model.LayerRoute {
		t.Errorf("deciding layer = %q, want %q", got.DecidingLayer, model.LayerRoute)
	}
}

// A flow that could not be evaluated at all is inconclusive rather than failed:
// nothing was learned about its reachability.
//
// Validates: Requirements 12.4
func TestJudgeReportsAnUnevaluatedFlowAsInconclusive(t *testing.T) {
	got := Judge(declaredFlow(Permitted), Evaluation{
		Err: errors.New(`--to "db-1" matches no collected instance or network interface`),
	})

	if got.Outcome != OutcomeInconclusive {
		t.Fatalf("outcome = %q, want %q (%s)", got.Outcome, OutcomeInconclusive, got.Summary)
	}
	if got.Actual != "" {
		t.Errorf("actual = %q, want empty: no verdict was reached", got.Actual)
	}
	if !strings.Contains(got.Reason, "matches no collected instance") {
		t.Errorf("reason = %q, want the evaluation failure", got.Reason)
	}
	// The declaration still locates the flow, since the engine rendered none.
	if got.Flow == "" {
		t.Errorf("flow is empty; the declaration should have described it")
	}
}

// Summarise tallies the three outcomes separately, and an inconclusive flow
// removes the run's authority without being counted as a pass or a failure.
//
// Validates: Requirements 12.3, 12.4
func TestSummariseCountsTheThreeOutcomesSeparately(t *testing.T) {
	cases := []Case{
		Judge(declaredFlow(Permitted), Evaluation{Verdict: permittedVerdict()}),
		Judge(declaredFlow(Permitted), Evaluation{Verdict: blockedVerdict()}),
		Judge(declaredFlow(Permitted), Evaluation{Err: errors.New("unmanaged")}),
	}

	got := Summarise(cases)
	want := Counts{Total: 3, Passed: 1, Failed: 1, Inconclusive: 1}
	if got.Counts != want {
		t.Fatalf("counts = %+v, want %+v", got.Counts, want)
	}
	if !got.Failed() {
		t.Errorf("Failed() = false, want true: one flow did not meet its declaration")
	}
	if !got.Inconclusive() {
		t.Errorf("Inconclusive() = false, want true")
	}
	if got.Authoritative {
		t.Errorf("authoritative = true, want false: one flow could not be established")
	}
	if n := len(got.Failures()); n != 1 {
		t.Errorf("failures = %d, want 1", n)
	}
	if n := len(got.Unresolved()); n != 1 {
		t.Errorf("unresolved = %d, want 1", n)
	}
	if !strings.Contains(got.Summary(), "FAILED") {
		t.Errorf("summary = %q, want a failed run", got.Summary())
	}

	// A run with no failures and one inconclusive flow is not reported as passed.
	partial := Summarise([]Case{
		Judge(declaredFlow(Permitted), Evaluation{Verdict: permittedVerdict()}),
		Judge(declaredFlow(Permitted), Evaluation{Err: errors.New("unmanaged")}),
	})
	if partial.Failed() {
		t.Errorf("Failed() = true, want false: nothing contradicted its declaration")
	}
	if !strings.Contains(partial.Summary(), "INCONCLUSIVE") {
		t.Errorf("summary = %q, want an inconclusive run", partial.Summary())
	}
}
