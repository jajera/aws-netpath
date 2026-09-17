package format

// The declared flow projection is tested on the three sections and on what has to
// be in each of them.
//
// A failure carries both verdicts and the deciding Citation, because requirement
// 12.2 asks for evidence and a build log without it sends the reader back to the
// tool. An inconclusive flow appears in its own section and in neither of the
// others, because requirement 12.4 makes it a third outcome rather than a shade of
// the other two. And a run holding one gets the banner, because a reader who stops
// at the outcome line has to learn that some of it was not established.

import (
	"bytes"
	"strings"
	"testing"

	"github.com/jajera/aws-netpath/internal/flowtest"
	"github.com/jajera/aws-netpath/internal/model"
)

// declaredRun builds a run with one flow of each outcome, judged by the package
// that owns the judgement rather than assembled by hand.
func declaredRun(t *testing.T) *flowtest.Result {
	t.Helper()

	declare := func(name string, expect flowtest.Reachability) flowtest.Declared {
		return flowtest.Declared{
			Name: name, From: "192.0.2.10", To: "198.51.100.20",
			Proto: "tcp", Port: 22, Expect: expect,
		}
	}

	permitted := model.Verdict{Results: []model.LayerResult{{
		Layer:   model.LayerSecurityGroup,
		Verdict: model.VerdictPass,
		Citations: []model.Citation{{
			Kind: "security_group", Identifier: "sg-0123456789abcdef0",
			Detail: "ingress rule allows tcp/22 from 192.0.2.0/24",
		}},
	}}}
	permitted.ComputeAuthoritative()

	blocked := model.Verdict{
		PrimaryBlocker: layer(model.LayerFirewall),
		Results: []model.LayerResult{{
			Layer:   model.LayerFirewall,
			Verdict: model.VerdictBlocked,
			Citations: []model.Citation{{
				Kind: "nfw_rule", Identifier: "nfr-deny-north-south sid 12 (priority 4)",
				Detail: "DROP tcp 192.0.2.0/24 -> 198.51.100.0/24 port 22",
			}},
		}},
	}
	blocked.ComputeAuthoritative()

	unread := model.Verdict{Results: []model.LayerResult{
		{
			Layer:   model.LayerRoute,
			Verdict: model.VerdictPass,
			Citations: []model.Citation{{
				Kind: "route", Identifier: "rtb-0aaa1111bbbb2222c", Detail: "local route for 198.51.100.0/24",
			}},
		},
		{
			Layer:   model.LayerSecurityGroup,
			Verdict: model.VerdictAbstain,
			Reason:  "destination 198.51.100.20 has no collected network interface",
		},
	}}
	unread.ComputeAuthoritative()

	for name, v := range map[string]model.Verdict{"permitted": permitted, "blocked": blocked, "unread": unread} {
		if err := v.Validate(); err != nil {
			t.Fatalf("%s fixture is not a verdict the engine could produce: %v", name, err)
		}
	}

	return flowtest.Summarise([]flowtest.Case{
		flowtest.Judge(declare("app to db ssh", flowtest.Permitted), flowtest.Evaluation{
			Flow: "192.0.2.10/32 -> 198.51.100.20/32 tcp/22", Verdict: permitted,
		}),
		flowtest.Judge(declare("bastion to db ssh", flowtest.Permitted), flowtest.Evaluation{
			Flow: "192.0.2.11/32 -> 198.51.100.20/32 tcp/22", Verdict: blocked,
		}),
		flowtest.Judge(declare("app to unattributed address", flowtest.Permitted), flowtest.Evaluation{
			Flow: "192.0.2.10/32 -> 198.51.100.21/32 tcp/22", Verdict: unread,
		}),
	})
}

// The three sections carry the three outcomes, and a failure arrives with both
// verdicts and its Citation.
//
// Validates: Requirements 12.2, 12.4
func TestFromFlowTestSeparatesTheThreeOutcomes(t *testing.T) {
	got := FromFlowTest(declaredRun(t))

	if got.Kind != KindFlowTest {
		t.Errorf("kind = %q, want %q", got.Kind, KindFlowTest)
	}
	for _, s := range []*Section{got.Finding, got.Cleared, got.Unresolved} {
		if s == nil {
			t.Fatal("a section is absent; every report carries all three")
		}
	}
	if !strings.Contains(got.Outcome, "FAILED") {
		t.Errorf("outcome = %q, want a failed run", got.Outcome)
	}

	// The failure leads, names both verdicts, and cites the rule that decided the
	// actual one.
	var citedRule bool
	for _, row := range got.Finding.Rows {
		if strings.Contains(row.Subject, "nfr-deny-north-south sid 12") {
			citedRule = true
		}
	}
	if !citedRule {
		t.Errorf("failure section cites no firewall rule: %+v", got.Finding.Rows)
	}
	head := got.Finding.Rows[0]
	if head.Layer != "bastion to db ssh" || head.Verdict != labelFail {
		t.Errorf("failure heading = %+v, want the flow labelled %s", head, labelFail)
	}
	for _, want := range []string{string(flowtest.Permitted), string(flowtest.Blocked)} {
		if !strings.Contains(head.Detail, want) {
			t.Errorf("failure summary %q does not name the %s verdict", head.Detail, want)
		}
	}

	// The flow that held is named and not detailed.
	if len(got.Cleared.Rows) != 1 || got.Cleared.Rows[0].Layer != "app to db ssh" {
		t.Errorf("cleared rows = %+v, want the one flow that met its declaration", got.Cleared.Rows)
	}

	// The inconclusive flow is in its own section, in neither of the others, and
	// the run says it cannot be relied on.
	if len(got.Unresolved.Rows) == 0 {
		t.Fatal("inconclusive section is empty")
	}
	if got.Unresolved.Rows[0].Verdict != labelInconclusive {
		t.Errorf("inconclusive label = %q, want %q", got.Unresolved.Rows[0].Verdict, labelInconclusive)
	}
	for _, s := range []*Section{got.Finding, got.Cleared} {
		for _, row := range s.Rows {
			if row.Layer == "app to unattributed address" {
				t.Errorf("section %q carries the inconclusive flow", s.Title)
			}
		}
	}
	if got.Authoritative {
		t.Errorf("authoritative = true, want false")
	}
	if got.Notice == "" {
		t.Error("no notice; a run resting on an unestablished flow has to say so")
	}
}

// Every renderer accepts the projection, and the text rendering carries the
// outcome, the banner, and the evidence.
//
// Validates: Requirements 12.2
func TestWriteFlowTestRendersInEveryMode(t *testing.T) {
	report := FromFlowTest(declaredRun(t))

	for _, mode := range []Mode{ModeText, ModeMarkdown, ModeJSON} {
		var b bytes.Buffer
		if err := Write(&b, report, Options{Mode: mode}); err != nil {
			t.Fatalf("Write(%s) error = %v", mode, err)
		}
		out := b.String()
		for _, want := range []string{"FAILED", "nfr-deny-north-south sid 12", "inconclusive"} {
			if !strings.Contains(out, want) {
				t.Errorf("%s rendering does not mention %q", mode, want)
			}
		}
	}
}

// A nil run renders rather than panicking, and says it asserted nothing.
func TestFromFlowTestHandlesAnEmptyRun(t *testing.T) {
	if got := FromFlowTest(nil).Outcome; got != outcomeNoFlows {
		t.Errorf("outcome = %q, want %q", got, outcomeNoFlows)
	}
	if got := FromFlowTest(flowtest.Summarise(nil)).Outcome; got != outcomeNoFlows {
		t.Errorf("empty run outcome = %q, want %q", got, outcomeNoFlows)
	}
}
