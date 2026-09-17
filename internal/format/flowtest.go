package format

// Projecting a declared flow run onto the same three sections.
//
// The slots hold what a build gate found — the flows that did not meet their
// declaration, the flows that did, the flows whose reachability could not be
// established — in the order the diagnosis and comparison renderers already use.
// A reader who learned the layout on one command does not learn it again here.
//
// The failures lead and carry their evidence. Requirement 12.2 asks a mismatch to
// report the Flow, both verdicts, and the deciding Citation, and the first two
// without the third leave the operator where a monitoring alert would have.
//
// The flows that held are named and nothing more. A file of fifty declared flows
// with two failures should read as two findings, not fifty rows.
//
// Inconclusive flows are their own section, as they are their own count.
// Requirement 12.4 — folding them into either of the other two would state
// something that was not established, and the whole point of a gate is that its
// green means something.

import (
	"fmt"

	"github.com/jajera/aws-netpath/internal/flowtest"
)

// KindFlowTest names a declared flow run in the JSON output.
const KindFlowTest Kind = "flow_test"

// Row-level labels for a declared flow's outcome. They are the report's
// vocabulary rather than the engine's: a declared flow is asserted and met, or
// asserted and contradicted, and neither is an ALLOW or a DENY.
const (
	labelPass         = "PASS"
	labelFail         = "FAIL"
	labelInconclusive = "INCONCLUSIVE"
)

// FromFlowTest projects a declared flow run onto a Report.
func FromFlowTest(t *flowtest.Result) Report {
	if t == nil {
		return Report{Kind: KindFlowTest, Outcome: outcomeNoFlows}
	}

	r := Report{
		Kind:          KindFlowTest,
		Outcome:       t.Summary(),
		Authoritative: t.Authoritative,
		Notes:         dedupe(t.Notes),
	}
	r.Finding = failureSection(t)
	r.Cleared = metSection(t)
	r.Unresolved = inconclusiveSection(t)
	if !t.Authoritative {
		r.Notice = notEstablished(t)
	}
	return r
}

// outcomeNoFlows is what an empty run says. A gate that asserted nothing reports
// that, rather than reporting a pass it did not earn.
const outcomeNoFlows = "NO DECLARED FLOWS"

// failureSection is section one: the flows whose actual verdict differs from the
// one declared, each with both verdicts and the evidence that decided the actual
// one. Requirement 12.2.
func failureSection(t *flowtest.Result) *Section {
	s := &Section{Title: "failures"}
	for _, c := range t.Failures() {
		s.add(caseRows(c, labelFail)...)
	}
	if len(s.Rows) == 0 {
		s.Note = "no declared flow was found to differ from its expected verdict"
	}
	return s
}

// metSection is section two: the flows that met their declaration, named only.
func metSection(t *flowtest.Result) *Section {
	s := &Section{Title: "flows that met their expected verdict"}
	for _, c := range t.Passes() {
		s.add(Row{Layer: c.Name, Verdict: labelPass})
	}
	if len(s.Rows) == 0 {
		s.Note = "no declared flow was established as matching its expected verdict"
		return s
	}
	s.Note = "evidence omitted: a declared flow run details the flows that did not meet their expected verdict"
	return s
}

// inconclusiveSection is section three: the flows whose reachability was not
// established, each with the reason. Requirement 12.4.
func inconclusiveSection(t *flowtest.Result) *Section {
	s := &Section{Title: "inconclusive flows"}
	for _, c := range t.Unresolved() {
		s.add(caseRows(c, labelInconclusive)...)
	}
	if len(s.Rows) == 0 {
		s.Note = "every declared flow was established"
		return s
	}
	s.Note = "an inconclusive flow is not a pass and not a failure"
	return s
}

// caseRows renders one judged flow: a heading row carrying its name, label, and
// summary, then the evidence behind the actual verdict.
func caseRows(c flowtest.Case, label string) []Row {
	head := Row{Layer: c.Name, Verdict: label, Detail: c.Summary}
	rows := []Row{head}
	if c.Name != c.Flow {
		// The declaration named the flow, so the flow itself is not on the page
		// yet, and a failure an operator cannot locate is not actionable.
		rows = append(rows, Row{Detail: fmt.Sprintf("flow: %s", c.Flow)})
	}
	return append(rows, citationRows(c.Deciding)...)
}

// notEstablished states why the run cannot be relied on. Requirement 14.6 applied
// to a gate: a run with an inconclusive flow has not asserted what it was asked
// to assert, and a reader who stops at the outcome line has to be told so.
func notEstablished(t *flowtest.Result) string {
	unresolved := t.Unresolved()
	if len(unresolved) == 0 {
		return "this run is not authoritative: a declared flow's reachability could not be established"
	}
	return fmt.Sprintf("this run is not authoritative: %s could not be established, so %s neither passed nor failed",
		flowCount(len(unresolved)), pluralThey(len(unresolved)))
}

func flowCount(n int) string {
	if n == 1 {
		return "1 declared flow"
	}
	return fmt.Sprintf("%d declared flows", n)
}

func pluralThey(n int) string {
	if n == 1 {
		return "it"
	}
	return "they"
}
