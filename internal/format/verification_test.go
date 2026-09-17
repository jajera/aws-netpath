package format

// The cross-check projection is tested on what a reader must not be able to miss.
//
// A disagreement has to be prominent and has to prefer neither source, so the
// assertions are deliberately about placement as well as content: the outcome line,
// the banner, both labels, both verdicts, and both citations, in every rendering. A
// disagreement that is merely present somewhere in the page is the failure
// requirement 13.3 describes.
//
// The caveats are asserted the same way. Requirement 13.4 is a statement an
// operator acts on before spending a run, and requirement 13.5 is one they act on
// before trusting a green result, so neither is allowed to be text the renderers
// drop.
//
// Every identifier is a placeholder and every address is RFC 1918 or RFC 5737
// space.

import (
	"strings"
	"testing"

	"github.com/jajera/aws-netpath/internal/model"
)

// The caveats the Verifier states about the analyser rather than about the
// network. They are written out here rather than imported, because internal/format
// does not depend on the Verifier and a renderer test that shared its constants
// would stop being able to catch a projection that dropped them.
var (
	billingCaveat = Caveat{
		Subject: "analysis cost",
		Summary: "Reachability Analyzer analyses are billable: each run creates a network insights path and an analysis and is charged per analysis, where the offline query over the snapshot costs nothing",
	}
	forwardOnlyCaveat = Caveat{
		Subject:  "forward direction only",
		Summary:  "for TCP over a transit gateway route table, Reachability Analyzer evaluates forward traffic only: this comparison says nothing about the return direction, which is where an asymmetric path fails",
		Coverage: true,
	}
	crossRegionCaveat = Caveat{
		Subject:  "cross-region path",
		Summary:  "no single Reachability Analyzer run covers us-west-2 to us-east-1: an analysis is scoped to one region, so no run evaluates this path end to end and two runs cannot be joined into one verdict",
		Coverage: true,
	}
)

func engineAnswer(verdict, summary string, cs ...model.Citation) Source {
	return Source{Label: EngineLabel, Verdict: verdict, Summary: summary, Citations: cs}
}

func analyserAnswer(verdict, summary string, cs ...model.Citation) Source {
	return Source{Label: AnalyserLabel, Verdict: verdict, Summary: summary, Citations: cs}
}

// disagreedVerification is the case requirement 13.3 exists for: the engine reads
// the policy as permitting the flow, the provider's own analyser finds no path, and
// one of the two is wrong.
func disagreedVerification() Verification {
	return Verification{
		Flow: "10.0.1.10/32 -> 10.1.2.30/32 tcp/443",
		Engine: engineAnswer("PERMITTED", "7 hops evaluated, none blocked",
			model.Citation{
				Kind: "engine", Identifier: "offline path walk",
				Detail: "7 hops evaluated, none blocked",
			},
			model.Citation{
				Kind: "nfw_rule", Identifier: "nfw-inspection-usw2",
				Detail: "nfr-allow-east-west sid 3 (priority 6) PASS",
			},
		),
		Analyser: analyserAnswer("NOT REACHABLE",
			"analysis in us-west-2 from eni-0123456789abcdef0 to eni-0abcdef123456789a",
			model.Citation{
				Kind:       "reachability_analyzer",
				Identifier: "nia-0123456789abcdef0",
				Detail:     "analysis in us-west-2 from eni-0123456789abcdef0 to eni-0abcdef123456789a",
			},
		),
		Concordance: ConcordanceDisagree,
		Detail:      "model permits but AWS blocks",
		Caveats:     []Caveat{billingCaveat, forwardOnlyCaveat},
	}
}

// agreedVerification is the corroborated case, with the analyser's transit gateway
// limit still narrowing what the agreement covers.
func agreedVerification() Verification {
	return Verification{
		Flow: "10.0.1.10/32 -> 10.1.2.30/32 tcp/443",
		Engine: engineAnswer("BLOCKED", "stopped at nacl acl-0123456789abcdef0 after 4 hops",
			model.Citation{
				Kind: "engine", Identifier: "nacl acl-0123456789abcdef0",
				Detail: "ingress no matching rule (implicit deny)",
			},
		),
		Analyser: analyserAnswer("NOT REACHABLE", "analysis in us-west-2",
			model.Citation{
				Kind: "reachability_analyzer", Identifier: "nia-0123456789abcdef0",
				Detail: "analysis in us-west-2",
			},
		),
		Concordance: ConcordanceAgree,
		Detail:      "model and AWS both block the flow",
		Caveats:     []Caveat{billingCaveat, forwardOnlyCaveat},
	}
}

// crossRegionVerification is a flow no single analysis reaches across.
func crossRegionVerification() Verification {
	return Verification{
		Flow: "10.0.1.10/32 -> 10.2.3.40/32 tcp/443",
		Engine: engineAnswer("PERMITTED", "9 hops evaluated, none blocked",
			model.Citation{
				Kind: "engine", Identifier: "offline path walk",
				Detail: "9 hops evaluated, none blocked",
			},
		),
		Analyser: analyserAnswer(labelNoResultForTest,
			"cross-region (us-west-2 → us-east-1): Reachability Analyzer is single-region",
			model.Citation{
				Kind: "reachability_analyzer", Identifier: "no analysis",
				Detail: "cross-region (us-west-2 → us-east-1): Reachability Analyzer is single-region",
			},
		),
		Concordance: ConcordanceUnestablished,
		Detail:      "AWS Reachability Analyzer did not return a result",
		Caveats:     []Caveat{billingCaveat, forwardOnlyCaveat, crossRegionCaveat},
	}
}

// labelNoResultForTest is the verdict an analyser that never ran reports. The
// projection that produces it lives in internal/ops, so the renderer test states
// it rather than importing it.
const labelNoResultForTest = "NO RESULT"

// The three sections hold for a cross-check too, in the same order and present
// when empty.
func TestFromVerificationRendersTheThreeSections(t *testing.T) {
	cases := []struct {
		name    string
		report  Report
		mode    Mode
		ordered []string
	}{
		{"disagreement text", FromVerification(disagreedVerification()), ModeText,
			[]string{"verdicts compared:", "corroborated:", "caveats:"}},
		{"disagreement markdown", FromVerification(disagreedVerification()), ModeMarkdown,
			[]string{"## verdicts compared", "## corroborated", "## caveats"}},
		{"agreement text", FromVerification(agreedVerification()), ModeText,
			[]string{"verdicts compared:", "corroborated:", "caveats:"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := render(t, tc.report, Options{Mode: tc.mode})
			at := -1
			for _, want := range tc.ordered {
				i := strings.Index(got, want)
				if i < 0 {
					t.Fatalf("section %q is missing:\n%s", want, got)
				}
				if i < at {
					t.Fatalf("section %q is out of order:\n%s", want, got)
				}
				at = i
			}
		})
	}
}

// Requirement 13.3: the disagreement leads, carries the banner, cites both
// sources, and states outright that neither is preferred.
//
// Validates: Requirements 13.3
func TestVerificationReportsDisagreementProminentlyPreferringNeither(t *testing.T) {
	v := disagreedVerification()
	report := FromVerification(v)

	if !strings.HasPrefix(report.Outcome, "DISAGREEMENT") {
		t.Errorf("Outcome = %q, want the disagreement first", report.Outcome)
	}
	if report.Authoritative {
		t.Error("a disagreement rendered as authoritative; the two sources established nothing between them")
	}
	for _, want := range []string{"neither is preferred", "neither is treated as correct", "rather than resolved"} {
		if !strings.Contains(report.Notice, want) {
			t.Errorf("the notice omits %q: %s", want, report.Notice)
		}
	}

	// Both answers appear in the same section, with the same shape, each with its
	// own evidence. A source rendered without a citation would be one the reader
	// cannot check, and the one they cannot check is the one they discount.
	labels := map[string]bool{}
	for _, row := range report.Finding.Rows {
		if row.Layer != "" {
			labels[row.Layer] = true
		}
	}
	for _, label := range []string{EngineLabel, AnalyserLabel} {
		if !labels[label] {
			t.Errorf("the %s is missing from the compared verdicts: %+v", label, report.Finding.Rows)
		}
	}

	// Every rendering carries both verdicts, both citations, and the statement that
	// neither source wins.
	for _, mode := range []Mode{ModeText, ModeMarkdown, ModeJSON} {
		got := render(t, report, Options{Mode: mode})
		for _, want := range []string{
			"DISAGREEMENT",
			EngineLabel, AnalyserLabel,
			v.Engine.Verdict, v.Analyser.Verdict,
			"nia-0123456789abcdef0",
			"nfr-allow-east-west sid 3 (priority 6)",
			"neither is preferred",
		} {
			if !strings.Contains(got, want) {
				t.Errorf("the %s rendering omits %q:\n%s", mode, want, got)
			}
		}
	}

	// The banner is where a reader who stopped at the verdict line will see it.
	text := render(t, report, Options{Mode: ModeText})
	if !strings.Contains(text, "!! the engine and the reachability analyzer disagree") {
		t.Errorf("the text rendering carries no banner:\n%s", text)
	}
	if md := render(t, report, Options{Mode: ModeMarkdown}); !strings.Contains(md, "> **Not authoritative.** the engine and the reachability analyzer disagree") {
		t.Errorf("the markdown rendering carries no banner:\n%s", md)
	}
	if js := render(t, report, Options{Mode: ModeJSON}); !strings.Contains(js, `"authoritative": false`) {
		t.Errorf("the json rendering does not report the disagreement as unsettled:\n%s", js)
	}

	// Nothing was corroborated, and the section says so rather than reprinting one
	// side's verdict as the answer.
	if !strings.Contains(report.Cleared.Note, "neither was preferred") {
		t.Errorf("the corroborated section note = %q, want it to state that neither source settled it", report.Cleared.Note)
	}
}

// Requirement 13.4: the cost and the forward-only limit are on the page in every
// rendering.
//
// Validates: Requirements 13.4
func TestVerificationStatesTheAnalyserCaveats(t *testing.T) {
	report := FromVerification(agreedVerification())

	if report.Unresolved == nil || len(report.Unresolved.Rows) != 2 {
		t.Fatalf("caveat section = %+v, want both caveats", report.Unresolved)
	}
	if report.Authoritative {
		t.Error("an agreement covering one direction rendered as authoritative for the flow")
	}
	if !strings.Contains(report.Notice, "does not cover the whole flow") {
		t.Errorf("the notice does not state the limit: %s", report.Notice)
	}

	for _, mode := range []Mode{ModeText, ModeMarkdown, ModeJSON} {
		got := render(t, report, Options{Mode: mode})
		for _, want := range []string{
			"billable",
			"charged per analysis",
			"transit gateway route table",
			"forward traffic only",
		} {
			if !strings.Contains(got, want) {
				t.Errorf("the %s rendering omits %q:\n%s", mode, want, got)
			}
		}
	}
}

// Requirement 13.5: a cross-region flow reports that no single run covers the
// path, and does not read as corroborated.
//
// Validates: Requirements 13.5
func TestVerificationReportsNoSingleRunCoversACrossRegionFlow(t *testing.T) {
	report := FromVerification(crossRegionVerification())

	if !strings.HasPrefix(report.Outcome, "NOT CORROBORATED") {
		t.Errorf("Outcome = %q, want it to state that nothing corroborated the engine", report.Outcome)
	}
	if report.Authoritative {
		t.Error("a flow no single analysis covers rendered as corroborated")
	}
	if len(report.Cleared.Rows) != 0 {
		t.Errorf("the corroborated section carries rows with only one source reporting: %+v", report.Cleared.Rows)
	}

	for _, mode := range []Mode{ModeText, ModeMarkdown, ModeJSON} {
		got := render(t, report, Options{Mode: mode})
		for _, want := range []string{
			"no single Reachability Analyzer run covers us-west-2 to us-east-1",
			"scoped to one region",
			"cross-region path",
		} {
			if !strings.Contains(got, want) {
				t.Errorf("the %s rendering omits %q:\n%s", mode, want, got)
			}
		}
	}
}

// An agreement that nothing narrows is the one outcome this report stands behind,
// and it says so without a banner.
func TestVerificationAgreementWithoutCaveatsIsAuthoritative(t *testing.T) {
	v := agreedVerification()
	v.Caveats = []Caveat{billingCaveat}

	report := FromVerification(v)
	if !report.Authoritative {
		t.Errorf("an unnarrowed agreement rendered as unreliable: %s", report.Notice)
	}
	if report.Notice != "" {
		t.Errorf("Notice = %q, want none", report.Notice)
	}
	if !strings.HasPrefix(report.Outcome, "AGREEMENT") {
		t.Errorf("Outcome = %q, want the agreement first", report.Outcome)
	}
	if !strings.Contains(report.Cleared.Note, "two independent evaluations") {
		t.Errorf("the corroborated note = %q, want it to name what corroborated the verdict", report.Cleared.Note)
	}
	if got := render(t, report, Options{Mode: ModeText}); strings.Contains(got, "!!") {
		t.Errorf("an unnarrowed agreement carries a banner:\n%s", got)
	}
}

// A cross-check that never happened renders rather than panicking, and says it
// compared nothing.
func TestFromVerificationHandlesAnEmptyCrossCheck(t *testing.T) {
	report := FromVerification(Verification{})
	if report.Kind != KindVerification {
		t.Errorf("Kind = %q, want %q", report.Kind, KindVerification)
	}
	if report.Outcome != outcomeNoVerification {
		t.Errorf("Outcome = %q, want %q", report.Outcome, outcomeNoVerification)
	}
	if _, err := renderErr(report); err != nil {
		t.Errorf("rendering an empty cross-check: %v", err)
	}
}

// A caller that supplied neither labels nor a one-clause detail still gets a
// readable report, since the projection is the only place those defaults belong.
func TestFromVerificationFillsMissingLabels(t *testing.T) {
	report := FromVerification(Verification{
		Concordance: ConcordanceDisagree,
		Engine:      Source{Verdict: "PERMITTED"},
		Analyser:    Source{Verdict: "NOT REACHABLE"},
	})
	for _, want := range []string{EngineLabel, AnalyserLabel, "PERMITTED", "NOT REACHABLE"} {
		if !strings.Contains(report.Outcome+report.Notice, want) {
			t.Errorf("the report omits %q: outcome %q, notice %q", want, report.Outcome, report.Notice)
		}
	}
}
