package format

// Projecting a cross-check onto the same three sections.
//
// The slots hold what a verification found — how the two answers compare, what
// they corroborate, and what the cross-check does not cover — in the order every
// other report uses. A reader who learned the layout on a diagnosis meets the
// answer, then what has been established, then what has not.
//
// The two sources are symmetric on purpose. Requirement 13.3 forbids silently
// preferring either when they disagree, and a renderer is where that would
// quietly happen: an engine verdict presented as the finding with the analyser
// relegated to a footnote prefers one source without ever saying so. So one type
// describes both answers, both are rendered by the same rows in the same section,
// and a disagreement is an outcome of its own rather than one source correcting
// the other. Nothing here resolves it.
//
// A disagreement is also prominent rather than merely present. It leads the
// outcome line and it carries the banner the Formatter already uses for a finding
// that cannot be relied on, so a reader who stops after two lines has still been
// told that the two sources do not agree.

import (
	"fmt"

	"github.com/jajera/aws-netpath/internal/model"
)

// KindVerification names a cross-check in the JSON output.
const KindVerification Kind = "verification"

// Default labels for the two sources. They are neutral by design: "model" and
// "actual", or "expected" and "found", would settle by wording the question
// requirement 13.3 says to leave open.
const (
	EngineLabel   = "engine"
	AnalyserLabel = "reachability analyzer"
)

// Row-level labels for a verification. A caveat is neither a pass nor a failure,
// so it gets its own.
const (
	labelAgree    = "AGREE"
	labelDisagree = "DISAGREE"
	labelCaveat   = "CAVEAT"
)

// Outcome strings for a verification.
const (
	outcomeAgree          = "AGREEMENT: %s"
	outcomeDisagree       = "DISAGREEMENT: %s"
	outcomeUnestablished  = "NOT CORROBORATED: %s"
	outcomeNoVerification = "NO VERIFICATION"
)

// Concordance is whether the two sources reached the same conclusion.
//
// Three values, not a boolean. A comparison that never ran and a comparison whose
// sources disagree are different findings with different next actions, and a
// boolean would flatten the first into the second.
type Concordance string

const (
	ConcordanceAgree         Concordance = "agree"
	ConcordanceDisagree      Concordance = "disagree"
	ConcordanceUnestablished Concordance = "unestablished"
)

// Source is one of the two independent answers a verification compares.
//
// Both sources are the same type carrying the same fields, which is the structural
// half of requirement 13.3: a projection that gave the engine a verdict and the
// analyser a note would have decided which one matters before any renderer ran.
type Source struct {
	// Label names the source for a reader: the engine, or the provider's analyser.
	Label string
	// Verdict is what this source concluded, already rendered in its own
	// vocabulary — the engine permits or blocks, the analyser finds a path or does
	// not — because translating both into one vocabulary would imply they answer
	// exactly the same question.
	Verdict string
	// Summary is what the source did to reach that verdict.
	Summary string
	// Citations are the evidence: the deciding hop for the engine, the analysis
	// for the analyser. Cross-cutting 2 applies to both, and requirement 13.2 asks
	// for both to be cited when they agree.
	Citations []model.Citation
}

// Caveat is something that bounds what a verification established.
type Caveat struct {
	Subject string
	Summary string
	// Coverage marks a Caveat that narrows what was established, as distinct from
	// one a reader needs before running the check again.
	Coverage bool
}

// Verification is a cross-check as the Formatter consumes it.
//
// It is not the Verifier's own result type: that type reaches the AWS SDK, and a
// renderer has no business carrying that dependency — the same seam the diagnosis
// projection uses, for the same reason.
type Verification struct {
	// Flow is the traffic under test, already rendered.
	Flow string
	// Engine and Analyser are the two answers. Field order is reading order and
	// nothing more; neither is the reference.
	Engine   Source
	Analyser Source
	// Concordance is how the two answers compare. The zero value means no
	// comparison was made.
	Concordance Concordance
	// Detail is the comparison in one clause, as the Verifier phrased it.
	Detail  string
	Caveats []Caveat
	Notes   []string
}

// FromVerification projects a cross-check onto a Report.
func FromVerification(v Verification) Report {
	if v.Concordance == "" {
		return Report{Kind: KindVerification, Outcome: outcomeNoVerification}
	}
	v = v.withDefaults()

	r := Report{
		Kind:         KindVerification,
		Flow:         v.Flow,
		Subjects:     []string{sourceSubject(v.Engine), sourceSubject(v.Analyser)},
		SubjectLabel: "source",
		Notes:        dedupe(v.Notes),
	}
	r.Outcome, r.Finding = concordanceSection(v)
	r.Cleared = corroboratedSection(v)
	r.Unresolved = verificationCaveatSection(v)

	// Agreement over the whole flow is the only outcome this report can stand
	// behind. A disagreement establishes nothing, an absent analysis corroborates
	// nothing, and an agreement a caveat narrows is an agreement about less than
	// was asked.
	r.Authoritative = v.Concordance == ConcordanceAgree && len(coverageSubjects(v)) == 0
	if !r.Authoritative {
		r.Notice = notCorroborated(v)
	}
	return r
}

// withDefaults fills the labels and the one-clause detail a caller left empty, so
// a partial projection renders as a report rather than as blanks.
func (v Verification) withDefaults() Verification {
	if v.Engine.Label == "" {
		v.Engine.Label = EngineLabel
	}
	if v.Analyser.Label == "" {
		v.Analyser.Label = AnalyserLabel
	}
	if v.Detail != "" {
		return v
	}
	switch v.Concordance {
	case ConcordanceAgree:
		v.Detail = fmt.Sprintf("both sources report %s", v.Engine.Verdict)
	case ConcordanceDisagree:
		v.Detail = fmt.Sprintf("%s reports %s, %s reports %s",
			v.Engine.Label, v.Engine.Verdict, v.Analyser.Label, v.Analyser.Verdict)
	default:
		v.Detail = fmt.Sprintf("the %s produced no verdict to compare", v.Analyser.Label)
	}
	return v
}

// sourceSubject identifies one source and what it concluded, so the header names
// both answers before the sections compare them.
func sourceSubject(s Source) string {
	out := fmt.Sprintf("%s: %s", s.Label, s.Verdict)
	if s.Summary != "" {
		out += fmt.Sprintf(" (%s)", s.Summary)
	}
	return out
}

// concordanceSection is section one: both verdicts, side by side, each with its
// own evidence. Requirements 13.2 and 13.3.
func concordanceSection(v Verification) (outcome string, s *Section) {
	s = &Section{Title: "verdicts compared"}
	for _, src := range []Source{v.Engine, v.Analyser} {
		s.add(Row{Layer: src.Label, Verdict: src.Verdict, Detail: src.Summary})
		s.add(citationRows(src.Citations)...)
	}

	switch v.Concordance {
	case ConcordanceAgree:
		s.Note = fmt.Sprintf("the %s and the %s agree, and both are cited above",
			v.Engine.Label, v.Analyser.Label)
		return fmt.Sprintf(outcomeAgree, v.Detail), s
	case ConcordanceDisagree:
		s.Note = fmt.Sprintf("the %s and the %s disagree; both verdicts stand as reported, neither is taken as correct, and this section resolves nothing",
			v.Engine.Label, v.Analyser.Label)
		return fmt.Sprintf(outcomeDisagree, v.Detail), s
	default:
		s.Note = fmt.Sprintf("only the %s reached a verdict, so there is nothing to compare it against",
			v.Engine.Label)
		return fmt.Sprintf(outcomeUnestablished, v.Detail), s
	}
}

// corroboratedSection is section two: what the cross-check established.
//
// It is the verification's equivalent of the Layers a diagnosis cleared, and it is
// present and says so when empty — an absent section reads as a report with
// nothing to say about corroboration, which is the confusion this whole command
// exists to remove.
func corroboratedSection(v Verification) *Section {
	s := &Section{Title: "corroborated"}
	switch v.Concordance {
	case ConcordanceAgree:
		s.add(Row{Layer: "verdict", Verdict: labelAgree, Detail: v.Detail})
		s.Note = fmt.Sprintf("two independent evaluations reached this conclusion: the %s over the snapshot, and the %s against the live account",
			v.Engine.Label, v.Analyser.Label)
	case ConcordanceDisagree:
		s.add(Row{Layer: "verdict", Verdict: labelDisagree, Detail: v.Detail})
		s.Note = "nothing was corroborated: the two sources reached different conclusions and neither was preferred to settle it"
	default:
		s.Note = "nothing was corroborated: only one source reached a verdict"
	}
	return s
}

// verificationCaveatSection is section three: what this cross-check does not
// cover. Requirements 13.4 and 13.5 land here.
func verificationCaveatSection(v Verification) *Section {
	s := &Section{Title: "caveats"}
	for _, c := range v.Caveats {
		s.add(Row{Layer: c.Subject, Verdict: labelCaveat, Detail: c.Summary})
	}

	coverage := coverageSubjects(v)
	switch {
	case len(s.Rows) == 0:
		s.Note = "no caveat applies to this verification"
	case len(coverage) == 0:
		s.Note = "these are properties of the analyser rather than findings about the network, and none of them narrows what this comparison established"
	default:
		s.Note = fmt.Sprintf("what this comparison established is narrowed by %s", joinList(coverage))
	}
	return s
}

// notCorroborated states why the outcome cannot be relied on, in the banner
// requirement 14.6 already put at the top of every report.
//
// The disagreement wording is the load-bearing part of requirement 13.3. It names
// both sources and both verdicts, and it says outright that neither is preferred,
// because a reader who has been trained by every other tool to treat the provider
// as ground truth will otherwise supply that preference themselves.
func notCorroborated(v Verification) string {
	switch v.Concordance {
	case ConcordanceDisagree:
		return fmt.Sprintf("the %s and the %s disagree: %s reports %s, %s reports %s — neither is preferred and neither is treated as correct, so the disagreement is reported rather than resolved, and one of the two is wrong about this flow",
			v.Engine.Label, v.Analyser.Label,
			v.Engine.Label, v.Engine.Verdict,
			v.Analyser.Label, v.Analyser.Verdict)
	case ConcordanceUnestablished:
		return fmt.Sprintf("this verdict is not corroborated: %s", v.Detail)
	default:
		return fmt.Sprintf("this agreement does not cover the whole flow — %s; the caveats below state what it leaves out",
			joinList(coverageSubjects(v)))
	}
}

// coverageSubjects names the Caveats that narrow what was established, leaving out
// the ones that only tell a reader what a rerun would cost.
func coverageSubjects(v Verification) []string {
	var out []string
	for _, c := range v.Caveats {
		if c.Coverage {
			out = append(out, c.Subject)
		}
	}
	return out
}
