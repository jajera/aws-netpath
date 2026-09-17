package ops

// The seam between an operation and the Formatter.
//
// The projection lives here rather than in internal/format because the direction
// of the dependency matters. This package reaches the AWS SDK through the host
// prober and the collectors; the Formatter renders and nothing else, and pulling
// an SDK into its build graph would make that claim unverifiable. So an operation
// hands the Formatter a view of its result, and the Formatter never learns what
// produced it — which is also what keeps the remaining operations cheap to add.

import (
	"fmt"

	"github.com/jajera/aws-netpath/internal/format"
	"github.com/jajera/aws-netpath/internal/model"
	"github.com/jajera/aws-netpath/internal/query"
	"github.com/jajera/aws-netpath/internal/verify"
)

// Report projects a collection run onto the Formatter's input.
//
// The Snapshot is left behind. It is a large document the other operations read
// from disk, and the one thing a caller has to carry forward from a collection is
// whether it is complete.
func (r *CollectResult) Report() format.Report {
	if r == nil {
		return format.FromCollection(format.Collection{})
	}
	return format.FromCollection(format.Collection{
		OutputPath: r.OutputPath,
		Targets:    r.Targets,
		Errors:     r.Errors,
		Complete:   !r.Partial(),
		Counts:     r.Counts(),
	})
}

// QueryReport projects a reachability walk onto the Formatter's input.
//
// A function rather than a method, because Query returns the engine's own result:
// a walk has one shape whoever asked for it, and a wrapper type here would carry
// nothing but the method.
func QueryReport(r *query.Result) format.Report {
	return format.FromQuery(r)
}

// Report projects a firewall policy evaluation onto the Formatter's input.
//
// Blocked and Authoritative are passed in rather than left for the Formatter to
// work out. They are judgements about the evaluation, this result is where they
// are already made, and a renderer deriving them again would be a second answer
// to a question that has one.
func (r *FirewallResult) Report() format.Report {
	if r == nil {
		return format.FromFirewall(format.FirewallEvaluation{})
	}
	return format.FromFirewall(format.FirewallEvaluation{
		Flow:          r.Flow.String(),
		Results:       r.Results,
		Blocked:       r.Blocked(),
		Authoritative: r.Authoritative(),
	})
}

// Report projects the diagnosis onto the Formatter's input.
func (r *DiagnoseResult) Report() format.Report {
	if r == nil {
		return format.Report{Kind: format.KindDiagnosis}
	}
	return format.FromDiagnosis(format.Diagnosis{
		Flow:        r.Flow.String(),
		Source:      r.Source.Description(),
		Destination: r.Destination.Description(),
		Symptom:     string(r.Classification.Symptom),
		Host:        r.Host.describe(),
		Verdict:     r.Verdict,
		Notes:       r.Notes,
	})
}

// Report projects the comparison onto the Formatter's input.
//
// The diff is what it leads with. Both diagnoses are on the result for a reader
// who wants a difference in context, and requirement 10.1 asks for the
// differences rather than for both paths in full.
func (r *CompareResult) Report() format.Report {
	if r == nil {
		return format.Report{Kind: format.KindComparison}
	}
	return format.FromComparison(r.Diff)
}

// Report projects the snapshot diff onto the Formatter's input.
//
// There is no header to assemble: a diff describes the two collections it
// compared rather than a flow through a network, and the Formatter builds that
// from the summaries the diff already carries.
func (r *DiffSnapshotResult) Report() format.Report {
	if r == nil {
		return format.Report{Kind: format.KindSnapshotDiff}
	}
	return format.FromSnapshotDiff(r.Diff)
}

// describe names the instance probed and whether it was reached, so a host Layer
// abstention has the instance beside it in the header rather than only in a note.
func (s HostStage) describe() string {
	if s.InstanceID == "" {
		return ""
	}
	if s.Probed {
		return fmt.Sprintf("%s (probed)", s.InstanceID)
	}
	return fmt.Sprintf("%s (not probed)", s.InstanceID)
}

// Report projects the declared flow run onto the Formatter's input.
//
// The failures lead. Requirement 12.2 asks a mismatch to report the Flow, both
// verdicts, and the deciding Citation, and the flows that met their declaration
// are named rather than detailed: a gate over fifty flows with two failures should
// read as two findings.
func (r *TestFlowsResult) Report() format.Report {
	if r == nil {
		return format.Report{Kind: format.KindFlowTest}
	}
	return format.FromFlowTest(r.Result)
}

// VerifyReport projects a cross-check onto the Formatter's input.
//
// A function rather than a method, because Verify returns the Verifier's own
// result: a cross-check has one shape whoever asked for it, and a wrapper type
// here would carry nothing but the method.
//
// The two sources are assembled symmetrically and deliberately. Requirement 13.3
// forbids preferring either when they disagree, and this is where a preference
// would slip in unnoticed — the engine has a rich result to draw on and the
// analyser has a status field, so the easy projection gives one a verdict with
// evidence and the other a footnote. Both get a verdict, a summary, and a
// citation, or the report has already decided which one to believe.
func VerifyReport(r *verify.Result) format.Report {
	if r == nil {
		return format.Report{Kind: format.KindVerification}
	}
	return format.FromVerification(format.Verification{
		Flow:        r.Flow.String(),
		Engine:      engineSource(r),
		Analyser:    analyserSource(r),
		Concordance: concordance(r.Agreement),
		Detail:      r.Detail,
		Caveats:     verificationCaveats(r.Caveats),
		Notes:       r.Notes,
	})
}

// Verdict labels for the analyser. It answers whether a path was found, which is
// not the same question the engine answers, so it keeps its own words.
const (
	labelReachable    = "REACHABLE"
	labelNotReachable = "NOT REACHABLE"
	labelNoResult     = "NO RESULT"
)

// engineSource renders what the offline walk concluded and the evidence for it:
// the hop that blocked, or the path that did not.
//
// Firewall decisions are cited alongside, whatever the verdict. Requirement 14.4
// wants the rule behind every firewall decision, and a cross-check whose two
// sources disagree is precisely when an operator needs to know which rule the
// engine read.
func engineSource(r *verify.Result) format.Source {
	s := format.Source{Label: format.EngineLabel, Verdict: labelNoResult}
	if r.Model == nil {
		s.Summary = "the offline query produced no result"
		s.Citations = []model.Citation{{
			Kind: "engine", Identifier: "offline query", Detail: s.Summary,
		}}
		return s
	}

	s.Verdict = string(r.Model.Verdict)
	path := r.Model.Path()
	if hop := r.Model.BlockedAt; hop != nil {
		s.Summary = fmt.Sprintf("stopped at %s after %s", hopName(*hop), hopCount(len(path)))
		s.Citations = append(s.Citations, model.Citation{
			Kind: "engine", Identifier: hopName(*hop), Detail: hop.Detail,
		})
	} else {
		s.Summary = fmt.Sprintf("%s evaluated, none blocked", hopCount(len(path)))
		s.Citations = append(s.Citations, model.Citation{
			Kind: "engine", Identifier: "offline path walk", Detail: s.Summary,
		})
	}

	for _, h := range path {
		if h.Layer == string(model.LayerFirewall) && h.Resource != "" {
			s.Citations = append(s.Citations, model.Citation{
				Kind: "nfw_rule", Identifier: h.Resource, Detail: h.Detail,
			})
		}
	}
	return s
}

// analyserSource renders what Reachability Analyzer concluded, or that it reached
// no conclusion and why.
//
// A skipped analysis is cited rather than left blank. Cross-cutting 2 wants
// evidence behind every finding, and "no analysis ran, because the path crosses a
// region boundary" is a finding an operator acts on.
func analyserSource(r *verify.Result) format.Source {
	s := format.Source{Label: format.AnalyserLabel, Verdict: labelNoResult}

	a := r.AWS
	if a == nil {
		s.Summary = "no analysis was attempted"
		s.Citations = []model.Citation{{
			Kind: analyserCitation, Identifier: "no analysis", Detail: s.Summary,
		}}
		return s
	}

	if a.Reachable == nil {
		s.Summary = analyserSkipSummary(a)
		s.Citations = []model.Citation{{
			Kind: analyserCitation, Identifier: "no analysis", Detail: s.Summary,
		}}
		return s
	}

	s.Verdict = labelNotReachable
	if *a.Reachable {
		s.Verdict = labelReachable
	}
	s.Summary = analyserRunSummary(a)
	identifier := a.AnalysisID
	if identifier == "" {
		identifier = "reachability analyzer"
	}
	s.Citations = []model.Citation{{
		Kind: analyserCitation, Identifier: identifier, Detail: s.Summary,
	}}
	return s
}

// analyserCitation is the Citation kind for analyser evidence.
const analyserCitation = "reachability_analyzer"

func analyserSkipSummary(a *verify.AWSOutcome) string {
	switch {
	case a.SkipReason != "":
		return a.SkipReason
	case a.StatusMessage != "":
		return a.StatusMessage
	default:
		return "the analysis returned no result"
	}
}

func analyserRunSummary(a *verify.AWSOutcome) string {
	out := "analysis"
	if a.Region != "" {
		out += " in " + a.Region
	}
	if a.SourceResource != "" && a.DestinationResource != "" {
		out += fmt.Sprintf(" from %s to %s", a.SourceResource, a.DestinationResource)
	}
	if a.WarningMessage != "" {
		out += fmt.Sprintf(" (warning: %s)", a.WarningMessage)
	}
	return out
}

// hopName identifies a hop the way an operator would look it up: the layer that
// decided, and the resource that decided it.
func hopName(h query.Hop) string {
	if h.Resource == "" {
		return h.Layer
	}
	return fmt.Sprintf("%s %s", h.Layer, h.Resource)
}

func hopCount(n int) string {
	if n == 1 {
		return "1 hop"
	}
	return fmt.Sprintf("%d hops", n)
}

func concordance(a verify.Agreement) format.Concordance {
	switch a {
	case verify.AgreementMatch:
		return format.ConcordanceAgree
	case verify.AgreementMismatch:
		return format.ConcordanceDisagree
	default:
		return format.ConcordanceUnestablished
	}
}

func verificationCaveats(in []verify.Caveat) []format.Caveat {
	out := make([]format.Caveat, 0, len(in))
	for _, c := range in {
		out = append(out, format.Caveat{Subject: c.Subject, Summary: c.Summary, Coverage: c.Coverage})
	}
	return out
}
