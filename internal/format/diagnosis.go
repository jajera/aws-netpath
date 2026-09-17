package format

// Projecting a diagnosis onto the three sections.
//
// The input is a correlated model.Verdict and the header text around it. It is
// deliberately not the diagnose operation's own result type: that type reaches
// the AWS SDK through the host prober, and a renderer has no business carrying
// that dependency. The operation supplies the projection; this package renders
// it. The seam is one struct wide, which is what keeps the other operations
// cheap to add.

import (
	"fmt"
	"strings"

	"github.com/jajera/aws-netpath/internal/model"
)

// Diagnosis is a diagnosis as the Formatter consumes it: the correlated Verdict
// plus the header an operator needs to recognise which flow it describes.
type Diagnosis struct {
	// Flow is the traffic under test, already rendered.
	Flow string
	// Source and Destination describe the resolved endpoints.
	Source      string
	Destination string
	// Symptom is the failure the operator reported, empty when none was given.
	Symptom string
	// Host names the instance probed, empty when none was.
	Host string
	// Verdict is the correlated outcome, with every Layer finding behind it.
	Verdict model.Verdict
	Notes   []string
}

// FromDiagnosis projects a diagnosis onto a Report.
func FromDiagnosis(d Diagnosis) Report {
	v := d.Verdict
	r := Report{
		Kind:          KindDiagnosis,
		Flow:          d.Flow,
		Source:        d.Source,
		Destination:   d.Destination,
		Symptom:       d.Symptom,
		Host:          d.Host,
		Authoritative: v.Authoritative,
		Notes:         dedupe(d.Notes),
	}

	results := sortResults(v.Results)
	r.Outcome, r.Finding = blockingSection(v, results)
	r.Cleared = clearedSection(results)
	r.Unresolved = abstentionSection(results, v.ConclusionAffectingAbstentions())
	r.Extra = diagnosisExtras(v)
	if !v.Authoritative {
		r.Notice = notAuthoritative(v)
	}
	return r
}

// blockingSection is section one: the blocking Layer with its Citations.
//
// Exactly one Layer leads it. Additional blockers are listed after the primary
// and named in the note, because requirement 14.1 asks for one primary blocker
// and dropping the others would hide that fixing the first will not be enough.
func blockingSection(v model.Verdict, results []model.LayerResult) (outcome string, s *Section) {
	if v.PrimaryBlocker == nil {
		return outcomeNoBlocker, &Section{
			Title: "blocking layer",
			Note:  "no layer was shown to block this flow",
		}
	}

	primary := *v.PrimaryBlocker
	s = &Section{Title: fmt.Sprintf("blocking layer — %s", primary)}
	if res, ok := v.Result(primary); ok {
		s.add(layerRows(res)...)
	}

	additional := sortLayers(v.AdditionalBlocked)
	for _, l := range additional {
		for _, res := range results {
			if res.Layer == l {
				s.add(layerRows(res)...)
			}
		}
	}
	if len(additional) > 0 {
		s.Note = fmt.Sprintf("%s also blocked this flow, later in flow order than %s",
			layerList(additional), primary)
	}
	return fmt.Sprintf(outcomeBlocked, primary), s
}

// clearedSection is section two: the Layers that passed.
func clearedSection(results []model.LayerResult) *Section {
	s := &Section{Title: "cleared layers"}
	for _, res := range results {
		if res.Verdict == model.VerdictPass {
			s.add(layerRows(res)...)
		}
	}
	if len(s.Rows) == 0 {
		s.Note = "no layer was evaluated as permitting this flow"
	}
	return s
}

// abstentionSection is section three: the Abstentions with their reasons.
//
// It is present and says so when empty. An absent section reads as a report that
// had nothing to say about unevaluated Layers, which is the confusion the whole
// Abstention machinery exists to prevent.
func abstentionSection(results, affecting []model.LayerResult) *Section {
	s := &Section{Title: "abstentions"}
	for _, res := range results {
		if res.Verdict == model.VerdictAbstain {
			s.add(layerRows(res)...)
		}
	}
	switch {
	case len(s.Rows) == 0:
		s.Note = "no layer abstained"
	case len(affecting) > 0:
		s.Note = fmt.Sprintf("%s could have changed this verdict", layerList(resultLayers(affecting)))
	default:
		s.Note = "no abstention could have changed this verdict"
	}
	return s
}

// diagnosisExtras renders the findings that carry no Layer verdict: what was
// observed, what probably explains the Symptom, and where the findings and the
// Symptom disagree.
func diagnosisExtras(v model.Verdict) []Section {
	var out []Section

	if len(v.Observations) > 0 {
		s := Section{Title: "observations"}
		for _, o := range v.Observations {
			s.add(Row{Layer: string(o.Layer), Detail: o.Summary})
			s.add(citationRows(o.Citations)...)
		}
		out = append(out, s)
	}

	if c := v.ProbableCause; c != nil {
		s := Section{
			Title: "probable cause",
			Note:  "nothing was shown to block this flow, so this is an explanation to check rather than a verdict",
		}
		s.add(Row{Layer: string(c.Layer), Detail: c.Summary})
		s.add(citationRows(c.Citations)...)
		out = append(out, s)
	}

	if len(v.Contradictions) > 0 {
		s := Section{
			Title: "contradictions",
			Note:  "the findings and the reported symptom disagree; neither was discarded to resolve it",
		}
		for _, c := range v.Contradictions {
			s.add(Row{Detail: c})
		}
		out = append(out, s)
	}
	return out
}

// notAuthoritative states why a verdict cannot be relied on. Requirement 14.6.
//
// It names the Layers and their reasons rather than saying "an abstention
// occurred", because the operator's next move is to go and evaluate whichever
// Layer could not be read, and they need to know which one that is.
func notAuthoritative(v model.Verdict) string {
	affecting := v.ConclusionAffectingAbstentions()
	if len(affecting) == 0 {
		return "this verdict is not authoritative: it rests on a layer that could not be evaluated"
	}

	parts := make([]string, 0, len(affecting))
	for _, res := range affecting {
		parts = append(parts, fmt.Sprintf("%s (%s)", res.Layer, res.Reason))
	}
	tail := "a layer that could not be evaluated may be the one blocking this flow"
	if v.PrimaryBlocker != nil {
		tail = fmt.Sprintf("a layer that could not be evaluated sits before %s in flow order and may be blocking this flow first",
			*v.PrimaryBlocker)
	}
	return fmt.Sprintf("this verdict is not authoritative: it rests on %s — %s; %s",
		abstentionCount(len(affecting)), strings.Join(parts, "; "), tail)
}

func abstentionCount(n int) string {
	if n == 1 {
		return "1 abstention"
	}
	return fmt.Sprintf("%d abstentions", n)
}

func resultLayers(in []model.LayerResult) []model.Layer {
	out := make([]model.Layer, 0, len(in))
	for _, res := range in {
		out = append(out, res.Layer)
	}
	return out
}
