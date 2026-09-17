package format

// Projecting a comparison onto the same three sections.
//
// The slots are filled with what a comparison found rather than with what a
// diagnosis found — differences, Layers that matched, comparisons that could not
// be made — and the order is the same, so a reader who learned the layout on one
// command already knows it on the other.
//
// The matched Layers are named and nothing more. Requirement 10.1 asks for the
// differences, and a comparison that reprints both paths in full hands the reader
// the same haystack twice.

import (
	"fmt"

	"github.com/jajera/aws-netpath/internal/compare"
	"github.com/jajera/aws-netpath/internal/model"
)

// FromComparison projects a comparison onto a Report.
func FromComparison(c *compare.Result) Report {
	if c == nil {
		return Report{Kind: KindComparison, Outcome: outcomeNoDiff}
	}

	r := Report{
		Kind:          KindComparison,
		Subjects:      []string{pathSubject(c.Subject), pathSubject(c.Reference)},
		SubjectLabel:  "path",
		Authoritative: c.Authoritative,
		Notes:         dedupe(c.Notes),
	}
	r.Outcome, r.Finding = differenceSection(c)
	r.Cleared = matchedSection(c)
	r.Unresolved = incompleteSection(c)
	r.Extra = comparisonExtras(c)
	if !c.Authoritative {
		r.Notice = notComparable(c)
	}
	return r
}

// pathSubject identifies one path and what it did, which is what makes a
// difference below attributable to a side.
func pathSubject(p compare.PathSummary) string {
	outcome := "permitted"
	if p.PrimaryBlocker != nil {
		outcome = fmt.Sprintf("blocked at %s", *p.PrimaryBlocker)
	}
	s := fmt.Sprintf("%s path %s -> %s: %s", p.Label, p.From, p.To, outcome)
	if p.Symptom != "" {
		s += fmt.Sprintf(", symptom %s", p.Symptom)
	}
	return s
}

// differenceSection is section one: what the two paths do not share.
func differenceSection(c *compare.Result) (outcome string, s *Section) {
	s = &Section{Title: "differences"}
	for _, d := range c.Differences {
		s.add(Row{Layer: string(d.Layer), Verdict: labelDiffers, Detail: d.Summary})
		s.add(onlyRows(c.Subject.Label, d.Subject.Only)...)
		s.add(onlyRows(c.Reference.Label, d.Reference.Only)...)
	}

	switch {
	case len(c.Differences) > 0:
		outcome = fmt.Sprintf(outcomeDiffers, layerList(diffLayers(c.Differences)))
	case len(c.Matched) > 0:
		outcome = outcomeIdentical
	default:
		outcome = outcomeNoDiff
	}

	if len(s.Rows) == 0 {
		s.Note = fmt.Sprintf("the %s and %s paths are identical at every layer compared",
			c.Subject.Label, c.Reference.Label)
	}
	if c.Behaviour != "" {
		s.Note = joinNote(s.Note, c.Behaviour)
	}
	return outcome, s
}

// matchedSection is section two: the Layers both paths met identically, named
// only.
func matchedSection(c *compare.Result) *Section {
	s := &Section{Title: "matched layers"}
	for _, l := range sortLayers(c.Matched) {
		s.add(Row{Layer: string(l), Verdict: labelMatch})
	}
	if len(s.Rows) == 0 {
		s.Note = "no layer was found identical on both paths"
		return s
	}
	s.Note = "entries omitted: a comparison reports differences only"
	return s
}

// incompleteSection is section three: the comparisons that could not be made.
// Requirement 10.4 — never silently equal, never a difference.
func incompleteSection(c *compare.Result) *Section {
	s := &Section{Title: "incomplete comparisons"}
	for _, d := range c.Incomplete {
		s.add(Row{Layer: string(d.Layer), Verdict: labelIncomplete, Detail: d.Summary})
	}
	if len(s.Rows) == 0 {
		s.Note = "every layer either path reported was compared"
	}
	return s
}

// comparisonExtras renders the Layers left as an explanation once the compared
// Layers are accounted for. Requirement 10.3.
func comparisonExtras(c *compare.Result) []Section {
	if c.Direction == nil {
		return nil
	}
	s := Section{
		Title: "remaining explanation",
		Note:  "nothing here was shown to block the traffic; these are the layers the comparison does not rule out",
	}
	s.add(Row{Layer: layerList(c.Direction.Layers), Detail: c.Direction.Summary})
	s.add(citationRows(c.Direction.Citations)...)
	return []Section{s}
}

// notComparable states why a comparison cannot be relied on. Requirement 14.6
// applied to a diff: a Layer read on one path and not the other leaves a
// difference that might be the whole cause unaccounted for.
func notComparable(c *compare.Result) string {
	if len(c.Incomplete) > 0 {
		return fmt.Sprintf("this comparison is not authoritative: %s could not be compared, so a difference there is neither ruled in nor ruled out",
			layerList(diffLayers(c.Incomplete)))
	}
	for _, p := range []compare.PathSummary{c.Subject, c.Reference} {
		if !p.Authoritative {
			return fmt.Sprintf("this comparison is not authoritative: the %s path's own verdict rests on a layer that could not be evaluated",
				p.Label)
		}
	}
	return "this comparison is not authoritative: it rests on a layer that could not be evaluated"
}

// onlyRows renders the entries one path met and the other did not, labelled with
// the path they were found on. Cross-cutting 2 applied to a diff: "the security
// groups differ" is not something an operator can act on.
func onlyRows(label string, cs []model.Citation) []Row {
	out := citationRows(cs)
	for i := range out {
		out[i].Subject = fmt.Sprintf("%s only: %s", label, out[i].Subject)
	}
	return out
}

func diffLayers(in []compare.LayerDiff) []model.Layer {
	out := make([]model.Layer, 0, len(in))
	for _, d := range in {
		out = append(out, d.Layer)
	}
	return sortLayers(out)
}

func joinNote(existing, add string) string {
	if existing == "" {
		return add
	}
	return existing + "; " + add
}
