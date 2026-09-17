// Package compare diffs a failing path against a reference path that works.
//
// The premise is the one an operator already uses by hand: two hosts, the same
// destination, one connects and one does not. Whatever the two paths share
// cannot be the cause, so the difference between them is the answer. This
// package does that subtraction, and requirement 10.1 is emphatic about the
// output — only the differences. A comparison that echoes both full paths hands
// the reader the same haystack twice.
//
// Nothing is evaluated here. Both paths come in already walked, correlated, and
// probed by the diagnose pipeline, so the two sides are compared on findings
// produced by one implementation rather than by two that could drift. That keeps
// this package pure logic: no Snapshot, no AWS call, no host command.
//
// Three rules shape the output.
//
// Differences carry both sides. An entry present on one path and absent on the
// other is cited where it was found and named as missing where it was not, which
// is cross-cutting 2 applied to a diff: "the security groups differ" is not a
// finding an operator can act on.
//
// An Abstention on one side makes that Layer's comparison incomplete. Never
// silently equal, never a difference — requirement 10.4 — because a Layer that
// could not be read on one path might be identical or might be the whole cause,
// and both readings are guesses. A Layer one walk never reached is reported the
// same way for the same reason.
//
// Identical cloud Layers point at the host. When the two paths meet the same
// route entries, the same NACL entries, the same security group rules and the
// same firewall rules, and they still behave differently, the cloud
// configuration cannot be what separates them. Requirement 10.3 names the host
// Layers as the remaining explanation, which is exactly the conclusion the
// motivating incident took two days to reach.
package compare

import (
	"fmt"
	"strings"

	"github.com/jajera/aws-netpath/internal/model"
	"github.com/jajera/aws-netpath/internal/symptom"
)

// Default labels for the two paths. The subject is the path under
// investigation; the reference is the one believed to work.
const (
	SubjectLabel   = "failing"
	ReferenceLabel = "reference"
)

// citationKindComparison is the evidence category for a finding the comparison
// itself produced, as opposed to one either walk produced.
const citationKindComparison = "comparison"

// Status is the outcome of comparing one Layer across the two paths.
type Status string

const (
	// StatusEqual is a Layer both paths were evaluated at, reaching the same
	// verdict on the same entries. It is named in the result and its contents
	// are dropped: shared configuration is not a difference.
	StatusEqual Status = "equal"
	// StatusDiffers is a Layer where the verdicts differ, the entries differ, or
	// both.
	StatusDiffers Status = "differs"
	// StatusIncomplete is a Layer that could not be compared: it abstained on
	// one side, or one walk never reached it. Requirement 10.4.
	StatusIncomplete Status = "incomplete"
)

// Side is one path in the comparison, as the diagnose pipeline evaluated it.
//
// It carries a correlated model.Verdict rather than a raw walk because
// correlation has already collapsed several findings per Layer into one result
// per Layer, in flow order, with every Citation kept. Comparing before that
// would mean re-implementing the aggregation, and the two implementations could
// then disagree about what a Layer concluded.
type Side struct {
	// Label names the path in the output, defaulting to SubjectLabel or
	// ReferenceLabel.
	Label string `json:"label"`
	// From and To are the endpoints as the operator named them.
	From string `json:"from"`
	To   string `json:"to"`
	// Symptom is the failure the operator observed on this path, or
	// symptom.None. It is one of the two ways a behaviour difference is
	// established, and the only way when both paths evaluate the same.
	Symptom symptom.Symptom `json:"symptom,omitempty"`
	// Verdict is the correlated outcome for this path.
	Verdict model.Verdict `json:"verdict"`
}

func (s Side) withDefault(label string) Side {
	if strings.TrimSpace(s.Label) == "" {
		s.Label = label
	}
	return s
}

func (s Side) validate() error {
	if len(s.Verdict.Results) == 0 {
		return fmt.Errorf("compare: the %s path has no layer findings to compare", s.Label)
	}
	for _, r := range s.Verdict.Results {
		if err := r.Validate(); err != nil {
			return fmt.Errorf("compare: %s path: %w", s.Label, err)
		}
	}
	return nil
}

func (s Side) summary() PathSummary {
	return PathSummary{
		Label: s.Label, From: s.From, To: s.To, Symptom: s.Symptom,
		PrimaryBlocker: s.Verdict.PrimaryBlocker,
		Authoritative:  s.Verdict.Authoritative,
	}
}

// PathSummary identifies one path in the result without repeating its findings.
type PathSummary struct {
	Label   string          `json:"label"`
	From    string          `json:"from"`
	To      string          `json:"to"`
	Symptom symptom.Symptom `json:"symptom,omitempty"`
	// PrimaryBlocker is the Layer that blocked this path, nil when none did.
	PrimaryBlocker *model.Layer `json:"primary_blocker,omitempty"`
	Authoritative  bool         `json:"authoritative"`
}

func (p PathSummary) blocker() (model.Layer, bool) {
	if p.PrimaryBlocker == nil {
		return "", false
	}
	return *p.PrimaryBlocker, true
}

// SideFinding is one path's half of a Layer comparison.
type SideFinding struct {
	// Reached is false when this path's walk never got to the Layer, which is
	// what a forward block earlier in flow order does. It is not an Abstention
	// and not a pass.
	Reached bool               `json:"reached"`
	Verdict model.LayerVerdict `json:"verdict,omitempty"`
	// Reason is the Abstention reason, when this side abstained.
	Reason string `json:"reason,omitempty"`
	// Only are the entries this path met and the other did not. They are the
	// substance of a difference: the route, the NACL entry, the security group
	// rule, the firewall rule match, or the host firewall allowlist entry.
	Only []model.Citation `json:"only,omitempty"`
}

// LayerDiff is the comparison of one Layer across the two paths.
type LayerDiff struct {
	Layer  model.Layer `json:"layer"`
	Status Status      `json:"status"`
	// Summary leads with the answer: what differs, or why the comparison could
	// not be made.
	Summary   string      `json:"summary"`
	Subject   SideFinding `json:"subject"`
	Reference SideFinding `json:"reference"`
}

// Direction names the Layers that remain as an explanation once the compared
// Layers have been accounted for. Requirement 10.3.
//
// It is not a verdict and never becomes one. Nothing here was shown to block the
// traffic; what was shown is that the cloud configuration the two paths meet is
// the same, so the cloud configuration cannot be what distinguishes them.
type Direction struct {
	Layers  []model.Layer `json:"layers"`
	Summary string        `json:"summary"`
	// Citations are the evidence: the cloud Layers found identical, and whatever
	// the named Layers reported on each path.
	Citations []model.Citation `json:"citations,omitempty"`
}

// Result is the comparison, differences first.
type Result struct {
	Subject   PathSummary `json:"subject"`
	Reference PathSummary `json:"reference"`
	// Differences are the Layers the two paths do not share. This is the answer
	// the operator came for.
	Differences []LayerDiff `json:"differences,omitempty"`
	// Incomplete are the Layers that could not be compared, each with the
	// reason. Listed separately from the differences on the same grounds the
	// Formatter separates Abstentions from blockers.
	Incomplete []LayerDiff `json:"incomplete,omitempty"`
	// Matched names the Layers both paths met identically. Named only — their
	// contents are what "differences only" excludes.
	Matched []model.Layer `json:"matched,omitempty"`
	// BehaviourDiffers is true when the two paths were shown to behave
	// differently, either because the engine reached different verdicts or
	// because the operator reported a Symptom on the failing path that its
	// verdict does not account for.
	BehaviourDiffers bool `json:"behaviour_differs"`
	// Behaviour states how that was established, empty when it was not.
	Behaviour string     `json:"behaviour,omitempty"`
	Direction *Direction `json:"direction,omitempty"`
	// Authoritative is false when any Layer's comparison is incomplete, or when
	// either path's own verdict was not authoritative.
	Authoritative bool     `json:"authoritative"`
	Notes         []string `json:"notes,omitempty"`
}

// Differs reports whether the two paths were found to differ anywhere.
func (r *Result) Differs() bool { return len(r.Differences) > 0 }

// Difference returns the comparison recorded for one Layer, whatever its status.
func (r *Result) Difference(l model.Layer) (LayerDiff, bool) {
	for _, group := range [][]LayerDiff{r.Differences, r.Incomplete} {
		for _, d := range group {
			if d.Layer == l {
				return d, true
			}
		}
	}
	return LayerDiff{}, false
}

// Paths diffs the subject path against the reference path.
//
// Both sides must carry findings: comparing a path against nothing produces a
// list of one-sided entries that reads like a diagnosis and is not one.
func Paths(subject, reference Side) (*Result, error) {
	subject = subject.withDefault(SubjectLabel)
	reference = reference.withDefault(ReferenceLabel)
	if err := subject.validate(); err != nil {
		return nil, err
	}
	if err := reference.validate(); err != nil {
		return nil, err
	}

	res := &Result{Subject: subject.summary(), Reference: reference.summary()}
	res.BehaviourDiffers, res.Behaviour = behaviour(res.Subject, res.Reference)

	for _, layer := range model.FlowOrder() {
		diff, compared := compareLayer(layer, subject, reference)
		if !compared {
			continue
		}
		switch diff.Status {
		case StatusEqual:
			res.Matched = append(res.Matched, layer)
		case StatusIncomplete:
			res.Incomplete = append(res.Incomplete, diff)
		default:
			res.Differences = append(res.Differences, diff)
		}
	}

	res.Direction = res.direction(subject, reference)
	res.Notes = res.notes()
	res.Authoritative = len(res.Incomplete) == 0 &&
		subject.Verdict.Authoritative && reference.Verdict.Authoritative
	return res, nil
}

// compareLayer compares one Layer across the two paths. compared is false for a
// Layer neither path reported, which is a Layer with nothing to say rather than
// one that matched.
func compareLayer(layer model.Layer, subject, reference Side) (diff LayerDiff, compared bool) {
	sub, subOK := subject.Verdict.Result(layer)
	ref, refOK := reference.Verdict.Result(layer)
	if !subOK && !refOK {
		return LayerDiff{}, false
	}

	diff = LayerDiff{
		Layer:     layer,
		Subject:   SideFinding{Reached: subOK, Verdict: sub.Verdict, Reason: sub.Reason},
		Reference: SideFinding{Reached: refOK, Verdict: ref.Verdict, Reason: ref.Reason},
	}

	// Requirement 10.4 and its close relative. A Layer evaluated for one path
	// and not the other cannot be called equal and cannot be called different,
	// so it is called incomplete and says which side is missing what.
	if !subOK || !refOK {
		diff.Status = StatusIncomplete
		diff.Summary = fmt.Sprintf("%s was evaluated for the %s path and not reached on the %s path, so the two cannot be compared here",
			layer, presentLabel(subject, reference, subOK), absentLabel(subject, reference, subOK))
		return diff, true
	}
	if sub.Verdict == model.VerdictAbstain || ref.Verdict == model.VerdictAbstain {
		diff.Status = StatusIncomplete
		diff.Summary = abstainSummary(layer, subject, reference, sub, ref)
		return diff, true
	}

	if entryDiffed(layer) {
		diff.Subject.Only = onlyIn(sub.Citations, ref.Citations)
		diff.Reference.Only = onlyIn(ref.Citations, sub.Citations)
	}

	verdictDiffers := sub.Verdict != ref.Verdict
	entriesDiffer := len(diff.Subject.Only) > 0 || len(diff.Reference.Only) > 0
	if !verdictDiffers && !entriesDiffer {
		diff.Status = StatusEqual
		diff.Summary = fmt.Sprintf("both paths %s at %s on the same entries", verdictVerb(sub.Verdict), layer)
		return diff, true
	}

	diff.Status = StatusDiffers
	diff.Summary = differsSummary(layer, subject, reference, sub, ref, verdictDiffers, diff)
	return diff, true
}

// entryDiffed reports whether a Layer's Citations are compared entry by entry.
//
// Requirement 10.2 names what has to be diffed: route entries, NACL entries,
// security group rules, firewall rule matches, and host firewall allowlists. The
// return direction is included because its evidence is route and NACL entries
// too, and the listener because a different process on a different port is the
// kind of difference an operator can act on immediately.
//
// RESOLUTION is compared by verdict only. Its Citations name the endpoints, and
// the endpoints differ by construction — that is the premise of the comparison,
// not a finding, and reporting it as a difference would put noise at the top of
// every result.
func entryDiffed(l model.Layer) bool { return l != model.LayerResolution }

// onlyIn returns the entries in a that are absent from b, in the order a
// recorded them, with exact duplicates dropped.
func onlyIn(a, b []model.Citation) []model.Citation {
	if len(a) == 0 {
		return nil
	}
	other := make(map[model.Citation]bool, len(b))
	for _, c := range b {
		other[c] = true
	}
	var out []model.Citation
	seen := make(map[model.Citation]bool, len(a))
	for _, c := range a {
		if other[c] || seen[c] {
			continue
		}
		seen[c] = true
		out = append(out, c)
	}
	return out
}

// abstainSummary states which side abstained and why. Both sides abstaining is
// reported as such rather than as agreement: two unread Layers are not a match.
func abstainSummary(layer model.Layer, subject, reference Side, sub, ref model.LayerResult) string {
	switch {
	case sub.Verdict == model.VerdictAbstain && ref.Verdict == model.VerdictAbstain:
		return fmt.Sprintf("%s abstained on both paths, so neither was evaluated: %s path: %s; %s path: %s",
			layer, subject.Label, sub.Reason, reference.Label, ref.Reason)
	case sub.Verdict == model.VerdictAbstain:
		return fmt.Sprintf("%s abstained on the %s path and %s on the %s path, so the comparison is incomplete: %s",
			layer, subject.Label, verdictVerb(ref.Verdict), reference.Label, sub.Reason)
	default:
		return fmt.Sprintf("%s abstained on the %s path and %s on the %s path, so the comparison is incomplete: %s",
			layer, reference.Label, verdictVerb(sub.Verdict), subject.Label, ref.Reason)
	}
}

// differsSummary leads with the verdict difference when there is one, because a
// Layer that blocked one path and passed the other is the answer and the entries
// are the supporting detail.
func differsSummary(layer model.Layer, subject, reference Side, sub, ref model.LayerResult, verdictDiffers bool, diff LayerDiff) string {
	if verdictDiffers {
		return fmt.Sprintf("%s %s the %s path and %s the %s path (%s only on the %s path, %s only on the %s path)",
			layer, verdictVerbFor(sub.Verdict), subject.Label, verdictVerbFor(ref.Verdict), reference.Label,
			entryCount(len(diff.Subject.Only)), subject.Label,
			entryCount(len(diff.Reference.Only)), reference.Label)
	}
	return fmt.Sprintf("both paths %s at %s on different entries: %s only on the %s path, %s only on the %s path",
		verdictVerb(sub.Verdict), layer,
		entryCount(len(diff.Subject.Only)), subject.Label,
		entryCount(len(diff.Reference.Only)), reference.Label)
}

// direction reports the Layers that remain as an explanation. Requirement 10.3.
//
// Two conditions, both necessary. Every compared cloud Layer matched, so nothing
// in the cloud configuration separates the two paths — an incomplete cloud
// comparison disqualifies this, because a Layer that could not be read on one
// side has not been shown to match. And the two paths were shown to behave
// differently, because with no difference in behaviour there is nothing left to
// explain and naming the host Layers would be an accusation rather than a
// deduction.
func (r *Result) direction(subject, reference Side) *Direction {
	if !r.BehaviourDiffers {
		return nil
	}
	// Only the Layers whose entries were compared are claimed as identical, so
	// the claim is exactly as strong as the comparison that supports it.
	var cloud []model.Layer
	for _, l := range cloudLayers(r.Matched) {
		if entryDiffed(l) {
			cloud = append(cloud, l)
		}
	}
	if len(cloud) == 0 || r.hasCloudDifference() {
		return nil
	}

	layers := hostLayers(subject, reference)
	if len(layers) == 0 {
		return nil
	}

	citations := []model.Citation{{
		Kind:       citationKindComparison,
		Identifier: layerList(cloud),
		Detail: fmt.Sprintf("the %s and %s paths meet the same entries at every compared cloud layer: %s",
			subject.Label, reference.Label, layerList(cloud)),
	}}
	for _, side := range []Side{subject, reference} {
		for _, layer := range layers {
			res, ok := side.Verdict.Result(layer)
			if !ok {
				continue
			}
			citations = append(citations, sideCitations(side, res)...)
		}
	}

	return &Direction{
		Layers: layers,
		Summary: fmt.Sprintf("%s, so the cloud configuration is not what separates them; %s %s the remaining explanation (%s)",
			citations[0].Detail, layerList(layers), isAre(len(layers)), r.Behaviour),
		Citations: citations,
	}
}

// sideCitations renders one path's finding for a Layer as evidence, labelled with
// the path it came from. The label is in the detail rather than the identifier
// because the identifier is often the same on both sides — the same command, the
// same route table — and that sameness is the point being reported.
func sideCitations(side Side, res model.LayerResult) []model.Citation {
	if res.Verdict == model.VerdictAbstain {
		return []model.Citation{{
			Kind:       citationKindComparison,
			Identifier: fmt.Sprintf("%s %s", side.Label, res.Layer),
			Detail:     fmt.Sprintf("%s path: %s abstained: %s", side.Label, res.Layer, res.Reason),
		}}
	}
	out := make([]model.Citation, 0, len(res.Citations))
	for _, c := range res.Citations {
		out = append(out, model.Citation{
			Kind:       c.Kind,
			Identifier: c.Identifier,
			Detail:     fmt.Sprintf("%s path: %s", side.Label, c.Detail),
		})
	}
	return out
}

// hasCloudDifference reports whether any cloud Layer differed or could not be
// compared.
func (r *Result) hasCloudDifference() bool {
	for _, group := range [][]LayerDiff{r.Differences, r.Incomplete} {
		for _, d := range group {
			if !d.Layer.Host() {
				return true
			}
		}
	}
	return false
}

// notes record what an operator should know about the comparison itself.
func (r *Result) notes() []string {
	var out []string
	if len(r.Differences) == 0 && len(r.Incomplete) == 0 {
		out = append(out, fmt.Sprintf("the %s and %s paths are identical at every layer compared",
			r.Subject.Label, r.Reference.Label))
	}
	if !r.BehaviourDiffers && !r.hasCloudDifference() && len(cloudLayers(r.Matched)) > 0 {
		out = append(out, fmt.Sprintf(
			"the cloud layers match and neither verdict differs, so no behaviour difference was established; supply the symptom observed on the %s path to have the remaining layers named",
			r.Subject.Label))
	}
	for _, p := range []PathSummary{r.Subject, r.Reference} {
		if !p.Authoritative {
			out = append(out, fmt.Sprintf("the %s path's own verdict is not authoritative, so this comparison is not either", p.Label))
		}
	}
	if len(r.Incomplete) > 0 {
		// The reasons live on the comparisons themselves, so this states the
		// consequence rather than repeating them.
		out = append(out, fmt.Sprintf("%s could not be compared, so this comparison is not authoritative",
			layerList(incompleteLayers(r.Incomplete))))
	}
	return out
}

// behaviour reports whether the two paths were shown to behave differently, and
// how.
//
// Two ways, and no third. The engine reached different verdicts, which is a
// difference it can demonstrate. Or the operator reported a Symptom on the
// failing path that its own verdict does not account for, which is a difference
// they observed. Absent either, no behaviour difference is asserted: the caller
// naming one path "failing" is a premise, and treating a premise as a finding is
// how a comparison starts inventing conclusions.
func behaviour(subject, reference PathSummary) (bool, string) {
	subBlocker, subBlocked := subject.blocker()
	refBlocker, refBlocked := reference.blocker()

	switch {
	case subBlocked && !refBlocked:
		return true, fmt.Sprintf("the %s path is blocked at %s while the %s path is permitted",
			subject.Label, subBlocker, reference.Label)
	case !subBlocked && refBlocked:
		return true, fmt.Sprintf("the %s path is permitted while the %s path is blocked at %s",
			subject.Label, reference.Label, refBlocker)
	case subBlocked && refBlocked && subBlocker != refBlocker:
		return true, fmt.Sprintf("the %s path is blocked at %s and the %s path at %s",
			subject.Label, subBlocker, reference.Label, refBlocker)
	case subject.Symptom != symptom.None && !subBlocked:
		return true, fmt.Sprintf("symptom %s was observed on the %s path, which no layer accounts for",
			subject.Symptom, subject.Label)
	default:
		return false, ""
	}
}

// cloudLayers filters to the Layers evaluated from cloud configuration.
func cloudLayers(layers []model.Layer) []model.Layer {
	var out []model.Layer
	for _, l := range layers {
		if !l.Host() {
			out = append(out, l)
		}
	}
	return out
}

// hostLayers returns the host Layers either path reported, in flow order.
func hostLayers(sides ...Side) []model.Layer {
	var out []model.Layer
	for _, l := range model.FlowOrder() {
		if !l.Host() {
			continue
		}
		for _, side := range sides {
			if _, ok := side.Verdict.Result(l); ok {
				out = append(out, l)
				break
			}
		}
	}
	return out
}

func incompleteLayers(diffs []LayerDiff) []model.Layer {
	out := make([]model.Layer, 0, len(diffs))
	for _, d := range diffs {
		out = append(out, d.Layer)
	}
	return out
}

func layerList(layers []model.Layer) string {
	names := make([]string, 0, len(layers))
	for _, l := range layers {
		names = append(names, string(l))
	}
	return strings.Join(names, ", ")
}

// presentLabel and absentLabel name the two sides of a one-sided comparison.
func presentLabel(subject, reference Side, subjectReached bool) string {
	if subjectReached {
		return subject.Label
	}
	return reference.Label
}

func absentLabel(subject, reference Side, subjectReached bool) string {
	if subjectReached {
		return reference.Label
	}
	return subject.Label
}

// verdictVerb renders a verdict as what both paths did, for a summary whose
// subject is plural.
func verdictVerb(v model.LayerVerdict) string {
	switch v {
	case model.VerdictBlocked:
		return "are blocked"
	case model.VerdictPass:
		return "pass"
	default:
		return "abstained"
	}
}

// verdictVerbFor renders a verdict as what one Layer did to one path.
func verdictVerbFor(v model.LayerVerdict) string {
	switch v {
	case model.VerdictBlocked:
		return "blocks"
	case model.VerdictPass:
		return "permits"
	default:
		return "abstained for"
	}
}

// entryCount renders a one-sided entry count in words a reader does not have to
// decode.
func entryCount(n int) string {
	if n == 1 {
		return "1 entry"
	}
	return fmt.Sprintf("%d entries", n)
}

func isAre(n int) string {
	if n == 1 {
		return "is"
	}
	return "are"
}
