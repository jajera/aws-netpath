// Package correlate combines the findings the Path_Walker and the Host_Prober
// produce separately into one Verdict.
//
// Three things happen here and nothing else. Precedence: when several Layers
// block, the earliest in flow order is the primary blocker and the rest are
// listed after it, because the traffic never reached them. Aggregation: several
// findings for the same Layer collapse into one result, and an Abstention never
// collapses into a pass. Reconciliation: findings are checked against the
// Symptom the operator reported, and a disagreement is recorded rather than
// resolved, because a disagreement is itself diagnostic.
//
// Correlation is pure logic: no AWS call, no Snapshot, no I/O. It decides
// nothing about what a Layer says, only what the collection of Layer findings
// amounts to.
package correlate

import (
	"fmt"
	"sort"
	"strings"

	"github.com/jajera/aws-netpath/internal/model"
	"github.com/jajera/aws-netpath/internal/symptom"
)

// Input is the set of findings to correlate.
type Input struct {
	// Symptom is the failure the operator observed, or symptom.None when none
	// was supplied. It is used only to reconcile against the findings; it never
	// changes a verdict.
	Symptom symptom.Symptom
	// Results are the Layer findings, in any order. Several findings for the
	// same Layer are permitted: a Flow crossing two inspection points produces
	// a firewall verdict for each, and both are kept as Citations on one
	// result.
	Results []model.LayerResult
	// Observations are findings that carry no verdict: something true about the
	// path that may explain the Symptom without having blocked anything. They
	// are reported as given, and at most one is promoted to the probable cause.
	Observations []model.Observation
}

// Correlate reduces the findings to a single Verdict.
//
// The returned Verdict lists its results in flow order, names at most one
// primary blocker, and carries Authoritative computed from the Abstentions that
// could have changed the conclusion. Requirement 7.4 needs no special handling:
// a blocked return direction under a permitted forward direction is the
// earliest blocking Layer in flow order, so precedence alone makes it primary.
//
// An error is returned when a finding is not emittable — an Abstention with no
// reason, a decision with no Citation, an unknown Layer — because correlating
// unusable input would launder it into a verdict.
func Correlate(in Input) (model.Verdict, error) {
	classification, err := symptom.Classify(in.Symptom)
	if err != nil {
		return model.Verdict{}, err
	}

	for _, r := range in.Results {
		if err := r.Validate(); err != nil {
			return model.Verdict{}, err
		}
	}
	for _, o := range in.Observations {
		if err := o.Validate(); err != nil {
			return model.Verdict{}, err
		}
	}

	results := aggregate(in.Results)

	verdict := model.Verdict{Results: results, Observations: copyObservations(in.Observations)}
	verdict.PrimaryBlocker, verdict.AdditionalBlocked = precedence(results)
	// Before contradictions, which need to know whether anything explains the
	// Symptom before calling it unexplained.
	verdict.ProbableCause = probableCause(classification, verdict)
	verdict.Contradictions = contradictions(classification, verdict)
	verdict.ComputeAuthoritative()

	if err := verdict.Validate(); err != nil {
		return model.Verdict{}, fmt.Errorf("correlate: %w", err)
	}
	return verdict, nil
}

// aggregate collapses findings for the same Layer into one result per Layer and
// returns them in flow order.
//
// The combined verdict is the strongest finding present: BLOCKED over ABSTAIN
// over PASS. Ordering ABSTAIN above PASS is the whole point — a Layer that
// passed at one inspection point and could not be evaluated at another has not
// been cleared, and reporting it as a pass would be the exact failure the
// abstention machinery exists to prevent.
func aggregate(in []model.LayerResult) []model.LayerResult {
	order := make([]model.Layer, 0, len(in))
	byLayer := make(map[model.Layer]model.LayerResult, len(in))

	for _, r := range in {
		existing, seen := byLayer[r.Layer]
		if !seen {
			order = append(order, r.Layer)
			byLayer[r.Layer] = model.LayerResult{
				Layer:     r.Layer,
				Verdict:   r.Verdict,
				Citations: copyCitations(r.Citations),
				Reason:    r.Reason,
			}
			continue
		}
		byLayer[r.Layer] = merge(existing, r)
	}

	sort.SliceStable(order, func(i, j int) bool {
		return order[i].FlowIndex() < order[j].FlowIndex()
	})

	out := make([]model.LayerResult, 0, len(order))
	for _, l := range order {
		out = append(out, byLayer[l])
	}
	return out
}

// merge combines two findings for the same Layer, keeping every Citation and
// every Abstention reason so the evidence for the combined verdict survives.
func merge(a, b model.LayerResult) model.LayerResult {
	out := model.LayerResult{
		Layer:     a.Layer,
		Verdict:   strongest(a.Verdict, b.Verdict),
		Citations: appendCitations(a.Citations, b.Citations),
		Reason:    joinReasons(a, b),
	}
	return out
}

// verdictRank orders verdicts by strength for aggregation.
func verdictRank(v model.LayerVerdict) int {
	switch v {
	case model.VerdictBlocked:
		return 2
	case model.VerdictAbstain:
		return 1
	default:
		return 0
	}
}

func strongest(a, b model.LayerVerdict) model.LayerVerdict {
	if verdictRank(b) > verdictRank(a) {
		return b
	}
	return a
}

// joinReasons keeps the reason from every Abstention that contributed. A
// combined verdict of BLOCKED still carries the reason an earlier finding
// abstained, because that Layer is only partly evaluated and the report says so.
func joinReasons(a, b model.LayerResult) string {
	var reasons []string
	for _, r := range []model.LayerResult{a, b} {
		if r.Reason == "" {
			continue
		}
		if !containsString(reasons, r.Reason) {
			reasons = append(reasons, r.Reason)
		}
	}
	return strings.Join(reasons, "; ")
}

// precedence returns the earliest blocking Layer in flow order and every other
// blocking Layer after it. Results are already in flow order.
func precedence(results []model.LayerResult) (*model.Layer, []model.Layer) {
	var primary *model.Layer
	var additional []model.Layer
	for i := range results {
		if results[i].Verdict != model.VerdictBlocked {
			continue
		}
		if primary == nil {
			layer := results[i].Layer
			primary = &layer
			continue
		}
		additional = append(additional, results[i].Layer)
	}
	return primary, additional
}

// probableCause promotes the Observation that explains the observed Symptom.
//
// Requirement 7.3: an asymmetric path across a stateful component accounts for a
// connect-then-stall precisely. Both directions are permitted, so the handshake
// completes and no Layer blocks; then traffic stops, because the device holding
// the connection state never sees the response, which came back another way. That
// is a ranked explanation rather than a verdict, so it is reported separately and
// never becomes a blocker.
//
// A Symptom is required. Without one there is no failure to explain, and calling
// an asymmetry the cause of something nobody observed would be a guess. A primary
// blocker is disqualifying for the same reason: a Layer shown to have dropped the
// traffic is the cause, and the Observation is still reported alongside it.
func probableCause(c symptom.Classification, v model.Verdict) *model.ProbableCause {
	if c.Symptom == symptom.None || v.PrimaryBlocker != nil {
		return nil
	}
	for _, o := range v.Observations {
		if !explains(c, o) {
			continue
		}
		return &model.ProbableCause{
			Layer:     o.Layer,
			Summary:   fmt.Sprintf("symptom %s (%s) is explained by %s: %s", c.Symptom, c.Mechanism, o.Kind, o.Summary),
			Citations: copyCitations(o.Citations),
		}
	}
	return nil
}

// explains reports whether an Observation accounts for the classified Symptom.
//
// The established response is the one that matters. It means no Layer blocked the
// handshake, so the failure came after the connection was made — which is exactly
// the kind of failure an Observation describes, since an Observation never blocks
// anything. The Observation's Layer has to be one the Symptom implicates as well,
// so an unrelated finding is not promoted to an explanation it does not support.
//
// An asymmetric path with nothing stateful on it stays an Observation. It is
// irregular and worth reporting, but a stateless path carries a response that
// returns another way without noticing, so on its own it explains no stall.
func explains(c symptom.Classification, o model.Observation) bool {
	if o.Kind != model.ObservationAsymmetricStateful {
		return false
	}
	return c.Response == symptom.ResponseEstablished && c.Candidate(o.Layer)
}

// layerResponse is what the far side does when a Layer blocks, expressed in the
// same terms the Symptom_Classifier uses.
//
// A security group, a NACL, or a missing route discards the packet and says
// nothing, so the client sees a timeout. A listener that is absent answers with
// a RST, so the client sees a connection refused. Everything else is mixed:
// Network Firewall can drop or reject depending on the rule action, firewalld
// can be configured either way, and resolution failure is not a network
// response at all. Mixed Layers are not used to claim a contradiction, because
// they are consistent with either observation.
func layerResponse(l model.Layer) symptom.Response {
	switch l {
	case model.LayerRoute, model.LayerNACL, model.LayerSecurityGroup, model.LayerReturnPath:
		return symptom.ResponseSilent
	case model.LayerHostListener:
		return symptom.ResponseActive
	default:
		return symptom.ResponseMixed
	}
}

// contradictions reports where the findings and the Symptom disagree.
//
// Nothing here changes a verdict. Requirement 9.4 is explicit that a
// contradiction is recorded rather than resolved: an operator who saw a RST
// while every Layer reports a silent discard has learned something real, and
// discarding either observation to keep the report tidy would throw it away.
func contradictions(c symptom.Classification, v model.Verdict) []string {
	if c.Symptom == symptom.None {
		return nil
	}

	var out []string

	// A probable cause settles it: every Layer did permit the traffic, and
	// something on the path explains why the operator still saw it fail, so the
	// findings and the Symptom no longer disagree.
	if v.PrimaryBlocker == nil && len(v.Abstentions()) == 0 && v.ProbableCause == nil {
		out = append(out, fmt.Sprintf(
			"symptom %s was observed (%s), but every evaluated layer permitted the traffic",
			c.Symptom, c.Mechanism))
	}

	if v.PrimaryBlocker != nil {
		primary := *v.PrimaryBlocker
		switch response := layerResponse(primary); {
		case c.Response == symptom.ResponseActive && response == symptom.ResponseSilent:
			out = append(out, fmt.Sprintf(
				"symptom %s indicates the far side replied (%s), but the primary blocker %s discards silently",
				c.Symptom, c.Mechanism, primary))
		case c.Response == symptom.ResponseSilent && response == symptom.ResponseActive:
			out = append(out, fmt.Sprintf(
				"symptom %s indicates the packet was discarded without a reply, but the primary blocker %s replies",
				c.Symptom, primary))
		}
	}

	// An established connection means no Layer blocked the handshake. A Layer
	// the Symptom already implicates is the expected cause of the later
	// failure, not a contradiction: a return path that blocks is exactly how a
	// connect-then-stall arises.
	if c.Response == symptom.ResponseEstablished {
		for _, l := range blockedLayers(v) {
			if c.Candidate(l) {
				continue
			}
			out = append(out, fmt.Sprintf(
				"symptom %s indicates the connection was established, but layer %s reports the traffic blocked",
				c.Symptom, l))
		}
	}

	return out
}

func blockedLayers(v model.Verdict) []model.Layer {
	var out []model.Layer
	if v.PrimaryBlocker != nil {
		out = append(out, *v.PrimaryBlocker)
	}
	out = append(out, v.AdditionalBlocked...)
	return out
}

func copyObservations(in []model.Observation) []model.Observation {
	if in == nil {
		return nil
	}
	out := make([]model.Observation, 0, len(in))
	for _, o := range in {
		o.Citations = copyCitations(o.Citations)
		out = append(out, o)
	}
	return out
}

func copyCitations(in []model.Citation) []model.Citation {
	if in == nil {
		return nil
	}
	out := make([]model.Citation, len(in))
	copy(out, in)
	return out
}

// appendCitations concatenates two Citation lists, dropping exact duplicates so
// two inspection points citing the same rule group entry are reported once.
func appendCitations(a, b []model.Citation) []model.Citation {
	out := copyCitations(a)
	for _, c := range b {
		if !containsCitation(out, c) {
			out = append(out, c)
		}
	}
	return out
}

func containsCitation(citations []model.Citation, want model.Citation) bool {
	for _, c := range citations {
		if c == want {
			return true
		}
	}
	return false
}

func containsString(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}
