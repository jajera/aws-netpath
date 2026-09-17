package model

import "fmt"

// LayerVerdict is the outcome for one evaluation Layer. Abstain is a first-class
// verdict rather than a missing value, which is what stops "could not check"
// from rendering as "checked and fine".
type LayerVerdict string

const (
	VerdictPass    LayerVerdict = "pass"
	VerdictBlocked LayerVerdict = "blocked"
	VerdictAbstain LayerVerdict = "abstain"
)

// Valid reports whether v is one of the three defined verdicts.
func (v LayerVerdict) Valid() bool {
	switch v {
	case VerdictPass, VerdictBlocked, VerdictAbstain:
		return true
	default:
		return false
	}
}

// Layer is one evaluation stage of a path.
type Layer string

const (
	LayerResolution    Layer = "resolution"
	LayerRoute         Layer = "route"
	LayerNACL          Layer = "nacl"
	LayerSecurityGroup Layer = "security_group"
	LayerFirewall      Layer = "firewall"
	LayerReturnPath    Layer = "return_path"
	LayerHostFirewall  Layer = "host_firewall"
	LayerHostListener  Layer = "host_listener"
)

// flowOrder is the order Layers are encountered along a Flow. Verdict
// precedence depends on it: the earliest blocking Layer is the primary blocker.
var flowOrder = []Layer{
	LayerResolution,
	LayerRoute,
	LayerNACL,
	LayerSecurityGroup,
	LayerFirewall,
	LayerReturnPath,
	LayerHostFirewall,
	LayerHostListener,
}

// FlowOrder returns the Layers in flow order.
func FlowOrder() []Layer {
	out := make([]Layer, len(flowOrder))
	copy(out, flowOrder)
	return out
}

// FlowIndex returns the position of l in flow order, or -1 if l is not a
// defined Layer.
func (l Layer) FlowIndex() int {
	for i, candidate := range flowOrder {
		if candidate == l {
			return i
		}
	}
	return -1
}

// Valid reports whether l is a defined Layer.
func (l Layer) Valid() bool { return l.FlowIndex() >= 0 }

// Host reports whether l is evaluated on the host rather than from cloud
// configuration. The Symptom_Classifier uses this to order host checks first
// for actively rejected symptoms.
func (l Layer) Host() bool {
	return l == LayerHostFirewall || l == LayerHostListener
}

// Citation is the evidence behind a decision: a resource ID, a rule reference,
// or the command whose output was read. A finding without one is not emitted.
type Citation struct {
	// Kind is the evidence category: "route", "nacl", "security_group",
	// "nfw_rule", or "command".
	Kind string `json:"kind"`
	// Identifier names the evidence, for example rtb-…, sg-…, or
	// "nfr-allow-east-west sid 3 (priority 6)".
	Identifier string `json:"identifier"`
	Detail     string `json:"detail,omitempty"`
}

// LayerResult is the outcome of evaluating one Layer.
type LayerResult struct {
	Layer     Layer        `json:"layer"`
	Verdict   LayerVerdict `json:"verdict"`
	Citations []Citation   `json:"citations,omitempty"`
	// Reason is required when Verdict is VerdictAbstain: an Abstention without
	// a stated reason is indistinguishable from a silent pass.
	Reason string `json:"reason,omitempty"`
}

// Validate reports whether r may be emitted. An Abstention needs a reason, and
// a pass or a block needs at least one Citation.
func (r LayerResult) Validate() error {
	if !r.Layer.Valid() {
		return fmt.Errorf("layer result: unknown layer %q", r.Layer)
	}
	if !r.Verdict.Valid() {
		return fmt.Errorf("layer result %s: unknown verdict %q", r.Layer, r.Verdict)
	}
	if r.Verdict == VerdictAbstain && r.Reason == "" {
		return fmt.Errorf("layer result %s: abstain requires a reason", r.Layer)
	}
	if r.Verdict != VerdictAbstain && len(r.Citations) == 0 {
		return fmt.Errorf("layer result %s: verdict %s requires at least one citation", r.Layer, r.Verdict)
	}
	return nil
}

// ObservationKind categorises a finding that carries no verdict of its own.
type ObservationKind string

const (
	// ObservationAsymmetric is a path whose two directions resolve to different
	// next hops. Traffic still flows, so no Layer blocks; it is reported because
	// the two directions are supposed to match.
	ObservationAsymmetric ObservationKind = "asymmetric"
	// ObservationAsymmetricStateful is an asymmetric path that crosses a
	// component keeping per-connection state. The response returns through a
	// device other than the one holding that state, so a connection can
	// establish and then stop with nothing having blocked it.
	ObservationAsymmetricStateful ObservationKind = "asymmetric-stateful"
)

// Observation is something true about the path that is not a Layer decision.
//
// A Layer verdict answers "was this traffic permitted here". An Observation
// answers a different question: something about the shape of the path that may
// explain a failure the verdicts alone do not account for. It never blocks and
// never changes a verdict, which is why it is a separate kind of finding rather
// than a Layer result with a verdict it did not earn.
type Observation struct {
	Kind ObservationKind `json:"kind"`
	// Layer is the Layer the Observation concerns, which is how a Symptom that
	// implicates that Layer connects to it.
	Layer   Layer  `json:"layer"`
	Summary string `json:"summary"`
	// Citations are the evidence, on the same terms as a Layer decision: an
	// Observation without one is not emitted.
	Citations []Citation `json:"citations,omitempty"`
}

// Validate reports whether o may be emitted.
func (o Observation) Validate() error {
	if o.Kind == "" {
		return fmt.Errorf("observation: kind is required")
	}
	if !o.Layer.Valid() {
		return fmt.Errorf("observation %s: unknown layer %q", o.Kind, o.Layer)
	}
	if o.Summary == "" {
		return fmt.Errorf("observation %s: summary is required", o.Kind)
	}
	if len(o.Citations) == 0 {
		return fmt.Errorf("observation %s: requires at least one citation", o.Kind)
	}
	return nil
}

// ProbableCause is the Observation that best explains an observed Symptom.
//
// It is a ranked explanation, not a verdict. Nothing was shown to drop the
// packet, so it never becomes a blocker and never makes a verdict
// unauthoritative; it names what to look at when every Layer permitted the
// traffic and the operator still saw it fail.
type ProbableCause struct {
	Layer     Layer      `json:"layer"`
	Summary   string     `json:"summary"`
	Citations []Citation `json:"citations,omitempty"`
}

// Verdict is the correlated outcome across every Layer evaluated.
type Verdict struct {
	// PrimaryBlocker is the earliest blocking Layer in flow order, or nil when
	// no Layer blocked.
	PrimaryBlocker    *Layer        `json:"primary_blocker,omitempty"`
	AdditionalBlocked []Layer       `json:"additional_blocked,omitempty"`
	Results           []LayerResult `json:"results,omitempty"`
	// Observations are the findings that carry no verdict. They are reported
	// whether or not they explain anything, because a path whose directions
	// disagree is worth knowing about on its own.
	Observations []Observation `json:"observations,omitempty"`
	// ProbableCause names the Observation that explains the observed Symptom. It
	// is nil when a Layer blocked — that block is the cause — and when nothing
	// observed accounts for the Symptom.
	ProbableCause  *ProbableCause `json:"probable_cause,omitempty"`
	Contradictions []string       `json:"contradictions,omitempty"`
	// Authoritative is false when an Abstention affects the conclusion. Set it
	// with ComputeAuthoritative rather than by hand.
	Authoritative bool `json:"authoritative"`
}

// Result returns the result recorded for the given Layer.
func (v *Verdict) Result(l Layer) (LayerResult, bool) {
	for _, r := range v.Results {
		if r.Layer == l {
			return r, true
		}
	}
	return LayerResult{}, false
}

// Abstentions returns every Layer that could not be authoritatively evaluated.
func (v *Verdict) Abstentions() []LayerResult {
	var out []LayerResult
	for _, r := range v.Results {
		if r.Verdict == VerdictAbstain {
			out = append(out, r)
		}
	}
	return out
}

// ConclusionAffectingAbstentions returns the Abstentions that could change the
// verdict.
//
// With no blocker found, every Abstention qualifies: an unverified Layer might
// have been the one that blocked, so "permitted" cannot be asserted. With a
// blocker found, an Abstention earlier in flow order qualifies, because it
// might have blocked first and so displaced the primary blocker. An Abstention
// after the primary blocker changes nothing: the traffic is already blocked
// before reaching it.
func (v *Verdict) ConclusionAffectingAbstentions() []LayerResult {
	limit := len(flowOrder)
	if v.PrimaryBlocker != nil {
		if i := v.PrimaryBlocker.FlowIndex(); i >= 0 {
			limit = i
		}
	}
	var out []LayerResult
	for _, r := range v.Abstentions() {
		if i := r.Layer.FlowIndex(); i >= 0 && i < limit {
			out = append(out, r)
		}
	}
	return out
}

// ComputeAuthoritative sets Authoritative from the recorded results and returns
// it. A verdict is authoritative only when no Abstention affects the
// conclusion.
func (v *Verdict) ComputeAuthoritative() bool {
	v.Authoritative = len(v.ConclusionAffectingAbstentions()) == 0
	return v.Authoritative
}

// Validate reports whether v is internally consistent: every result emittable,
// exactly one primary blocker, and every other blocked Layer listed as an
// additional blocker.
func (v *Verdict) Validate() error {
	seen := map[Layer]bool{}
	for _, r := range v.Results {
		if err := r.Validate(); err != nil {
			return err
		}
		if seen[r.Layer] {
			return fmt.Errorf("verdict: duplicate result for layer %s", r.Layer)
		}
		seen[r.Layer] = true
	}

	for _, o := range v.Observations {
		if err := o.Validate(); err != nil {
			return err
		}
	}

	if err := v.validateProbableCause(); err != nil {
		return err
	}

	var blocked []Layer
	for _, r := range v.Results {
		if r.Verdict == VerdictBlocked {
			blocked = append(blocked, r.Layer)
		}
	}

	if v.PrimaryBlocker == nil {
		if len(blocked) > 0 {
			return fmt.Errorf("verdict: layer %s blocked but no primary blocker set", blocked[0])
		}
		if len(v.AdditionalBlocked) > 0 {
			return fmt.Errorf("verdict: additional blockers listed without a primary blocker")
		}
		return nil
	}

	primary := *v.PrimaryBlocker
	if r, ok := v.Result(primary); !ok || r.Verdict != VerdictBlocked {
		return fmt.Errorf("verdict: primary blocker %s has no blocked result", primary)
	}
	for _, l := range blocked {
		if l == primary {
			continue
		}
		if l.FlowIndex() < primary.FlowIndex() {
			return fmt.Errorf("verdict: layer %s blocked earlier in flow order than primary blocker %s", l, primary)
		}
		if !containsLayer(v.AdditionalBlocked, l) {
			return fmt.Errorf("verdict: blocked layer %s missing from additional blockers", l)
		}
	}
	for _, l := range v.AdditionalBlocked {
		if l == primary {
			return fmt.Errorf("verdict: primary blocker %s repeated as an additional blocker", primary)
		}
		if !containsLayer(blocked, l) {
			return fmt.Errorf("verdict: additional blocker %s has no blocked result", l)
		}
	}
	return nil
}

// validateProbableCause holds a probable cause to the same evidence standard as
// a decision, and refuses one alongside a blocker: a Layer that demonstrably
// dropped the traffic is the cause, so naming something else as probable would
// compete with it.
func (v *Verdict) validateProbableCause() error {
	if v.ProbableCause == nil {
		return nil
	}
	cause := v.ProbableCause
	if !cause.Layer.Valid() {
		return fmt.Errorf("verdict: probable cause has unknown layer %q", cause.Layer)
	}
	if cause.Summary == "" {
		return fmt.Errorf("verdict: probable cause for layer %s requires a summary", cause.Layer)
	}
	if len(cause.Citations) == 0 {
		return fmt.Errorf("verdict: probable cause for layer %s requires at least one citation", cause.Layer)
	}
	if v.PrimaryBlocker != nil {
		return fmt.Errorf("verdict: probable cause %s reported alongside primary blocker %s", cause.Layer, *v.PrimaryBlocker)
	}
	return nil
}

func containsLayer(layers []Layer, want Layer) bool {
	for _, l := range layers {
		if l == want {
			return true
		}
	}
	return false
}
