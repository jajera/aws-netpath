package flowtest

// Judging a declared flow against what the engine found.
//
// One rule decides everything here, and it is the same rule internal/query
// applies to its own verdict: a block is demonstrated, a permit is only as good
// as the Layers that were evaluated.
//
// A Layer shown to drop the traffic drops it whatever else abstained — an
// unevaluated Layer cannot un-block a packet another Layer was shown to discard.
// So a blocked flow is a certain answer, and a declared flow expecting a block
// passes on that evidence even when a later Layer could not be read.
//
// A permitted flow is different. Nothing blocked among the Layers that were
// evaluated, which is not the same as nothing blocking: an Abstention before the
// end of the path might be the block, and asserting reachability on that basis is
// the confident wrong answer this tool refuses to give. Such a flow is
// inconclusive — its own category, counted separately, never a pass, whichever
// verdict was declared. Requirement 12.4.
//
// The order the cases are tested in follows from that. Certainty is established
// first, because an uncertain evaluation can neither meet an expectation nor
// contradict one; only then does the comparison of declared against actual decide
// between a pass and a failure.

import (
	"fmt"
	"strings"

	"github.com/jajera/aws-netpath/internal/model"
)

// Outcome is what one declared flow's assertion came to.
type Outcome string

const (
	// OutcomePass is a flow whose actual reachability was established and matches
	// what was declared.
	OutcomePass Outcome = "pass"
	// OutcomeFail is a flow whose actual reachability was established and differs
	// from what was declared. Requirement 12.2, and the caller's signal to exit 1.
	OutcomeFail Outcome = "fail"
	// OutcomeInconclusive is a flow whose reachability was not established: a
	// Layer abstained, or the flow could not be evaluated at all. Never a pass and
	// never a failure. Requirement 12.4.
	OutcomeInconclusive Outcome = "inconclusive"
)

// Evaluation is one declared flow's engine result, as this package consumes it.
//
// It carries a correlated model.Verdict rather than a raw walk, so the actual
// reachability read here is the one the rest of the tool reports: precedence and
// aggregation have already been applied, by the one implementation that owns
// them.
type Evaluation struct {
	// Flow is the traffic as the engine rendered it, empty when evaluation never
	// got that far.
	Flow string
	// Verdict is the correlated outcome for the flow.
	Verdict model.Verdict
	// Err is set when the flow could not be evaluated at all — an endpoint that
	// resolves to nothing, an input the engine refused. The flow is inconclusive
	// rather than failed: nothing was learned about its reachability, and calling
	// that a regression would point the operator at the network instead of at
	// their declaration.
	Err error
}

// Case is one declared flow, judged.
type Case struct {
	// Name labels the flow, defaulting to the flow itself.
	Name string `json:"name"`
	// Flow is the traffic under test as the engine rendered it, falling back to
	// the declaration when the engine never rendered one.
	Flow     string   `json:"flow"`
	Declared Declared `json:"declared"`
	// Expected and Actual are the two verdicts requirement 12.2 asks a mismatch
	// to report. Actual is empty when the flow could not be evaluated.
	Expected Reachability `json:"expected"`
	Actual   Reachability `json:"actual,omitempty"`
	Outcome  Outcome      `json:"outcome"`
	// Summary states the judgement in one line, naming both verdicts and where
	// the actual one was decided.
	Summary string `json:"summary"`
	// DecidingLayer is the Layer that decided the actual reachability: the
	// blocking Layer, or the last gate the traffic cleared.
	DecidingLayer model.Layer `json:"deciding_layer,omitempty"`
	// Deciding is the evidence behind the actual verdict. Requirement 12.2 — a
	// mismatch without a Citation is a notification, not a finding.
	Deciding []model.Citation `json:"deciding,omitempty"`
	// Reason states why the flow is inconclusive, empty when it is not.
	Reason string `json:"reason,omitempty"`
	// Established is false when the actual reachability was not demonstrated.
	Established bool `json:"established"`
}

// Failed reports whether this flow did not meet its declaration.
func (c Case) Failed() bool { return c.Outcome == OutcomeFail }

// Counts is the tally a build gate reads.
type Counts struct {
	Total        int `json:"total"`
	Passed       int `json:"passed"`
	Failed       int `json:"failed"`
	Inconclusive int `json:"inconclusive"`
}

// Result is the run: every declared flow, judged, with the tally in front.
type Result struct {
	Counts Counts `json:"counts"`
	Cases  []Case `json:"cases,omitempty"`
	// Authoritative is false when any flow was inconclusive, so a caller reading
	// only the tally still learns that some of it could not be established.
	Authoritative bool     `json:"authoritative"`
	Notes         []string `json:"notes,omitempty"`
}

// Failed reports whether any declared flow did not meet its expected verdict.
// This is what requirement 12.3 maps to exit 1; the mapping itself is the CLI's.
func (r *Result) Failed() bool { return r != nil && r.Counts.Failed > 0 }

// Inconclusive reports whether any declared flow could not be established. It is
// separate from Failed on purpose: an inconclusive flow is not a regression, and
// it is not a pass either.
func (r *Result) Inconclusive() bool { return r != nil && r.Counts.Inconclusive > 0 }

// Failures, Passes, and Unresolved group the cases by outcome, which is the
// order a report reads them in: what broke, what held, what could not be said.
func (r *Result) Failures() []Case   { return r.withOutcome(OutcomeFail) }
func (r *Result) Passes() []Case     { return r.withOutcome(OutcomePass) }
func (r *Result) Unresolved() []Case { return r.withOutcome(OutcomeInconclusive) }

func (r *Result) withOutcome(o Outcome) []Case {
	if r == nil {
		return nil
	}
	var out []Case
	for _, c := range r.Cases {
		if c.Outcome == o {
			out = append(out, c)
		}
	}
	return out
}

// Summary is the run in one line.
func (r *Result) Summary() string {
	if r == nil || r.Counts.Total == 0 {
		return "NO DECLARED FLOWS"
	}
	switch {
	case r.Counts.Failed > 0:
		return fmt.Sprintf("FAILED: %d of %s did not meet the declared verdict",
			r.Counts.Failed, flowCount(r.Counts.Total))
	case r.Counts.Inconclusive > 0:
		return fmt.Sprintf("INCONCLUSIVE: %d of %s could not be established, %d met the declared verdict",
			r.Counts.Inconclusive, flowCount(r.Counts.Total), r.Counts.Passed)
	default:
		return fmt.Sprintf("PASSED: %s met the declared verdict", flowCount(r.Counts.Total))
	}
}

// Judge decides one declared flow against its evaluation.
func Judge(d Declared, e Evaluation) Case {
	c := Case{
		Name:     d.Title(),
		Flow:     d.Describe(),
		Declared: d,
		Expected: d.Expect,
	}
	if e.Flow != "" {
		c.Flow = e.Flow
	}

	if e.Err != nil {
		c.Outcome = OutcomeInconclusive
		c.Reason = e.Err.Error()
		c.Summary = fmt.Sprintf("%s could not be evaluated, so the declared verdict %s was neither met nor contradicted: %s",
			c.Flow, c.Expected, c.Reason)
		return c
	}

	verdict := e.Verdict
	c.Actual = reachability(verdict)
	c.Established = established(verdict)
	c.DecidingLayer, c.Deciding = deciding(verdict)

	switch {
	case !c.Established:
		// Only a permit can be uncertain, so this is a flow that was not shown to
		// be blocked and was not shown to be permitted either.
		c.Outcome = OutcomeInconclusive
		c.Reason = abstentionReason(verdict)
		c.Summary = fmt.Sprintf("declared %s: no layer was shown to block this flow, but %s, so its reachability is not established",
			c.Expected, c.Reason)
	case c.Actual != c.Expected:
		c.Outcome = OutcomeFail
		c.Summary = fmt.Sprintf("declared %s, actual %s, decided at %s",
			c.Expected, c.Actual, c.decidedAt())
	default:
		c.Outcome = OutcomePass
		c.Summary = fmt.Sprintf("declared %s and found %s, decided at %s",
			c.Expected, c.Actual, c.decidedAt())
	}
	return c
}

// decidedAt names where the actual verdict came from, for a summary that has to
// stand on its own in a one-line CI log.
func (c Case) decidedAt() string {
	if c.DecidingLayer == "" {
		return "no layer"
	}
	return string(c.DecidingLayer)
}

// Summarise tallies the judged cases into the run's outcome.
func Summarise(cases []Case) *Result {
	r := &Result{Cases: cases}
	r.Counts.Total = len(cases)
	for _, c := range cases {
		switch c.Outcome {
		case OutcomePass:
			r.Counts.Passed++
		case OutcomeFail:
			r.Counts.Failed++
		default:
			r.Counts.Inconclusive++
		}
	}
	r.Authoritative = r.Counts.Inconclusive == 0
	r.Notes = r.notes()
	return r
}

// notes record what a reader of the tally needs to know about the tally itself.
func (r *Result) notes() []string {
	var out []string
	if r.Counts.Total == 0 {
		return []string{"no flows were declared, so nothing was asserted"}
	}
	if r.Counts.Inconclusive > 0 {
		out = append(out, fmt.Sprintf(
			"%d of %s could not be established; an inconclusive flow is neither a pass nor a failure, and is not counted as either",
			r.Counts.Inconclusive, flowCount(r.Counts.Total)))
	}
	if r.Counts.Failed > 0 {
		out = append(out, "a declared flow that did not meet its expected verdict is a failure of the declaration or of the network, and this run does not decide which")
	}
	return out
}

// reachability reads a correlated Verdict back into the vocabulary a declared
// flow asserts in.
func reachability(v model.Verdict) Reachability {
	if v.PrimaryBlocker != nil {
		return Blocked
	}
	return Permitted
}

// established reports whether the actual reachability was demonstrated.
//
// A block was: the primary blocker is a Layer shown to drop the traffic, and an
// Abstention elsewhere cannot undo that. Whether some earlier Layer would have
// blocked first is a question about attribution, not about reachability, and a
// declared flow asserts reachability.
//
// A permit was only if nothing that could have blocked went unevaluated, which is
// what Verdict.Authoritative already computes.
func established(v model.Verdict) bool {
	if v.PrimaryBlocker != nil {
		return true
	}
	return v.Authoritative
}

// deciding returns the Layer that decided the actual reachability and its
// evidence. Requirement 12.2.
//
// For a blocked flow that is the primary blocker, which is the rule an operator
// has to change or accept. For a permitted flow it is the last gate the traffic
// cleared: the latest Layer in flow order that permitted it, which is the last
// thing that could have stopped the flow and did not.
func deciding(v model.Verdict) (model.Layer, []model.Citation) {
	if v.PrimaryBlocker != nil {
		if res, ok := v.Result(*v.PrimaryBlocker); ok {
			return res.Layer, res.Citations
		}
		return *v.PrimaryBlocker, nil
	}

	var last model.LayerResult
	var found bool
	for _, res := range v.Results {
		if res.Verdict != model.VerdictPass {
			continue
		}
		if !found || res.Layer.FlowIndex() >= last.Layer.FlowIndex() {
			last, found = res, true
		}
	}
	if !found {
		return "", nil
	}
	return last.Layer, last.Citations
}

// abstentionReason names the Layers that leave a permit unestablished, with the
// reason each gave.
//
// The Layers are named rather than counted because the operator's next move is to
// go and evaluate whichever one could not be read, and a count does not tell them
// which.
func abstentionReason(v model.Verdict) string {
	affecting := v.ConclusionAffectingAbstentions()
	if len(affecting) == 0 {
		return "the evaluation was not authoritative"
	}
	parts := make([]string, 0, len(affecting))
	for _, res := range affecting {
		parts = append(parts, fmt.Sprintf("%s could not be evaluated (%s)", res.Layer, res.Reason))
	}
	return strings.Join(parts, "; ")
}

func flowCount(n int) string {
	if n == 1 {
		return "1 declared flow"
	}
	return fmt.Sprintf("%d declared flows", n)
}
