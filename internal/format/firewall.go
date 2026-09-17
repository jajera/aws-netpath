package format

// Projecting a firewall policy evaluation onto the same three sections.
//
// The slots hold what a policy walk found — the traffic a rule denied, the
// traffic a rule permitted, the rule groups that could not be read — in the
// order every other report uses. A reader who learned the layout on a diagnosis
// does not learn a second one for a policy question.
//
// Every decision row is pinned. Requirement 14.4 wants the rule group, priority,
// and SID behind every firewall decision, and this is the one report where the
// firewall decisions are the whole finding: a row budget that took them would
// leave a verdict with no policy behind it. The rows are short by construction —
// a rule reference and the slice of traffic it decided — so pinning them is cheap
// as well as required.
//
// Traffic is described as a slice rather than as a single flow because that is
// what the evaluator decided. A rule matching part of the requested port set
// splits the flow, and collapsing the parts back into one line would state a
// verdict over traffic no rule was shown to have matched.

import (
	"fmt"
	"strings"

	"github.com/jajera/aws-netpath/internal/nfw"
)

// KindFirewall names a firewall policy evaluation in the JSON output.
const KindFirewall Kind = "firewall_policy"

// FirewallEvaluation is a policy walk as the Formatter consumes it: the flow that
// was asked about, one result per firewall, and the two judgements the operation
// has already made about them.
//
// The judgements arrive rather than being re-derived here. This package arranges
// a finding and decides nothing, and a renderer that worked out for itself
// whether a flow was blocked would be a second answer to a question that already
// has one.
type FirewallEvaluation struct {
	// Flow is the traffic under test, already rendered.
	Flow string
	// Results is one outcome per firewall, in the order the operation evaluated
	// them.
	Results []nfw.Result
	// Blocked is true when any firewall denied part of the flow.
	Blocked bool
	// Authoritative is false when any rule group could not be evaluated: the
	// unevaluated group might have been the one that decided the flow.
	Authoritative bool
}

// outcomeNoFirewall is what an evaluation with nothing to evaluate says. A
// snapshot holding no firewall has not permitted the flow, and reporting a permit
// would be the one reading requirement 14.6 exists to prevent.
const outcomeNoFirewall = "NO FIREWALL EVALUATED"

// FromFirewall projects a firewall policy evaluation onto a Report.
func FromFirewall(f FirewallEvaluation) Report {
	if len(f.Results) == 0 {
		return Report{Kind: KindFirewall, Flow: f.Flow, Outcome: outcomeNoFirewall}
	}

	r := Report{
		Kind:          KindFirewall,
		Flow:          f.Flow,
		Outcome:       firewallOutcome(f),
		Authoritative: f.Authoritative,
	}
	r.Finding = deniedSection(f.Results)
	r.Cleared = permittedSection(f.Results)
	r.Unresolved = firewallAbstentionSection(f.Results)
	if !f.Authoritative {
		r.Notice = notEvaluatedGroups(f.Results)
	}
	return r
}

// firewallOutcome names the firewall that denied, or states the permit.
//
// The first denying firewall in evaluation order leads, on the same grounds as
// the Correlator's precedence: traffic dropped at the first inspection point
// never reaches the second, so the later denial is not the one to fix first.
func firewallOutcome(f FirewallEvaluation) string {
	if !f.Blocked {
		return outcomePermitted
	}
	for _, res := range f.Results {
		if !res.Denied().IsEmpty() {
			return fmt.Sprintf(outcomeBlocked, firewallName(res))
		}
	}
	return fmt.Sprintf(outcomeBlocked, "firewall policy")
}

// deniedSection is section one: the traffic a rule dropped, with the rule.
func deniedSection(results []nfw.Result) *Section {
	s := &Section{Title: "denied traffic"}
	for _, res := range results {
		s.add(decisionRows(res, nfw.Drop)...)
	}
	if len(s.Rows) == 0 {
		s.Note = "no firewall rule was shown to drop any part of this flow"
	}
	return s
}

// permittedSection is section two: the traffic a rule passed, with the rule.
//
// The permits carry their rules too. Requirement 14.4 asks for the rule behind
// every firewall decision rather than behind every denial, and an operator
// checking why traffic they expected to be inspected went through needs the
// rule that let it.
func permittedSection(results []nfw.Result) *Section {
	s := &Section{Title: "permitted traffic"}
	for _, res := range results {
		s.add(decisionRows(res, nfw.Pass)...)
	}
	if len(s.Rows) == 0 {
		s.Note = "no firewall rule was shown to pass any part of this flow"
	}
	return s
}

// firewallAbstentionSection is section three: the rule groups that could not be
// evaluated, with the construct that could not be modelled.
func firewallAbstentionSection(results []nfw.Result) *Section {
	s := &Section{Title: "abstentions"}
	for _, res := range results {
		s.add(firewallAbstentionRows(res)...)
	}
	if len(s.Rows) == 0 {
		s.Note = "every rule group in the path was evaluated"
		return s
	}
	s.Note = "an unevaluated rule group might have been the one that decided this flow"
	return s
}

// decisionRows renders one firewall's decisions of one verdict, pinned so a row
// budget cannot take the policy evidence with it. Requirement 14.4.
func decisionRows(res nfw.Result, want nfw.Verdict) []Row {
	var out []Row
	for _, d := range res.Decisions {
		if d.Verdict != want {
			continue
		}
		out = append(out, Row{
			Layer:   firewallName(res),
			Verdict: firewallVerdictLabel(d.Verdict),
			Subject: d.Rule.String(),
			Detail:  decisionDetail(d),
			pinned:  true,
		})
	}
	return out
}

// firewallAbstentionRows renders the rule groups one firewall could not evaluate.
func firewallAbstentionRows(res nfw.Result) []Row {
	out := make([]Row, 0, len(res.Abstentions))
	for _, a := range res.Abstentions {
		out = append(out, Row{
			Layer:   firewallName(res),
			Verdict: labelAbstain,
			Subject: groupSubject(a),
			Detail:  a.Reason,
		})
	}
	return out
}

// decisionDetail describes the traffic a decision covered, and says when no rule
// matched it.
//
// A default action is called what it is. "Dropped by the policy default" and
// "dropped by a rule that names this traffic" send an operator to different
// places, and a row that showed only the verdict would let them read the first
// as the second.
func decisionDetail(d nfw.Decision) string {
	out := d.Slice.String()
	if d.ByDefault {
		return out + " — no rule matched, so the policy default action applied"
	}
	return out
}

// firewallName identifies the firewall a row belongs to, falling back through
// what the result carries rather than rendering an empty cell.
func firewallName(res nfw.Result) string {
	switch {
	case res.Firewall != "":
		return res.Firewall
	case res.Policy != "":
		return res.Policy
	default:
		return string(labelFirewallLayer)
	}
}

// labelFirewallLayer is the row label for a firewall whose result names neither
// the firewall nor its policy. It matches the Layer name the engine uses.
const labelFirewallLayer = "firewall"

// groupSubject identifies an unevaluated rule group the way an operator would
// look it up: by name where there is one, by ARN otherwise, with the priority
// that placed it in the policy.
func groupSubject(a nfw.Abstention) string {
	name := a.GroupName
	if name == "" {
		name = a.GroupARN
	}
	if name == "" {
		return "rule group"
	}
	if a.Priority > 0 {
		return fmt.Sprintf("%s (priority %d)", name, a.Priority)
	}
	return name
}

func firewallVerdictLabel(v nfw.Verdict) string {
	switch v {
	case nfw.Pass:
		return labelAllow
	case nfw.Drop:
		return labelDeny
	default:
		return labelAbstain
	}
}

// notEvaluatedGroups states why a policy verdict cannot be relied on.
// Requirement 14.6, in the vocabulary of a policy question: the group that could
// not be read is the group an operator has to go and read.
func notEvaluatedGroups(results []nfw.Result) string {
	var parts []string
	for _, res := range results {
		for _, a := range res.Abstentions {
			parts = append(parts, fmt.Sprintf("%s (%s)", groupSubject(a), a.Reason))
		}
	}
	if len(parts) == 0 {
		return "this verdict is not authoritative: it rests on a rule group that could not be evaluated"
	}
	return fmt.Sprintf("this verdict is not authoritative: it rests on %s — %s; an unevaluated rule group might have been the one that decided this flow",
		abstentionCount(len(parts)), strings.Join(parts, "; "))
}
