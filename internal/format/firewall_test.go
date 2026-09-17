package format

// What projecting a policy evaluation has to preserve.
//
// Requirement 14.4 is the whole of it: the rule group, priority, and SID behind
// every firewall decision. This is the one report where the decisions are the
// finding, so the two ways of losing them both matter — dropping the permits
// because only denials look like evidence, and letting the row budget take rows
// that requirement 14.4 says are not optional.

import (
	"strings"
	"testing"

	"github.com/jajera/aws-netpath/internal/nfw"
)

// splitPolicy is one firewall that passed part of the requested port set on a rule
// and dropped the rest on the policy default, with a rule group it could not read.
//
// A rule matching part of a port set splits the flow rather than deciding it, so
// this is the ordinary shape rather than an awkward case.
func splitPolicy() FirewallEvaluation {
	return FirewallEvaluation{
		Flow:          walkSlice().String(),
		Blocked:       true,
		Authoritative: false,
		Results: []nfw.Result{{
			Firewall: "nfw-inspection-use1",
			Region:   "us-east-1",
			Policy:   "inspection-policy",
			Decisions: []nfw.Decision{
				{
					Slice:   walkSlice(),
					Verdict: nfw.Pass,
					Rule: nfw.RuleRef{
						GroupName: "nfr-allow-east-west", Priority: 6, SID: "3", Action: "pass",
					},
				},
				{
					Slice:     walkSlice(),
					Verdict:   nfw.Drop,
					ByDefault: true,
				},
			},
			Abstentions: []nfw.Abstention{{
				GroupName: "domain-allowlist",
				Priority:  1,
				Reason:    "domain list rule group is not modelled",
			}},
		}},
	}
}

// Every decision carries the rule that made it, permits included.
// Requirement 14.4.
func TestFromFirewallCitesTheRuleBehindEveryDecision(t *testing.T) {
	got := FromFirewall(splitPolicy())

	if got.Kind != KindFirewall {
		t.Errorf("kind = %q, want %q", got.Kind, KindFirewall)
	}
	if !strings.Contains(got.Outcome, "nfw-inspection-use1") {
		t.Errorf("outcome = %q, want the firewall that denied named", got.Outcome)
	}

	if denied := rowText(got.Finding.Rows); !strings.Contains(denied, "default action") {
		t.Errorf("the denial does not say the policy default applied:\n%s", denied)
	}
	permitted := rowText(got.Cleared.Rows)
	if !strings.Contains(permitted, "nfr-allow-east-west sid 3 (priority 6)") {
		t.Errorf("the permit carries no rule reference:\n%s", permitted)
	}
}

// A rule group that could not be evaluated is reported as one, with the construct
// that could not be modelled. Requirement 5.4 and 14.6.
func TestFromFirewallReportsAnUnevaluatedRuleGroup(t *testing.T) {
	got := FromFirewall(splitPolicy())

	if got.Authoritative {
		t.Error("a policy verdict resting on an unread rule group was reported as authoritative")
	}
	if !strings.Contains(got.Notice, "domain-allowlist (priority 1)") {
		t.Errorf("the notice does not name the unread rule group: %q", got.Notice)
	}
	if unresolved := rowText(got.Unresolved.Rows); !strings.Contains(unresolved, "domain list rule group is not modelled") {
		t.Errorf("the abstention carries no reason:\n%s", unresolved)
	}
}

// The rule references survive a budget that could not fit them.
// Requirement 14.4 against requirement 14.5.
func TestFromFirewallKeepsEveryRuleUnderTheRowBudget(t *testing.T) {
	body := render(t, FromFirewall(splitPolicy()), Options{Mode: ModeMarkdown, MaxRows: 1})

	for _, want := range []string{"nfr-allow-east-west sid 3 (priority 6)", "default action"} {
		if !strings.Contains(body, want) {
			t.Errorf("the row budget took %q:\n%s", want, body)
		}
	}
}

// A snapshot holding no firewall has not permitted the flow.
func TestFromFirewallDoesNotReadNoFirewallAsAPermit(t *testing.T) {
	got := FromFirewall(FirewallEvaluation{Flow: walkSlice().String()})

	if got.Outcome != outcomeNoFirewall {
		t.Errorf("outcome = %q, want %q", got.Outcome, outcomeNoFirewall)
	}
	if strings.Contains(got.Outcome, outcomePermitted) {
		t.Errorf("outcome = %q, which reads as a permit", got.Outcome)
	}
	if _, err := renderErr(got); err != nil {
		t.Errorf("rendering an empty evaluation failed: %v", err)
	}
}
