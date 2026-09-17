package format

// What projecting a walk has to preserve.
//
// A walk arrives as hops, abstentions, a reverse direction, and one firewall
// result per inspection point, and the projection has to put each of them
// somewhere a reader will find it. Three things fail silently if it does not: an
// abstention folded into the cleared hops reads as a pass, a blocking hop whose
// citations were dropped leaves an operator with a verdict and nowhere to check
// it, and a firewall decision taken by the row budget leaves a policy verdict with
// no policy behind it.
//
// Every address is RFC 1918 or RFC 5737 documentation space and every identifier
// is a placeholder, per requirement 17.

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/jajera/aws-netpath/internal/flow"
	"github.com/jajera/aws-netpath/internal/model"
	"github.com/jajera/aws-netpath/internal/nfw"
	"github.com/jajera/aws-netpath/internal/query"
)

// walkSlice is the flow every fixture here walks.
func walkSlice() flow.Slice {
	return flow.NewSlice(
		flow.NewPrefixSet(netip.MustParsePrefix("10.0.1.10/32")),
		flow.NewPrefixSet(netip.MustParsePrefix("10.1.2.30/32")),
		flow.ProtoTCP,
		flow.SinglePort(443),
	)
}

// blockedWalk is a walk that cleared routing and stopped at a NACL, with the
// firewall policy it met on the way.
func blockedWalk() *query.Result {
	blocked := query.Hop{
		Layer: "nacl", Region: "us-east-1", Resource: "acl-0123456789abcdef0",
		Detail: "no ingress rule allows tcp/443 from 10.0.1.10",
		Citations: []model.Citation{{
			Kind: "nacl", Identifier: "acl-0123456789abcdef0",
			Detail: "ingress rule 32767 denies all",
		}},
	}
	return &query.Result{
		Flow:    walkSlice(),
		Verdict: query.VerdictBlocked,
		Hops: []query.Hop{
			{
				Layer: "route", Region: "us-east-1", Resource: "rtb-0aaa1111bbbb2222c",
				Detail: "route: 10.1.0.0/16", NextHop: "tgw-0abc1234def567890", Allowed: true,
			},
			{
				Layer: "sg", Resource: "sg-0123456789abcdef0",
				Detail: "egress rule allows tcp/443 to 10.1.0.0/16", Allowed: true,
			},
		},
		BlockedAt: &blocked,
		Firewalls: []nfw.Result{permittingFirewall()},
	}
}

// abstainedWalk is the case requirement 14.6 exists for: nothing blocked, and one
// layer could not be evaluated, so "permitted" is not a claim this walk can make.
func abstainedWalk() *query.Result {
	return &query.Result{
		Flow:    walkSlice(),
		Verdict: query.VerdictPermitted,
		Hops: []query.Hop{
			{
				Layer: "route", Resource: "rtb-0aaa1111bbbb2222c",
				Detail: "route: 10.1.0.0/16", Allowed: true,
			},
		},
		Abstentions: []model.LayerResult{{
			Layer:   model.LayerFirewall,
			Verdict: model.VerdictAbstain,
			Reason:  "domain-allowlist (priority 1): domain list rule group is not modelled",
			Citations: []model.Citation{{
				Kind: "nfw_rule", Identifier: "domain-allowlist (priority 1)",
				Detail: "domain list rule group is not modelled",
			}},
		}},
	}
}

// permittingFirewall is one inspection point that passed the traffic on a rule.
func permittingFirewall() nfw.Result {
	return nfw.Result{
		Firewall: "nfw-inspection-use1",
		Region:   "us-east-1",
		Policy:   "inspection-policy",
		Decisions: []nfw.Decision{{
			Slice:   walkSlice(),
			Verdict: nfw.Pass,
			Rule: nfw.RuleRef{
				GroupName: "nfr-allow-east-west", Priority: 6, SID: "3", Action: "pass",
			},
		}},
	}
}

// A blocked walk names the hop that blocked, and keeps the evidence behind it.
// Requirement 14.1 and 14.2.
func TestFromQueryNamesTheBlockingHopWithItsEvidence(t *testing.T) {
	got := FromQuery(blockedWalk())

	if got.Kind != KindQuery {
		t.Errorf("kind = %q, want %q", got.Kind, KindQuery)
	}
	if !strings.Contains(got.Outcome, "acl-0123456789abcdef0") {
		t.Errorf("outcome = %q, want the blocking resource named", got.Outcome)
	}
	if got.Finding == nil {
		t.Fatal("a blocked walk carries no finding section")
	}

	finding := rowText(got.Finding.Rows)
	for _, want := range []string{"acl-0123456789abcdef0", "ingress rule 32767 denies all"} {
		if !strings.Contains(finding, want) {
			t.Errorf("the finding section omits %q:\n%s", want, finding)
		}
	}

	cleared := rowText(got.Cleared.Rows)
	for _, want := range []string{"rtb-0aaa1111bbbb2222c", "sg-0123456789abcdef0", "tgw-0abc1234def567890"} {
		if !strings.Contains(cleared, want) {
			t.Errorf("the cleared section omits %q:\n%s", want, cleared)
		}
	}

	// A block stands whatever abstained, so this one is authoritative: an
	// unevaluated layer cannot un-block traffic another layer already dropped.
	if !got.Authoritative {
		t.Error("a block with nothing abstained was reported as not authoritative")
	}
}

// A walk that met an abstention and found no blocker is not a pass.
// Cross-cutting semantic 1, requirement 14.6.
func TestFromQueryNeverReadsAnAbstentionAsAPass(t *testing.T) {
	got := FromQuery(abstainedWalk())

	if got.Authoritative {
		t.Error("a walk resting on an abstention was reported as authoritative")
	}
	if got.Notice == "" {
		t.Fatal("a non-authoritative walk states no reason")
	}
	if !strings.Contains(got.Notice, "domain list rule group is not modelled") {
		t.Errorf("the notice does not name what could not be evaluated: %q", got.Notice)
	}
	if got.Unresolved == nil || len(got.Unresolved.Rows) == 0 {
		t.Fatal("the abstention is absent from the unresolved section")
	}
	// The abstention must not also appear among the hops that cleared, which is the
	// one arrangement that would read as a pass.
	if cleared := rowText(got.Cleared.Rows); strings.Contains(cleared, "domain-allowlist") {
		t.Errorf("the abstained layer appears among the cleared hops:\n%s", cleared)
	}

	body := render(t, got, Options{Mode: ModeMarkdown})
	if !strings.Contains(body, "**Not authoritative.**") {
		t.Errorf("the markdown rendering drops the banner:\n%s", body)
	}
}

// A firewall decision survives the row budget. Requirement 14.4 against
// requirement 14.5: a display limit is not a reason to stop citing policy.
func TestFromQueryKeepsFirewallEvidenceUnderTheRowBudget(t *testing.T) {
	body := render(t, FromQuery(blockedWalk()), Options{Mode: ModeMarkdown, MaxRows: 1})

	if !strings.Contains(body, "nfr-allow-east-west sid 3 (priority 6)") {
		t.Errorf("the row budget took the firewall rule reference:\n%s", body)
	}
}

// An absent result says so rather than reporting a permit it did not earn.
func TestFromQueryHandlesAnAbsentWalk(t *testing.T) {
	got := FromQuery(nil)

	if got.Kind != KindQuery {
		t.Errorf("kind = %q, want %q", got.Kind, KindQuery)
	}
	if got.Outcome != outcomeNoWalk {
		t.Errorf("outcome = %q, want %q", got.Outcome, outcomeNoWalk)
	}
	if _, err := renderErr(got); err != nil {
		t.Errorf("rendering an absent walk failed: %v", err)
	}
}

// rowText joins a section's rows into one string, for assertions that care that a
// value reached the reader rather than which cell it landed in.
func rowText(rows []Row) string {
	parts := make([]string, 0, len(rows))
	for _, row := range rows {
		parts = append(parts, strings.Join([]string{row.Layer, row.Verdict, row.Subject, row.Detail}, " "))
	}
	return strings.Join(parts, "\n")
}
