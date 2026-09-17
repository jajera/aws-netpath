package nfw

import (
	"strings"
	"testing"

	"github.com/jajera/aws-netpath/internal/flow"
	"github.com/jajera/aws-netpath/internal/model"
)

func mustSlice(t *testing.T, src, dst, proto, ports string) flow.Slice {
	t.Helper()
	s, err := flow.ParsePrefixSet(src)
	if err != nil {
		t.Fatalf("src %q: %v", src, err)
	}
	d, err := flow.ParsePrefixSet(dst)
	if err != nil {
		t.Fatalf("dst %q: %v", dst, err)
	}
	p, err := flow.ParseProtocol(proto)
	if err != nil {
		t.Fatalf("proto %q: %v", proto, err)
	}
	ports2, err := flow.ParsePortSet(ports)
	if err != nil {
		t.Fatalf("ports %q: %v", ports, err)
	}
	return flow.NewSlice(s, d, p, ports2)
}

// denyByDefault builds a policy with the common production posture: strict order,
// alert on unmatched traffic, drop only established flows without a matching rule.
func denyByDefault(name string, refs ...model.RuleGroupRef) *model.FirewallPolicy {
	return &model.FirewallPolicy{
		Meta:                   model.Meta{ID: name, Name: name},
		StatefulRuleOrder:      model.StrictOrder,
		StatefulDefaultActions: []string{"aws:drop_established", "aws:alert_strict"},
		StatefulGroups:         refs,
	}
}

func strictDenyByDefault(name string, refs ...model.RuleGroupRef) *model.FirewallPolicy {
	return &model.FirewallPolicy{
		Meta:                   model.Meta{ID: name, Name: name},
		StatefulRuleOrder:      model.StrictOrder,
		StatefulDefaultActions: []string{"aws:drop_strict", "aws:drop_established", "aws:alert_strict"},
		StatefulGroups:         refs,
	}
}

func passRule(sid, src, dst, proto, port string) model.StatefulRule {
	return model.StatefulRule{
		Action: "PASS", Protocol: proto, SID: sid, Direction: model.DirForward,
		Source: src, SourcePort: "ANY", Destination: dst, DestinationPort: port,
	}
}

func TestPassRulePermitsAndCitesRule(t *testing.T) {
	group := &model.RuleGroup{
		Meta:      model.Meta{ID: "rg-allow", ARN: "arn:rg-allow", Name: "allow-east-west"},
		RuleOrder: model.StrictOrder,
		Rules:     []model.StatefulRule{passRule("3", "10.30.32.0/19", "10.30.192.0/20", "TCP", "443")},
	}
	policy := denyByDefault("use1", model.RuleGroupRef{ARN: "arn:rg-allow", Priority: 6})
	groups := map[string]*model.RuleGroup{"arn:rg-allow": group}

	res, err := Evaluate(policy, groups, mustSlice(t, "10.30.32.0/19", "10.30.192.0/20", "tcp", "443"))
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}

	if res.Denied().IsEmpty() != true {
		t.Errorf("expected nothing denied, got %s", res.Denied())
	}
	if res.Permitted().IsEmpty() {
		t.Fatal("expected traffic to be permitted")
	}
	if !res.Certain() {
		t.Errorf("expected a certain result, got abstentions %+v", res.Abstentions)
	}

	d := res.Decisions[0]
	if d.Rule.SID != "3" || d.Rule.Priority != 6 || d.Rule.GroupName != "allow-east-west" {
		t.Errorf("verdict cites %s, want allow-east-west sid 3 priority 6", d.Rule)
	}
}

func TestUnmatchedTrafficPassesWithDropEstablishedOnly(t *testing.T) {
	policy := denyByDefault("usw2")

	res, err := Evaluate(policy, nil, mustSlice(t, "10.30.32.0/19", "10.30.192.0/20", "tcp", "443"))
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}

	if !res.Denied().IsEmpty() {
		t.Errorf("expected nothing denied, got %s", res.Denied())
	}
	if res.Permitted().IsEmpty() {
		t.Fatal("expected traffic to be permitted by default")
	}
	if d := res.Decisions[0]; !d.ByDefault || !strings.Contains(d.Rule.Action, "aws:drop_established") {
		t.Errorf("expected default pass, got %+v", d)
	}
}

func TestUnmatchedTrafficHitsDefaultDropStrict(t *testing.T) {
	policy := strictDenyByDefault("usw2")

	res, err := Evaluate(policy, nil, mustSlice(t, "10.30.32.0/19", "10.30.192.0/20", "tcp", "443"))
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}

	if !res.Permitted().IsEmpty() {
		t.Errorf("expected nothing permitted, got %s", res.Permitted())
	}
	if res.Denied().IsEmpty() {
		t.Fatal("expected traffic to be denied")
	}
	if d := res.Decisions[0]; !d.ByDefault || !strings.Contains(d.Rule.Action, "aws:drop_strict") {
		t.Errorf("expected default drop, got %+v", d)
	}
}

// A rule permitting one port must split the flow, leaving the rest to default.
func TestPartialPortMatchSplitsTraffic(t *testing.T) {
	group := &model.RuleGroup{
		Meta:      model.Meta{ARN: "arn:rg", Name: "web-only"},
		RuleOrder: model.StrictOrder,
		Rules:     []model.StatefulRule{passRule("1", "ANY", "ANY", "TCP", "443")},
	}
	policy := strictDenyByDefault("p", model.RuleGroupRef{ARN: "arn:rg", Priority: 1})

	res, err := Evaluate(policy, map[string]*model.RuleGroup{"arn:rg": group},
		mustSlice(t, "10.0.0.0/8", "10.1.0.0/16", "tcp", "443,8080"))
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}

	if got := res.Permitted().String(); !strings.Contains(got, "443") || strings.Contains(got, "8080") {
		t.Errorf("permitted = %s, want only 443", got)
	}
	if got := res.Denied().String(); !strings.Contains(got, "8080") {
		t.Errorf("denied = %s, want 8080", got)
	}
}

// Lower priority numbers are evaluated first, so a drop at priority 1 wins over
// a pass at priority 2 even though the pass rule also matches.
func TestLowerPriorityGroupDecidesFirst(t *testing.T) {
	deny := &model.RuleGroup{
		Meta:      model.Meta{ARN: "arn:deny", Name: "deny-ssh"},
		RuleOrder: model.StrictOrder,
		Rules: []model.StatefulRule{{
			Action: "DROP", Protocol: "TCP", SID: "9", Direction: model.DirForward,
			Source: "ANY", SourcePort: "ANY", Destination: "ANY", DestinationPort: "22",
		}},
	}
	allow := &model.RuleGroup{
		Meta:      model.Meta{ARN: "arn:allow", Name: "allow-all"},
		RuleOrder: model.StrictOrder,
		Rules:     []model.StatefulRule{passRule("1", "ANY", "ANY", "TCP", "ANY")},
	}
	policy := denyByDefault("p",
		model.RuleGroupRef{ARN: "arn:allow", Priority: 2},
		model.RuleGroupRef{ARN: "arn:deny", Priority: 1},
	)
	groups := map[string]*model.RuleGroup{"arn:deny": deny, "arn:allow": allow}

	res, err := Evaluate(policy, groups, mustSlice(t, "10.0.0.0/8", "10.1.0.0/16", "tcp", "22"))
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !res.Permitted().IsEmpty() {
		t.Errorf("permitted = %s, want none", res.Permitted())
	}
	if d := res.Decisions[0]; d.Rule.SID != "9" {
		t.Errorf("decided by %s, want deny-ssh sid 9", d.Rule)
	}
}

// An ALERT rule logs without deciding, so traffic continues to later rules.
func TestAlertRuleDoesNotDecide(t *testing.T) {
	group := &model.RuleGroup{
		Meta:      model.Meta{ARN: "arn:rg", Name: "monitor"},
		RuleOrder: model.StrictOrder,
		Rules: []model.StatefulRule{
			{Action: "ALERT", Protocol: "TCP", SID: "1", Direction: model.DirForward,
				Source: "ANY", SourcePort: "ANY", Destination: "ANY", DestinationPort: "ANY"},
			passRule("2", "ANY", "ANY", "TCP", "443"),
		},
	}
	policy := denyByDefault("p", model.RuleGroupRef{ARN: "arn:rg", Priority: 1})

	res, err := Evaluate(policy, map[string]*model.RuleGroup{"arn:rg": group},
		mustSlice(t, "10.0.0.0/8", "10.1.0.0/16", "tcp", "443"))
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res.Permitted().IsEmpty() {
		t.Fatal("alert should not have consumed the traffic")
	}
	if d := res.Decisions[0]; d.Rule.SID != "2" {
		t.Errorf("decided by %s, want sid 2", d.Rule)
	}
}

// A rule with direction ANY matches traffic flowing the other way too.
func TestBidirectionalRuleMatchesReverse(t *testing.T) {
	group := &model.RuleGroup{
		Meta:      model.Meta{ARN: "arn:rg", Name: "any-direction"},
		RuleOrder: model.StrictOrder,
		Rules: []model.StatefulRule{{
			Action: "PASS", Protocol: "IP", SID: "1", Direction: model.DirAny,
			Source: "10.30.0.0/19", SourcePort: "ANY",
			Destination: "10.30.128.0/19", DestinationPort: "ANY",
		}},
	}
	policy := denyByDefault("p", model.RuleGroupRef{ARN: "arn:rg", Priority: 1})
	groups := map[string]*model.RuleGroup{"arn:rg": group}

	// Reverse of the rule as written.
	res, err := Evaluate(policy, groups, mustSlice(t, "10.30.128.0/19", "10.30.0.0/19", "tcp", "443"))
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res.Permitted().IsEmpty() {
		t.Errorf("reverse direction should match, decisions: %+v", res.Decisions)
	}
}

// A domain allowlist cannot be judged on the 5-tuple, so the evaluator must
// abstain loudly rather than assume the traffic is dropped.
func TestDomainListProducesAbstention(t *testing.T) {
	domains := &model.RuleGroup{
		Meta:          model.Meta{ARN: "arn:domains", Name: "domain-allowlist"},
		RuleOrder:     model.StrictOrder,
		DomainTargets: []string{".example.com"},
	}
	policy := denyByDefault("p", model.RuleGroupRef{ARN: "arn:domains", Priority: 1})

	res, err := Evaluate(policy, map[string]*model.RuleGroup{"arn:domains": domains},
		mustSlice(t, "10.0.0.0/8", "10.1.0.0/16", "tcp", "443"))
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}

	if res.Certain() {
		t.Fatal("expected an abstention for the domain list")
	}
	if got := res.Abstentions[0].Reason; !strings.Contains(got, "domain list") {
		t.Errorf("abstention reason = %q, want it to mention the domain list", got)
	}
	// The traffic still falls through to the default action, but the caller can
	// see the verdict is not authoritative.
	if res.Permitted().IsEmpty() {
		t.Error("expected the default action to pass new flows")
	}
}

// A rule group named by the policy but missing from the snapshot, usually a
// permissions gap during collection, must not be silently ignored.
func TestMissingRuleGroupProducesAbstention(t *testing.T) {
	policy := denyByDefault("p", model.RuleGroupRef{ARN: "arn:absent", Priority: 1})

	res, err := Evaluate(policy, map[string]*model.RuleGroup{}, mustSlice(t, "10.0.0.0/8", "10.1.0.0/16", "tcp", "443"))
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res.Certain() {
		t.Fatal("expected an abstention for the missing rule group")
	}
	if got := res.Abstentions[0].Reason; !strings.Contains(got, "absent from the snapshot") {
		t.Errorf("abstention reason = %q", got)
	}
}

// The case that motivates the tool: traffic crossing a region boundary is
// inspected twice, and a rule present in only one region does not make the flow
// work. No single Reachability Analyzer run can show this.
func TestDoubleInspectionAcrossRegions(t *testing.T) {
	eastAllows := &model.RuleGroup{
		Meta:      model.Meta{ARN: "arn:east", Name: "allow-prod-to-edge"},
		RuleOrder: model.StrictOrder,
		Rules:     []model.StatefulRule{passRule("3", "10.30.32.0/19", "10.30.192.0/20", "TCP", "443")},
	}
	east := denyByDefault("use1", model.RuleGroupRef{ARN: "arn:east", Priority: 6})
	// West uses strict default drop; East permits the flow.
	west := strictDenyByDefault("usw2")

	traffic := mustSlice(t, "10.30.32.0/19", "10.30.192.0/20", "tcp", "443")

	first, err := Evaluate(east, map[string]*model.RuleGroup{"arn:east": eastAllows}, traffic)
	if err != nil {
		t.Fatalf("east: %v", err)
	}
	if first.Permitted().IsEmpty() {
		t.Fatal("east should permit the flow")
	}

	// Only what survived the first firewall reaches the second.
	survived := first.Permitted().Slices[0]
	second, err := Evaluate(west, nil, survived)
	if err != nil {
		t.Fatalf("west: %v", err)
	}
	if !second.Permitted().IsEmpty() {
		t.Errorf("west has no matching rule, so nothing should survive")
	}
	if d := second.Decisions[0]; !d.ByDefault {
		t.Errorf("expected west default drop, got %+v", d)
	}
}
