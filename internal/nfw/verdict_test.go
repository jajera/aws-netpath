package nfw

import (
	"strings"
	"testing"

	"github.com/jajera/aws-netpath/internal/flow"
	"github.com/jajera/aws-netpath/internal/model"
)

// A permitted flow maps to a pass citing the rule that allowed it, in the same
// form the inherited reports already use.
func TestLayerResultPassCitesRule(t *testing.T) {
	group := &model.RuleGroup{
		Meta:      model.Meta{ARN: "arn:rg-allow", Name: "allow-east-west"},
		RuleOrder: model.StrictOrder,
		Rules:     []model.StatefulRule{passRule("3", "10.30.32.0/19", "10.30.192.0/20", "TCP", "443")},
	}
	policy := denyByDefault("use1", model.RuleGroupRef{ARN: "arn:rg-allow", Priority: 6})

	res, err := Evaluate(policy, map[string]*model.RuleGroup{"arn:rg-allow": group},
		mustSlice(t, "10.30.32.0/19", "10.30.192.0/20", "tcp", "443"))
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}

	lr := res.LayerResult()
	if err := lr.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if lr.Layer != model.LayerFirewall {
		t.Errorf("layer = %s, want %s", lr.Layer, model.LayerFirewall)
	}
	if lr.Verdict != model.VerdictPass {
		t.Fatalf("verdict = %s, want pass", lr.Verdict)
	}
	if got := lr.Citations[0].Identifier; got != "allow-east-west sid 3 (priority 6)" {
		t.Errorf("citation = %q, want the rule reference", got)
	}
	if got := lr.Citations[0].Kind; got != "nfw_rule" {
		t.Errorf("citation kind = %q, want nfw_rule", got)
	}
}

// A default drop maps to blocked, citing the default action rather than a rule.
func TestLayerResultBlockedCitesDefaultAction(t *testing.T) {
	policy := strictDenyByDefault("usw2")

	res, err := Evaluate(policy, nil, mustSlice(t, "10.30.32.0/19", "10.30.192.0/20", "tcp", "443"))
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}

	lr := res.LayerResult()
	if err := lr.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if lr.Verdict != model.VerdictBlocked {
		t.Fatalf("verdict = %s, want blocked", lr.Verdict)
	}
	if got := lr.Citations[0].Detail; !strings.Contains(got, "aws:drop_strict") {
		t.Errorf("citation detail = %q, want the policy default action", got)
	}
}

// Every construct the evaluator does not model must surface as an abstention
// naming it, never as a pass, even when the traffic falls through to a default
// action that would otherwise read as permitted.
func TestLayerResultAbstainsNamingTheConstruct(t *testing.T) {
	domains := &model.RuleGroup{
		Meta:          model.Meta{ARN: "arn:domains", Name: "domain-allowlist"},
		RuleOrder:     model.StrictOrder,
		DomainTargets: []string{".example.com"},
	}

	tests := []struct {
		name     string
		policy   *model.FirewallPolicy
		groups   map[string]*model.RuleGroup
		wantIn   string
		wantCite string
	}{
		{
			name:     "domain list",
			policy:   denyByDefault("p", model.RuleGroupRef{ARN: "arn:domains", Priority: 1}),
			groups:   map[string]*model.RuleGroup{"arn:domains": domains},
			wantIn:   "domain list",
			wantCite: "domain-allowlist (priority 1)",
		},
		{
			name:     "rule group absent from the snapshot",
			policy:   denyByDefault("p", model.RuleGroupRef{ARN: "arn:absent", Priority: 2}),
			groups:   map[string]*model.RuleGroup{},
			wantIn:   "absent from the snapshot",
			wantCite: "arn:absent (priority 2)",
		},
		{
			name: "policy evaluated by default action order",
			policy: &model.FirewallPolicy{
				Meta:                   model.Meta{ID: "p", Name: "p"},
				StatefulRuleOrder:      model.DefaultActionOrder,
				StatefulDefaultActions: []string{"aws:drop_strict"},
			},
			wantIn:   "DEFAULT_ACTION_ORDER",
			wantCite: "p",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res, err := Evaluate(tc.policy, tc.groups, mustSlice(t, "10.0.0.0/8", "10.1.0.0/16", "tcp", "443"))
			if err != nil {
				t.Fatalf("Evaluate: %v", err)
			}
			if res.Certain() {
				t.Fatal("expected the evaluator to abstain")
			}

			lr := res.LayerResult()
			if err := lr.Validate(); err != nil {
				t.Fatalf("Validate: %v", err)
			}
			if lr.Verdict != model.VerdictAbstain {
				t.Fatalf("verdict = %s, want abstain", lr.Verdict)
			}
			if !strings.Contains(lr.Reason, tc.wantIn) {
				t.Errorf("reason = %q, want it to name %q", lr.Reason, tc.wantIn)
			}
			if got := lr.Citations[0].Identifier; got != tc.wantCite {
				t.Errorf("citation = %q, want %q", got, tc.wantCite)
			}

			// The single-abstention mapping must agree with the result-level one.
			one := res.Abstentions[0].LayerResult()
			if one.Verdict != model.VerdictAbstain || !strings.Contains(one.Reason, tc.wantIn) {
				t.Errorf("abstention mapped to %+v", one)
			}
		})
	}
}

// A firewall abstention must leave the correlated verdict non-authoritative,
// which is the whole point of mapping it rather than dropping it.
func TestFirewallAbstentionMakesVerdictNonAuthoritative(t *testing.T) {
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

	v := model.Verdict{Results: []model.LayerResult{res.LayerResult()}}
	if err := v.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if v.ComputeAuthoritative() {
		t.Error("a firewall abstention must not yield an authoritative verdict")
	}
}

// An empty flow decides nothing, so it must not read as permitted either.
func TestLayerResultAbstainsWithoutDecisions(t *testing.T) {
	res, err := Evaluate(strictDenyByDefault("p"), nil, flow.Slice{})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}

	lr := res.LayerResult()
	if err := lr.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if lr.Verdict != model.VerdictAbstain {
		t.Fatalf("verdict = %s, want abstain", lr.Verdict)
	}
	if !strings.Contains(lr.Reason, "no decision") {
		t.Errorf("reason = %q, want it to state that nothing was decided", lr.Reason)
	}
}
