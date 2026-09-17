package nfw

import (
	"testing"

	"github.com/jajera/aws-netpath/internal/flow"
	"github.com/jajera/aws-netpath/internal/model"
)

func TestParseRulesStringExpandsIPSetVariables(t *testing.T) {
	rules := "pass tcp $SRC_0 any -> $DEST 53 (sid:1; rev:1;)\npass udp $SRC_0 any -> $DEST 53 (sid:2; rev:1;)"
	vars := map[string][]string{
		"SRC_0": {"10.30.160.0/19", "10.30.192.0/20"},
		"DEST":  {"10.29.16.144/32", "10.29.16.167/32", "10.29.16.178/32"},
	}

	got, err := ParseRulesString(rules, vars)
	if err != nil {
		t.Fatalf("ParseRulesString: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d rules, want 2", len(got))
	}
	if got[0].Source != "10.30.160.0/19,10.30.192.0/20" {
		t.Errorf("source = %q", got[0].Source)
	}
	if got[0].Destination != "10.29.16.144/32,10.29.16.167/32,10.29.16.178/32" {
		t.Errorf("destination = %q", got[0].Destination)
	}
}

func TestSharedServicesDNSRuleGroupPermitsProdWest(t *testing.T) {
	group := &model.RuleGroup{
		Meta:      model.Meta{ARN: "arn:dns", Name: "nfr-prod-usw2-svc-shared-services-dns"},
		RuleOrder: model.StrictOrder,
		RulesString: "pass tcp $SRC_0 any -> $DEST 53 (sid:1; rev:1;)\n" +
			"pass udp $SRC_0 any -> $DEST 53 (sid:2; rev:1;)",
		RuleVariables: map[string][]string{
			"SRC_0": {"10.30.192.0/20", "10.30.160.0/19"},
			"DEST":  {"10.29.16.144/32", "10.29.16.167/32", "10.29.16.178/32"},
		},
	}
	policy := denyByDefault("usw2", model.RuleGroupRef{ARN: "arn:dns", Priority: 20})

	res, err := Evaluate(policy, map[string]*model.RuleGroup{"arn:dns": group},
		mustSlice(t, "10.30.163.155/32", "10.29.16.144/32", "tcp", "53"))
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res.Permitted().IsEmpty() {
		t.Fatalf("expected permitted, decisions=%+v abstentions=%+v", res.Decisions, res.Abstentions)
	}
	if !res.Denied().IsEmpty() {
		t.Errorf("denied = %s", res.Denied())
	}
}

func TestResolvedRulesUsesExplicitRulesFirst(t *testing.T) {
	group := &model.RuleGroup{
		Rules:       []model.StatefulRule{{Action: "PASS", Protocol: "TCP", Source: "10.0.0.0/8", Destination: "ANY", SourcePort: "ANY", DestinationPort: "443", Direction: model.DirForward}},
		RulesString: "pass tcp $SRC_0 any -> $DEST 53 (sid:1; rev:1;)",
	}
	got, err := ResolvedRules(group)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Source != "10.0.0.0/8" {
		t.Fatalf("got %+v", got)
	}
	_ = flow.ProtoTCP
}
