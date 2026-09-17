package format

// Fixtures for the renderer tests.
//
// Every address is RFC 1918 or RFC 5737 documentation space and every identifier
// is a placeholder, so a golden file can never carry an environment detail out of
// the repository.
//
// The Verdicts are validated rather than asserted: model.Verdict.Validate refuses
// an Abstention without a reason, a decision without a Citation, and a blocked
// Layer missing from the blocker list, so a fixture that drifts into a shape the
// engine could not produce fails here instead of quietly making a renderer test
// meaningless.

import (
	"fmt"
	"testing"

	"github.com/jajera/aws-netpath/internal/compare"
	"github.com/jajera/aws-netpath/internal/model"
	"github.com/jajera/aws-netpath/internal/symptom"
)

func layer(l model.Layer) *model.Layer { return &l }

// blockedDiagnosis is the motivating incident: every cloud Layer permits the
// flow, and the host firewall allowlist does not cover the source.
//
// The Layer findings are deliberately out of flow order, because the renderer
// sorts them and a fixture already in order would not show it.
func blockedDiagnosis(t *testing.T) Diagnosis {
	t.Helper()

	v := model.Verdict{
		PrimaryBlocker: layer(model.LayerHostFirewall),
		Results: []model.LayerResult{
			{
				Layer:   model.LayerHostFirewall,
				Verdict: model.VerdictBlocked,
				Citations: []model.Citation{{
					Kind:       "command",
					Identifier: "firewall-cmd --zone=public --list-rich-rules",
					Detail:     "zone public allows 10.0.2.0/24 and 10.0.3.0/24; source 10.0.1.10 is in neither",
				}},
			},
			{
				Layer:   model.LayerFirewall,
				Verdict: model.VerdictPass,
				Citations: []model.Citation{{
					Kind:       "nfw_rule",
					Identifier: "nfr-allow-east-west sid 3 (priority 6)",
					Detail:     "PASS",
				}},
			},
			{
				Layer:   model.LayerRoute,
				Verdict: model.VerdictPass,
				Citations: []model.Citation{{
					Kind:       "route",
					Identifier: "rtb-0aaa1111bbbb2222c",
					Detail:     "route: 10.1.0.0/16 -> tgw-0abc1234def567890",
				}},
			},
			{
				Layer:   model.LayerNACL,
				Verdict: model.VerdictPass,
				Citations: []model.Citation{{
					Kind:       "nacl",
					Identifier: "acl-0123456789abcdef0",
					Detail:     "egress rule 100 allows tcp/443",
				}},
			},
			{
				Layer:   model.LayerSecurityGroup,
				Verdict: model.VerdictPass,
				Citations: []model.Citation{{
					Kind:       "security_group",
					Identifier: "sg-0123456789abcdef0",
					Detail:     "egress rule allows tcp/443 to 10.1.0.0/16",
				}},
			},
			{
				Layer:   model.LayerHostListener,
				Verdict: model.VerdictPass,
				Citations: []model.Citation{{
					Kind:       "command",
					Identifier: "ss -tlnp",
					Detail:     "listening on 0.0.0.0:443",
				}},
			},
			{
				Layer:   model.LayerResolution,
				Verdict: model.VerdictPass,
				Citations: []model.Citation{{
					Kind:       "resolution",
					Identifier: "eni-0123456789abcdef0",
					Detail:     "source 10.0.1.10 resolved to i-0123456789abcdef0 in subnet-0123456789abcdef0",
				}},
			},
		},
	}
	v.ComputeAuthoritative()
	if err := v.Validate(); err != nil {
		t.Fatalf("blocked fixture is not a verdict the engine could produce: %v", err)
	}

	return Diagnosis{
		Flow:        "10.0.1.10/32 -> 10.1.2.30/32 tcp/443",
		Source:      "10.0.1.10 (eni-0123456789abcdef0) in subnet-0123456789abcdef0",
		Destination: "10.1.2.30 (eni-0abcdef123456789a) in subnet-0abcdef123456789a",
		Symptom:     string(symptom.Timeout),
		Host:        "i-0abcdef123456789a (probed)",
		Verdict:     v,
		Notes: []string{
			"return direction uses any destination port for TCP/UDP (client ephemeral port unknown)",
		},
	}
}

// abstainedDiagnosis is the case requirement 14.6 exists for: no Layer blocked,
// and one Layer could not be evaluated, so "permitted" is not a claim this run
// can make.
func abstainedDiagnosis(t *testing.T) Diagnosis {
	t.Helper()

	v := model.Verdict{
		Results: []model.LayerResult{
			{
				Layer:   model.LayerResolution,
				Verdict: model.VerdictPass,
				Citations: []model.Citation{{
					Kind:       "resolution",
					Identifier: "eni-0123456789abcdef0",
					Detail:     "source 10.0.1.10 resolved to i-0123456789abcdef0 in subnet-0123456789abcdef0",
				}},
			},
			{
				Layer:   model.LayerRoute,
				Verdict: model.VerdictPass,
				Citations: []model.Citation{{
					Kind:       "route",
					Identifier: "rtb-0aaa1111bbbb2222c",
					Detail:     "route: 198.51.100.0/24 -> igw-0123456789abcdef0",
				}},
			},
			{
				Layer:   model.LayerFirewall,
				Verdict: model.VerdictAbstain,
				Reason:  "nfw-inspection-usw2: domain-allowlist (priority 1): domain list rule group is not modelled",
				Citations: []model.Citation{{
					Kind:       "nfw_rule",
					Identifier: "domain-allowlist (priority 1)",
					Detail:     "domain list rule group is not modelled",
				}},
			},
			{
				Layer:   model.LayerHostFirewall,
				Verdict: model.VerdictAbstain,
				Reason:  "systems manager does not manage i-0abcdef123456789a, so the host firewall was not read",
			},
		},
	}
	v.ComputeAuthoritative()
	if err := v.Validate(); err != nil {
		t.Fatalf("abstained fixture is not a verdict the engine could produce: %v", err)
	}

	return Diagnosis{
		Flow:        "10.0.1.10/32 -> 198.51.100.5/32 tcp/443",
		Source:      "10.0.1.10 (eni-0123456789abcdef0) in subnet-0123456789abcdef0",
		Destination: "198.51.100.5 (declared external partner-service)",
		Verdict:     v,
	}
}

// comparisonResult is built by the Comparator itself rather than assembled by
// hand, so the renderer is tested against the shape the operation really
// produces.
func comparisonResult(t *testing.T) *compare.Result {
	t.Helper()

	shared := []model.LayerResult{
		{
			Layer:   model.LayerRoute,
			Verdict: model.VerdictPass,
			Citations: []model.Citation{{
				Kind: "route", Identifier: "rtb-0aaa1111bbbb2222c",
				Detail: "route: 10.1.0.0/16 -> tgw-0abc1234def567890",
			}},
		},
		{
			Layer:   model.LayerNACL,
			Verdict: model.VerdictPass,
			Citations: []model.Citation{{
				Kind: "nacl", Identifier: "acl-0123456789abcdef0",
				Detail: "egress rule 100 allows tcp/443",
			}},
		},
		{
			Layer:   model.LayerFirewall,
			Verdict: model.VerdictPass,
			Citations: []model.Citation{{
				Kind: "nfw_rule", Identifier: "nfr-allow-east-west sid 3 (priority 6)",
				Detail: "PASS",
			}},
		},
	}

	subject := model.Verdict{
		PrimaryBlocker: layer(model.LayerHostFirewall),
		Results: append(append([]model.LayerResult(nil), shared...),
			model.LayerResult{
				Layer:   model.LayerSecurityGroup,
				Verdict: model.VerdictPass,
				Citations: []model.Citation{{
					Kind: "security_group", Identifier: "sg-0111111111111111a",
					Detail: "egress rule allows tcp/443 to 10.1.0.0/16",
				}},
			},
			model.LayerResult{
				Layer:   model.LayerHostFirewall,
				Verdict: model.VerdictBlocked,
				Citations: []model.Citation{{
					Kind: "command", Identifier: "firewall-cmd --zone=public --list-rich-rules",
					Detail: "zone public allows 10.0.2.0/24; source 10.0.1.10 is not covered",
				}},
			},
		),
	}
	subject.ComputeAuthoritative()

	reference := model.Verdict{
		Results: append(append([]model.LayerResult(nil), shared...),
			model.LayerResult{
				Layer:   model.LayerSecurityGroup,
				Verdict: model.VerdictPass,
				Citations: []model.Citation{{
					Kind: "security_group", Identifier: "sg-0222222222222222b",
					Detail: "egress rule allows tcp/443 to 10.1.0.0/16",
				}},
			},
			model.LayerResult{
				Layer:   model.LayerHostFirewall,
				Verdict: model.VerdictPass,
				Citations: []model.Citation{{
					Kind: "command", Identifier: "firewall-cmd --zone=public --list-rich-rules",
					Detail: "zone public allows 10.0.2.0/24; source 10.0.2.20 is covered",
				}},
			},
		),
	}
	reference.ComputeAuthoritative()

	for name, v := range map[string]model.Verdict{"subject": subject, "reference": reference} {
		if err := v.Validate(); err != nil {
			t.Fatalf("%s fixture is not a verdict the engine could produce: %v", name, err)
		}
	}

	res, err := compare.Paths(
		compare.Side{
			Label: compare.SubjectLabel, From: "10.0.1.10", To: "10.1.2.30",
			Symptom: symptom.Timeout, Verdict: subject,
		},
		compare.Side{
			Label: compare.ReferenceLabel, From: "10.0.2.20", To: "10.1.2.30",
			Verdict: reference,
		},
	)
	if err != nil {
		t.Fatalf("compare.Paths: %v", err)
	}
	return res
}

// repeatedRowsDiagnosis is the case the markdown row budget exists for: a long
// path whose ROUTE Layer carries a Citation per forwarding decision, alongside a
// firewall decision whose rule reference must survive the budget.
func repeatedRowsDiagnosis(t *testing.T) Diagnosis {
	t.Helper()

	routes := make([]model.Citation, 0, 12)
	for i := range 12 {
		routes = append(routes, model.Citation{
			Kind:       "route",
			Identifier: fmt.Sprintf("rtb-0aaa1111bbbb2222%02d", i),
			Detail:     fmt.Sprintf("route: 10.%d.0.0/16 -> tgw-0abc1234def567890", i+1),
		})
	}

	v := model.Verdict{
		PrimaryBlocker: layer(model.LayerNACL),
		Results: []model.LayerResult{
			{Layer: model.LayerRoute, Verdict: model.VerdictPass, Citations: routes},
			{
				Layer:   model.LayerFirewall,
				Verdict: model.VerdictPass,
				Citations: []model.Citation{
					{Kind: "nfw_rule", Identifier: "nfr-allow-east-west sid 3 (priority 6)", Detail: "PASS"},
					{Kind: "nfw_rule", Identifier: "nfr-inspect-egress sid 11 (priority 20)", Detail: "PASS"},
				},
			},
			{
				Layer:   model.LayerNACL,
				Verdict: model.VerdictBlocked,
				Citations: []model.Citation{{
					Kind: "nacl", Identifier: "acl-0123456789abcdef0",
					Detail: "no ingress rule allows tcp/443 from 10.0.1.10",
				}},
			},
		},
	}
	v.ComputeAuthoritative()
	if err := v.Validate(); err != nil {
		t.Fatalf("repeated-rows fixture is not a verdict the engine could produce: %v", err)
	}

	return Diagnosis{
		Flow:    "10.0.1.10/32 -> 10.12.2.30/32 tcp/443",
		Verdict: v,
	}
}
