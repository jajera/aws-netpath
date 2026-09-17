package nfw

import (
	"fmt"
	"strings"

	"github.com/jajera/aws-netpath/internal/model"
)

// citationKind is the evidence category the shared model uses for firewall
// findings.
const citationKind = "nfw_rule"

// subject names the rule group an abstention came from, preferring the group
// name and falling back to its ARN. An abstention recorded against the policy
// itself carries the policy name in GroupName.
func (a Abstention) subject() string {
	name := a.GroupName
	if name == "" {
		name = a.GroupARN
	}
	if name == "" {
		return ""
	}
	if a.Priority > 0 {
		return fmt.Sprintf("%s (priority %d)", name, a.Priority)
	}
	return name
}

// Describe renders the abstention as one line naming both the rule group and
// the construct that could not be modelled. Requirement 5.4 asks for the
// construct to be named; the existing Reason strings already do that, so this
// only prefixes the group they were recorded against.
func (a Abstention) Describe() string {
	subject := a.subject()
	if subject == "" {
		return a.Reason
	}
	return fmt.Sprintf("%s: %s", subject, a.Reason)
}

// Citation renders the abstention as evidence, so an unevaluated rule group is
// as traceable as a rule that decided the traffic.
func (a Abstention) Citation() model.Citation {
	subject := a.subject()
	if subject == "" {
		subject = "firewall policy"
	}
	return model.Citation{Kind: citationKind, Identifier: subject, Detail: a.Reason}
}

// LayerResult maps the abstention onto the FIREWALL Layer of the shared verdict
// model, preserving the construct name in Reason.
func (a Abstention) LayerResult() model.LayerResult {
	return model.LayerResult{
		Layer:     model.LayerFirewall,
		Verdict:   model.VerdictAbstain,
		Citations: []model.Citation{a.Citation()},
		Reason:    a.Describe(),
	}
}

// Citation renders the deciding rule as evidence, reusing RuleRef's inherited
// "group sid N (priority P)" rendering so reports keep citing policy the same
// way they already do.
func (d Decision) Citation() model.Citation {
	c := model.Citation{Kind: citationKind, Identifier: d.Rule.String(), Detail: d.Rule.Action}
	if d.ByDefault {
		c.Detail = strings.TrimSpace("policy default action " + d.Rule.Action)
	}
	return c
}

// LayerResult maps the evaluation onto the FIREWALL Layer of the shared verdict
// model.
//
// Any abstention makes the whole firewall verdict uncertain: an unevaluated
// rule group might have passed traffic this evaluation dropped, or dropped
// traffic it passed. Such a Result therefore maps to VerdictAbstain naming
// every construct that could not be modelled, which is how requirements 5.4
// and 5.5 declare the result non-authoritative — Verdict.ComputeAuthoritative
// then carries that fact to the top level. A fully evaluated Result maps to
// VerdictBlocked when any of the traffic was dropped, and VerdictPass
// otherwise, citing the rules that decided it.
func (r Result) LayerResult() model.LayerResult {
	out := model.LayerResult{Layer: model.LayerFirewall}

	if !r.Certain() {
		out.Verdict = model.VerdictAbstain
		reasons := make([]string, 0, len(r.Abstentions))
		for _, a := range r.Abstentions {
			reasons = append(reasons, a.Describe())
			out.Citations = append(out.Citations, a.Citation())
		}
		out.Reason = r.prefix() + strings.Join(reasons, "; ")
		return out
	}

	switch {
	case !r.Denied().IsEmpty():
		out.Verdict = model.VerdictBlocked
		out.Citations = r.citations(Drop)
	case !r.Permitted().IsEmpty():
		out.Verdict = model.VerdictPass
		out.Citations = r.citations(Pass)
	default:
		// Neither a rule nor a default action decided any of the traffic, so
		// there is nothing to assert in either direction.
		out.Verdict = model.VerdictAbstain
		out.Reason = r.prefix() + "evaluation recorded no decision for the traffic"
	}
	return out
}

// citations gathers one citation per distinct rule that reached the given
// verdict. A rule deciding several slices of the flow is cited once.
func (r Result) citations(v Verdict) []model.Citation {
	var out []model.Citation
	seen := map[string]bool{}
	for _, d := range r.Decisions {
		if d.Verdict != v {
			continue
		}
		c := d.Citation()
		if seen[c.Identifier] {
			continue
		}
		seen[c.Identifier] = true
		out = append(out, c)
	}
	return out
}

// prefix names the firewall the result came from, so a flow inspected at two
// points reports which one abstained.
func (r Result) prefix() string {
	name := r.Firewall
	if name == "" {
		name = r.Policy
	}
	if name == "" {
		return ""
	}
	return name + ": "
}
