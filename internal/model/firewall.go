package model

import "strings"

// Firewall is a managed inspection appliance placed in the traffic path.
type Firewall struct {
	Meta
	VPCID     string   `json:"vpc_id"`
	PolicyARN string   `json:"policy_arn"`
	SubnetIDs []string `json:"subnet_ids,omitempty"`
	// EndpointsBySubnet maps a subnet to the firewall endpoint serving it,
	// which is what route tables actually target.
	EndpointsBySubnet map[string]string `json:"endpoints_by_subnet,omitempty"`
}

// RuleOrder controls how a stateful engine evaluates rule groups.
type RuleOrder string

const (
	// StrictOrder evaluates rule groups by priority and rules in written
	// order, taking the first match.
	StrictOrder RuleOrder = "STRICT_ORDER"
	// DefaultActionOrder applies pass/drop/alert precedence instead of written
	// order. aws-netpath does not model its precedence rules and abstains.
	DefaultActionOrder RuleOrder = "DEFAULT_ACTION_ORDER"
)

// FirewallPolicy binds ordered rule groups to a default action.
type FirewallPolicy struct {
	Meta
	StatefulRuleOrder       RuleOrder      `json:"stateful_rule_order"`
	StatefulDefaultActions  []string       `json:"stateful_default_actions,omitempty"`
	StatefulGroups          []RuleGroupRef `json:"stateful_groups,omitempty"`
	StatelessDefaultActions []string       `json:"stateless_default_actions,omitempty"`
}

// RuleGroupRef attaches a rule group to a policy at a given priority. Lower
// priority values are evaluated first.
type RuleGroupRef struct {
	ARN      string `json:"arn"`
	Priority int    `json:"priority"`
}

// DropsByDefault reports whether new flows matching no stateful rule are
// dropped. Only aws:drop_strict does that; aws:drop_established affects
// established traffic that aws-netpath does not model as a separate phase.
func (p *FirewallPolicy) DropsByDefault() bool {
	for _, a := range p.StatefulDefaultActions {
		if strings.EqualFold(strings.TrimSpace(a), "aws:drop_strict") {
			return true
		}
	}
	return false
}

// RuleGroup is a set of firewall rules evaluated as a unit.
type RuleGroup struct {
	Meta
	Capacity  int       `json:"capacity,omitempty"`
	RuleOrder RuleOrder `json:"rule_order,omitempty"`

	// Rules holds 5-tuple stateful rules, the form aws-netpath evaluates.
	Rules []StatefulRule `json:"rules,omitempty"`

	// DomainTargets capture rule sources aws-netpath cannot evaluate: domain
	// allowlists depend on TLS SNI or HTTP Host.
	DomainTargets []string `json:"domain_targets,omitempty"`
	// RulesString holds raw Suricata rules from AWS when the group was authored
	// that way. RuleVariables supplies $VAR IP set definitions for expansion.
	RulesString   string              `json:"rules_string,omitempty"`
	RuleVariables map[string][]string `json:"rule_variables,omitempty"`
}

// Unevaluatable reports whether the group contains constructs outside the
// 5-tuple model, along with a human-readable reason.
func (g *RuleGroup) Unevaluatable() (bool, string) {
	switch {
	case len(g.DomainTargets) > 0:
		return true, "contains a domain list, which matches on TLS SNI or HTTP Host rather than the 5-tuple"
	case strings.TrimSpace(g.RulesString) != "" && len(g.Rules) == 0 && len(g.RuleVariables) == 0:
		return true, "contains raw Suricata rules without resolvable IP set variables"
	case g.RuleOrder == DefaultActionOrder:
		return true, "uses DEFAULT_ACTION_ORDER, whose precedence aws-netpath does not model"
	default:
		return false, ""
	}
}

// Direction constrains which way a stateful rule matches.
type Direction string

const (
	// DirForward matches only source to destination as written.
	DirForward Direction = "FORWARD"
	// DirAny matches the header in either direction.
	DirAny Direction = "ANY"
)

// StatefulRule is one 5-tuple rule: a header to match and an action to take.
type StatefulRule struct {
	Action string `json:"action"`
	// Protocol is a name such as TCP, UDP, ICMP, or IP for any protocol.
	Protocol        string    `json:"protocol"`
	Source          string    `json:"source"`
	SourcePort      string    `json:"source_port"`
	Destination     string    `json:"destination"`
	DestinationPort string    `json:"destination_port"`
	Direction       Direction `json:"direction"`
	SID             string    `json:"sid,omitempty"`
}
