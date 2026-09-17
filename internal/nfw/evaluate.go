// Package nfw evaluates a network firewall policy against a symbolic flow set.
//
// This is the capability that motivates aws-netpath. AWS Reachability Analyzer
// documents that it does not support domain lists, raw Suricata rules, or rule
// options, and it analyzes one region at a time. Traffic crossing a region
// boundary is inspected by a firewall at each end, so no single Reachability
// Analyzer run can tell you whether a cross-region flow survives both.
//
// The evaluator walks rule groups in priority order, narrowing the flow set at
// each rule, and reports which rule decided each portion of the traffic. When
// it meets a construct outside the 5-tuple model it records an abstention
// rather than guessing, because a firewall simulator that is confidently wrong
// is worse than one that admits uncertainty.
package nfw

import (
	"fmt"
	"sort"
	"strings"

	"github.com/jajera/aws-netpath/internal/flow"
	"github.com/jajera/aws-netpath/internal/model"
)

// Verdict is the outcome for one portion of the evaluated traffic.
type Verdict string

const (
	Pass Verdict = "pass"
	Drop Verdict = "drop"
)

// RuleRef identifies the rule that decided a portion of the traffic, so every
// verdict can be traced back to a specific line of policy.
type RuleRef struct {
	GroupARN  string `json:"group_arn,omitempty"`
	GroupName string `json:"group_name,omitempty"`
	Priority  int    `json:"priority"`
	SID       string `json:"sid,omitempty"`
	Action    string `json:"action,omitempty"`
	// Index is the rule's position within its group, used when a rule has no
	// SID of its own.
	Index int `json:"index"`
}

func (r RuleRef) String() string {
	if r.GroupName == "" {
		return "default action"
	}
	if r.SID != "" {
		return fmt.Sprintf("%s sid %s (priority %d)", r.GroupName, r.SID, r.Priority)
	}
	return fmt.Sprintf("%s rule %d (priority %d)", r.GroupName, r.Index, r.Priority)
}

// Decision records a verdict for one slice of traffic.
type Decision struct {
	Slice   flow.Slice `json:"slice"`
	Verdict Verdict    `json:"verdict"`
	Rule    RuleRef    `json:"rule"`
	// ByDefault is true when no rule matched and the policy default applied.
	ByDefault bool `json:"by_default"`
}

// Abstention records a rule group that could not be evaluated. Any drop verdict
// reached while abstentions exist is uncertain: an unevaluated group might have
// passed the traffic.
type Abstention struct {
	GroupARN  string `json:"group_arn,omitempty"`
	GroupName string `json:"group_name,omitempty"`
	Priority  int    `json:"priority"`
	Reason    string `json:"reason"`
}

// Result is the outcome of evaluating one flow against one firewall.
type Result struct {
	Firewall    string       `json:"firewall,omitempty"`
	Region      string       `json:"region,omitempty"`
	Policy      string       `json:"policy,omitempty"`
	Decisions   []Decision   `json:"decisions,omitempty"`
	Abstentions []Abstention `json:"abstentions,omitempty"`
}

// Permitted returns the traffic the firewall allows.
func (r Result) Permitted() flow.Set { return r.collect(Pass) }

// Denied returns the traffic the firewall blocks.
func (r Result) Denied() flow.Set { return r.collect(Drop) }

func (r Result) collect(v Verdict) flow.Set {
	var out flow.Set
	for _, d := range r.Decisions {
		if d.Verdict == v {
			out = out.Add(d.Slice)
		}
	}
	return out
}

// Certain reports whether every rule group in the path was fully evaluated.
func (r Result) Certain() bool { return len(r.Abstentions) == 0 }

// Evaluate runs a flow through a firewall policy.
//
// A slice with protocol "any" is expanded into TCP, UDP, and ICMP so that
// subtraction stays sound in the protocol dimension; other IP protocols are not
// modeled.
func Evaluate(policy *model.FirewallPolicy, groups map[string]*model.RuleGroup, in flow.Slice) (Result, error) {
	if policy == nil {
		return Result{}, fmt.Errorf("nil firewall policy")
	}
	if in.IsEmpty() {
		return Result{Policy: policy.Name}, nil
	}

	res := Result{Policy: policy.Name, Region: policy.Region}

	if in.Proto == flow.ProtoAny {
		for _, p := range []flow.Protocol{flow.ProtoTCP, flow.ProtoUDP, flow.ProtoICMP} {
			sub := flow.NewSlice(in.Src, in.Dst, p, in.DstPorts)
			part, err := Evaluate(policy, groups, sub)
			if err != nil {
				return Result{}, err
			}
			res.Decisions = append(res.Decisions, part.Decisions...)
			res.Abstentions = mergeAbstentions(res.Abstentions, part.Abstentions)
		}
		return res, nil
	}

	// A policy using DEFAULT_ACTION_ORDER is evaluated by precedence rather
	// than written order, which this evaluator does not model.
	if policy.StatefulRuleOrder == model.DefaultActionOrder {
		res.Abstentions = append(res.Abstentions, Abstention{
			GroupName: policy.Name,
			Reason:    "policy uses DEFAULT_ACTION_ORDER, whose precedence aws-netpath does not model",
		})
	}

	refs := append([]model.RuleGroupRef(nil), policy.StatefulGroups...)
	sort.SliceStable(refs, func(i, j int) bool { return refs[i].Priority < refs[j].Priority })

	remaining := []flow.Slice{in}

	for _, ref := range refs {
		if len(remaining) == 0 {
			break
		}

		g, ok := groups[ref.ARN]
		if !ok || g == nil {
			res.Abstentions = append(res.Abstentions, Abstention{
				GroupARN: ref.ARN,
				Priority: ref.Priority,
				Reason:   "rule group is referenced by the policy but absent from the snapshot",
			})
			continue
		}

		if skip, reason := g.Unevaluatable(); skip {
			res.Abstentions = append(res.Abstentions, Abstention{
				GroupARN:  g.ARN,
				GroupName: g.Name,
				Priority:  ref.Priority,
				Reason:    reason,
			})
			continue
		}

		rules, err := ResolvedRules(g)
		if err != nil {
			res.Abstentions = append(res.Abstentions, Abstention{
				GroupARN:  g.ARN,
				GroupName: g.Name,
				Priority:  ref.Priority,
				Reason:    fmt.Sprintf("Suricata rules could not be expanded: %v", err),
			})
			continue
		}
		if len(rules) == 0 {
			continue
		}

		evalGroup := *g
		evalGroup.Rules = rules
		remaining = applyGroup(&res, &evalGroup, ref, remaining)
	}

	// Whatever no rule matched is decided by the policy default.
	if len(remaining) > 0 {
		verdict := Pass
		if policy.DropsByDefault() {
			verdict = Drop
		}
		action := strings.Join(policy.StatefulDefaultActions, ",")
		for _, s := range remaining {
			res.Decisions = append(res.Decisions, Decision{
				Slice:     s,
				Verdict:   verdict,
				Rule:      RuleRef{Action: action},
				ByDefault: true,
			})
		}
	}

	return res, nil
}

// applyGroup evaluates every rule in a group against the remaining traffic,
// returning whatever no rule in the group decided.
func applyGroup(res *Result, g *model.RuleGroup, ref model.RuleGroupRef, remaining []flow.Slice) []flow.Slice {
	for i, rule := range g.Rules {
		if len(remaining) == 0 {
			return nil
		}

		verdict, decides := verdictFor(rule.Action)
		matcher, err := compile(rule)
		if err != nil {
			res.Abstentions = append(res.Abstentions, Abstention{
				GroupARN:  g.ARN,
				GroupName: g.Name,
				Priority:  ref.Priority,
				Reason:    fmt.Sprintf("rule %d could not be parsed: %v", i, err),
			})
			continue
		}

		var next []flow.Slice
		for _, rem := range remaining {
			matched, ok := matcher.match(rem)
			if !ok {
				next = append(next, rem)
				continue
			}

			// An ALERT rule only logs, so the traffic carries on to later rules.
			if !decides {
				next = append(next, rem)
				continue
			}

			res.Decisions = append(res.Decisions, Decision{
				Slice:   matched,
				Verdict: verdict,
				Rule: RuleRef{
					GroupARN:  g.ARN,
					GroupName: g.Name,
					Priority:  ref.Priority,
					SID:       rule.SID,
					Action:    rule.Action,
					Index:     i,
				},
			})
			next = append(next, subtract(rem, matched)...)
		}
		remaining = next
	}
	return remaining
}

// verdictFor maps a rule action to a verdict. The second return is false for
// actions that do not decide the traffic's fate.
func verdictFor(action string) (Verdict, bool) {
	switch strings.ToUpper(strings.TrimSpace(action)) {
	case "PASS":
		return Pass, true
	case "DROP", "REJECT":
		return Drop, true
	default:
		// ALERT and anything unrecognized only observe.
		return "", false
	}
}

// subtract removes the matched box from rem, returning the disjoint remainder.
//
// Removing a box from a box leaves up to three boxes, one per dimension: the
// sources outside the match, then the destinations outside it for the matched
// sources, then the ports outside it for the matched sources and destinations.
func subtract(rem, matched flow.Slice) []flow.Slice {
	var out []flow.Slice

	if src := rem.Src.Subtract(matched.Src); !src.IsEmpty() {
		out = append(out, flow.NewSlice(src, rem.Dst, rem.Proto, rem.DstPorts))
	}
	if dst := rem.Dst.Subtract(matched.Dst); !dst.IsEmpty() {
		out = append(out, flow.NewSlice(matched.Src, dst, rem.Proto, rem.DstPorts))
	}
	if rem.Proto.HasPorts() {
		if ports := rem.DstPorts.Subtract(matched.DstPorts); !ports.IsEmpty() {
			out = append(out, flow.NewSlice(matched.Src, matched.Dst, rem.Proto, ports))
		}
	}
	return out
}

func mergeAbstentions(dst, src []Abstention) []Abstention {
	for _, a := range src {
		dup := false
		for _, existing := range dst {
			if existing == a {
				dup = true
				break
			}
		}
		if !dup {
			dst = append(dst, a)
		}
	}
	return dst
}
