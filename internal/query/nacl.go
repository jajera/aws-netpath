package query

import (
	"fmt"
	"sort"

	"github.com/jajera/aws-netpath/internal/flow"
	"github.com/jajera/aws-netpath/internal/model"
)

// evalNACL checks whether the flow is permitted by NACL rules (egress from source
// or ingress to destination). AWS NACLs are stateless; use evalReturnNACL for the
// response path.
func evalNACL(nacl *model.NACL, slice flow.Slice, egress bool) *Hop {
	if nacl == nil {
		return nil
	}
	rules := nacl.Ingress
	direction := "ingress"
	if egress {
		rules = nacl.Egress
		direction = "egress"
	}
	if len(rules) == 0 {
		return &Hop{
			Layer: "nacl", Resource: nacl.Name,
			Detail: fmt.Sprintf("no %s rules (implicit deny)", direction), Allowed: false,
		}
	}

	sorted := append([]model.NACLRule(nil), rules...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].RuleNumber < sorted[j].RuleNumber })

	for _, r := range sorted {
		if !naclRuleMatches(r, slice, egress) {
			continue
		}
		return &Hop{
			Layer: "nacl", Region: nacl.Region, Resource: nacl.Name,
			Detail:  fmt.Sprintf("%s rule %d %s", direction, r.RuleNumber, allowDeny(r.Allow)),
			Allowed: r.Allow,
		}
	}

	return &Hop{
		Layer: "nacl", Region: nacl.Region, Resource: nacl.Name,
		Detail: fmt.Sprintf("%s no matching rule (implicit deny)", direction), Allowed: false,
	}
}

func allowDeny(allow bool) string {
	if allow {
		return "allow"
	}
	return "deny"
}

func naclRuleMatches(r model.NACLRule, slice flow.Slice, egress bool) bool {
	// Egress rules match the remote (destination) address; ingress matches source.
	addr := slice.Src.Prefixes()[0].Addr()
	if egress {
		addr = slice.Dst.Prefixes()[0].Addr()
	}
	if r.CIDR.IsValid() && !r.CIDR.Contains(addr) {
		return false
	}
	if r.Protocol != "any" && r.Protocol != "" {
		p, err := flow.ParseProtocol(r.Protocol)
		if err == nil && p != slice.Proto && p != flow.ProtoAny && slice.Proto != flow.ProtoAny {
			return false
		}
	}
	if slice.Proto.HasPorts() {
		port := slice.DstPorts.Ranges()[0].Lo // host query → single port
		if r.FromPort != 0 || r.ToPort != 0 {
			if port < uint16(r.FromPort) || port > uint16(r.ToPort) {
				return false
			}
		}
	}
	return true
}
