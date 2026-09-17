package query

// Security group evaluation for the source and destination endpoints.
//
// A group attaches to an interface, not to an address, so evaluation starts from
// the interface that owns the endpoint address. AWS takes the union of every
// group on that interface: one permitting rule anywhere is enough, and traffic
// is dropped only when no rule in any group matches. Groups are stateful, so the
// return direction needs no rule of its own — unlike NACLs, which
// evalReturnNACL evaluates in both directions.
//
// Anything the snapshot cannot answer abstains rather than passing: a missing
// interface, a referenced group that was not collected, or a managed prefix list
// that was never expanded. An endpoint the snapshot cannot see is not an
// endpoint that permits everything.

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/jajera/aws-netpath/internal/flow"
	"github.com/jajera/aws-netpath/internal/model"
)

// sgCitationKind is the evidence category for security group findings, matching
// the shared model's Citation vocabulary.
const sgCitationKind = "security_group"

// eniForAddr returns the interface that owns addr.
//
// Interfaces in state "available" are skipped: they are attached to nothing, so
// their addresses are reserved rather than live and they do not attribute an
// endpoint. Ties are broken on interface ID so a repeated query cites the same
// interface every time.
func (g *graph) eniForAddr(addr netip.Addr) *model.NetworkIface {
	var best *model.NetworkIface
	for _, eni := range g.snap.NetworkIfaces {
		if eni.Status == "available" {
			continue
		}
		if !eniHasAddr(eni, addr) {
			continue
		}
		if best == nil || eni.ID < best.ID {
			best = eni
		}
	}
	return best
}

// eniHasAddr reports whether addr is one of the interface's own addresses. The
// associated public address counts: a query naming it is still naming this
// endpoint.
func eniHasAddr(eni *model.NetworkIface, addr netip.Addr) bool {
	if eni == nil {
		return false
	}
	for _, ip := range eni.PrivateIPs {
		if ip == addr {
			return true
		}
	}
	return eni.PublicIP != nil && *eni.PublicIP == addr
}

func (g *graph) securityGroupsForENI(eni *model.NetworkIface) []*model.SecurityGroup {
	if eni == nil {
		return nil
	}
	var out []*model.SecurityGroup
	for _, id := range eni.SecurityGroupIDs {
		if sg := g.snap.SecurityGroups[id]; sg != nil {
			out = append(out, sg)
		}
	}
	return out
}

// missingSecurityGroupIDs returns the groups the interface references that the
// snapshot does not contain. Their rules are unknown, so a block cannot be
// asserted while any of them is missing.
func (g *graph) missingSecurityGroupIDs(eni *model.NetworkIface) []string {
	if eni == nil {
		return nil
	}
	var out []string
	for _, id := range eni.SecurityGroupIDs {
		if g.snap.SecurityGroups[id] == nil {
			out = append(out, id)
		}
	}
	return out
}

// evalEndpointSG evaluates the groups on one endpoint against the flow. egress
// selects the source endpoint's outbound rules; otherwise the destination
// endpoint's inbound rules are evaluated.
//
// Exactly one of the returned hop and abstention is non-nil: the layer either
// decided the traffic, or it recorded why it could not.
func evalEndpointSG(g *graph, eni *model.NetworkIface, addr netip.Addr, slice flow.Slice, egress bool) (*Hop, *model.LayerResult) {
	role, direction := "destination", "ingress"
	if egress {
		role, direction = "source", "egress"
	}

	if eni == nil {
		return nil, sgAbstain(fmt.Sprintf(
			"%s %s has no collected network interface, so its security groups were not evaluated; re-collect with the account owning that address",
			role, addr), nil)
	}

	groups := g.securityGroupsForENI(eni)
	missing := g.missingSecurityGroupIDs(eni)
	eniCitation := []model.Citation{{
		Kind: sgCitationKind, Identifier: eni.ID,
		Detail: fmt.Sprintf("%s interface for %s", role, addr),
	}}

	if len(groups) == 0 {
		reason := fmt.Sprintf("%s interface %s has no collected security groups", role, eni.ID)
		if len(missing) > 0 {
			reason = fmt.Sprintf("%s interface %s references security groups absent from the snapshot: %s",
				role, eni.ID, strings.Join(missing, ", "))
		}
		return nil, sgAbstain(reason, eniCitation)
	}

	var unmodelled []string
	for _, sg := range groups {
		rules := sg.Ingress
		if egress {
			rules = sg.Egress
		}
		rule, skipped := sgFirstMatch(rules, g, slice, egress)
		unmodelled = append(unmodelled, skipped...)
		if rule == nil {
			continue
		}
		cited := fmt.Sprintf("%s %s", sg.ID, sgRuleDetail(*rule, egress))
		return &Hop{
			Layer: "sg", Region: sg.Region, Resource: sgResource(sg),
			Detail:  fmt.Sprintf("%s permitted by %s", direction, cited),
			Allowed: true,
			Citations: []model.Citation{{
				Kind: sgCitationKind, Identifier: sg.ID,
				Detail: fmt.Sprintf("%s %s", direction, sgRuleDetail(*rule, egress)),
			}},
		}, nil
	}

	// Nothing matched. That is a block only when every rule was decidable: an
	// unexpanded prefix list or an uncollected peer group might have been the
	// rule that permitted this traffic.
	if len(missing) > 0 {
		unmodelled = append(unmodelled, fmt.Sprintf("groups absent from the snapshot: %s", strings.Join(missing, ", ")))
	}
	if len(unmodelled) > 0 {
		return nil, sgAbstain(fmt.Sprintf(
			"no %s rule on %s interface %s matched %s, but the groups could not be fully evaluated (%s)",
			direction, role, eni.ID, sgFlowDetail(slice, egress), strings.Join(dedupe(unmodelled), "; ")), eniCitation)
	}

	return &Hop{
		Layer: "sg", Region: groups[0].Region, Resource: sgResource(groups[0]),
		Detail: fmt.Sprintf("%s denied: no rule in %s permits %s",
			direction, strings.Join(sgIDs(groups), ", "), sgFlowDetail(slice, egress)),
		Allowed:   false,
		Citations: sgGroupCitations(groups, direction),
	}, nil
}

// sgAbstain builds a SECURITY_GROUP abstention. The reason is mandatory: an
// abstention without one is indistinguishable from a silent pass.
func sgAbstain(reason string, citations []model.Citation) *model.LayerResult {
	return &model.LayerResult{
		Layer:     model.LayerSecurityGroup,
		Verdict:   model.VerdictAbstain,
		Citations: citations,
		Reason:    reason,
	}
}

// sgFirstMatch returns the first rule permitting the flow, plus any construct
// that stopped a rule being decided. An undecidable rule is neither a match nor
// a miss, which is why the caller abstains rather than reporting a block when
// nothing matched.
func sgFirstMatch(rules []model.SGRule, g *graph, slice flow.Slice, egress bool) (*model.SGRule, []string) {
	var unmodelled []string
	for i := range rules {
		r := rules[i]
		if !sgProtoMatches(r, slice) || !sgPortMatches(r, slice) {
			continue
		}
		matched, skipped := sgRemoteMatches(r, g, sgRemoteAddr(slice, egress))
		unmodelled = append(unmodelled, skipped...)
		if matched {
			return &rules[i], unmodelled
		}
	}
	return nil, unmodelled
}

func sgProtoMatches(r model.SGRule, slice flow.Slice) bool {
	if r.Protocol == "any" || r.Protocol == "" || r.Protocol == "-1" {
		return true
	}
	p, err := flow.ParseProtocol(r.Protocol)
	if err != nil {
		return true
	}
	return p == slice.Proto || p == flow.ProtoAny || slice.Proto == flow.ProtoAny
}

func sgPortMatches(r model.SGRule, slice flow.Slice) bool {
	if !slice.Proto.HasPorts() {
		return true
	}
	if r.FromPort == 0 && r.ToPort == 0 {
		return true // no port restriction recorded
	}
	port := int32(slice.DstPorts.Ranges()[0].Lo)
	return port >= r.FromPort && port <= r.ToPort
}

// sgRemoteAddr is the address a rule is written about: the destination for an
// egress rule, the source for an ingress rule.
func sgRemoteAddr(slice flow.Slice, egress bool) netip.Addr {
	if egress {
		return slice.Dst.Prefixes()[0].Addr()
	}
	return slice.Src.Prefixes()[0].Addr()
}

// sgRemoteMatches reports whether the rule covers remote, and names any
// construct it could not resolve.
func sgRemoteMatches(r model.SGRule, g *graph, remote netip.Addr) (bool, []string) {
	for _, cidr := range r.CIDRs {
		if cidr.Contains(remote) {
			return true, nil
		}
	}

	var unmodelled []string
	for _, sgID := range r.PeerGroupIDs {
		if g.addrInSecurityGroup(sgID, remote) {
			return true, nil
		}
		// A group reference resolves to the addresses of its current members.
		// Without the group, its members are unknown too.
		if g.snap.SecurityGroups[sgID] == nil {
			unmodelled = append(unmodelled, fmt.Sprintf("referenced group %s is not in the snapshot", sgID))
		}
	}
	for _, id := range r.PrefixListIDs {
		unmodelled = append(unmodelled, fmt.Sprintf("managed prefix list %s is not expanded in the snapshot", id))
	}

	if len(r.CIDRs) == 0 && len(r.PeerGroupIDs) == 0 && len(r.PrefixListIDs) == 0 {
		return true, nil // a rule naming no remote covers every address
	}
	return false, unmodelled
}

// addrInSecurityGroup reports whether a collected interface in the group holds
// remote as a private address. Group references resolve to private addresses
// only, so an associated public address does not count here.
func (g *graph) addrInSecurityGroup(sgID string, remote netip.Addr) bool {
	for _, eni := range g.snap.NetworkIfaces {
		for _, id := range eni.SecurityGroupIDs {
			if id != sgID {
				continue
			}
			for _, ip := range eni.PrivateIPs {
				if ip == remote {
					return true
				}
			}
		}
	}
	return false
}

// sgResource is the label a hop carries for a group, preferring the operator's
// name. The group ID always appears in the hop detail and citations, so a
// nameless group is still traceable.
func sgResource(sg *model.SecurityGroup) string {
	if sg.Name != "" {
		return sg.Name
	}
	return sg.ID
}

func sgIDs(groups []*model.SecurityGroup) []string {
	out := make([]string, 0, len(groups))
	for _, sg := range groups {
		if sg.Name != "" {
			out = append(out, fmt.Sprintf("%s (%s)", sg.ID, sg.Name))
			continue
		}
		out = append(out, sg.ID)
	}
	return out
}

// sgGroupCitations cites every group consulted, because a block is a statement
// about all of them rather than about any one rule.
func sgGroupCitations(groups []*model.SecurityGroup, direction string) []model.Citation {
	out := make([]model.Citation, 0, len(groups))
	for _, sg := range groups {
		out = append(out, model.Citation{
			Kind: sgCitationKind, Identifier: sg.ID,
			Detail: fmt.Sprintf("no matching %s rule (%d recorded)", direction, sgRuleCount(sg, direction)),
		})
	}
	return out
}

func sgRuleCount(sg *model.SecurityGroup, direction string) int {
	if direction == "egress" {
		return len(sg.Egress)
	}
	return len(sg.Ingress)
}

// sgFlowDetail names the traffic a decision was about, in the same shape the
// rule citations use.
func sgFlowDetail(slice flow.Slice, egress bool) string {
	preposition := "from"
	if egress {
		preposition = "to"
	}
	proto := slice.Proto.String()
	if slice.Proto.HasPorts() {
		proto = fmt.Sprintf("%s/%d", proto, slice.DstPorts.Ranges()[0].Lo)
	}
	return fmt.Sprintf("%s %s %s", proto, preposition, sgRemoteAddr(slice, egress))
}

// sgRuleDetail renders one rule as evidence: what it permits, and to or from
// which remote.
func sgRuleDetail(r model.SGRule, egress bool) string {
	preposition := "from"
	if egress {
		preposition = "to"
	}
	return fmt.Sprintf("allow %s/%s %s %s", sgRuleProto(r), sgRulePorts(r), preposition, sgRuleRemote(r))
}

func sgRuleProto(r model.SGRule) string {
	if r.Protocol == "" || r.Protocol == "-1" {
		return "any"
	}
	return r.Protocol
}

func sgRulePorts(r model.SGRule) string {
	switch {
	case r.FromPort < 0 || r.ToPort < 0:
		return "any"
	case r.FromPort == 0 && r.ToPort == 0:
		return "any"
	case r.FromPort == r.ToPort:
		return strconv.Itoa(int(r.FromPort))
	default:
		return fmt.Sprintf("%d-%d", r.FromPort, r.ToPort)
	}
}

func sgRuleRemote(r model.SGRule) string {
	var parts []string
	for _, c := range r.CIDRs {
		parts = append(parts, c.String())
	}
	parts = append(parts, r.PeerGroupIDs...)
	parts = append(parts, r.PrefixListIDs...)
	if len(parts) == 0 {
		return "anywhere"
	}
	return strings.Join(parts, ",")
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
