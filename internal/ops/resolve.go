package ops

// Endpoint resolution from the Snapshot: turning what an operator typed into the
// resource the engine reasons about.
//
// Four inputs are accepted, because those are the four ways an operator already
// thinks about an endpoint: an address, a CIDR, an instance ID, and a Name tag.
// What comes back is the same resolved Endpoint in every case, so nothing
// downstream has to know which was typed.
//
// Two decisions here are requirements rather than conveniences. Ambiguity halts:
// an input matching two resources is listed with every candidate's account and
// region and nothing is chosen, because choosing would silently answer a
// question about a resource the operator did not name. And address space
// belonging to no collected VPC is an ordinary external node rather than an
// error, because a path to on-premises or to the internet is a path worth
// walking — the destination-side policy simply abstains, which the walk already
// handles.

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/jajera/aws-netpath/internal/model"
)

// EndpointKind is the level of the Snapshot an input resolved to.
type EndpointKind string

const (
	// EndpointInterface is an endpoint attributed to a collected network
	// interface, which is the only kind carrying security groups.
	EndpointInterface EndpointKind = "network_interface"
	// EndpointSubnet is an address inside a collected subnet that no collected
	// interface holds.
	EndpointSubnet EndpointKind = "subnet"
	// EndpointVPC is address space inside a collected VPC but in no collected
	// subnet.
	EndpointVPC EndpointKind = "vpc"
	// EndpointExternal is address space belonging to no collected VPC. It is an
	// ordinary node, not a failure.
	EndpointExternal EndpointKind = "external"
)

// Endpoint is a resolved source or destination.
type Endpoint struct {
	// Input is what the operator typed, kept so a finding can name the endpoint
	// the way it was asked about.
	Input string       `json:"input"`
	Kind  EndpointKind `json:"kind"`
	// Addr is the address the flow is evaluated for. For a CIDR input it is the
	// network address of the prefix, and Prefix records what was asked.
	Addr   netip.Addr   `json:"addr"`
	Prefix netip.Prefix `json:"prefix,omitempty"`

	InterfaceID string `json:"interface_id,omitempty"`
	InstanceID  string `json:"instance_id,omitempty"`
	SubnetID    string `json:"subnet_id,omitempty"`
	VPCID       string `json:"vpc_id,omitempty"`
	Account     string `json:"account,omitempty"`
	Region      string `json:"region,omitempty"`
	// ExternalNetworkID names the declared external network the address belongs
	// to, when one covers it. An external endpoint without it is address space
	// nothing in the Snapshot describes.
	ExternalNetworkID string `json:"external_network_id,omitempty"`
	// Notes record what an operator should know about the resolution itself,
	// such as a CIDR having been evaluated as one representative address.
	Notes []string `json:"notes,omitempty"`
}

// External reports whether the endpoint lies outside every collected VPC.
func (e Endpoint) External() bool { return e.Kind == EndpointExternal }

// Scope renders the account and region the endpoint was found in, which is the
// part of an endpoint's identity a multi-account operator needs first.
func (e Endpoint) Scope() string { return scopeText(e.Account, e.Region) }

// Description renders the endpoint as evidence: the address, what owns it, and
// where that lives.
func (e Endpoint) Description() string {
	var b strings.Builder
	b.WriteString(e.Addr.String())
	if e.Prefix.IsValid() && e.Prefix.Bits() != e.Addr.BitLen() {
		fmt.Fprintf(&b, " in %s", e.Prefix)
	}
	for _, part := range []struct{ label, value string }{
		{"interface", e.InterfaceID},
		{"instance", e.InstanceID},
		{"subnet", e.SubnetID},
		{"vpc", e.VPCID},
		{"external network", e.ExternalNetworkID},
	} {
		if part.value != "" {
			fmt.Fprintf(&b, ", %s %s", part.label, part.value)
		}
	}
	if scope := e.Scope(); scope != "" {
		fmt.Fprintf(&b, ", %s", scope)
	}
	if e.Kind == EndpointExternal && e.ExternalNetworkID == "" {
		b.WriteString(", outside every collected VPC")
	}
	return b.String()
}

// EndpointCandidate is one resource an input matched. It exists for the
// ambiguous case: requirement 6.3 asks for every candidate with its account and
// region, so the operator can name the one they meant.
type EndpointCandidate struct {
	Kind       EndpointKind `json:"kind"`
	ID         string       `json:"id"`
	Name       string       `json:"name,omitempty"`
	Addr       netip.Addr   `json:"addr,omitempty"`
	InstanceID string       `json:"instance_id,omitempty"`
	SubnetID   string       `json:"subnet_id,omitempty"`
	VPCID      string       `json:"vpc_id,omitempty"`
	Account    string       `json:"account,omitempty"`
	Region     string       `json:"region,omitempty"`
}

func (c EndpointCandidate) String() string {
	var b strings.Builder
	b.WriteString(c.ID)
	if c.Name != "" {
		fmt.Fprintf(&b, " (%s)", c.Name)
	}
	if c.Addr.IsValid() {
		fmt.Fprintf(&b, " %s", c.Addr)
	}
	if c.InstanceID != "" {
		fmt.Fprintf(&b, " on instance %s", c.InstanceID)
	}
	if c.VPCID != "" {
		fmt.Fprintf(&b, " in %s", c.VPCID)
	}
	if scope := scopeText(c.Account, c.Region); scope != "" {
		fmt.Fprintf(&b, ", %s", scope)
	}
	return b.String()
}

// AmbiguousEndpointError reports an input matching more than one resource.
//
// It is an error rather than a best guess on purpose. Overlapping RFC 1918 space
// in two accounts is ordinary, and answering for the wrong one would be a
// confident wrong answer — the failure mode this tool exists to avoid.
type AmbiguousEndpointError struct {
	Field      string
	Input      string
	Candidates []EndpointCandidate
}

func (e *AmbiguousEndpointError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "--%s %q matches %d resources; name one of them instead:", e.Field, e.Input, len(e.Candidates))
	for _, c := range e.Candidates {
		fmt.Fprintf(&b, "\n  %s", c)
	}
	return b.String()
}

// UnresolvedEndpointError reports an input matching nothing in the Snapshot,
// stating the accounts and regions it does cover so the operator can see whether
// the endpoint they named was ever collected.
type UnresolvedEndpointError struct {
	Field    string
	Input    string
	Accounts []string
	Regions  []string
}

func (e *UnresolvedEndpointError) Error() string {
	return fmt.Sprintf("--%s %q matches no collected instance or network interface; the snapshot covers %s",
		e.Field, e.Input, coverage(e.Accounts, e.Regions))
}

// ResolveEndpoint resolves one operator-supplied endpoint against the Snapshot.
//
// An address or CIDR is resolved by containment; anything else is looked up as
// an instance ID or a Name tag. The order matters only in that an address is
// never treated as a name, which keeps the answer independent of what happens to
// be tagged in the Snapshot.
func ResolveEndpoint(snap *model.Snapshot, field, input string) (Endpoint, error) {
	if snap == nil {
		return Endpoint{}, fmt.Errorf("snapshot is required to resolve --%s", field)
	}
	input = strings.TrimSpace(input)
	if input == "" {
		return Endpoint{}, missingField(field)
	}

	if addr, err := netip.ParseAddr(input); err == nil {
		return resolveAddr(snap, field, input, addr, netip.Prefix{})
	}
	if prefix, err := netip.ParsePrefix(input); err == nil {
		return resolvePrefix(snap, field, input, prefix.Masked())
	}
	return resolveName(snap, field, input)
}

// resolveAddr resolves one address. prefix is the CIDR the address came from,
// invalid when the operator named the address directly.
//
// Requirement 6.1 is satisfied at the first step: the interface holding the
// address carries the instance, subnet, VPC, account, and region with it. The
// later steps are the honest answers when no interface holds it — an address in
// a collected subnet is still located, and an address in no collected VPC is
// external rather than unresolvable.
func resolveAddr(snap *model.Snapshot, field, input string, addr netip.Addr, prefix netip.Prefix) (Endpoint, error) {
	base := Endpoint{Input: input, Addr: addr, Prefix: prefix}

	ifaces := interfacesHoldingAddr(snap, addr)
	if len(ifaces) > 1 {
		return Endpoint{}, ambiguous(field, input, interfaceCandidates(ifaces))
	}
	if len(ifaces) == 1 {
		return interfaceEndpoint(base, ifaces[0], addr), nil
	}

	subnets := subnetsContaining(snap, addr, prefix)
	if len(subnets) > 1 {
		return Endpoint{}, ambiguous(field, input, subnetCandidates(subnets))
	}
	if len(subnets) == 1 {
		sub := subnets[0]
		base.Kind = EndpointSubnet
		base.SubnetID = sub.ID
		base.VPCID = sub.VPCID
		base.Account, base.Region = sub.Account, sub.Region
		return base, nil
	}

	vpcs := vpcsContaining(snap, addr, prefix)
	if len(vpcs) > 1 {
		return Endpoint{}, ambiguous(field, input, vpcCandidates(vpcs))
	}
	if len(vpcs) == 1 {
		vpc := vpcs[0]
		base.Kind = EndpointVPC
		base.VPCID = vpc.ID
		base.Account, base.Region = vpc.Account, vpc.Region
		return base, nil
	}

	// Requirement 6.5: address space no collected VPC owns is an ordinary node.
	base.Kind = EndpointExternal
	if ext, ok := externalContaining(snap, addr); ok {
		base.ExternalNetworkID = ext.ID
		base.Account, base.Region = ext.Account, ext.Region
	}
	return base, nil
}

// resolvePrefix resolves a CIDR.
//
// A diagnosis walks one Flow, so the prefix is evaluated through its network
// address and the substitution is stated in a note. Rules match by containment,
// so a prefix that sits wholly inside every rule it meets is answered
// identically for any address in it — and a prefix that does not is exactly the
// case the note exists to flag.
func resolvePrefix(snap *model.Snapshot, field, input string, prefix netip.Prefix) (Endpoint, error) {
	endpoint, err := resolveAddr(snap, field, input, prefix.Addr(), prefix)
	if err != nil {
		return Endpoint{}, err
	}
	if prefix.Bits() != prefix.Addr().BitLen() {
		endpoint.Notes = append(endpoint.Notes, fmt.Sprintf(
			"%s was evaluated as %s: one Flow is walked at a time, so a prefix is represented by its network address",
			prefix, prefix.Addr()))
	}
	return endpoint, nil
}

// resolveName resolves an instance ID or a Name tag against the collected
// interfaces.
//
// Requirement 6.2 asks for the primary interface and its private IPv4 address.
// The Snapshot records no device index, so an instance with two collected
// interfaces has no primary this can identify — that is reported as ambiguity
// with both interfaces listed rather than resolved by picking one.
func resolveName(snap *model.Snapshot, field, input string) (Endpoint, error) {
	ifaces := interfacesNamed(snap, input)
	if len(ifaces) > 1 {
		return Endpoint{}, ambiguous(field, input, interfaceCandidates(ifaces))
	}
	if len(ifaces) == 0 {
		accounts, regions := snapshotScopes(snap)
		return Endpoint{}, &UnresolvedEndpointError{
			Field: field, Input: input, Accounts: accounts, Regions: regions,
		}
	}

	eni := ifaces[0]
	addr, ok := primaryAddr(eni)
	if !ok {
		return Endpoint{}, fmt.Errorf("--%s %q resolves to interface %s, which has no collected private IPv4 address",
			field, input, eni.ID)
	}
	return interfaceEndpoint(Endpoint{Input: input, Addr: addr}, eni, addr), nil
}

// interfaceEndpoint fills in the resource chain an interface belongs to, which
// is the whole of requirement 6.1.
func interfaceEndpoint(base Endpoint, eni *model.NetworkIface, addr netip.Addr) Endpoint {
	base.Kind = EndpointInterface
	base.Addr = addr
	base.InterfaceID = eni.ID
	base.InstanceID = eni.AttachedTo
	base.SubnetID = eni.SubnetID
	base.VPCID = eni.VPCID
	base.Account, base.Region = eni.Account, eni.Region
	return base
}

// interfacesHoldingAddr returns the in-use interfaces holding addr.
//
// Interfaces in state "available" are skipped, matching the security group
// layer: their addresses are reserved rather than live, so naming one as the
// endpoint would report an interface whose groups the walk then ignores.
func interfacesHoldingAddr(snap *model.Snapshot, addr netip.Addr) []*model.NetworkIface {
	var out []*model.NetworkIface
	for _, eni := range snap.NetworkIfaces {
		if eni == nil || eni.Status == "available" {
			continue
		}
		if ifaceHasAddr(eni, addr) {
			out = append(out, eni)
		}
	}
	return sortIfaces(out)
}

// interfacesNamed returns the in-use interfaces an instance ID or Name tag
// selects. The interface's own ID is accepted too, since an operator reading a
// previous verdict has one to hand.
func interfacesNamed(snap *model.Snapshot, input string) []*model.NetworkIface {
	var out []*model.NetworkIface
	for _, eni := range snap.NetworkIfaces {
		if eni == nil || eni.Status == "available" {
			continue
		}
		switch {
		case eni.AttachedTo == input, eni.ID == input, eni.Name == input, eni.Tags["Name"] == input:
			out = append(out, eni)
		}
	}
	return sortIfaces(out)
}

func ifaceHasAddr(eni *model.NetworkIface, addr netip.Addr) bool {
	for _, ip := range eni.PrivateIPs {
		if ip == addr {
			return true
		}
	}
	return eni.PublicIP != nil && *eni.PublicIP == addr
}

// primaryAddr returns the interface's primary private address. Collection puts
// the primary first, so position carries the meaning the model has no field for.
func primaryAddr(eni *model.NetworkIface) (netip.Addr, bool) {
	for _, ip := range eni.PrivateIPs {
		if ip.IsValid() {
			return ip, true
		}
	}
	return netip.Addr{}, false
}

// subnetsContaining returns the subnets covering addr, or wholly covering
// prefix when a CIDR was named. Subnets within one VPC do not overlap, so more
// than one match means more than one VPC — genuine ambiguity rather than a tie
// to break.
func subnetsContaining(snap *model.Snapshot, addr netip.Addr, prefix netip.Prefix) []*model.Subnet {
	var out []*model.Subnet
	for _, sub := range snap.Subnets {
		if sub == nil || !sub.CIDR.IsValid() || !sub.CIDR.Contains(addr) {
			continue
		}
		if prefix.IsValid() && prefix.Bits() < sub.CIDR.Bits() {
			// The named CIDR is wider than the subnet, so the subnet does not
			// describe it.
			continue
		}
		out = append(out, sub)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// vpcsContaining returns the VPCs whose address space covers addr.
func vpcsContaining(snap *model.Snapshot, addr netip.Addr, prefix netip.Prefix) []*model.VPC {
	var out []*model.VPC
	for _, vpc := range snap.VPCs {
		if vpc == nil {
			continue
		}
		for _, cidr := range vpc.CIDRs {
			if !cidr.IsValid() || !cidr.Contains(addr) {
				continue
			}
			if prefix.IsValid() && prefix.Bits() < cidr.Bits() {
				continue
			}
			out = append(out, vpc)
			break
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func externalContaining(snap *model.Snapshot, addr netip.Addr) (*model.ExternalNetwork, bool) {
	var best *model.ExternalNetwork
	for _, ext := range snap.ExternalNetworks {
		if ext == nil {
			continue
		}
		for _, cidr := range ext.CIDRs {
			if cidr.IsValid() && cidr.Contains(addr) {
				if best == nil || ext.ID < best.ID {
					best = ext
				}
				break
			}
		}
	}
	return best, best != nil
}

func sortIfaces(in []*model.NetworkIface) []*model.NetworkIface {
	sort.Slice(in, func(i, j int) bool { return in[i].ID < in[j].ID })
	return in
}

func ambiguous(field, input string, candidates []EndpointCandidate) error {
	return &AmbiguousEndpointError{Field: field, Input: input, Candidates: candidates}
}

func interfaceCandidates(ifaces []*model.NetworkIface) []EndpointCandidate {
	out := make([]EndpointCandidate, 0, len(ifaces))
	for _, eni := range ifaces {
		addr, _ := primaryAddr(eni)
		out = append(out, EndpointCandidate{
			Kind: EndpointInterface, ID: eni.ID, Name: eni.Name, Addr: addr,
			InstanceID: eni.AttachedTo, SubnetID: eni.SubnetID, VPCID: eni.VPCID,
			Account: eni.Account, Region: eni.Region,
		})
	}
	return out
}

func subnetCandidates(subnets []*model.Subnet) []EndpointCandidate {
	out := make([]EndpointCandidate, 0, len(subnets))
	for _, sub := range subnets {
		out = append(out, EndpointCandidate{
			Kind: EndpointSubnet, ID: sub.ID, Name: sub.Name, SubnetID: sub.ID,
			VPCID: sub.VPCID, Account: sub.Account, Region: sub.Region,
		})
	}
	return out
}

func vpcCandidates(vpcs []*model.VPC) []EndpointCandidate {
	out := make([]EndpointCandidate, 0, len(vpcs))
	for _, vpc := range vpcs {
		out = append(out, EndpointCandidate{
			Kind: EndpointVPC, ID: vpc.ID, Name: vpc.Name, VPCID: vpc.ID,
			Account: vpc.Account, Region: vpc.Region,
		})
	}
	return out
}

// snapshotScopes returns the accounts and regions the Snapshot covers, which is
// what requirement 6.4 reports when nothing matched.
//
// The declared lists come first, then the scopes the collected resources
// actually carry: a snapshot merged from several runs can hold resources whose
// scope the top-level lists do not mention, and the operator needs the truth
// rather than the declaration.
func snapshotScopes(snap *model.Snapshot) (accounts, regions []string) {
	accountSet := make(map[string]bool, len(snap.Accounts))
	regionSet := make(map[string]bool, len(snap.Regions))
	add := func(account, region string) {
		if account != "" {
			accountSet[account] = true
		}
		if region != "" {
			regionSet[region] = true
		}
	}

	for _, a := range snap.Accounts {
		add(a, "")
	}
	for _, r := range snap.Regions {
		add("", r)
	}
	for _, eni := range snap.NetworkIfaces {
		add(eni.Account, eni.Region)
	}
	for _, sub := range snap.Subnets {
		add(sub.Account, sub.Region)
	}
	for _, vpc := range snap.VPCs {
		add(vpc.Account, vpc.Region)
	}
	return sortedKeys(accountSet), sortedKeys(regionSet)
}

func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// coverage renders the accounts and regions a snapshot covers for an error
// message. An empty snapshot says so rather than reporting nothing at all.
func coverage(accounts, regions []string) string {
	switch {
	case len(accounts) == 0 && len(regions) == 0:
		return "no accounts or regions (the snapshot is empty)"
	case len(accounts) == 0:
		return fmt.Sprintf("regions %s", strings.Join(regions, ", "))
	case len(regions) == 0:
		return fmt.Sprintf("accounts %s", strings.Join(accounts, ", "))
	default:
		return fmt.Sprintf("accounts %s and regions %s",
			strings.Join(accounts, ", "), strings.Join(regions, ", "))
	}
}

func scopeText(account, region string) string {
	switch {
	case account == "" && region == "":
		return ""
	case account == "":
		return fmt.Sprintf("region %s", region)
	case region == "":
		return fmt.Sprintf("account %s", account)
	default:
		return fmt.Sprintf("account %s region %s", account, region)
	}
}
