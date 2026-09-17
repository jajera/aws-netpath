// Package model holds aws-netpath's normalized view of a network.
//
// A Snapshot is captured once from live cloud APIs and then queried offline as
// many times as needed. Nothing here is provider-specific by design: collectors
// translate provider resources into these types, and the engine reasons only
// about these types. Adding a second cloud means writing a collector, not
// rewriting the engine.
package model

import (
	"net/netip"
	"time"
)

// SchemaVersion is bumped when the on-disk snapshot format changes
// incompatibly, so old snapshots are rejected rather than misread.
const SchemaVersion = 1

// Snapshot is a point-in-time capture of every resource aws-netpath reasons about.
type Snapshot struct {
	SchemaVersion int       `json:"schema_version"`
	CapturedAt    time.Time `json:"captured_at"`
	Accounts      []string  `json:"accounts,omitempty"`
	Regions       []string  `json:"regions,omitempty"`

	VPCs           map[string]*VPC           `json:"vpcs,omitempty"`
	Subnets        map[string]*Subnet        `json:"subnets,omitempty"`
	RouteTables    map[string]*RouteTable    `json:"route_tables,omitempty"`
	SecurityGroups map[string]*SecurityGroup `json:"security_groups,omitempty"`
	NACLs          map[string]*NACL          `json:"nacls,omitempty"`
	NetworkIfaces  map[string]*NetworkIface  `json:"network_interfaces,omitempty"`

	TransitGateways  map[string]*TransitGateway  `json:"transit_gateways,omitempty"`
	TGWRouteTables   map[string]*TGWRouteTable   `json:"tgw_route_tables,omitempty"`
	TGWAttachments   map[string]*TGWAttachment   `json:"tgw_attachments,omitempty"`
	VPCPeerings      map[string]*VPCPeering      `json:"vpc_peerings,omitempty"`
	Firewalls        map[string]*Firewall        `json:"firewalls,omitempty"`
	FirewallPolicies map[string]*FirewallPolicy  `json:"firewall_policies,omitempty"`
	RuleGroups       map[string]*RuleGroup       `json:"rule_groups,omitempty"`
	ExternalNetworks map[string]*ExternalNetwork `json:"external_networks,omitempty"`

	// CollectionErrors records resources that could not be read, usually
	// because of missing permissions. The engine surfaces these rather than
	// silently treating an unreadable policy as absent.
	CollectionErrors []CollectionError `json:"collection_errors,omitempty"`
}

// NewSnapshot returns an empty snapshot with all maps initialized.
func NewSnapshot() *Snapshot {
	return &Snapshot{
		SchemaVersion:    SchemaVersion,
		CapturedAt:       time.Now().UTC(),
		VPCs:             map[string]*VPC{},
		Subnets:          map[string]*Subnet{},
		RouteTables:      map[string]*RouteTable{},
		SecurityGroups:   map[string]*SecurityGroup{},
		NACLs:            map[string]*NACL{},
		NetworkIfaces:    map[string]*NetworkIface{},
		TransitGateways:  map[string]*TransitGateway{},
		TGWRouteTables:   map[string]*TGWRouteTable{},
		TGWAttachments:   map[string]*TGWAttachment{},
		VPCPeerings:      map[string]*VPCPeering{},
		Firewalls:        map[string]*Firewall{},
		FirewallPolicies: map[string]*FirewallPolicy{},
		RuleGroups:       map[string]*RuleGroup{},
		ExternalNetworks: map[string]*ExternalNetwork{},
	}
}

// CollectionError notes a resource that could not be read during collection.
type CollectionError struct {
	Region   string `json:"region,omitempty"`
	Account  string `json:"account,omitempty"`
	Resource string `json:"resource"`
	Err      string `json:"error"`
}

// Meta is the identity every resource carries.
type Meta struct {
	ID      string            `json:"id"`
	ARN     string            `json:"arn,omitempty"`
	Name    string            `json:"name,omitempty"`
	Region  string            `json:"region,omitempty"`
	Account string            `json:"account,omitempty"`
	Tags    map[string]string `json:"tags,omitempty"`
}

// VPC is an isolated virtual network.
type VPC struct {
	Meta
	CIDRs []netip.Prefix `json:"cidrs"`
}

// Subnet is a routable slice of a VPC bound to one availability zone.
type Subnet struct {
	Meta
	VPCID            string       `json:"vpc_id"`
	CIDR             netip.Prefix `json:"cidr"`
	AvailabilityZone string       `json:"availability_zone,omitempty"`
	RouteTableID     string       `json:"route_table_id,omitempty"`
	NACLID           string       `json:"nacl_id,omitempty"`
}

// TargetKind classifies what a route or path hop points at. Keeping this as an
// explicit enum lets the engine decide how to continue without string matching
// on provider-specific identifier prefixes.
type TargetKind string

const (
	TargetLocal            TargetKind = "local"
	TargetInternetGateway  TargetKind = "internet-gateway"
	TargetNATGateway       TargetKind = "nat-gateway"
	TargetTransitGateway   TargetKind = "transit-gateway"
	TargetVPCPeering       TargetKind = "vpc-peering"
	TargetVirtualGateway   TargetKind = "virtual-gateway"
	TargetNetworkInterface TargetKind = "network-interface"
	TargetGatewayEndpoint  TargetKind = "gateway-endpoint"
	TargetBlackhole        TargetKind = "blackhole"
	TargetAttachment       TargetKind = "attachment"
	TargetUnknown          TargetKind = "unknown"
)

// Route is one entry in a route table.
type Route struct {
	Destination netip.Prefix `json:"destination"`
	TargetKind  TargetKind   `json:"target_kind"`
	TargetID    string       `json:"target_id,omitempty"`
	// PrefixListID is set when the destination comes from a managed prefix
	// list rather than a literal CIDR.
	PrefixListID string `json:"prefix_list_id,omitempty"`
	State        string `json:"state,omitempty"`
}

// RouteTable directs traffic leaving a subnet or gateway.
type RouteTable struct {
	Meta
	VPCID  string  `json:"vpc_id"`
	Routes []Route `json:"routes"`
}

// SecurityGroup is a stateful allow-only filter attached to interfaces.
type SecurityGroup struct {
	Meta
	VPCID   string   `json:"vpc_id"`
	Ingress []SGRule `json:"ingress,omitempty"`
	Egress  []SGRule `json:"egress,omitempty"`
}

// SGRule permits traffic. Security groups have no deny rules; anything not
// permitted is dropped, and return traffic is allowed automatically.
type SGRule struct {
	Protocol string         `json:"protocol"`
	FromPort int32          `json:"from_port"`
	ToPort   int32          `json:"to_port"`
	CIDRs    []netip.Prefix `json:"cidrs,omitempty"`
	// PeerGroupIDs holds referenced security groups, which resolve to the
	// addresses of every interface currently in those groups.
	PeerGroupIDs  []string `json:"peer_group_ids,omitempty"`
	PrefixListIDs []string `json:"prefix_list_ids,omitempty"`
	Description   string   `json:"description,omitempty"`
}

// NACL is a stateless, ordered, subnet-level filter.
type NACL struct {
	Meta
	VPCID   string     `json:"vpc_id"`
	Ingress []NACLRule `json:"ingress,omitempty"`
	Egress  []NACLRule `json:"egress,omitempty"`
}

// NACLRule is evaluated in ascending rule-number order; the first match wins.
type NACLRule struct {
	RuleNumber int32        `json:"rule_number"`
	Protocol   string       `json:"protocol"`
	FromPort   int32        `json:"from_port"`
	ToPort     int32        `json:"to_port"`
	CIDR       netip.Prefix `json:"cidr"`
	Allow      bool         `json:"allow"`
}

// NetworkIface is an elastic network interface, the usual source of a query.
type NetworkIface struct {
	Meta
	VPCID            string       `json:"vpc_id"`
	SubnetID         string       `json:"subnet_id"`
	PrivateIPs       []netip.Addr `json:"private_ips,omitempty"`
	PublicIP         *netip.Addr  `json:"public_ip,omitempty"`
	SecurityGroupIDs []string     `json:"security_group_ids,omitempty"`
	AttachedTo       string       `json:"attached_to,omitempty"`
	Status           string       `json:"status,omitempty"`
}

// TransitGateway is a regional hub joining VPCs, VPNs, and other gateways.
type TransitGateway struct {
	Meta
	ASN                    int64  `json:"asn,omitempty"`
	DefaultRouteTableID    string `json:"default_route_table_id,omitempty"`
	AssociationDefaultRTID string `json:"association_default_route_table_id,omitempty"`
	PropagationDefaultRTID string `json:"propagation_default_route_table_id,omitempty"`
}

// TGWRouteTable forwards traffic between transit gateway attachments.
type TGWRouteTable struct {
	Meta
	TransitGatewayID string  `json:"transit_gateway_id"`
	Routes           []Route `json:"routes"`
	// AssociatedAttachments are the attachments whose inbound traffic is
	// evaluated against this table.
	AssociatedAttachments []string `json:"associated_attachments,omitempty"`
}

// AttachmentKind distinguishes what a transit gateway attachment connects to.
type AttachmentKind string

const (
	AttachVPC           AttachmentKind = "vpc"
	AttachVPN           AttachmentKind = "vpn"
	AttachPeering       AttachmentKind = "peering"
	AttachConnect       AttachmentKind = "connect"
	AttachDirectConnect AttachmentKind = "direct-connect"
)

// TGWAttachment joins a resource to a transit gateway.
type TGWAttachment struct {
	Meta
	TransitGatewayID string         `json:"transit_gateway_id"`
	Kind             AttachmentKind `json:"kind"`
	ResourceID       string         `json:"resource_id,omitempty"`
	SubnetIDs        []string       `json:"subnet_ids,omitempty"`
	// PeerAttachmentID and PeerRegion are set for peering attachments and are
	// how the engine crosses a region boundary.
	PeerAttachmentID string `json:"peer_attachment_id,omitempty"`
	PeerRegion       string `json:"peer_region,omitempty"`
	PeerTGWID        string `json:"peer_transit_gateway_id,omitempty"`
	AssociatedRTID   string `json:"associated_route_table_id,omitempty"`
	State            string `json:"state,omitempty"`
}

// VPCPeering is a direct link between two VPCs.
type VPCPeering struct {
	Meta
	RequesterVPCID string `json:"requester_vpc_id"`
	AccepterVPCID  string `json:"accepter_vpc_id"`
	State          string `json:"state,omitempty"`
}

// ExternalNetwork is address space aws-netpath knows about but does not manage,
// such as an on-premises range reached over Direct Connect or VPN. Declaring
// these makes a non-cloud destination an ordinary node in the graph.
type ExternalNetwork struct {
	Meta
	CIDRs       []netip.Prefix `json:"cidrs"`
	ReachedVia  string         `json:"reached_via,omitempty"`
	Description string         `json:"description,omitempty"`
}
