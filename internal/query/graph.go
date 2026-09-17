package query

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/jajera/aws-netpath/internal/model"
)

// graph indexes a snapshot for fast lookups during path walks.
type graph struct {
	snap *model.Snapshot
}

func newGraph(snap *model.Snapshot) *graph {
	return &graph{snap: snap}
}

func (g *graph) subnetForAddr(addr netip.Addr) (*model.Subnet, bool) {
	var best *model.Subnet
	bestBits := -1
	for _, s := range g.snap.Subnets {
		if !s.CIDR.Contains(addr) {
			continue
		}
		bits := s.CIDR.Bits()
		if bits > bestBits {
			best = s
			bestBits = bits
			continue
		}
		if bits == bestBits && best != nil && best.RouteTableID == "" && s.RouteTableID != "" {
			// Same prefix length in different VPCs: prefer the subnet with an
			// explicit route table association (the routable one).
			best = s
		}
	}
	return best, best != nil
}

func (g *graph) externalForAddr(addr netip.Addr) (*model.ExternalNetwork, bool) {
	for _, ext := range g.snap.ExternalNetworks {
		for _, p := range ext.CIDRs {
			if p.Contains(addr) {
				return ext, true
			}
		}
	}
	return nil, false
}

func (g *graph) routeTableForSubnet(sub *model.Subnet) *model.RouteTable {
	if sub.RouteTableID != "" {
		return g.snap.RouteTables[sub.RouteTableID]
	}
	// Fallback: first route table in the VPC (main RT not explicitly linked during collect).
	for _, rt := range g.snap.RouteTables {
		if rt.VPCID == sub.VPCID {
			return rt
		}
	}
	return nil
}

func (g *graph) nacl(id string) *model.NACL {
	if id == "" {
		return nil
	}
	return g.snap.NACLs[id]
}

func (g *graph) firewallInVPC(vpcID string) *model.Firewall {
	for _, fw := range g.snap.Firewalls {
		if fw.VPCID == vpcID {
			return fw
		}
	}
	return nil
}

// firewallForEndpoint returns the firewall served by the given endpoint, which is
// what a route table targets when inspection sits inside the VPC rather than
// behind a transit gateway. Endpoints are per-availability-zone, so which one a
// route resolves to is the difference that matters when comparing directions.
func (g *graph) firewallForEndpoint(endpointID string) *model.Firewall {
	if endpointID == "" {
		return nil
	}
	for _, fw := range g.snap.Firewalls {
		for _, id := range fw.EndpointsBySubnet {
			if id == endpointID {
				return fw
			}
		}
	}
	return nil
}

// inspectionEgressRouteTable finds a route table in the inspection VPC that
// sends traffic back to the transit gateway (firewall subnet egress).
func (g *graph) inspectionEgressRouteTable(vpcID, tgwID string) *model.RouteTable {
	var best *model.RouteTable
	for _, rt := range g.snap.RouteTables {
		if rt.VPCID != vpcID {
			continue
		}
		for _, r := range rt.Routes {
			if r.TargetKind == model.TargetTransitGateway && r.TargetID == tgwID {
				return rt
			}
		}
		if best == nil {
			best = rt
		}
	}
	return best
}

func (g *graph) tgwRouteTableForPeering(peeringAttachID, remoteTGWID string) *model.TGWRouteTable {
	for _, rt := range g.snap.TGWRouteTables {
		if rt.TransitGatewayID != remoteTGWID {
			continue
		}
		for _, id := range rt.AssociatedAttachments {
			if id == peeringAttachID {
				return rt
			}
		}
	}
	return nil
}

// attachmentForTGWRoute resolves a TGW route next hop from the current TGW.
// Targets may be an attachment id, a VPC id, or a peer transit gateway id.
func (g *graph) attachmentForTGWRoute(fromTGWID, targetID string) *model.TGWAttachment {
	if a := g.snap.TGWAttachments[targetID]; a != nil {
		return a
	}
	for _, a := range g.snap.TGWAttachments {
		if a.ResourceID == targetID && a.Kind == model.AttachVPC {
			return a
		}
	}
	if strings.HasPrefix(targetID, "tgw-") {
		return g.peeringBetween(fromTGWID, targetID)
	}
	return nil
}

func (g *graph) peeringBetween(fromTGWID, toTGWID string) *model.TGWAttachment {
	var fallback *model.TGWAttachment
	for _, a := range g.snap.TGWAttachments {
		if a.Kind != model.AttachPeering || a.State != "available" {
			continue
		}
		peer := a.PeerTGWID
		if peer == "" {
			peer = a.ResourceID
		}
		if a.TransitGatewayID == fromTGWID && peer == toTGWID {
			return a
		}
		if a.TransitGatewayID == toTGWID && peer == fromTGWID {
			fallback = a
		}
	}
	return fallback
}

func (g *graph) vpcAttachment(vpcID, region, tgwID string) *model.TGWAttachment {
	var best *model.TGWAttachment
	for _, a := range g.snap.TGWAttachments {
		if a.Kind != model.AttachVPC || a.ResourceID != vpcID || a.Region != region || a.State != "available" {
			continue
		}
		if tgwID != "" && a.TransitGatewayID != tgwID {
			continue
		}
		if best == nil || a.ID < best.ID {
			best = a
		}
	}
	return best
}

func (g *graph) tgwRouteTableForAttachment(attachID string) *model.TGWRouteTable {
	for _, rt := range g.snap.TGWRouteTables {
		for _, id := range rt.AssociatedAttachments {
			if id == attachID {
				return rt
			}
		}
	}
	// Fallback: only RT on same TGW if exactly one (association list may be incomplete).
	return nil
}

func (g *graph) transitGateway(id string) *model.TransitGateway {
	return g.snap.TransitGateways[id]
}

// missingTGWRouteReason explains when a route targets a TGW absent from the snapshot.
func (g *graph) missingTGWRouteReason(tgwID string, attach *model.TGWAttachment) string {
	if g.transitGateway(tgwID) != nil {
		return ""
	}
	msg := fmt.Sprintf("TGW route targets %s which is not in the snapshot (add the owning account to aws-netpath.yaml and re-collect)", tgwID)
	if attach != nil && attach.Name != "" {
		msg += fmt.Sprintf("; via peering attachment %q", attach.Name)
	}
	return msg
}
