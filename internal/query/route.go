package query

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/jajera/aws-netpath/internal/model"
)

// routeNextHop names the component a matched route forwards to.
//
// A local route contributes nothing: it names the VPC's own address space rather
// than a device, and both directions of a flow inside one VPC resolve to it, so
// there is no component for the two directions to disagree about. A target with
// no identifier is left out for the same reason — an unnamed next hop cannot be
// compared with anything.
func routeNextHop(r model.Route) (id, kind string) {
	if r.TargetKind == model.TargetLocal || r.TargetID == "" {
		return "", ""
	}
	return r.TargetID, string(r.TargetKind)
}

// matchRoute picks the longest-prefix route toward dest. Blackhole routes block
// only when they are the most specific matching route.
func matchRoute(routes []model.Route, dest netip.Addr) (model.Route, bool, bool) {
	var best model.Route
	bestBits := -1
	found := false
	for _, r := range routes {
		if r.Destination.IsValid() && !r.Destination.Contains(dest) {
			continue
		}
		bits := 0
		if r.Destination.IsValid() {
			bits = r.Destination.Bits()
		}
		if bits > bestBits {
			best = r
			bestBits = bits
			found = true
		}
	}
	if !found {
		return best, false, false
	}
	if best.TargetKind == model.TargetBlackhole || best.State == "blackhole" {
		return best, true, true
	}
	return best, true, false
}

func walkRoutes(w *pathWalker, srcSub, dstSub *model.Subnet, dstExternal bool, dstIP netip.Addr) ([]Hop, *Hop) {
	var hops []Hop

	// Same VPC: subnet route table only.
	if !dstExternal && dstSub != nil && dstSub.VPCID == srcSub.VPCID {
		rt := w.g.routeTableForSubnet(srcSub)
		if rt == nil {
			h := Hop{Layer: "route", Region: srcSub.Region, Resource: srcSub.ID, Detail: "no route table for subnet", Allowed: false}
			return hops, &h
		}
		r, ok, blackhole := matchRoute(rt.Routes, dstIP)
		if blackhole {
			h := Hop{Layer: "route", Region: srcSub.Region, Resource: rt.Name, Detail: fmt.Sprintf("blackhole for %s", dstIP), Allowed: false}
			return append(hops, h), &h
		}
		if !ok {
			h := Hop{Layer: "route", Region: srcSub.Region, Resource: rt.Name, Detail: fmt.Sprintf("no route to %s", dstIP), Allowed: false}
			return append(hops, h), &h
		}
		nextHop, nextHopKind := routeNextHop(r)
		hops = append(hops, Hop{
			Layer: "route", Region: srcSub.Region, Resource: rt.Name,
			Detail: fmt.Sprintf("%s → %s (%s)", r.Destination, r.TargetID, r.TargetKind), Allowed: true,
			NextHop: nextHop, NextHopKind: nextHopKind,
		})
		return hops, nil
	}

	// Cross-VPC / cross-region / external via TGW.
	rt := w.g.routeTableForSubnet(srcSub)
	if rt == nil {
		h := Hop{Layer: "route", Region: srcSub.Region, Detail: "no subnet route table", Allowed: false}
		return hops, &h
	}
	r, ok, blackhole := matchRoute(rt.Routes, dstIP)
	if blackhole {
		h := Hop{Layer: "route", Region: srcSub.Region, Resource: rt.Name, Detail: "subnet blackhole", Allowed: false}
		return append(hops, h), &h
	}
	if !ok || r.TargetKind != model.TargetTransitGateway {
		h := Hop{Layer: "route", Region: srcSub.Region, Resource: rt.Name,
			Detail: fmt.Sprintf("no transit gateway route to %s (need TGW in path)", dstIP), Allowed: false}
		return append(hops, h), &h
	}
	hops = append(hops, Hop{
		Layer: "route", Region: srcSub.Region, Resource: rt.Name,
		Detail: fmt.Sprintf("vpc route → TGW %s", r.TargetID), Allowed: true,
		NextHop: r.TargetID, NextHopKind: string(model.TargetTransitGateway),
	})

	attach := w.g.vpcAttachment(srcSub.VPCID, srcSub.Region, r.TargetID)
	if attach == nil {
		h := Hop{Layer: "tgw", Region: srcSub.Region, Detail: fmt.Sprintf("no TGW VPC attachment for %s", srcSub.VPCID), Allowed: false}
		return append(hops, h), &h
	}
	hops = append(hops, Hop{
		Layer: "tgw", Region: srcSub.Region, Resource: attach.ID, Detail: "entered transit gateway", Allowed: true,
		NextHop: attach.ID, NextHopKind: nextHopAttachment,
	})

	tgwRT := w.g.tgwRouteTableForAttachment(attach.ID)
	if tgwRT == nil {
		for _, rt := range w.g.snap.TGWRouteTables {
			if rt.TransitGatewayID == attach.TransitGatewayID && rt.Region == srcSub.Region {
				tgwRT = rt
				break
			}
		}
	}
	if tgwRT == nil {
		h := Hop{Layer: LayerTGWRoute, Region: srcSub.Region, Detail: "no TGW route table for attachment", Allowed: false}
		return append(hops, h), &h
	}

	return w.walkTGW(hops, tgwRT, attach, dstSub, dstExternal, dstIP)
}

func (w *pathWalker) walkTGW(hops []Hop, tgwRT *model.TGWRouteTable, via *model.TGWAttachment, dstSub *model.Subnet, dstExternal bool, dstIP netip.Addr) ([]Hop, *Hop) {
	r, ok, blackhole := matchRoute(tgwRT.Routes, dstIP)
	if blackhole {
		h := Hop{Layer: LayerTGWRoute, Region: tgwRT.Region, Resource: tgwRT.Name, Detail: fmt.Sprintf("blackhole for %s", dstIP), Allowed: false}
		return append(hops, h), &h
	}
	if !ok {
		h := Hop{Layer: LayerTGWRoute, Region: tgwRT.Region, Resource: tgwRT.Name, Detail: fmt.Sprintf("no TGW route to %s", dstIP), Allowed: false}
		return append(hops, h), &h
	}

	nextHop, nextHopKind := routeNextHop(r)
	hops = append(hops, Hop{
		Layer: LayerTGWRoute, Region: tgwRT.Region, Resource: tgwRT.Name,
		Detail: fmt.Sprintf("%s → %s (%s)", r.Destination, r.TargetID, r.TargetKind), Allowed: true,
		NextHop: nextHop, NextHopKind: nextHopKind,
	})

	if dstExternal {
		return hops, nil
	}

	switch r.TargetKind {
	case model.TargetAttachment, model.TargetUnknown:
		nextAttach := w.g.attachmentForTGWRoute(tgwRT.TransitGatewayID, r.TargetID)
		if nextAttach == nil {
			h := Hop{Layer: "tgw", Region: tgwRT.Region, Detail: fmt.Sprintf("unknown attachment %s", r.TargetID), Allowed: false}
			return append(hops, h), &h
		}

		if nextAttach.Kind == model.AttachPeering {
			remoteTGWID := r.TargetID
			if !strings.HasPrefix(remoteTGWID, "tgw-") {
				remoteTGWID = nextAttach.PeerTGWID
				if remoteTGWID == "" || remoteTGWID == tgwRT.TransitGatewayID {
					remoteTGWID = nextAttach.ResourceID
				}
			}
			hops = append(hops, Hop{
				Layer: "tgw-peering", Region: nextAttach.Region, Resource: nextAttach.ID,
				Detail: fmt.Sprintf("cross-region peering → %s", remoteTGWID), Allowed: true,
				NextHop: remoteTGWID, NextHopKind: string(model.TargetTransitGateway),
			})
			remoteTGW := w.g.transitGateway(remoteTGWID)
			if remoteTGW == nil {
				detail := w.g.missingTGWRouteReason(remoteTGWID, nextAttach)
				if detail == "" {
					detail = fmt.Sprintf("peer TGW %s not in snapshot", remoteTGWID)
				}
				h := Hop{Layer: "tgw-peering", Region: nextAttach.Region, Resource: nextAttach.ID, Detail: detail, Allowed: false}
				return append(hops, h), &h
			}
			peerRT := w.g.tgwRouteTableForPeering(nextAttach.ID, remoteTGW.ID)
			if peerRT == nil {
				for _, rt := range w.g.snap.TGWRouteTables {
					if rt.TransitGatewayID == remoteTGW.ID && rt.Region == remoteTGW.Region {
						peerRT = rt
						break
					}
				}
			}
			if peerRT == nil {
				h := Hop{Layer: LayerTGWRoute, Region: remoteTGW.Region, Detail: "no route table on peer TGW", Allowed: false}
				return append(hops, h), &h
			}
			peerVia := &model.TGWAttachment{
				Meta:             model.Meta{Region: remoteTGW.Region},
				TransitGatewayID: remoteTGW.ID,
				Kind:             model.AttachPeering,
				State:            "available",
			}
			return w.walkTGW(hops, peerRT, peerVia, dstSub, false, dstIP)
		}

		if nextAttach.Kind == model.AttachVPC {
			if w.g.firewallInVPC(nextAttach.ResourceID) != nil {
				if dstSub == nil || dstSub.VPCID != nextAttach.ResourceID {
					return w.walkThroughInspectionVPC(hops, nextAttach, dstSub, dstExternal, dstIP)
				}
			}
			if dstSub != nil && nextAttach.ResourceID != dstSub.VPCID {
				h := Hop{Layer: "tgw", Region: nextAttach.Region, Detail: fmt.Sprintf("attachment %s does not reach destination VPC", nextAttach.ID), Allowed: false}
				return append(hops, h), &h
			}
			hops = append(hops, Hop{
				Layer: "tgw", Region: nextAttach.Region, Resource: nextAttach.ID,
				Detail: fmt.Sprintf("delivered to VPC %s", nextAttach.ResourceID), Allowed: true,
				NextHop: nextAttach.ID, NextHopKind: nextHopAttachment,
			})
			return hops, nil
		}

		h := Hop{Layer: "tgw", Region: nextAttach.Region, Detail: fmt.Sprintf("unsupported attachment kind %s", nextAttach.Kind), Allowed: false}
		return append(hops, h), &h

	default:
		if dstSub != nil && tgwRT.Region == dstSub.Region {
			return hops, nil
		}
		h := Hop{Layer: LayerTGWRoute, Region: tgwRT.Region, Detail: fmt.Sprintf("unsupported next hop %s", r.TargetKind), Allowed: false}
		return append(hops, h), &h
	}
}
