package query

import (
	"fmt"
	"net/netip"

	"github.com/jajera/aws-netpath/internal/model"
)

// walkThroughInspectionVPC models traffic entering an inspection VPC, passing
// the regional Network Firewall, and returning to the transit gateway on the
// post-inspection route table.
func (w *pathWalker) walkThroughInspectionVPC(hops []Hop, attach *model.TGWAttachment, dstSub *model.Subnet, dstExternal bool, dstIP netip.Addr) ([]Hop, *Hop) {
	vpcID := attach.ResourceID
	label := vpcID
	if v := w.g.snap.VPCs[vpcID]; v != nil && v.Name != "" {
		label = v.Name
	}
	hops = append(hops, Hop{
		Layer: "inspection-vpc", Region: attach.Region, Resource: label,
		Detail: "traffic enters inspection VPC via TGW", Allowed: true,
		// The VPC ID rather than the label: a direction is compared on
		// identifiers, and the label may be an operator-chosen name.
		NextHop: vpcID, NextHopKind: nextHopInspectionVPC,
	})

	if fw := w.g.firewallInVPC(vpcID); fw != nil {
		if w.skipFirewall {
			w.recordSkippedFirewall(fw)
		} else {
			var blocked *Hop
			hops, blocked = w.evalFirewall(hops, fw)
			if blocked != nil {
				return hops, blocked
			}
		}
	}

	if rt := w.g.inspectionEgressRouteTable(vpcID, attach.TransitGatewayID); rt != nil {
		hops = append(hops, Hop{
			Layer: "inspection-vpc", Region: attach.Region, Resource: rt.Name,
			Detail: fmt.Sprintf("egress → TGW %s", attach.TransitGatewayID), Allowed: true,
			NextHop: attach.TransitGatewayID, NextHopKind: string(model.TargetTransitGateway),
		})
	}

	tgwRT := w.g.tgwRouteTableForAttachment(attach.ID)
	if tgwRT == nil {
		h := Hop{Layer: LayerTGWRoute, Region: attach.Region, Detail: "no post-inspection TGW route table", Allowed: false}
		return append(hops, h), &h
	}
	hops = append(hops, Hop{
		Layer: "tgw", Region: attach.Region, Resource: attach.ID,
		Detail: "re-entered transit gateway after inspection", Allowed: true,
		NextHop: attach.ID, NextHopKind: nextHopAttachment,
	})
	return w.walkTGW(hops, tgwRT, attach, dstSub, dstExternal, dstIP)
}
