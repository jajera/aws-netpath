package verify

import (
	"fmt"
	"net/netip"

	"github.com/jajera/aws-netpath/internal/model"
)

// RAEndpoints are Reachability Analyzer source/destination resource IDs.
// AWS accepts instance, network-interface, transit-gateway-attachment, etc. — not VPC IDs.
type RAEndpoints struct {
	Source         string
	Destination    string
	SourceVPC      string
	DestinationVPC string
	SkipReason     string
}

// ResolveRAEndpoints picks supported AWS resource IDs for a flow.
func ResolveRAEndpoints(snap *model.Snapshot, src, dst netip.Addr) RAEndpoints {
	srcVPC, srcRegion, srcOK := SubnetForAddr(snap, src)
	dstVPC, dstRegion, dstOK := SubnetForAddr(snap, dst)
	if !srcOK || !dstOK {
		return RAEndpoints{SkipReason: "source or destination IP not in snapshot subnets"}
	}

	srcENI := eniForAddr(snap, src)
	dstENI := eniForAddr(snap, dst)

	if srcVPC == dstVPC {
		if srcENI != "" && dstENI != "" {
			return RAEndpoints{
				Source: srcENI, Destination: dstENI,
				SourceVPC: srcVPC, DestinationVPC: dstVPC,
			}
		}
		return RAEndpoints{
			SourceVPC: srcVPC, DestinationVPC: dstVPC,
			SkipReason: "intra-VPC paths need network-interface IDs; collect ENIs or pick endpoints in different VPCs",
		}
	}

	out := RAEndpoints{SourceVPC: srcVPC, DestinationVPC: dstVPC}

	if srcENI != "" {
		out.Source = srcENI
	} else if attach := vpcTGWAttachment(snap, srcVPC, srcRegion); attach != "" {
		out.Source = attach
	} else {
		return RAEndpoints{
			SourceVPC: srcVPC, DestinationVPC: dstVPC,
			SkipReason: fmt.Sprintf("no network-interface or transit-gateway attachment for source VPC %s", srcVPC),
		}
	}

	if dstENI != "" {
		out.Destination = dstENI
	} else if attach := vpcTGWAttachment(snap, dstVPC, dstRegion); attach != "" {
		out.Destination = attach
	} else {
		return RAEndpoints{
			SourceVPC: srcVPC, DestinationVPC: dstVPC,
			SkipReason: fmt.Sprintf("no network-interface or transit-gateway attachment for destination VPC %s", dstVPC),
		}
	}

	return out
}

func eniForAddr(snap *model.Snapshot, addr netip.Addr) string {
	for id, eni := range snap.NetworkIfaces {
		for _, ip := range eni.PrivateIPs {
			if ip == addr {
				return id
			}
		}
		if eni.PublicIP != nil && *eni.PublicIP == addr {
			return id
		}
	}
	return ""
}

func vpcTGWAttachment(snap *model.Snapshot, vpcID, region string) string {
	tgwID := tgwForVPCRoute(snap, vpcID, region)
	var best string
	for id, a := range snap.TGWAttachments {
		if a.Kind != model.AttachVPC || a.ResourceID != vpcID || a.Region != region || a.State != "available" {
			continue
		}
		if tgwID != "" && a.TransitGatewayID != tgwID {
			continue
		}
		if best == "" || id < best {
			best = id
		}
	}
	return best
}

func tgwForVPCRoute(snap *model.Snapshot, vpcID, region string) string {
	for _, rt := range snap.RouteTables {
		if rt.VPCID != vpcID || rt.Region != region {
			continue
		}
		for _, r := range rt.Routes {
			if r.TargetKind == model.TargetTransitGateway && r.TargetID != "" {
				return r.TargetID
			}
		}
	}
	return ""
}
