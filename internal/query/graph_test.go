package query

import (
	"net/netip"
	"testing"

	"github.com/jajera/aws-netpath/internal/model"
)

func TestSubnetForAddrPrefersRoutableSubnetOnCIDRTie(t *testing.T) {
	addr := netip.MustParseAddr("10.30.0.106")
	g := newGraph(&model.Snapshot{
		Subnets: map[string]*model.Subnet{
			"subnet-legacy": {
				Meta:  model.Meta{ID: "subnet-legacy"},
				VPCID: "vpc-old",
				CIDR:  netip.MustParsePrefix("10.30.0.0/24"),
			},
			"subnet-routed": {
				Meta:         model.Meta{ID: "subnet-routed"},
				VPCID:        "vpc-new",
				CIDR:         netip.MustParsePrefix("10.30.0.0/24"),
				RouteTableID: "rtb-routed",
			},
		},
	})

	sub, ok := g.subnetForAddr(addr)
	if !ok || sub.ID != "subnet-routed" {
		t.Fatalf("subnetForAddr() = (%v, %v), want subnet-routed", sub, ok)
	}
}

func TestPeeringBetweenFindsInterRegionPeer(t *testing.T) {
	g := newGraph(&model.Snapshot{
		TGWAttachments: map[string]*model.TGWAttachment{
			"tgw-attach-legacy-peer": {
				Meta:             model.Meta{ID: "tgw-attach-legacy-peer"},
				TransitGatewayID: "tgw-east",
				Kind:             model.AttachPeering,
				ResourceID:       "tgw-deleted",
				PeerTGWID:        "tgw-deleted",
				State:            "available",
			},
			"tgw-attach-interregion": {
				Meta:             model.Meta{ID: "tgw-attach-interregion"},
				TransitGatewayID: "tgw-east",
				Kind:             model.AttachPeering,
				ResourceID:       "tgw-west",
				PeerTGWID:        "tgw-west",
				State:            "available",
			},
		},
	})

	got := g.attachmentForTGWRoute("tgw-west", "tgw-east")
	if got == nil || got.ID != "tgw-attach-interregion" {
		t.Fatalf("attachmentForTGWRoute() = %v, want interregion peering", got)
	}
}
