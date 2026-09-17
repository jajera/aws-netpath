package query

import (
	"net/netip"
	"testing"

	"github.com/jajera/aws-netpath/internal/flow"
	"github.com/jajera/aws-netpath/internal/model"
)

func TestQuerySameVPCLocalRoute(t *testing.T) {
	snap := model.NewSnapshot()
	vpc := "vpc-1"
	subA := &model.Subnet{
		Meta:  model.Meta{ID: "subnet-a", Region: "us-east-1", Name: "a"},
		VPCID: vpc, CIDR: netip.MustParsePrefix("10.0.1.0/24"), RouteTableID: "rt-1",
	}
	subB := &model.Subnet{
		Meta:  model.Meta{ID: "subnet-b", Region: "us-east-1", Name: "b"},
		VPCID: vpc, CIDR: netip.MustParsePrefix("10.0.2.0/24"),
	}
	snap.Subnets[subA.ID] = subA
	snap.Subnets[subB.ID] = subB
	snap.RouteTables["rt-1"] = &model.RouteTable{
		Meta:  model.Meta{ID: "rt-1", Name: "main", Region: "us-east-1"},
		VPCID: vpc,
		Routes: []model.Route{
			{Destination: netip.MustParsePrefix("10.0.0.0/16"), TargetKind: model.TargetLocal, TargetID: "local"},
		},
	}

	res, err := Run(Options{
		Snapshot:     snap,
		SrcIP:        netip.MustParseAddr("10.0.1.10"),
		DstIP:        netip.MustParseAddr("10.0.2.20"),
		Proto:        flow.ProtoTCP,
		Port:         443,
		SkipFirewall: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict != VerdictPermitted {
		t.Fatalf("verdict = %s, want PERMITTED (hops %+v)", res.Verdict, res.Hops)
	}
}

func TestQueryBlocksWithoutTGWRoute(t *testing.T) {
	snap := model.NewSnapshot()
	vpcA, vpcB := "vpc-a", "vpc-b"
	snap.Subnets["subnet-a"] = &model.Subnet{
		Meta:  model.Meta{ID: "subnet-a", Region: "us-east-1"},
		VPCID: vpcA, CIDR: netip.MustParsePrefix("10.30.32.0/24"), RouteTableID: "rt-a",
	}
	snap.Subnets["subnet-b"] = &model.Subnet{
		Meta:  model.Meta{ID: "subnet-b", Region: "us-west-2"},
		VPCID: vpcB, CIDR: netip.MustParsePrefix("10.30.192.0/24"),
	}
	snap.RouteTables["rt-a"] = &model.RouteTable{
		Meta:  model.Meta{ID: "rt-a", Name: "spoke-rt", Region: "us-east-1"},
		VPCID: vpcA,
		Routes: []model.Route{
			{Destination: netip.MustParsePrefix("10.30.32.0/19"), TargetKind: model.TargetLocal},
			{Destination: netip.MustParsePrefix("0.0.0.0/0"), TargetKind: model.TargetTransitGateway, TargetID: "tgw-a"},
		},
	}
	snap.TGWAttachments["tgw-attach-a"] = &model.TGWAttachment{
		Meta:             model.Meta{ID: "tgw-attach-a", Region: "us-east-1"},
		TransitGatewayID: "tgw-a", Kind: model.AttachVPC, ResourceID: vpcA, State: "available",
	}
	snap.TGWRouteTables["tgw-rt-a"] = &model.TGWRouteTable{
		Meta:             model.Meta{ID: "tgw-rt-a", Name: "inspection", Region: "us-east-1"},
		TransitGatewayID: "tgw-a", AssociatedAttachments: []string{"tgw-attach-a"},
		Routes: []model.Route{
			{Destination: netip.MustParsePrefix("10.30.0.0/16"), TargetKind: model.TargetBlackhole, State: "blackhole"},
		},
	}

	res, err := Run(Options{
		Snapshot:     snap,
		SrcIP:        netip.MustParseAddr("10.30.32.10"),
		DstIP:        netip.MustParseAddr("10.30.192.10"),
		Proto:        flow.ProtoTCP,
		Port:         443,
		SkipFirewall: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict != VerdictBlocked {
		t.Fatalf("verdict = %s, want BLOCKED", res.Verdict)
	}
}
