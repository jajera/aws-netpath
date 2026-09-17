package verify

import (
	"net/netip"
	"testing"

	"github.com/jajera/aws-netpath/internal/model"
)

func TestResolveRAEndpointsIntraVPCSkipsWithoutENI(t *testing.T) {
	snap := loadFixture(t, "../query/testdata/default-action-pass.json")
	ep := ResolveRAEndpoints(snap, mustAddr(t, "10.30.32.10"), mustAddr(t, "10.30.32.20"))
	if ep.SkipReason == "" {
		t.Fatalf("expected skip for intra-VPC, got source=%q dest=%q", ep.Source, ep.Destination)
	}
}

func TestResolveRAEndpointsCrossVPCUsesTGWAttachments(t *testing.T) {
	snap := loadFixture(t, "../query/testdata/double-inspection.json")
	ep := ResolveRAEndpoints(snap, mustAddr(t, "10.30.32.10"), mustAddr(t, "10.29.17.10"))
	if ep.SkipReason != "" {
		t.Fatalf("unexpected skip: %s", ep.SkipReason)
	}
	if ep.Source != "tgw-attach-prod-east" {
		t.Fatalf("source = %q, want tgw-attach-prod-east", ep.Source)
	}
	if ep.Destination != "tgw-attach-inspection-east" {
		t.Fatalf("destination = %q, want tgw-attach-inspection-east", ep.Destination)
	}
}

func TestResolveRAEndpointsUsesENIWhenPresent(t *testing.T) {
	snap := loadFixture(t, "../query/testdata/default-action-pass.json")
	sub := snap.Subnets["subnet-prod-east-a"]
	dup := *sub
	dup.ID = "subnet-prod-east-b"
	dup.CIDR = netip.MustParsePrefix("10.30.33.0/24")
	snap.Subnets[dup.ID] = &dup

	if snap.NetworkIfaces == nil {
		snap.NetworkIfaces = map[string]*model.NetworkIface{}
	}
	snap.NetworkIfaces["eni-src"] = &model.NetworkIface{
		SubnetID:   "subnet-prod-east-a",
		VPCID:      sub.VPCID,
		PrivateIPs: []netip.Addr{mustAddr(t, "10.30.32.10")},
	}
	snap.NetworkIfaces["eni-dst"] = &model.NetworkIface{
		SubnetID:   "subnet-prod-east-b",
		VPCID:      sub.VPCID,
		PrivateIPs: []netip.Addr{mustAddr(t, "10.30.33.10")},
	}

	ep := ResolveRAEndpoints(snap, mustAddr(t, "10.30.32.10"), mustAddr(t, "10.30.33.10"))
	if ep.SkipReason != "" {
		t.Fatalf("unexpected skip: %s", ep.SkipReason)
	}
	if ep.Source != "eni-src" || ep.Destination != "eni-dst" {
		t.Fatalf("got source=%q dest=%q, want eni-src/eni-dst", ep.Source, ep.Destination)
	}
}
