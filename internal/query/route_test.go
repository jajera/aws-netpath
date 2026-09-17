package query

import (
	"net/netip"
	"testing"

	"github.com/jajera/aws-netpath/internal/model"
)

func TestMatchRouteLongestPrefixWinsOverBlackhole(t *testing.T) {
	routes := []model.Route{
		{Destination: netip.MustParsePrefix("10.0.0.0/8"), TargetKind: model.TargetBlackhole, State: "blackhole"},
		{Destination: netip.MustParsePrefix("10.30.128.0/17"), TargetKind: model.TargetAttachment, TargetID: "tgw-peer"},
	}
	dest := netip.MustParseAddr("10.30.192.10")
	r, ok, blackhole := matchRoute(routes, dest)
	if !ok || blackhole {
		t.Fatalf("matchRoute() = (%v, %v, %v), want specific peering route", r, ok, blackhole)
	}
	if r.TargetID != "tgw-peer" {
		t.Fatalf("TargetID = %q, want tgw-peer", r.TargetID)
	}
}
