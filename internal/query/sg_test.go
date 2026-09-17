package query

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/jajera/aws-netpath/internal/flow"
	"github.com/jajera/aws-netpath/internal/model"
)

func TestEvalSGPermitsMatchingEgress(t *testing.T) {
	snap := model.NewSnapshot()
	snap.SecurityGroups["sg-1"] = &model.SecurityGroup{
		Meta: model.Meta{ID: "sg-1", Name: "web", Region: "us-west-2"},
		Egress: []model.SGRule{{
			Protocol: "tcp", FromPort: 53, ToPort: 53,
			CIDRs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
		}},
	}
	snap.NetworkIfaces["eni-1"] = &model.NetworkIface{
		Meta:             model.Meta{ID: "eni-1"},
		Status:           "in-use",
		SecurityGroupIDs: []string{"sg-1"},
		PrivateIPs:       []netip.Addr{netip.MustParseAddr("10.30.163.155")},
	}
	g := newGraph(snap)
	slice := flow.NewSlice(
		flow.NewPrefixSet(netip.MustParsePrefix("10.30.163.155/32")),
		flow.NewPrefixSet(netip.MustParsePrefix("10.29.16.144/32")),
		flow.ProtoTCP,
		flow.SinglePort(53),
	)
	addr := netip.MustParseAddr("10.30.163.155")
	hop, abstain := evalEndpointSG(g, g.eniForAddr(addr), addr, slice, true)
	if abstain != nil {
		t.Fatalf("evalEndpointSG() abstained: %s", abstain.Reason)
	}
	if hop == nil || !hop.Allowed {
		t.Fatalf("evalEndpointSG() = %+v, want permitted", hop)
	}
	if len(hop.Citations) == 0 || hop.Citations[0].Identifier != "sg-1" {
		t.Fatalf("citations = %+v, want the deciding group id", hop.Citations)
	}
}

func TestEvalReturnNACLBlocksAsymmetric(t *testing.T) {
	snap := model.NewSnapshot()
	src := &model.Subnet{
		Meta:   model.Meta{ID: "subnet-src", Region: "us-west-2"},
		NACLID: "acl-src",
	}
	dst := &model.Subnet{
		Meta:   model.Meta{ID: "subnet-dst", Region: "us-west-2"},
		NACLID: "acl-dst",
	}
	snap.NACLs["acl-src"] = &model.NACL{
		Meta: model.Meta{ID: "acl-src", Name: "src-nacl"},
		Egress: []model.NACLRule{{
			RuleNumber: 100, Protocol: "any", Allow: true,
			CIDR: netip.MustParsePrefix("0.0.0.0/0"), FromPort: 0, ToPort: 65535,
		}},
		Ingress: []model.NACLRule{{
			RuleNumber: 100, Protocol: "icmp", Allow: false,
			CIDR: netip.MustParsePrefix("0.0.0.0/0"), FromPort: 0, ToPort: 65535,
		}},
	}
	snap.NACLs["acl-dst"] = &model.NACL{
		Meta: model.Meta{ID: "acl-dst", Name: "dst-nacl"},
		Egress: []model.NACLRule{{
			RuleNumber: 100, Protocol: "icmp", Allow: true,
			CIDR: netip.MustParsePrefix("0.0.0.0/0"), FromPort: 0, ToPort: 65535,
		}},
	}
	g := newGraph(snap)
	slice := flow.NewSlice(
		flow.NewPrefixSet(netip.MustParsePrefix("10.0.0.1/32")),
		flow.NewPrefixSet(netip.MustParsePrefix("10.0.0.2/32")),
		flow.ProtoICMP,
		flow.AllPorts(),
	)
	reverse, _ := returnFlow(slice)
	hop := evalReturnNACL(g, src, dst, true, reverse)
	if hop == nil || hop.Allowed {
		t.Fatalf("evalReturnNACL() = %+v, want blocked return on src ingress", hop)
	}
}

func TestMissingTGWRouteReason(t *testing.T) {
	g := newGraph(&model.Snapshot{})
	msg := g.missingTGWRouteReason("tgw-missing", &model.TGWAttachment{
		Meta: model.Meta{Name: "tga-peer"},
	})
	if msg == "" || !strings.Contains(msg, "not in the snapshot") {
		t.Fatalf("missingTGWRouteReason() = %q", msg)
	}
	if strings.Contains(msg, "deleted") || strings.Contains(msg, "stale") {
		t.Fatalf("should not imply deleted/stale: %q", msg)
	}
}
