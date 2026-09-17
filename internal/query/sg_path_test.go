package query

// End-to-end security group coverage for the path walk: one permitted path, one
// path the destination group blocks, and the cases where the snapshot cannot
// answer. The abstention cases matter most — an endpoint the snapshot cannot see
// must never read as an endpoint that permits everything.

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/jajera/aws-netpath/internal/flow"
	"github.com/jajera/aws-netpath/internal/model"
)

const (
	sgTestAccount = "111122223333"
	sgTestRegion  = "us-east-1"
)

var (
	sgTestSrcIP = netip.MustParseAddr("10.20.1.10")
	sgTestDstIP = netip.MustParseAddr("10.20.2.20")
	sgTestExtIP = netip.MustParseAddr("203.0.113.10")
)

// sgPathSnapshot builds two subnets in one VPC joined by a local route, each
// endpoint owning an interface with one group. No NACLs are attached, so the
// only policy in the path is the security groups under test.
func sgPathSnapshot() *model.Snapshot {
	snap := model.NewSnapshot()
	snap.Accounts = []string{sgTestAccount}
	snap.Regions = []string{sgTestRegion}

	snap.VPCs["vpc-app"] = &model.VPC{
		Meta:  model.Meta{ID: "vpc-app", Name: "app", Region: sgTestRegion, Account: sgTestAccount},
		CIDRs: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")},
	}
	snap.Subnets["subnet-app"] = &model.Subnet{
		Meta:  model.Meta{ID: "subnet-app", Name: "app-a", Region: sgTestRegion, Account: sgTestAccount},
		VPCID: "vpc-app", CIDR: netip.MustParsePrefix("10.20.1.0/24"), RouteTableID: "rt-app",
	}
	snap.Subnets["subnet-db"] = &model.Subnet{
		Meta:  model.Meta{ID: "subnet-db", Name: "db-a", Region: sgTestRegion, Account: sgTestAccount},
		VPCID: "vpc-app", CIDR: netip.MustParsePrefix("10.20.2.0/24"), RouteTableID: "rt-app",
	}
	snap.RouteTables["rt-app"] = &model.RouteTable{
		Meta:  model.Meta{ID: "rt-app", Name: "app-rt", Region: sgTestRegion, Account: sgTestAccount},
		VPCID: "vpc-app",
		Routes: []model.Route{
			{Destination: netip.MustParsePrefix("10.20.0.0/16"), TargetKind: model.TargetLocal, TargetID: "local"},
		},
	}

	snap.SecurityGroups["sg-app"] = &model.SecurityGroup{
		Meta:  model.Meta{ID: "sg-app", Name: "app", Region: sgTestRegion, Account: sgTestAccount},
		VPCID: "vpc-app",
		Egress: []model.SGRule{{
			Protocol: "tcp", FromPort: 443, ToPort: 443,
			CIDRs: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")},
		}},
	}
	snap.SecurityGroups["sg-db"] = &model.SecurityGroup{
		Meta:  model.Meta{ID: "sg-db", Name: "db", Region: sgTestRegion, Account: sgTestAccount},
		VPCID: "vpc-app",
		Ingress: []model.SGRule{{
			Protocol: "tcp", FromPort: 443, ToPort: 443,
			CIDRs: []netip.Prefix{netip.MustParsePrefix("10.20.1.0/24")},
		}},
	}

	snap.NetworkIfaces["eni-app"] = &model.NetworkIface{
		Meta:  model.Meta{ID: "eni-app", Region: sgTestRegion, Account: sgTestAccount},
		VPCID: "vpc-app", SubnetID: "subnet-app", Status: "in-use",
		SecurityGroupIDs: []string{"sg-app"},
		PrivateIPs:       []netip.Addr{sgTestSrcIP},
	}
	snap.NetworkIfaces["eni-db"] = &model.NetworkIface{
		Meta:  model.Meta{ID: "eni-db", Region: sgTestRegion, Account: sgTestAccount},
		VPCID: "vpc-app", SubnetID: "subnet-db", Status: "in-use",
		SecurityGroupIDs: []string{"sg-db"},
		PrivateIPs:       []netip.Addr{sgTestDstIP},
	}
	return snap
}

// sgExternalSnapshot routes the source out to a declared external network, so
// routing is decidable while the destination endpoint is not in the snapshot.
func sgExternalSnapshot() *model.Snapshot {
	snap := sgPathSnapshot()
	delete(snap.Subnets, "subnet-db")
	delete(snap.NetworkIfaces, "eni-db")
	delete(snap.SecurityGroups, "sg-db")

	snap.SecurityGroups["sg-app"].Egress = []model.SGRule{{
		Protocol: "tcp", FromPort: 443, ToPort: 443,
		CIDRs: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")},
	}}
	snap.RouteTables["rt-app"].Routes = append(snap.RouteTables["rt-app"].Routes, model.Route{
		Destination: netip.MustParsePrefix("0.0.0.0/0"),
		TargetKind:  model.TargetTransitGateway, TargetID: "tgw-hub",
	})
	snap.TGWAttachments["tgw-attach-app"] = &model.TGWAttachment{
		Meta:             model.Meta{ID: "tgw-attach-app", Region: sgTestRegion, Account: sgTestAccount},
		TransitGatewayID: "tgw-hub", Kind: model.AttachVPC, ResourceID: "vpc-app", State: "available",
	}
	snap.TGWRouteTables["tgw-rt-hub"] = &model.TGWRouteTable{
		Meta:             model.Meta{ID: "tgw-rt-hub", Name: "hub", Region: sgTestRegion, Account: sgTestAccount},
		TransitGatewayID: "tgw-hub", AssociatedAttachments: []string{"tgw-attach-app"},
		Routes: []model.Route{
			{Destination: netip.MustParsePrefix("203.0.113.0/24"), TargetKind: model.TargetAttachment, TargetID: "tgw-attach-onprem"},
		},
	}
	snap.ExternalNetworks["ext-onprem"] = &model.ExternalNetwork{
		Meta:  model.Meta{ID: "ext-onprem", Name: "on-premises", Region: sgTestRegion},
		CIDRs: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")},
	}
	return snap
}

// abstainWant is one expected abstention: the Layer that could not be evaluated
// and a substring of the reason it must give.
type abstainWant struct {
	layer  model.Layer
	reason string
}

// TestQuerySecurityGroupPath covers the security group layer end to end.
//
// Validates: Requirements 4.3
func TestQuerySecurityGroupPath(t *testing.T) {
	cases := []struct {
		name string
		snap func() *model.Snapshot
		dst  netip.Addr
		// wantVerdict is the overall query outcome.
		wantVerdict Verdict
		// wantBlockedLayer is the layer of BlockedAt, empty when nothing blocks.
		wantBlockedLayer string
		// wantEvidence are substrings that must appear in the security group
		// hop details or citations: the group IDs and the deciding rules.
		wantEvidence []string
		// wantNoEvidence guards against an implied pass for an endpoint the
		// snapshot could not evaluate.
		wantNoEvidence []string
		// wantAbstain is one entry per expected abstention, in the order the
		// result records them.
		wantAbstain       []abstainWant
		wantAuthoritative bool
	}{
		{
			name:        "source egress and destination ingress both permit",
			snap:        sgPathSnapshot,
			dst:         sgTestDstIP,
			wantVerdict: VerdictPermitted,
			wantEvidence: []string{
				"sg-app", "allow tcp/443 to 10.20.0.0/16",
				"sg-db", "allow tcp/443 from 10.20.1.0/24",
			},
			wantAuthoritative: true,
		},
		{
			name: "destination ingress omits the source",
			snap: func() *model.Snapshot {
				snap := sgPathSnapshot()
				snap.SecurityGroups["sg-db"].Ingress = []model.SGRule{{
					Protocol: "tcp", FromPort: 443, ToPort: 443,
					CIDRs: []netip.Prefix{netip.MustParsePrefix("10.20.9.0/24")},
				}}
				return snap
			},
			dst:              sgTestDstIP,
			wantVerdict:      VerdictBlocked,
			wantBlockedLayer: "sg",
			wantEvidence: []string{
				"sg-app", "allow tcp/443 to 10.20.0.0/16",
				"ingress denied", "no rule in sg-db", "tcp/443 from 10.20.1.10",
				"no matching ingress rule (1 recorded)",
			},
			wantAuthoritative: true,
		},
		{
			name: "source interface absent from the snapshot",
			snap: func() *model.Snapshot {
				snap := sgPathSnapshot()
				delete(snap.NetworkIfaces, "eni-app")
				return snap
			},
			dst:            sgTestDstIP,
			wantVerdict:    VerdictPermitted,
			wantEvidence:   []string{"sg-db", "allow tcp/443 from 10.20.1.0/24"},
			wantNoEvidence: []string{"egress permitted", "egress denied"},
			wantAbstain: []abstainWant{
				{model.LayerSecurityGroup, "source 10.20.1.10 has no collected network interface"},
			},
			wantAuthoritative: false,
		},
		{
			name: "destination interface absent from the snapshot",
			snap: func() *model.Snapshot {
				snap := sgPathSnapshot()
				delete(snap.NetworkIfaces, "eni-db")
				return snap
			},
			dst:            sgTestDstIP,
			wantVerdict:    VerdictPermitted,
			wantEvidence:   []string{"sg-app", "allow tcp/443 to 10.20.0.0/16"},
			wantNoEvidence: []string{"ingress permitted", "ingress denied"},
			wantAbstain: []abstainWant{
				{model.LayerSecurityGroup, "destination 10.20.2.20 has no collected network interface"},
			},
			wantAuthoritative: false,
		},
		{
			name:           "destination outside the snapshot",
			snap:           sgExternalSnapshot,
			dst:            sgTestExtIP,
			wantVerdict:    VerdictPermitted,
			wantEvidence:   []string{"sg-app", "allow tcp/443 to 203.0.113.0/24"},
			wantNoEvidence: []string{"ingress permitted", "ingress denied"},
			// The destination sits outside the snapshot, so neither its groups
			// nor the route table the response would leave from can be read.
			wantAbstain: []abstainWant{
				{model.LayerSecurityGroup, "destination 203.0.113.10 lies outside the snapshot"},
				{model.LayerReturnPath, "whose routing is not in the snapshot"},
			},
			wantAuthoritative: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := Run(Options{
				Snapshot:     tc.snap(),
				SrcIP:        sgTestSrcIP,
				DstIP:        tc.dst,
				Proto:        flow.ProtoTCP,
				Port:         443,
				SkipFirewall: true,
			})
			if err != nil {
				t.Fatalf("Run() error = %v", err)
			}

			if res.Verdict != tc.wantVerdict {
				t.Fatalf("verdict = %s, want %s%s", res.Verdict, tc.wantVerdict, formatHops(res.Hops))
			}

			if tc.wantBlockedLayer == "" {
				if res.BlockedAt != nil {
					t.Fatalf("BlockedAt = %+v, want nil", res.BlockedAt)
				}
			} else {
				if res.BlockedAt == nil {
					t.Fatalf("BlockedAt = nil, want layer %q%s", tc.wantBlockedLayer, formatHops(res.Hops))
				}
				if res.BlockedAt.Layer != tc.wantBlockedLayer {
					t.Fatalf("BlockedAt.Layer = %q, want %q", res.BlockedAt.Layer, tc.wantBlockedLayer)
				}
				if len(res.BlockedAt.Citations) == 0 {
					t.Fatal("BlockedAt.Citations is empty, want the groups consulted")
				}
			}

			evidence := sgEvidence(res)
			for _, want := range tc.wantEvidence {
				if !strings.Contains(evidence, want) {
					t.Errorf("security group evidence missing %q, got:\n%s", want, evidence)
				}
			}
			for _, unwanted := range tc.wantNoEvidence {
				if strings.Contains(evidence, unwanted) {
					t.Errorf("security group evidence contains %q for an endpoint that abstained, got:\n%s", unwanted, evidence)
				}
			}

			if len(res.Abstentions) != len(tc.wantAbstain) {
				t.Fatalf("abstentions = %d %+v, want %d", len(res.Abstentions), res.Abstentions, len(tc.wantAbstain))
			}
			for i, want := range tc.wantAbstain {
				got := res.Abstentions[i]
				if err := got.Validate(); err != nil {
					t.Errorf("abstention %d not emittable: %v", i, err)
				}
				if got.Layer != want.layer {
					t.Errorf("abstention %d layer = %q, want %q", i, got.Layer, want.layer)
				}
				if got.Verdict != model.VerdictAbstain {
					t.Errorf("abstention %d verdict = %q, want %q", i, got.Verdict, model.VerdictAbstain)
				}
				if !strings.Contains(got.Reason, want.reason) {
					t.Errorf("abstention %d reason = %q, want it to contain %q", i, got.Reason, want.reason)
				}
			}

			if got := res.Authoritative(); got != tc.wantAuthoritative {
				t.Errorf("Authoritative() = %v, want %v (abstentions %+v)", got, tc.wantAuthoritative, res.Abstentions)
			}
			// An abstention is not a pass: a permitted verdict resting on one
			// has to say so.
			if !tc.wantAuthoritative && !strings.Contains(strings.Join(res.Notes, "\n"), "not authoritative") {
				t.Errorf("notes = %v, want one stating the verdict is not authoritative", res.Notes)
			}
		})
	}
}

// sgEvidence collects everything the result says about the security group layer:
// hop details plus citation identifiers and details.
func sgEvidence(res *Result) string {
	var b strings.Builder
	for _, h := range res.Hops {
		if h.Layer != "sg" {
			continue
		}
		b.WriteString(h.Detail)
		b.WriteString("\n")
		for _, c := range h.Citations {
			b.WriteString("  ")
			b.WriteString(c.Kind)
			b.WriteString(" ")
			b.WriteString(c.Identifier)
			b.WriteString(": ")
			b.WriteString(c.Detail)
			b.WriteString("\n")
		}
	}
	return b.String()
}
