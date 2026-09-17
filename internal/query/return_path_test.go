package query

// Return path coverage: four topologies walked end to end, plus what the
// Correlator makes of each one.
//
// The interesting cases here are the ones where nothing blocks. A path whose two
// directions resolve to different components still carries traffic in both
// directions, so every Layer passes and the only finding is that the two hop
// chains disagree. That is why each case asserts the next hops both directions
// resolved to rather than only the verdict: the pair is the finding, and a
// summary that named one side would not be checkable.
//
// Addresses are RFC 1918 and the account is a placeholder, so no fixture here
// describes a real network.

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/jajera/aws-netpath/internal/correlate"
	"github.com/jajera/aws-netpath/internal/flow"
	"github.com/jajera/aws-netpath/internal/model"
	"github.com/jajera/aws-netpath/internal/symptom"
)

const (
	rpAccount = "111122223333"
	rpRegion  = "us-east-1"
)

var (
	rpSrcIP = netip.MustParseAddr("10.16.1.10")
	rpDstIP = netip.MustParseAddr("10.32.1.20")
)

func rpMeta(id, name string) model.Meta {
	return model.Meta{ID: id, Name: name, Region: rpRegion, Account: rpAccount}
}

// rpSymmetricSnapshot builds two VPCs joined by one transit gateway, each
// direction routed back through the same hub. This is the shape a healthy
// topology has: the two directions meet the same components in opposite order.
//
// Both endpoints own an interface with a group permitting the flow, so the
// security group layer decides rather than abstaining and the return direction
// is the only thing under test.
func rpSymmetricSnapshot() *model.Snapshot {
	snap := model.NewSnapshot()
	snap.Accounts = []string{rpAccount}
	snap.Regions = []string{rpRegion}

	snap.VPCs["vpc-app"] = &model.VPC{
		Meta:  rpMeta("vpc-app", "app"),
		CIDRs: []netip.Prefix{netip.MustParsePrefix("10.16.0.0/16")},
	}
	snap.VPCs["vpc-db"] = &model.VPC{
		Meta:  rpMeta("vpc-db", "db"),
		CIDRs: []netip.Prefix{netip.MustParsePrefix("10.32.0.0/16")},
	}

	snap.Subnets["subnet-app"] = &model.Subnet{
		Meta: rpMeta("subnet-app", "app-a"), VPCID: "vpc-app",
		CIDR: netip.MustParsePrefix("10.16.1.0/24"), RouteTableID: "rt-app",
	}
	snap.Subnets["subnet-db"] = &model.Subnet{
		Meta: rpMeta("subnet-db", "db-a"), VPCID: "vpc-db",
		CIDR: netip.MustParsePrefix("10.32.1.0/24"), RouteTableID: "rt-db",
	}

	snap.RouteTables["rt-app"] = &model.RouteTable{
		Meta: rpMeta("rt-app", "app-rt"), VPCID: "vpc-app",
		Routes: []model.Route{
			{Destination: netip.MustParsePrefix("10.16.0.0/16"), TargetKind: model.TargetLocal, TargetID: "local"},
			{Destination: netip.MustParsePrefix("10.0.0.0/8"), TargetKind: model.TargetTransitGateway, TargetID: "tgw-hub"},
		},
	}
	snap.RouteTables["rt-db"] = &model.RouteTable{
		Meta: rpMeta("rt-db", "db-rt"), VPCID: "vpc-db",
		Routes: []model.Route{
			{Destination: netip.MustParsePrefix("10.32.0.0/16"), TargetKind: model.TargetLocal, TargetID: "local"},
			{Destination: netip.MustParsePrefix("10.0.0.0/8"), TargetKind: model.TargetTransitGateway, TargetID: "tgw-hub"},
		},
	}

	snap.TransitGateways["tgw-hub"] = &model.TransitGateway{Meta: rpMeta("tgw-hub", "hub")}
	snap.TGWAttachments["tgw-attach-app"] = &model.TGWAttachment{
		Meta: rpMeta("tgw-attach-app", "app"), TransitGatewayID: "tgw-hub",
		Kind: model.AttachVPC, ResourceID: "vpc-app", State: "available",
	}
	snap.TGWAttachments["tgw-attach-db"] = &model.TGWAttachment{
		Meta: rpMeta("tgw-attach-db", "db"), TransitGatewayID: "tgw-hub",
		Kind: model.AttachVPC, ResourceID: "vpc-db", State: "available",
	}
	snap.TGWRouteTables["tgw-rt-hub"] = &model.TGWRouteTable{
		Meta: rpMeta("tgw-rt-hub", "hub"), TransitGatewayID: "tgw-hub",
		AssociatedAttachments: []string{"tgw-attach-app", "tgw-attach-db"},
		Routes: []model.Route{
			{Destination: netip.MustParsePrefix("10.16.0.0/16"), TargetKind: model.TargetAttachment, TargetID: "tgw-attach-app"},
			{Destination: netip.MustParsePrefix("10.32.0.0/16"), TargetKind: model.TargetAttachment, TargetID: "tgw-attach-db"},
		},
	}

	snap.SecurityGroups["sg-app"] = &model.SecurityGroup{
		Meta: rpMeta("sg-app", "app"), VPCID: "vpc-app",
		Egress: []model.SGRule{{
			Protocol: "tcp", FromPort: 443, ToPort: 443,
			CIDRs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
		}},
	}
	snap.SecurityGroups["sg-db"] = &model.SecurityGroup{
		Meta: rpMeta("sg-db", "db"), VPCID: "vpc-db",
		Ingress: []model.SGRule{{
			Protocol: "tcp", FromPort: 443, ToPort: 443,
			CIDRs: []netip.Prefix{netip.MustParsePrefix("10.16.0.0/16")},
		}},
	}
	snap.NetworkIfaces["eni-app"] = &model.NetworkIface{
		Meta: rpMeta("eni-app", ""), VPCID: "vpc-app", SubnetID: "subnet-app", Status: "in-use",
		SecurityGroupIDs: []string{"sg-app"}, PrivateIPs: []netip.Addr{rpSrcIP},
	}
	snap.NetworkIfaces["eni-db"] = &model.NetworkIface{
		Meta: rpMeta("eni-db", ""), VPCID: "vpc-db", SubnetID: "subnet-db", Status: "in-use",
		SecurityGroupIDs: []string{"sg-db"}, PrivateIPs: []netip.Addr{rpDstIP},
	}
	return snap
}

// rpInspectionDetourSnapshot diverts the return direction through an inspection
// VPC that the forward direction never enters: the hub table sends app → db
// straight across but db → app via the firewall.
//
// Both directions still deliver, so no Layer blocks. The firewall holds state
// for connections whose forward half it never saw, which is the topology
// requirement 7.3 is about.
func rpInspectionDetourSnapshot() *model.Snapshot {
	snap := rpSymmetricSnapshot()

	snap.VPCs["vpc-inspect"] = &model.VPC{
		Meta:  rpMeta("vpc-inspect", "inspection"),
		CIDRs: []netip.Prefix{netip.MustParsePrefix("10.48.0.0/16")},
	}
	snap.Subnets["subnet-inspect"] = &model.Subnet{
		Meta: rpMeta("subnet-inspect", "inspect-a"), VPCID: "vpc-inspect",
		CIDR: netip.MustParsePrefix("10.48.1.0/24"), RouteTableID: "rt-inspect",
	}
	snap.RouteTables["rt-inspect"] = &model.RouteTable{
		Meta: rpMeta("rt-inspect", "inspect-rt"), VPCID: "vpc-inspect",
		Routes: []model.Route{
			{Destination: netip.MustParsePrefix("10.48.0.0/16"), TargetKind: model.TargetLocal, TargetID: "local"},
			{Destination: netip.MustParsePrefix("0.0.0.0/0"), TargetKind: model.TargetTransitGateway, TargetID: "tgw-hub"},
		},
	}
	snap.TGWAttachments["tgw-attach-inspect"] = &model.TGWAttachment{
		Meta: rpMeta("tgw-attach-inspect", "inspection"), TransitGatewayID: "tgw-hub",
		Kind: model.AttachVPC, ResourceID: "vpc-inspect", State: "available",
	}
	snap.Firewalls["fw-inspect"] = &model.Firewall{
		Meta: rpMeta("fw-inspect", "inspection"), VPCID: "vpc-inspect",
		PolicyARN: "arn:aws:network-firewall:us-east-1:111122223333:firewall-policy/inspection",
		SubnetIDs: []string{"subnet-inspect"},
		EndpointsBySubnet: map[string]string{
			"subnet-inspect": "vpce-inspect",
		},
	}

	// The stale half of the topology: traffic toward the app VPC is inspected,
	// traffic toward the db VPC is not.
	snap.TGWRouteTables["tgw-rt-hub"].Routes = []model.Route{
		{Destination: netip.MustParsePrefix("10.32.0.0/16"), TargetKind: model.TargetAttachment, TargetID: "tgw-attach-db"},
		{Destination: netip.MustParsePrefix("10.16.0.0/16"), TargetKind: model.TargetAttachment, TargetID: "tgw-attach-inspect"},
	}
	snap.TGWRouteTables["tgw-rt-inspect"] = &model.TGWRouteTable{
		Meta: rpMeta("tgw-rt-inspect", "post-inspection"), TransitGatewayID: "tgw-hub",
		AssociatedAttachments: []string{"tgw-attach-inspect"},
		Routes: []model.Route{
			{Destination: netip.MustParsePrefix("10.16.0.0/16"), TargetKind: model.TargetAttachment, TargetID: "tgw-attach-app"},
			{Destination: netip.MustParsePrefix("10.32.0.0/16"), TargetKind: model.TargetAttachment, TargetID: "tgw-attach-db"},
		},
	}
	return snap
}

// rpStaleHubSnapshot leaves a specific route in the destination VPC pointing at
// a hub the forward direction no longer uses, so the two directions cross
// different transit gateways with nothing stateful on either path.
func rpStaleHubSnapshot() *model.Snapshot {
	snap := rpSymmetricSnapshot()

	snap.TransitGateways["tgw-legacy"] = &model.TransitGateway{Meta: rpMeta("tgw-legacy", "legacy")}
	snap.TGWAttachments["tgw-attach-app-legacy"] = &model.TGWAttachment{
		Meta: rpMeta("tgw-attach-app-legacy", "app-legacy"), TransitGatewayID: "tgw-legacy",
		Kind: model.AttachVPC, ResourceID: "vpc-app", State: "available",
	}
	snap.TGWAttachments["tgw-attach-db-legacy"] = &model.TGWAttachment{
		Meta: rpMeta("tgw-attach-db-legacy", "db-legacy"), TransitGatewayID: "tgw-legacy",
		Kind: model.AttachVPC, ResourceID: "vpc-db", State: "available",
	}
	snap.TGWRouteTables["tgw-rt-legacy"] = &model.TGWRouteTable{
		Meta: rpMeta("tgw-rt-legacy", "legacy"), TransitGatewayID: "tgw-legacy",
		AssociatedAttachments: []string{"tgw-attach-app-legacy", "tgw-attach-db-legacy"},
		Routes: []model.Route{
			{Destination: netip.MustParsePrefix("10.16.0.0/16"), TargetKind: model.TargetAttachment, TargetID: "tgw-attach-app-legacy"},
			{Destination: netip.MustParsePrefix("10.32.0.0/16"), TargetKind: model.TargetAttachment, TargetID: "tgw-attach-db-legacy"},
		},
	}

	// More specific than the hub default, so the response leaves by the old hub.
	snap.RouteTables["rt-db"].Routes = []model.Route{
		{Destination: netip.MustParsePrefix("10.32.0.0/16"), TargetKind: model.TargetLocal, TargetID: "local"},
		{Destination: netip.MustParsePrefix("10.16.0.0/16"), TargetKind: model.TargetTransitGateway, TargetID: "tgw-legacy"},
		{Destination: netip.MustParsePrefix("10.0.0.0/8"), TargetKind: model.TargetTransitGateway, TargetID: "tgw-hub"},
	}
	return snap
}

// rpNoReturnRouteSnapshot removes the destination VPC's route back to the
// source, so the forward direction is permitted and the response has nowhere to
// go.
func rpNoReturnRouteSnapshot() *model.Snapshot {
	snap := rpSymmetricSnapshot()
	snap.RouteTables["rt-db"].Routes = []model.Route{
		{Destination: netip.MustParsePrefix("10.32.0.0/16"), TargetKind: model.TargetLocal, TargetID: "local"},
	}
	return snap
}

// asymmetryWant is the expected comparison of the two directions. Both hop
// chains are stated, because a difference only means something next to what the
// other direction resolved to instead.
type asymmetryWant struct {
	forward []string
	ret     []string
	// differences are "direction:id" pairs, in the order the comparison reports
	// them: forward-only first.
	differences []string
	stateful    []string
	// summary are substrings the human-readable finding must contain.
	summary []string
}

// TestReturnPathTopologies walks the reverse direction for a symmetric topology,
// two asymmetric ones, and one with no way back.
//
// Validates: Requirements 7.2
func TestReturnPathTopologies(t *testing.T) {
	cases := []struct {
		name string
		snap func() *model.Snapshot
		// wantVerdict is the forward reachability outcome, which an asymmetric
		// or blocked return direction does not change: forward packets still
		// arrive.
		wantVerdict       Verdict
		wantReturnVerdict model.LayerVerdict
		wantReturnReason  string
		// wantAsymmetry is nil when the two directions could not be compared.
		wantAsymmetry *asymmetryWant
		// wantReturnCitations are substrings the RETURN_PATH citations must
		// carry, which is where a consumer reads the comparison.
		wantReturnCitations []string
		wantNotes           []string
	}{
		{
			name:              "symmetric: two VPCs over one transit gateway",
			snap:              rpSymmetricSnapshot,
			wantVerdict:       VerdictPermitted,
			wantReturnVerdict: model.VerdictPass,
			wantAsymmetry: &asymmetryWant{
				forward: []string{"tgw-hub", "tgw-attach-app", "tgw-attach-db"},
				ret:     []string{"tgw-hub", "tgw-attach-db", "tgw-attach-app"},
				summary: []string{"resolve to the same next hops"},
			},
			wantReturnCitations: []string{"db-rt", "tgw-attach-app"},
		},
		{
			name:              "asymmetric: return diverted through an inspection VPC the forward direction skips",
			snap:              rpInspectionDetourSnapshot,
			wantVerdict:       VerdictPermitted,
			wantReturnVerdict: model.VerdictAbstain,
			wantReturnReason:  "firewall policy was not evaluated in the reverse direction at inspection",
			wantAsymmetry: &asymmetryWant{
				forward: []string{"tgw-hub", "tgw-attach-app", "tgw-attach-db"},
				ret:     []string{"tgw-hub", "tgw-attach-db", "tgw-attach-inspect", "vpc-inspect", "tgw-attach-app"},
				differences: []string{
					"return:tgw-attach-inspect",
					"return:vpc-inspect",
				},
				stateful: []string{"vpc-inspect"},
				summary: []string{
					"resolve to different next hops",
					"only the return direction traverses tgw-attach-inspect (attachment) → vpc-inspect (inspection-vpc)",
					"crosses stateful vpc-inspect (inspection-vpc)",
					"establish and then stall",
				},
			},
			// Requirement 7.2: the finding names both next hops. Every hop on
			// each side is cited, and each difference cites what the opposite
			// direction resolved to instead.
			wantReturnCitations: []string{
				"forward next hop at route",
				"forward next hop at tgw",
				"return next hop at inspection-vpc",
				"(stateful)",
				"has no counterpart in the forward direction",
				"tgw-attach-app (attachment)",
			},
			wantNotes: []string{"resolve to different next hops"},
		},
		{
			name:              "asymmetric and stateless: a stale route sends the response over another hub",
			snap:              rpStaleHubSnapshot,
			wantVerdict:       VerdictPermitted,
			wantReturnVerdict: model.VerdictPass,
			wantAsymmetry: &asymmetryWant{
				forward: []string{"tgw-hub", "tgw-attach-app", "tgw-attach-db"},
				ret:     []string{"tgw-legacy", "tgw-attach-db-legacy", "tgw-attach-app-legacy"},
				differences: []string{
					"forward:tgw-hub",
					"forward:tgw-attach-app",
					"forward:tgw-attach-db",
					"return:tgw-legacy",
					"return:tgw-attach-db-legacy",
					"return:tgw-attach-app-legacy",
				},
				summary: []string{"resolve to different next hops"},
			},
			wantReturnCitations: []string{"tgw-legacy", "has no counterpart"},
		},
		{
			name:              "blocked: the destination VPC has no route back",
			snap:              rpNoReturnRouteSnapshot,
			wantVerdict:       VerdictPermitted,
			wantReturnVerdict: model.VerdictBlocked,
			// Nothing to compare: the walk never reached the components past
			// the block, and the block is already the stronger statement.
			wantAsymmetry:       nil,
			wantReturnCitations: []string{"db-rt", "no transit gateway route to 10.16.1.10"},
			wantNotes:           []string{"return direction is blocked at"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := rpRun(t, tc.snap())

			if res.Verdict != tc.wantVerdict {
				t.Fatalf("forward verdict = %s, want %s%s", res.Verdict, tc.wantVerdict, formatHops(res.Hops))
			}
			if res.ReturnPath == nil {
				t.Fatal("ReturnPath = nil, want the reverse direction evaluated")
			}

			rp := res.ReturnPath
			if rp.Result.Verdict != tc.wantReturnVerdict {
				t.Errorf("return verdict = %s, want %s%s", rp.Result.Verdict, tc.wantReturnVerdict, formatHops(rp.Path()))
			}
			if err := rp.Result.Validate(); err != nil {
				t.Errorf("return result not emittable: %v", err)
			}
			if tc.wantReturnReason != "" && !strings.Contains(rp.Result.Reason, tc.wantReturnReason) {
				t.Errorf("return reason = %q, want it to contain %q", rp.Result.Reason, tc.wantReturnReason)
			}

			// The reverse Flow is the forward one turned around, with every
			// destination port because the client's ephemeral port is unknown.
			if got := rp.Flow.Src.Prefixes()[0].Addr(); got != rpDstIP {
				t.Errorf("return flow source = %s, want the forward destination %s", got, rpDstIP)
			}
			if got := rp.Flow.Dst.Prefixes()[0].Addr(); got != rpSrcIP {
				t.Errorf("return flow destination = %s, want the forward source %s", got, rpSrcIP)
			}
			if !rp.Flow.DstPorts.IsAll() {
				t.Errorf("return flow ports = %s, want every port", rp.Flow.DstPorts)
			}

			rpCheckAsymmetry(t, rp.Asymmetry, tc.wantAsymmetry)

			citations := rpCitationText(rp.Result.Citations)
			for _, want := range tc.wantReturnCitations {
				if !strings.Contains(citations, want) {
					t.Errorf("return citations missing %q, got:\n%s", want, citations)
				}
			}

			notes := strings.Join(res.Notes, "\n")
			for _, want := range tc.wantNotes {
				if !strings.Contains(notes, want) {
					t.Errorf("notes missing %q, got:\n%s", want, notes)
				}
			}
		})
	}
}

// rpCheckAsymmetry compares the recorded comparison against the expectation. A
// nil want means the two directions could not be compared at all.
func rpCheckAsymmetry(t *testing.T, got *Asymmetry, want *asymmetryWant) {
	t.Helper()

	if want == nil {
		if got != nil {
			t.Errorf("Asymmetry = %+v, want no comparison", got)
		}
		return
	}
	if got == nil {
		t.Fatal("Asymmetry = nil, want the two directions compared")
	}

	if ids := rpNextHopIDs(got.Forward); !slices.Equal(ids, want.forward) {
		t.Errorf("forward next hops = %v, want %v", ids, want.forward)
	}
	if ids := rpNextHopIDs(got.Return); !slices.Equal(ids, want.ret) {
		t.Errorf("return next hops = %v, want %v", ids, want.ret)
	}
	if diffs := rpDifferenceKeys(got.Differences); !slices.Equal(diffs, want.differences) {
		t.Errorf("differences = %v, want %v", diffs, want.differences)
	}
	if ids := rpNextHopIDs(got.Stateful); !slices.Equal(ids, want.stateful) {
		t.Errorf("stateful next hops = %v, want %v", ids, want.stateful)
	}

	wantAsymmetric := len(want.differences) > 0
	if got.Asymmetric() != wantAsymmetric {
		t.Errorf("Asymmetric() = %v, want %v", got.Asymmetric(), wantAsymmetric)
	}
	if wantStateful := wantAsymmetric && len(want.stateful) > 0; got.StatefulAsymmetry() != wantStateful {
		t.Errorf("StatefulAsymmetry() = %v, want %v", got.StatefulAsymmetry(), wantStateful)
	}

	for _, s := range want.summary {
		if !strings.Contains(got.Summary, s) {
			t.Errorf("summary missing %q, got:\n%s", s, got.Summary)
		}
	}

	// A symmetric path is not a finding, so it carries no evidence; an
	// asymmetric one is unemittable without it.
	obs, ok := got.Observation()
	if ok != wantAsymmetric {
		t.Fatalf("Observation() reported = %v, want %v", ok, wantAsymmetric)
	}
	if !wantAsymmetric {
		if len(got.Citations) > 0 {
			t.Errorf("symmetric path carries %d citations, want none", len(got.Citations))
		}
		return
	}
	if err := obs.Validate(); err != nil {
		t.Errorf("observation not emittable: %v", err)
	}
	if obs.Layer != model.LayerReturnPath {
		t.Errorf("observation layer = %s, want %s", obs.Layer, model.LayerReturnPath)
	}
	wantKind := model.ObservationAsymmetric
	if len(want.stateful) > 0 {
		wantKind = model.ObservationAsymmetricStateful
	}
	if obs.Kind != wantKind {
		t.Errorf("observation kind = %s, want %s", obs.Kind, wantKind)
	}
}

// TestReturnPathCorrelation feeds the same topologies to the Correlator, which
// is where a blocked return direction becomes the primary blocker and where a
// stateful asymmetry becomes the probable cause of a stall.
//
// Validates: Requirements 7.3, 7.4
func TestReturnPathCorrelation(t *testing.T) {
	cases := []struct {
		name string
		snap func() *model.Snapshot
		sym  symptom.Symptom
		// wantPrimary is the primary blocking Layer, empty when nothing blocked.
		wantPrimary model.Layer
		// wantPassed are the Layers that must be reported as passing, which is
		// what makes a return-path block the only finding.
		wantPassed        []model.Layer
		wantObservations  []model.ObservationKind
		wantCauseLayer    model.Layer
		wantCauseEvidence []string
		// wantCause is false when nothing observed should be promoted.
		wantCause          bool
		wantContradictions []string
		wantAuthoritative  bool
	}{
		{
			name: "requirement 7.4: a blocked return direction is the primary blocker while every forward layer passes",
			snap: rpNoReturnRouteSnapshot,
			sym:  symptom.None,
			// RETURN_PATH is the earliest blocking Layer in flow order, so
			// precedence alone makes it primary.
			wantPrimary:       model.LayerReturnPath,
			wantPassed:        []model.Layer{model.LayerRoute, model.LayerSecurityGroup},
			wantAuthoritative: true,
		},
		{
			name:             "requirement 7.3: stateful asymmetry is the probable cause of a connect-then-stall",
			snap:             rpInspectionDetourSnapshot,
			sym:              symptom.ConnectThenStall,
			wantObservations: []model.ObservationKind{model.ObservationAsymmetricStateful},
			wantCause:        true,
			wantCauseLayer:   model.LayerReturnPath,
			wantCauseEvidence: []string{
				"connect-then-stall",
				"asymmetric-stateful",
				"vpc-inspect",
			},
			// The reverse direction crosses an inspection point whose policy was
			// not evaluated backwards, so the verdict says so.
			wantAuthoritative: false,
		},
		{
			name:              "a timeout is not explained by asymmetry, which is still reported",
			snap:              rpInspectionDetourSnapshot,
			sym:               symptom.Timeout,
			wantObservations:  []model.ObservationKind{model.ObservationAsymmetricStateful},
			wantCause:         false,
			wantAuthoritative: false,
		},
		{
			name:              "with no symptom there is no failure to explain",
			snap:              rpInspectionDetourSnapshot,
			sym:               symptom.None,
			wantObservations:  []model.ObservationKind{model.ObservationAsymmetricStateful},
			wantCause:         false,
			wantAuthoritative: false,
		},
		{
			name: "a stateless asymmetry is reported but never promoted",
			snap: rpStaleHubSnapshot,
			sym:  symptom.ConnectThenStall,
			// Nothing on either path holds per-connection state, so a response
			// arriving another way is carried without anything noticing.
			wantObservations: []model.ObservationKind{model.ObservationAsymmetric},
			wantCause:        false,
			wantPassed: []model.Layer{
				model.LayerRoute, model.LayerSecurityGroup, model.LayerReturnPath,
			},
			wantContradictions: []string{"every evaluated layer permitted the traffic"},
			wantAuthoritative:  true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := rpRun(t, tc.snap())

			verdict, err := correlate.Correlate(correlate.Input{
				Symptom:      tc.sym,
				Results:      res.LayerResults(),
				Observations: res.Observations(),
			})
			if err != nil {
				t.Fatalf("Correlate() error = %v", err)
			}

			if tc.wantPrimary == "" {
				if verdict.PrimaryBlocker != nil {
					t.Errorf("PrimaryBlocker = %s, want none%s", *verdict.PrimaryBlocker, rpVerdictDetail(verdict))
				}
			} else {
				if verdict.PrimaryBlocker == nil {
					t.Fatalf("PrimaryBlocker = nil, want %s%s", tc.wantPrimary, rpVerdictDetail(verdict))
				}
				if *verdict.PrimaryBlocker != tc.wantPrimary {
					t.Errorf("PrimaryBlocker = %s, want %s", *verdict.PrimaryBlocker, tc.wantPrimary)
				}
				if len(verdict.AdditionalBlocked) > 0 {
					t.Errorf("AdditionalBlocked = %v, want none", verdict.AdditionalBlocked)
				}
			}

			for _, layer := range tc.wantPassed {
				got, ok := verdict.Result(layer)
				if !ok {
					t.Errorf("no result for layer %s%s", layer, rpVerdictDetail(verdict))
					continue
				}
				if got.Verdict != model.VerdictPass {
					t.Errorf("layer %s verdict = %s, want %s", layer, got.Verdict, model.VerdictPass)
				}
			}

			if kinds := rpObservationKinds(verdict.Observations); !slices.Equal(kinds, tc.wantObservations) {
				t.Errorf("observations = %v, want %v", kinds, tc.wantObservations)
			}

			if !tc.wantCause {
				if verdict.ProbableCause != nil {
					t.Errorf("ProbableCause = %+v, want none", verdict.ProbableCause)
				}
			} else {
				cause := verdict.ProbableCause
				if cause == nil {
					t.Fatalf("ProbableCause = nil, want one for layer %s%s", tc.wantCauseLayer, rpVerdictDetail(verdict))
				}
				if cause.Layer != tc.wantCauseLayer {
					t.Errorf("ProbableCause.Layer = %s, want %s", cause.Layer, tc.wantCauseLayer)
				}
				evidence := cause.Summary + "\n" + rpCitationText(cause.Citations)
				for _, want := range tc.wantCauseEvidence {
					if !strings.Contains(evidence, want) {
						t.Errorf("probable cause evidence missing %q, got:\n%s", want, evidence)
					}
				}
			}

			contradictions := strings.Join(verdict.Contradictions, "\n")
			for _, want := range tc.wantContradictions {
				if !strings.Contains(contradictions, want) {
					t.Errorf("contradictions missing %q, got:\n%s", want, contradictions)
				}
			}
			if len(tc.wantContradictions) == 0 && len(verdict.Contradictions) > 0 {
				t.Errorf("contradictions = %v, want none", verdict.Contradictions)
			}

			if verdict.Authoritative != tc.wantAuthoritative {
				t.Errorf("Authoritative = %v, want %v (abstentions %+v)",
					verdict.Authoritative, tc.wantAuthoritative, verdict.Abstentions())
			}
		})
	}
}

// rpRun queries the fixture for the one flow every case is about: TCP 443 from
// the app endpoint to the db endpoint.
func rpRun(t *testing.T, snap *model.Snapshot) *Result {
	t.Helper()
	res, err := Run(Options{
		Snapshot:     snap,
		SrcIP:        rpSrcIP,
		DstIP:        rpDstIP,
		Proto:        flow.ProtoTCP,
		Port:         443,
		SkipFirewall: true,
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	return res
}

func rpNextHopIDs(hops []NextHop) []string {
	if len(hops) == 0 {
		return nil
	}
	out := make([]string, 0, len(hops))
	for _, h := range hops {
		out = append(out, h.ID)
	}
	return out
}

func rpDifferenceKeys(diffs []NextHopDifference) []string {
	if len(diffs) == 0 {
		return nil
	}
	out := make([]string, 0, len(diffs))
	for _, d := range diffs {
		out = append(out, fmt.Sprintf("%s:%s", d.Direction, d.NextHop.ID))
	}
	return out
}

func rpObservationKinds(obs []model.Observation) []model.ObservationKind {
	if len(obs) == 0 {
		return nil
	}
	out := make([]model.ObservationKind, 0, len(obs))
	for _, o := range obs {
		out = append(out, o.Kind)
	}
	return out
}

func rpCitationText(citations []model.Citation) string {
	var b strings.Builder
	for _, c := range citations {
		fmt.Fprintf(&b, "  %s %s: %s\n", c.Kind, c.Identifier, c.Detail)
	}
	return b.String()
}

// rpVerdictDetail renders a correlated verdict for a failure message.
func rpVerdictDetail(v model.Verdict) string {
	var b strings.Builder
	for _, r := range v.Results {
		fmt.Fprintf(&b, "\n  %s = %s", r.Layer, r.Verdict)
		if r.Reason != "" {
			fmt.Fprintf(&b, " (%s)", r.Reason)
		}
	}
	return b.String()
}
