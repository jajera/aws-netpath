package ops

// The other failure the tool exists for, from snapshot to rendered report.
//
// The engine's own tests already assert that a divergent pair of hop chains is
// detected and that the Correlator promotes it under a connect-then-stall. What
// they cannot show is that the finding survives the whole operation: the walk is
// two directions, the Correlator turns one of them into an Observation with no
// verdict attached, and an Observation carries no Layer to sort by — so it is
// exactly the kind of finding a projection drops without any Layer assertion
// going red. A report that named the return direction and lost the two hop chains
// behind it would leave an operator with "the path is asymmetric" and nothing to
// go and fix.
//
// Nothing blocks here. Every AWS Layer permits the flow in both directions, the
// host admits the source, and the only finding is that the response comes back
// through a firewall that never saw the request. That is requirement 7.2's pair
// of next hops and requirement 7.3's probable cause, and neither is a verdict.

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/jajera/aws-netpath/internal/format"
	"github.com/jajera/aws-netpath/internal/host"
	"github.com/jajera/aws-netpath/internal/model"
	"github.com/jajera/aws-netpath/internal/symptom"
)

// The two endpoints of the asymmetric fixture, and the instance the destination
// interface is attached to so the host stage has something to probe.
const (
	asymSrcIP       = "10.16.1.10"
	asymDstIP       = "10.32.1.20"
	asymDstInstance = "i-0c3d4e5f6a7b81920"
)

// The components the comparison turns on. The forward direction crosses the hub
// and the two VPC attachments; the return direction crosses those and then two
// more, because the hub sends traffic bound for the app VPC through inspection.
const (
	asymHub           = "tgw-hub"
	asymForwardHop    = "tgw-attach-db"
	asymReturnHop     = "tgw-attach-inspect"
	asymStatefulHop   = "vpc-inspect"
	asymAllowlistCIDR = "10.16.0.0/16"
)

// A connection that establishes and then stops is diagnosed as an asymmetric
// path across a stateful component, with both directions' next hops cited in the
// rendered report.
//
// Validates: Requirements 7.2, 7.3
func TestAsymmetricPathRendersTheConnectThenStallCause(t *testing.T) {
	res, err := Diagnose(context.Background(), asymDiagnoseRequest())
	if err != nil {
		t.Fatalf("Diagnose() error = %v", err)
	}

	if res.Classification.Symptom != symptom.ConnectThenStall {
		t.Fatalf("symptom = %q, want %q", res.Classification.Symptom, symptom.ConnectThenStall)
	}

	// The finding only means anything on a path nothing blocks. A blocker would
	// be the cause, the Correlator would decline to promote anything, and the
	// assertions below would be about a report that never gets built in
	// production.
	if blocker, found := res.PrimaryBlocker(); found {
		t.Fatalf("primary blocker = %s, want none on a path every layer permits:%s",
			blocker, asymResultDetail(res))
	}

	// Requirement 7.2: the two directions resolved to different next hops, and
	// the comparison is on the walk rather than inferred from the forward result.
	rp := res.Walk.ReturnPath
	if rp == nil {
		t.Fatal("the walk evaluated no return direction")
	}
	if !rp.Asymmetry.Asymmetric() {
		t.Fatalf("the two directions were not reported as asymmetric: %+v", rp.Asymmetry)
	}
	if !rp.Asymmetry.StatefulAsymmetry() {
		t.Fatalf("the asymmetry was not reported as crossing a stateful component: %+v", rp.Asymmetry.Stateful)
	}

	// Requirement 7.2: the RETURN_PATH Layer is reported. It abstains rather than
	// passing, because the reverse direction crosses an inspection point whose
	// policy is deliberately not evaluated backwards — and an abstention with a
	// reason is a report, where a silent pass would be a claim the walk did not
	// make.
	returnResult, ok := res.Verdict.Result(model.LayerReturnPath)
	if !ok {
		t.Fatalf("no %s result in the verdict:%s", model.LayerReturnPath, asymResultDetail(res))
	}
	if returnResult.Verdict == model.VerdictBlocked {
		t.Errorf("%s = %s, want the return direction to carry traffic; the finding is the asymmetry, not a block",
			model.LayerReturnPath, returnResult.Verdict)
	}

	// Requirement 7.3: the asymmetry is the probable cause of the symptom the
	// operator reported, and it stays an explanation rather than becoming a
	// verdict.
	cause := res.Verdict.ProbableCause
	if cause == nil {
		t.Fatalf("no probable cause for symptom %s:%s", symptom.ConnectThenStall, asymResultDetail(res))
	}
	if cause.Layer != model.LayerReturnPath {
		t.Errorf("probable cause layer = %s, want %s", cause.Layer, model.LayerReturnPath)
	}
	for _, want := range []string{string(symptom.ConnectThenStall), string(model.ObservationAsymmetricStateful)} {
		if !strings.Contains(cause.Summary, want) {
			t.Errorf("probable cause summary = %q, want it to name %q", cause.Summary, want)
		}
	}

	// Requirement 7.2 on the in-memory finding: both directions' next hops are
	// cited, so a reader can check the comparison rather than take the summary on
	// trust.
	citations := asymCitationText(cause.Citations)
	for _, want := range []string{
		"forward next hop",
		"return next hop",
		asymForwardHop,
		asymReturnHop,
		asymStatefulHop,
		"has no counterpart in the forward direction",
	} {
		if !strings.Contains(citations, want) {
			t.Errorf("probable cause citations omit %q:\n%s", want, citations)
		}
	}

	asymCheckRendering(t, res)
}

// asymCheckRendering asserts the two hop chains survive the projection and every
// rendering. The verdict-level assertions above are on structure the Formatter
// never sees: an Observation carries no Layer verdict, so it is placed by the
// projection alone and nothing in the three fixed sections would miss it going.
func asymCheckRendering(t *testing.T, res *DiagnoseResult) {
	t.Helper()

	report := res.Report()
	rendered := renderReport(t, report, format.ModeText)

	// Scoped to the probable cause section, and asserted on its cited rows rather
	// than on the hop names. Both are deliberate. A whole-report search would pass
	// on hop names that had drifted into another section, and a search for the
	// names alone would pass on a projection that dropped every citation, because
	// the summary already names both chains in prose — leaving the section an
	// operator reads for the explanation without the evidence to check it. The
	// phrases below appear only in citations.
	cause := textSection(t, rendered, "probable cause")
	for _, want := range []string{
		string(model.LayerReturnPath),
		string(symptom.ConnectThenStall),
		"cited: " + asymForwardHop + "  forward next hop at ",
		"cited: " + asymReturnHop + "  return next hop at ",
		"cited: " + asymStatefulHop + "  return next hop at ",
		"has no counterpart in the forward direction",
	} {
		if !strings.Contains(cause, want) {
			t.Errorf("the probable cause section omits %q:\n%s", want, cause)
		}
	}

	// The observation is reported alongside the explanation drawn from it, so a
	// reader who disagrees with the promotion still has the comparison.
	observations := textSection(t, rendered, "observations")
	for _, want := range []string{
		asymHub,
		"cited: " + asymForwardHop + "  forward next hop at ",
		"cited: " + asymReturnHop + "  return next hop at ",
	} {
		if !strings.Contains(observations, want) {
			t.Errorf("the observations section omits %q:\n%s", want, observations)
		}
	}

	// Requirement 14.3 lets the caller choose the format, so a finding present in
	// text and absent from JSON would mean the agent and the operator are reading
	// different reports. Markdown carries a row budget an agent pays for, so it is
	// asserted on the titles rather than on every hop.
	for _, want := range []string{
		`"title": "probable cause"`,
		`"subject": "` + asymForwardHop + `"`,
		`"subject": "` + asymReturnHop + `"`,
		`"subject": "` + asymStatefulHop + `"`,
		"has no counterpart in the forward direction",
	} {
		if got := renderReport(t, report, format.ModeJSON); !strings.Contains(got, want) {
			t.Errorf("the json rendering omits %q:\n%s", want, got)
		}
	}
	if got := renderReport(t, report, format.ModeMarkdown); !strings.Contains(got, "## probable cause\n") {
		t.Errorf("the markdown rendering carries no probable cause section:\n%s", got)
	}
}

// asymDiagnoseRequest asks why a connection that establishes then stops does so.
//
// Firewall policy evaluation is skipped: the question here is which way the two
// directions go, and a policy verdict on the forward direction would answer a
// different one.
func asymDiagnoseRequest() DiagnoseRequest {
	return DiagnoseRequest{
		Snapshot:     asymInspectionDetourSnapshot(),
		From:         asymSrcIP,
		To:           asymDstIP,
		Proto:        "tcp",
		Port:         22,
		Symptom:      string(symptom.ConnectThenStall),
		SkipFirewall: true,
		Prober:       asymHostProber(),
	}
}

// asymHostProber probes a host that admits the source, so the host Layers pass
// and the asymmetry is the only finding left.
//
// The path MTU check runs because a connect-then-stall implicates it, and it is
// answered rather than left to abstain: a stall has two ordinary explanations,
// and ruling the other one out is what leaves the asymmetry standing.
func asymHostProber() *stubProber {
	return &stubProber{results: map[host.Check]host.Result{
		host.CheckListener: {Stdout: stubListening},
		host.CheckFirewalldRichRules: {Stdout: `rule family="ipv4" source address="` + asymAllowlistCIDR +
			`" port port="22" protocol="tcp" accept` + "\n"},
		host.CheckFirewalldServices: {Stdout: "dhcpv6-client\n"},
		host.CheckLocalRoute:        {Stdout: asymSrcIP + " via 10.32.1.1 dev eth0 src " + asymDstIP + " uid 0\n    cache\n"},
		host.CheckPathMTU: {Stdout: "PING " + asymSrcIP + " (" + asymSrcIP + ") 1472(1500) bytes of data.\n" +
			"1480 bytes from " + asymSrcIP + ": icmp_seq=1 ttl=254 time=1.10 ms\n" +
			"1480 bytes from " + asymSrcIP + ": icmp_seq=2 ttl=254 time=1.08 ms\n" +
			"\n--- " + asymSrcIP + " ping statistics ---\n" +
			"2 packets transmitted, 2 received, 0% packet loss, time 1001ms\n"},
	}}
}

// asymInspectionDetourSnapshot builds two VPCs joined by one transit gateway
// whose route table sends traffic bound for the app VPC through an inspection
// VPC, and traffic bound for the db VPC straight across.
//
// It is the topology internal/query's own return-path fixture uses, with the
// endpoints attached to instances and the flow on tcp/22 so the host stage runs
// too — the operation is what is under test, and a diagnosis that stopped at the
// cloud layers would not be one.
//
// Both directions deliver, so no Layer blocks. The firewall holds state for
// connections whose forward half it never saw, which is the shape requirement 7.3
// is about. Addresses are RFC 1918 and the account is a placeholder, so the
// fixture describes no real network.
func asymInspectionDetourSnapshot() *model.Snapshot {
	snap := model.NewSnapshot()
	snap.Accounts = []string{testAccountA}
	snap.Regions = []string{testRegionA}

	snap.VPCs["vpc-app"] = &model.VPC{
		Meta:  asymMeta("vpc-app", "app"),
		CIDRs: []netip.Prefix{netip.MustParsePrefix("10.16.0.0/16")},
	}
	snap.VPCs["vpc-db"] = &model.VPC{
		Meta:  asymMeta("vpc-db", "db"),
		CIDRs: []netip.Prefix{netip.MustParsePrefix("10.32.0.0/16")},
	}
	snap.VPCs["vpc-inspect"] = &model.VPC{
		Meta:  asymMeta("vpc-inspect", "inspection"),
		CIDRs: []netip.Prefix{netip.MustParsePrefix("10.48.0.0/16")},
	}

	snap.Subnets["subnet-app"] = &model.Subnet{
		Meta: asymMeta("subnet-app", "app-a"), VPCID: "vpc-app",
		CIDR: netip.MustParsePrefix("10.16.1.0/24"), RouteTableID: "rt-app",
	}
	snap.Subnets["subnet-db"] = &model.Subnet{
		Meta: asymMeta("subnet-db", "db-a"), VPCID: "vpc-db",
		CIDR: netip.MustParsePrefix("10.32.1.0/24"), RouteTableID: "rt-db",
	}
	snap.Subnets["subnet-inspect"] = &model.Subnet{
		Meta: asymMeta("subnet-inspect", "inspect-a"), VPCID: "vpc-inspect",
		CIDR: netip.MustParsePrefix("10.48.1.0/24"), RouteTableID: "rt-inspect",
	}

	snap.RouteTables["rt-app"] = &model.RouteTable{
		Meta: asymMeta("rt-app", "app-rt"), VPCID: "vpc-app",
		Routes: []model.Route{
			{Destination: netip.MustParsePrefix("10.16.0.0/16"), TargetKind: model.TargetLocal, TargetID: "local"},
			{Destination: netip.MustParsePrefix("10.0.0.0/8"), TargetKind: model.TargetTransitGateway, TargetID: "tgw-hub"},
		},
	}
	snap.RouteTables["rt-db"] = &model.RouteTable{
		Meta: asymMeta("rt-db", "db-rt"), VPCID: "vpc-db",
		Routes: []model.Route{
			{Destination: netip.MustParsePrefix("10.32.0.0/16"), TargetKind: model.TargetLocal, TargetID: "local"},
			{Destination: netip.MustParsePrefix("10.0.0.0/8"), TargetKind: model.TargetTransitGateway, TargetID: "tgw-hub"},
		},
	}
	snap.RouteTables["rt-inspect"] = &model.RouteTable{
		Meta: asymMeta("rt-inspect", "inspect-rt"), VPCID: "vpc-inspect",
		Routes: []model.Route{
			{Destination: netip.MustParsePrefix("10.48.0.0/16"), TargetKind: model.TargetLocal, TargetID: "local"},
			{Destination: netip.MustParsePrefix("0.0.0.0/0"), TargetKind: model.TargetTransitGateway, TargetID: "tgw-hub"},
		},
	}

	snap.TransitGateways["tgw-hub"] = &model.TransitGateway{Meta: asymMeta("tgw-hub", "hub")}
	snap.TGWAttachments["tgw-attach-app"] = &model.TGWAttachment{
		Meta: asymMeta("tgw-attach-app", "app"), TransitGatewayID: "tgw-hub",
		Kind: model.AttachVPC, ResourceID: "vpc-app", State: "available",
	}
	snap.TGWAttachments["tgw-attach-db"] = &model.TGWAttachment{
		Meta: asymMeta("tgw-attach-db", "db"), TransitGatewayID: "tgw-hub",
		Kind: model.AttachVPC, ResourceID: "vpc-db", State: "available",
	}
	snap.TGWAttachments["tgw-attach-inspect"] = &model.TGWAttachment{
		Meta: asymMeta("tgw-attach-inspect", "inspection"), TransitGatewayID: "tgw-hub",
		Kind: model.AttachVPC, ResourceID: "vpc-inspect", State: "available",
	}

	// The stale half of the topology: traffic toward the app VPC is inspected,
	// traffic toward the db VPC is not.
	snap.TGWRouteTables["tgw-rt-hub"] = &model.TGWRouteTable{
		Meta: asymMeta("tgw-rt-hub", "hub"), TransitGatewayID: "tgw-hub",
		AssociatedAttachments: []string{"tgw-attach-app", "tgw-attach-db"},
		Routes: []model.Route{
			{Destination: netip.MustParsePrefix("10.32.0.0/16"), TargetKind: model.TargetAttachment, TargetID: "tgw-attach-db"},
			{Destination: netip.MustParsePrefix("10.16.0.0/16"), TargetKind: model.TargetAttachment, TargetID: "tgw-attach-inspect"},
		},
	}
	snap.TGWRouteTables["tgw-rt-inspect"] = &model.TGWRouteTable{
		Meta: asymMeta("tgw-rt-inspect", "post-inspection"), TransitGatewayID: "tgw-hub",
		AssociatedAttachments: []string{"tgw-attach-inspect"},
		Routes: []model.Route{
			{Destination: netip.MustParsePrefix("10.16.0.0/16"), TargetKind: model.TargetAttachment, TargetID: "tgw-attach-app"},
			{Destination: netip.MustParsePrefix("10.32.0.0/16"), TargetKind: model.TargetAttachment, TargetID: "tgw-attach-db"},
		},
	}

	snap.Firewalls["fw-inspect"] = &model.Firewall{
		Meta: asymMeta("fw-inspect", "inspection"), VPCID: "vpc-inspect",
		PolicyARN: "arn:aws:network-firewall:" + testRegionA + ":" + testAccountA + ":firewall-policy/inspection",
		SubnetIDs: []string{"subnet-inspect"},
		EndpointsBySubnet: map[string]string{
			"subnet-inspect": "vpce-inspect",
		},
	}

	snap.SecurityGroups["sg-app"] = &model.SecurityGroup{
		Meta: asymMeta("sg-app", "app"), VPCID: "vpc-app",
		Egress: []model.SGRule{{
			Protocol: "tcp", FromPort: 22, ToPort: 22,
			CIDRs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
		}},
	}
	snap.SecurityGroups["sg-db"] = &model.SecurityGroup{
		Meta: asymMeta("sg-db", "db"), VPCID: "vpc-db",
		Ingress: []model.SGRule{{
			Protocol: "tcp", FromPort: 22, ToPort: 22,
			CIDRs: []netip.Prefix{netip.MustParsePrefix(asymAllowlistCIDR)},
		}},
	}

	snap.NetworkIfaces["eni-app"] = &model.NetworkIface{
		Meta: asymMeta("eni-app", "app-1"), VPCID: "vpc-app", SubnetID: "subnet-app", Status: "in-use",
		SecurityGroupIDs: []string{"sg-app"},
		PrivateIPs:       []netip.Addr{netip.MustParseAddr(asymSrcIP)},
		AttachedTo:       testSrcInstance,
	}
	snap.NetworkIfaces["eni-db"] = &model.NetworkIface{
		Meta: asymMeta("eni-db", "db-1"), VPCID: "vpc-db", SubnetID: "subnet-db", Status: "in-use",
		SecurityGroupIDs: []string{"sg-db"},
		PrivateIPs:       []netip.Addr{netip.MustParseAddr(asymDstIP)},
		AttachedTo:       asymDstInstance,
	}
	return snap
}

func asymMeta(id, name string) model.Meta {
	return model.Meta{ID: id, Name: name, Region: testRegionA, Account: testAccountA}
}

func asymCitationText(citations []model.Citation) string {
	var b strings.Builder
	for _, c := range citations {
		b.WriteString("  " + c.Kind + " " + c.Identifier + ": " + c.Detail + "\n")
	}
	return b.String()
}

// asymResultDetail renders every Layer finding for a failure message, since a
// test about a path nothing blocks fails most usefully by saying what did.
func asymResultDetail(res *DiagnoseResult) string {
	var b strings.Builder
	for _, r := range res.Verdict.Results {
		b.WriteString("\n  " + string(r.Layer) + " = " + string(r.Verdict))
		if r.Reason != "" {
			b.WriteString(" (" + r.Reason + ")")
		}
	}
	return b.String()
}
