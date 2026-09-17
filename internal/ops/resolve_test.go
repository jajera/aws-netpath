package ops

// Endpoint resolution, one case per acceptance criterion in requirement 6. The
// two that matter most are the refusals: an ambiguous input has to halt with
// every candidate named, and an input that matched nothing has to say what the
// snapshot does cover, because both are the difference between an operator
// correcting their invocation and an operator trusting an answer about the wrong
// resource.

import (
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/jajera/aws-netpath/internal/model"
)

const (
	testAccountA = "111122223333"
	testAccountB = "444455556666"
	testRegionA  = "us-east-1"
	testRegionB  = "eu-west-1"

	testSrcInstance = "i-0f1e2d3c4b5a69780"
	testDstInstance = "i-0a1b2c3d4e5f60718"
)

var (
	testSrcAddr = netip.MustParseAddr("10.30.1.10")
	testDstAddr = netip.MustParseAddr("10.30.2.20")
)

// diagnoseSnapshot builds two subnets in one VPC joined by a local route, each
// endpoint owning an interface attached to an instance, with security groups
// permitting tcp/22 in both directions. Every cloud layer passes, which is the
// shape the host stage has to be exercised on.
func diagnoseSnapshot() *model.Snapshot {
	snap := model.NewSnapshot()
	snap.Accounts = []string{testAccountA}
	snap.Regions = []string{testRegionA}

	snap.VPCs["vpc-app"] = &model.VPC{
		Meta:  model.Meta{ID: "vpc-app", Name: "app", Region: testRegionA, Account: testAccountA},
		CIDRs: []netip.Prefix{netip.MustParsePrefix("10.30.0.0/16")},
	}
	snap.Subnets["subnet-app"] = &model.Subnet{
		Meta:  model.Meta{ID: "subnet-app", Name: "app-a", Region: testRegionA, Account: testAccountA},
		VPCID: "vpc-app", CIDR: netip.MustParsePrefix("10.30.1.0/24"), RouteTableID: "rt-app",
	}
	snap.Subnets["subnet-db"] = &model.Subnet{
		Meta:  model.Meta{ID: "subnet-db", Name: "db-a", Region: testRegionA, Account: testAccountA},
		VPCID: "vpc-app", CIDR: netip.MustParsePrefix("10.30.2.0/24"), RouteTableID: "rt-app",
	}
	snap.RouteTables["rt-app"] = &model.RouteTable{
		Meta:  model.Meta{ID: "rt-app", Name: "app-rt", Region: testRegionA, Account: testAccountA},
		VPCID: "vpc-app",
		Routes: []model.Route{
			{Destination: netip.MustParsePrefix("10.30.0.0/16"), TargetKind: model.TargetLocal, TargetID: "local"},
		},
	}

	snap.SecurityGroups["sg-app"] = &model.SecurityGroup{
		Meta:  model.Meta{ID: "sg-app", Name: "app", Region: testRegionA, Account: testAccountA},
		VPCID: "vpc-app",
		Egress: []model.SGRule{{
			Protocol: "tcp", FromPort: 22, ToPort: 22,
			CIDRs: []netip.Prefix{netip.MustParsePrefix("10.30.0.0/16")},
		}},
	}
	snap.SecurityGroups["sg-db"] = &model.SecurityGroup{
		Meta:  model.Meta{ID: "sg-db", Name: "db", Region: testRegionA, Account: testAccountA},
		VPCID: "vpc-app",
		Ingress: []model.SGRule{{
			Protocol: "tcp", FromPort: 22, ToPort: 22,
			CIDRs: []netip.Prefix{netip.MustParsePrefix("10.30.1.0/24")},
		}},
	}

	snap.NetworkIfaces["eni-app"] = &model.NetworkIface{
		Meta: model.Meta{
			ID: "eni-app", Name: "app-1", Region: testRegionA, Account: testAccountA,
			Tags: map[string]string{"Name": "app-1"},
		},
		VPCID: "vpc-app", SubnetID: "subnet-app", Status: "in-use",
		SecurityGroupIDs: []string{"sg-app"},
		PrivateIPs:       []netip.Addr{testSrcAddr},
		AttachedTo:       testSrcInstance,
	}
	snap.NetworkIfaces["eni-db"] = &model.NetworkIface{
		Meta: model.Meta{
			ID: "eni-db", Name: "db-1", Region: testRegionA, Account: testAccountA,
			Tags: map[string]string{"Name": "db-1"},
		},
		VPCID: "vpc-app", SubnetID: "subnet-db", Status: "in-use",
		SecurityGroupIDs: []string{"sg-db"},
		PrivateIPs:       []netip.Addr{testDstAddr},
		AttachedTo:       testDstInstance,
	}
	return snap
}

// overlappingSnapshot adds a second account whose VPC reuses the destination
// address, which is the ordinary way an input becomes ambiguous.
func overlappingSnapshot() *model.Snapshot {
	snap := diagnoseSnapshot()
	snap.Accounts = append(snap.Accounts, testAccountB)
	snap.Regions = append(snap.Regions, testRegionB)

	snap.VPCs["vpc-other"] = &model.VPC{
		Meta:  model.Meta{ID: "vpc-other", Name: "other", Region: testRegionB, Account: testAccountB},
		CIDRs: []netip.Prefix{netip.MustParsePrefix("10.30.0.0/16")},
	}
	snap.Subnets["subnet-other"] = &model.Subnet{
		Meta:  model.Meta{ID: "subnet-other", Name: "other-a", Region: testRegionB, Account: testAccountB},
		VPCID: "vpc-other", CIDR: netip.MustParsePrefix("10.30.2.0/24"), RouteTableID: "rt-other",
	}
	snap.NetworkIfaces["eni-other"] = &model.NetworkIface{
		Meta:  model.Meta{ID: "eni-other", Name: "other-1", Region: testRegionB, Account: testAccountB},
		VPCID: "vpc-other", SubnetID: "subnet-other", Status: "in-use",
		PrivateIPs: []netip.Addr{testDstAddr},
		AttachedTo: "i-0999888777666555a",
	}
	return snap
}

// externalSnapshot declares an on-premises range, so one external endpoint is
// described by the snapshot and one is not.
func externalSnapshot() *model.Snapshot {
	snap := diagnoseSnapshot()
	snap.ExternalNetworks["ext-onprem"] = &model.ExternalNetwork{
		Meta:  model.Meta{ID: "ext-onprem", Name: "on-premises", Region: testRegionA, Account: testAccountA},
		CIDRs: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")},
	}
	return snap
}

// TestResolveEndpoint covers every way an endpoint can be named, and both ways
// naming one can fail.
//
// Validates: Requirements 6.1, 6.2, 6.3, 6.4, 6.5
func TestResolveEndpoint(t *testing.T) {
	cases := []struct {
		name  string
		snap  func() *model.Snapshot
		input string
		want  Endpoint
	}{
		{
			// 6.1: the interface holding the address carries the whole chain.
			name:  "private address resolves to its interface and scope",
			snap:  diagnoseSnapshot,
			input: "10.30.2.20",
			want: Endpoint{
				Kind: EndpointInterface, Addr: testDstAddr,
				InterfaceID: "eni-db", InstanceID: testDstInstance,
				SubnetID: "subnet-db", VPCID: "vpc-app",
				Account: testAccountA, Region: testRegionA,
			},
		},
		{
			// 6.2: an instance ID resolves to its interface and private address.
			name:  "instance id resolves to the primary interface",
			snap:  diagnoseSnapshot,
			input: testDstInstance,
			want: Endpoint{
				Kind: EndpointInterface, Addr: testDstAddr,
				InterfaceID: "eni-db", InstanceID: testDstInstance,
				SubnetID: "subnet-db", VPCID: "vpc-app",
				Account: testAccountA, Region: testRegionA,
			},
		},
		{
			// 6.2: a Name tag is the other way an operator names an endpoint.
			name:  "name tag resolves to the primary interface",
			snap:  diagnoseSnapshot,
			input: "db-1",
			want: Endpoint{
				Kind: EndpointInterface, Addr: testDstAddr,
				InterfaceID: "eni-db", InstanceID: testDstInstance,
				SubnetID: "subnet-db", VPCID: "vpc-app",
				Account: testAccountA, Region: testRegionA,
			},
		},
		{
			// An address in a collected subnet that no interface holds is still
			// located: the subnet, VPC, account, and region are known.
			name:  "address with no interface resolves to its subnet",
			snap:  diagnoseSnapshot,
			input: "10.30.2.99",
			want: Endpoint{
				Kind: EndpointSubnet, Addr: netip.MustParseAddr("10.30.2.99"),
				SubnetID: "subnet-db", VPCID: "vpc-app",
				Account: testAccountA, Region: testRegionA,
			},
		},
		{
			// 6.5: a CIDR no collected VPC owns is an ordinary external node.
			name:  "cidr outside every collected vpc is external",
			snap:  diagnoseSnapshot,
			input: "203.0.113.0/24",
			want: Endpoint{
				Kind: EndpointExternal, Addr: netip.MustParseAddr("203.0.113.0"),
				Prefix: netip.MustParsePrefix("203.0.113.0/24"),
			},
		},
		{
			// 6.5 again, with the range declared: the declared network names it.
			name:  "declared external network is named",
			snap:  externalSnapshot,
			input: "198.51.100.0/24",
			want: Endpoint{
				Kind: EndpointExternal, Addr: netip.MustParseAddr("198.51.100.0"),
				Prefix:            netip.MustParsePrefix("198.51.100.0/24"),
				ExternalNetworkID: "ext-onprem",
				Account:           testAccountA, Region: testRegionA,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ResolveEndpoint(tc.snap(), "to", tc.input)
			if err != nil {
				t.Fatalf("ResolveEndpoint(%q) error = %v", tc.input, err)
			}
			want := tc.want
			want.Input = tc.input
			// Notes are prose about the resolution, asserted separately.
			got.Notes = nil
			if !reflect.DeepEqual(got, want) {
				t.Errorf("ResolveEndpoint(%q) =\n  %+v\nwant\n  %+v", tc.input, got, want)
			}
		})
	}
}

// Requirement 6.3: an input matching more than one resource lists every
// candidate with its account and region, and selects none.
func TestResolveEndpointHaltsOnAmbiguity(t *testing.T) {
	_, err := ResolveEndpoint(overlappingSnapshot(), "to", "10.30.2.20")

	var ambiguousErr *AmbiguousEndpointError
	if !errors.As(err, &ambiguousErr) {
		t.Fatalf("error = %v, want *AmbiguousEndpointError", err)
	}
	if len(ambiguousErr.Candidates) != 2 {
		t.Fatalf("candidates = %+v, want both interfaces", ambiguousErr.Candidates)
	}
	for _, c := range ambiguousErr.Candidates {
		if c.Account == "" || c.Region == "" {
			t.Errorf("candidate %+v is missing its account or region", c)
		}
	}
	for _, want := range []string{"eni-db", "eni-other", testAccountA, testAccountB, testRegionA, testRegionB} {
		if !strings.Contains(ambiguousErr.Error(), want) {
			t.Errorf("error = %q, want it to name %q", ambiguousErr.Error(), want)
		}
	}
}

// Requirement 6.4: an input matching nothing reports the accounts and regions
// the snapshot does cover, which is how an operator sees they collected the
// wrong scope.
func TestResolveEndpointReportsScopesWhenNothingMatches(t *testing.T) {
	_, err := ResolveEndpoint(overlappingSnapshot(), "from", "web-1")

	var unresolved *UnresolvedEndpointError
	if !errors.As(err, &unresolved) {
		t.Fatalf("error = %v, want *UnresolvedEndpointError", err)
	}
	if got := unresolved.Accounts; len(got) != 2 || got[0] != testAccountA || got[1] != testAccountB {
		t.Errorf("accounts = %v, want both collected accounts", got)
	}
	if got := unresolved.Regions; len(got) != 2 {
		t.Errorf("regions = %v, want both collected regions", got)
	}
	for _, want := range []string{"web-1", testAccountA, testAccountB, testRegionA, testRegionB} {
		if !strings.Contains(unresolved.Error(), want) {
			t.Errorf("error = %q, want it to name %q", unresolved.Error(), want)
		}
	}
}

// A prefix wider than one address is walked through its network address, and the
// substitution is stated rather than left for the reader to infer.
func TestResolveEndpointNotesPrefixSubstitution(t *testing.T) {
	got, err := ResolveEndpoint(diagnoseSnapshot(), "to", "203.0.113.0/24")
	if err != nil {
		t.Fatalf("ResolveEndpoint() error = %v", err)
	}
	if len(got.Notes) != 1 || !strings.Contains(got.Notes[0], "203.0.113.0") {
		t.Errorf("notes = %v, want one stating the address the prefix was evaluated as", got.Notes)
	}
}
