package aws

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/jajera/aws-netpath/internal/model"
)

const (
	testAccount = "111122223333"
	testRegion  = "ap-southeast-2"
)

// stubENIClient replays canned DescribeNetworkInterfaces pages in order and
// records the inputs it was called with.
type stubENIClient struct {
	pages  []*ec2.DescribeNetworkInterfacesOutput
	errAt  int // index of the call that fails; -1 for never
	calls  int
	inputs []*ec2.DescribeNetworkInterfacesInput
}

func (s *stubENIClient) DescribeNetworkInterfaces(_ context.Context, in *ec2.DescribeNetworkInterfacesInput, _ ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
	s.inputs = append(s.inputs, in)
	i := s.calls
	s.calls++
	if s.errAt >= 0 && i == s.errAt {
		return nil, errors.New("AccessDenied: not authorized to perform ec2:DescribeNetworkInterfaces")
	}
	if i >= len(s.pages) {
		return &ec2.DescribeNetworkInterfacesOutput{}, nil
	}
	return s.pages[i], nil
}

func addr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return a
}

// Requirement 2.2: interfaces are ingested so security groups can be
// attributed to an endpoint.
func TestCollectNetworkInterfacesAttributesSecurityGroups(t *testing.T) {
	client := &stubENIClient{
		errAt: -1,
		pages: []*ec2.DescribeNetworkInterfacesOutput{
			{
				NetworkInterfaces: []ec2types.NetworkInterface{{
					NetworkInterfaceId: aws.String("eni-app"),
					VpcId:              aws.String("vpc-app"),
					SubnetId:           aws.String("subnet-app-a"),
					Status:             ec2types.NetworkInterfaceStatusInUse,
					Groups: []ec2types.GroupIdentifier{
						{GroupId: aws.String("sg-app")},
						{GroupId: aws.String("sg-shared")},
					},
					Attachment: &ec2types.NetworkInterfaceAttachment{
						InstanceId:      aws.String("i-0app"),
						InstanceOwnerId: aws.String(testAccount),
					},
					PrivateIpAddresses: []ec2types.NetworkInterfacePrivateIpAddress{{
						Primary:          aws.Bool(true),
						PrivateIpAddress: aws.String("10.20.1.10"),
						Association: &ec2types.NetworkInterfaceAssociation{
							PublicIp: aws.String("192.0.2.10"),
						},
					}},
					TagSet: []ec2types.Tag{{Key: aws.String("Name"), Value: aws.String("app-01")}},
				}},
				NextToken: aws.String("page-2"),
			},
			{
				NetworkInterfaces: []ec2types.NetworkInterface{{
					NetworkInterfaceId: aws.String("eni-db"),
					VpcId:              aws.String("vpc-app"),
					SubnetId:           aws.String("subnet-app-b"),
					Status:             ec2types.NetworkInterfaceStatusInUse,
					Groups:             []ec2types.GroupIdentifier{{GroupId: aws.String("sg-db")}},
					PrivateIpAddresses: []ec2types.NetworkInterfacePrivateIpAddress{{
						Primary:          aws.Bool(true),
						PrivateIpAddress: aws.String("10.20.2.10"),
					}},
				}},
			},
		},
	}

	snap := model.NewSnapshot()
	if err := collectNetworkInterfacesFrom(context.Background(), client, testRegion, testAccount, snap); err != nil {
		t.Fatalf("collect: %v", err)
	}

	if len(snap.NetworkIfaces) != 2 {
		t.Fatalf("collected %d interfaces, want 2 across both pages", len(snap.NetworkIfaces))
	}

	app := snap.NetworkIfaces["eni-app"]
	if app == nil {
		t.Fatal("eni-app missing from snapshot")
	}
	want := []string{"sg-app", "sg-shared"}
	if len(app.SecurityGroupIDs) != len(want) {
		t.Fatalf("security groups = %v, want %v", app.SecurityGroupIDs, want)
	}
	for i, id := range want {
		if app.SecurityGroupIDs[i] != id {
			t.Errorf("security group %d = %q, want %q", i, app.SecurityGroupIDs[i], id)
		}
	}
	if app.VPCID != "vpc-app" || app.SubnetID != "subnet-app-a" {
		t.Errorf("placement = %s/%s, want vpc-app/subnet-app-a", app.VPCID, app.SubnetID)
	}
	if app.AttachedTo != "i-0app" {
		t.Errorf("attached to %q, want the instance id i-0app", app.AttachedTo)
	}
	if app.Region != testRegion || app.Account != testAccount {
		t.Errorf("scope = %s/%s, want %s/%s", app.Account, app.Region, testAccount, testRegion)
	}
	if app.Name != "app-01" {
		t.Errorf("name = %q, want the Name tag app-01", app.Name)
	}
	if len(app.PrivateIPs) != 1 || app.PrivateIPs[0] != addr(t, "10.20.1.10") {
		t.Errorf("private ips = %v, want [10.20.1.10]", app.PrivateIPs)
	}
	if app.PublicIP == nil || *app.PublicIP != addr(t, "192.0.2.10") {
		t.Errorf("public ip = %v, want 192.0.2.10", app.PublicIP)
	}

	if len(client.inputs) == 0 {
		t.Fatal("no describe call recorded")
	}
	if !hasStatusFilter(client.inputs[0], eniStatuses) {
		t.Errorf("input filters = %+v, want a status filter of %v", client.inputs[0].Filters, eniStatuses)
	}
}

func hasStatusFilter(in *ec2.DescribeNetworkInterfacesInput, want []string) bool {
	for _, f := range in.Filters {
		if aws.ToString(f.Name) != "status" || len(f.Values) != len(want) {
			continue
		}
		match := true
		for i, v := range want {
			if f.Values[i] != v {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// The primary address identifies the endpoint, so it leads regardless of the
// order the API returns addresses in.
func TestCollectNetworkInterfacesOrdersPrimaryAddressFirst(t *testing.T) {
	client := &stubENIClient{
		errAt: -1,
		pages: []*ec2.DescribeNetworkInterfacesOutput{{
			NetworkInterfaces: []ec2types.NetworkInterface{{
				NetworkInterfaceId: aws.String("eni-multi"),
				Status:             ec2types.NetworkInterfaceStatusInUse,
				PrivateIpAddresses: []ec2types.NetworkInterfacePrivateIpAddress{
					{Primary: aws.Bool(false), PrivateIpAddress: aws.String("10.20.1.51")},
					{Primary: aws.Bool(true), PrivateIpAddress: aws.String("10.20.1.50")},
					{Primary: aws.Bool(false), PrivateIpAddress: aws.String("10.20.1.52")},
				},
			}},
		}},
	}

	snap := model.NewSnapshot()
	if err := collectNetworkInterfacesFrom(context.Background(), client, testRegion, testAccount, snap); err != nil {
		t.Fatalf("collect: %v", err)
	}

	eni := snap.NetworkIfaces["eni-multi"]
	if eni == nil {
		t.Fatal("eni-multi missing from snapshot")
	}
	want := []netip.Addr{
		addr(t, "10.20.1.50"),
		addr(t, "10.20.1.51"),
		addr(t, "10.20.1.52"),
	}
	if len(eni.PrivateIPs) != len(want) {
		t.Fatalf("private ips = %v, want %v", eni.PrivateIPs, want)
	}
	for i, a := range want {
		if eni.PrivateIPs[i] != a {
			t.Errorf("private ip %d = %v, want %v", i, eni.PrivateIPs[i], a)
		}
	}
}

// A service-owned interface reports an owner account rather than an instance.
// An account is not an endpoint, so the attachment stays empty.
func TestMapNetworkIfaceServiceOwnedAttachment(t *testing.T) {
	iface := mapNetworkIface(ec2types.NetworkInterface{
		NetworkInterfaceId: aws.String("eni-nat"),
		Status:             ec2types.NetworkInterfaceStatusInUse,
		Attachment: &ec2types.NetworkInterfaceAttachment{
			InstanceOwnerId: aws.String("amazon-aws"),
		},
	}, testRegion, testAccount)

	if iface == nil {
		t.Fatal("mapNetworkIface returned nil for a valid interface")
	}
	if iface.AttachedTo != "" {
		t.Errorf("attached to %q, want empty for a service-owned interface", iface.AttachedTo)
	}
}

func TestMapNetworkIfaceSkipsInterfaceWithoutID(t *testing.T) {
	if iface := mapNetworkIface(ec2types.NetworkInterface{}, testRegion, testAccount); iface != nil {
		t.Errorf("got %+v, want nil for an interface with no id", iface)
	}
}

// Requirement 2.4: a failure is reported to the caller, which records it in
// collection_errors, and whatever was already read stays usable.
func TestCollectNetworkInterfacesReturnsPageErrorKeepingEarlierPages(t *testing.T) {
	client := &stubENIClient{
		errAt: 1,
		pages: []*ec2.DescribeNetworkInterfacesOutput{{
			NetworkInterfaces: []ec2types.NetworkInterface{{
				NetworkInterfaceId: aws.String("eni-first"),
				Status:             ec2types.NetworkInterfaceStatusInUse,
				Groups:             []ec2types.GroupIdentifier{{GroupId: aws.String("sg-first")}},
			}},
			NextToken: aws.String("page-2"),
		}},
	}

	snap := model.NewSnapshot()
	err := collectNetworkInterfacesFrom(context.Background(), client, testRegion, testAccount, snap)
	if err == nil {
		t.Fatal("want the page error returned so it lands in collection_errors")
	}
	if snap.NetworkIfaces["eni-first"] == nil {
		t.Error("interfaces read before the failure must remain in the snapshot")
	}
}
