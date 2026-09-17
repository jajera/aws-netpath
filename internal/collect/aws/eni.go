package aws

// Elastic network interface collection.
//
// The interface, not the instance, is where a security group actually attaches.
// Without interfaces in the snapshot an endpoint has no groups to evaluate, so
// the SECURITY_GROUP layer can only abstain — which is why this is collected as
// its own resource type rather than inferred from instances.

import (
	"context"
	"net/netip"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/jajera/aws-netpath/internal/awsx"
	"github.com/jajera/aws-netpath/internal/guardrail"
	"github.com/jajera/aws-netpath/internal/model"
)

// eniAPI is the slice of the EC2 API this collector uses. Depending on the
// interface the SDK already exports, rather than on *ec2.Client, lets the
// paginator run against a stub under test.
type eniAPI = ec2.DescribeNetworkInterfacesAPIClient

// eniStatuses limits collection to interfaces that carry traffic now (in-use)
// or are configured and could (available). Interfaces mid-attach or mid-detach
// are transient and would describe a network that no longer exists by the time
// the snapshot is queried.
var eniStatuses = []string{"in-use", "available"}

func collectNetworkInterfaces(ctx context.Context, c *awsx.Clients, snap *model.Snapshot) error {
	return collectNetworkInterfacesFrom(ctx, c.EC2, c.Region, c.AccountID, snap)
}

// collectNetworkInterfacesFrom reads every interface in one account and region
// into snap. A page error is returned rather than swallowed: CollectRegion
// records it against this resource type in collection_errors and carries on
// with the remaining types.
func collectNetworkInterfacesFrom(ctx context.Context, api eniAPI, region, account string, snap *model.Snapshot) error {
	if err := guardrail.ValidateAction("DescribeNetworkInterfaces"); err != nil {
		return err
	}
	p := ec2.NewDescribeNetworkInterfacesPaginator(api, &ec2.DescribeNetworkInterfacesInput{
		Filters: []ec2types.Filter{{
			Name:   aws.String("status"),
			Values: eniStatuses,
		}},
	})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return err
		}
		for _, eni := range page.NetworkInterfaces {
			iface := mapNetworkIface(eni, region, account)
			if iface == nil {
				continue
			}
			snap.NetworkIfaces[iface.ID] = iface
		}
	}
	return nil
}

// mapNetworkIface translates one EC2 interface into the model. An interface
// carrying no identifier is skipped: it cannot key the snapshot and could not
// be cited in a verdict.
func mapNetworkIface(eni ec2types.NetworkInterface, region, account string) *model.NetworkIface {
	id := aws.ToString(eni.NetworkInterfaceId)
	if id == "" {
		return nil
	}
	tags := ec2Tags(eni.TagSet)
	iface := &model.NetworkIface{
		Meta:     meta(id, "", tagName(tags), region, account, tags),
		VPCID:    aws.ToString(eni.VpcId),
		SubnetID: aws.ToString(eni.SubnetId),
		Status:   string(eni.Status),
	}

	// Every group on the interface applies; AWS takes the union. Order is
	// preserved so a citation names groups the way the console does.
	for _, sg := range eni.Groups {
		if gid := aws.ToString(sg.GroupId); gid != "" {
			iface.SecurityGroupIDs = append(iface.SecurityGroupIDs, gid)
		}
	}

	// Only an instance attachment identifies an endpoint. Service-owned
	// interfaces — NAT gateways, load balancers, firewall endpoints — report an
	// owner instead, and an owner is an account, not an endpoint.
	if eni.Attachment != nil {
		iface.AttachedTo = aws.ToString(eni.Attachment.InstanceId)
	}

	iface.PrivateIPs, iface.PublicIP = interfaceAddresses(eni)
	return iface
}

// interfaceAddresses returns the interface's private addresses with the primary
// first, plus the public address associated with that primary if one exists.
// Order is deliberate: an endpoint is attributed by its own address, and the
// API does not promise the primary appears first.
func interfaceAddresses(eni ec2types.NetworkInterface) ([]netip.Addr, *netip.Addr) {
	var primary, secondary []netip.Addr
	var public *netip.Addr

	for _, pip := range eni.PrivateIpAddresses {
		isPrimary := aws.ToBool(pip.Primary)
		if addr, err := netip.ParseAddr(aws.ToString(pip.PrivateIpAddress)); err == nil {
			if isPrimary {
				primary = append(primary, addr)
			} else {
				secondary = append(secondary, addr)
			}
		}
		if isPrimary && pip.Association != nil && pip.Association.PublicIp != nil {
			if addr, err := netip.ParseAddr(aws.ToString(pip.Association.PublicIp)); err == nil {
				public = &addr
			}
		}
	}

	if len(primary) == 0 && len(secondary) == 0 {
		return nil, public
	}
	return append(primary, secondary...), public
}
