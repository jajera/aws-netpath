package aws

import (
	"context"

	"github.com/jajera/aws-netpath/internal/awsx"
	"github.com/jajera/aws-netpath/internal/model"
)

// CollectRegion gathers every supported resource type in one account and region.
func CollectRegion(ctx context.Context, c *awsx.Clients) (*model.Snapshot, []model.CollectionError) {
	snap := model.NewSnapshot()
	var errs []model.CollectionError

	appendErr := func(resource string, err error) {
		if err == nil {
			return
		}
		errs = append(errs, model.CollectionError{
			Region:   c.Region,
			Account:  c.AccountID,
			Resource: resource,
			Err:      err.Error(),
		})
	}

	if e := collectVPCs(ctx, c, snap); e != nil {
		appendErr("ec2:DescribeVpcs", e)
	}
	if e := collectSubnets(ctx, c, snap); e != nil {
		appendErr("ec2:DescribeSubnets", e)
	}
	if e := collectRouteTables(ctx, c, snap); e != nil {
		appendErr("ec2:DescribeRouteTables", e)
	}
	if e := collectSecurityGroups(ctx, c, snap); e != nil {
		appendErr("ec2:DescribeSecurityGroups", e)
	}
	if e := collectNACLs(ctx, c, snap); e != nil {
		appendErr("ec2:DescribeNetworkAcls", e)
	}
	if e := collectNetworkInterfaces(ctx, c, snap); e != nil {
		appendErr("ec2:DescribeNetworkInterfaces", e)
	}
	if e := collectTransitGateways(ctx, c, snap); e != nil {
		appendErr("ec2:DescribeTransitGateways", e)
	}
	if e := collectTGWAttachments(ctx, c, snap); e != nil {
		appendErr("ec2:DescribeTransitGatewayAttachments", e)
	}
	if e := collectTGWRouteTables(ctx, c, snap); e != nil {
		appendErr("ec2:DescribeTransitGatewayRouteTables", e)
	}
	if e := collectVPCPeerings(ctx, c, snap); e != nil {
		appendErr("ec2:DescribeVpcPeeringConnections", e)
	}
	if e := collectFirewalls(ctx, c, snap); e != nil {
		appendErr("network-firewall:ListFirewalls", e)
	}

	return snap, errs
}

func meta(id, arn, name, region, account string, tags map[string]string) model.Meta {
	if name == "" {
		name = tagName(tags)
	}
	return model.Meta{
		ID:      id,
		ARN:     arn,
		Name:    name,
		Region:  region,
		Account: account,
		Tags:    tags,
	}
}

func tagName(tags map[string]string) string {
	if tags == nil {
		return ""
	}
	return tags["Name"]
}
