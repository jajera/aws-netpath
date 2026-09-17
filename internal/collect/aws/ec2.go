package aws

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/jajera/aws-netpath/internal/awsx"
	"github.com/jajera/aws-netpath/internal/model"
)

func collectVPCs(ctx context.Context, c *awsx.Clients, snap *model.Snapshot) error {
	p := ec2.NewDescribeVpcsPaginator(c.EC2, &ec2.DescribeVpcsInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return err
		}
		for _, v := range page.Vpcs {
			id := aws.ToString(v.VpcId)
			var cidrs []netip.Prefix
			if v.CidrBlock != nil {
				if pfx, err := parseCIDR(aws.ToString(v.CidrBlock)); err == nil {
					cidrs = append(cidrs, pfx)
				}
			}
			for _, assoc := range v.CidrBlockAssociationSet {
				if assoc.CidrBlock != nil {
					if pfx, err := parseCIDR(aws.ToString(assoc.CidrBlock)); err == nil {
						cidrs = append(cidrs, pfx)
					}
				}
			}
			snap.VPCs[id] = &model.VPC{
				Meta:  meta(id, "", tagName(ec2Tags(v.Tags)), c.Region, c.AccountID, ec2Tags(v.Tags)),
				CIDRs: cidrs,
			}
		}
	}
	return nil
}

func collectSubnets(ctx context.Context, c *awsx.Clients, snap *model.Snapshot) error {
	p := ec2.NewDescribeSubnetsPaginator(c.EC2, &ec2.DescribeSubnetsInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return err
		}
		for _, s := range page.Subnets {
			id := aws.ToString(s.SubnetId)
			cidr, _ := parseCIDR(aws.ToString(s.CidrBlock))
			snap.Subnets[id] = &model.Subnet{
				Meta:             meta(id, "", tagName(ec2Tags(s.Tags)), c.Region, c.AccountID, ec2Tags(s.Tags)),
				VPCID:            aws.ToString(s.VpcId),
				CIDR:             cidr,
				AvailabilityZone: aws.ToString(s.AvailabilityZone),
			}
		}
	}
	return nil
}

func collectRouteTables(ctx context.Context, c *awsx.Clients, snap *model.Snapshot) error {
	p := ec2.NewDescribeRouteTablesPaginator(c.EC2, &ec2.DescribeRouteTablesInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return err
		}
		for _, rt := range page.RouteTables {
			id := aws.ToString(rt.RouteTableId)
			routes := make([]model.Route, 0, len(rt.Routes))
			for _, r := range rt.Routes {
				routes = append(routes, mapRoute(r))
			}
			snap.RouteTables[id] = &model.RouteTable{
				Meta:   meta(id, "", tagName(ec2Tags(rt.Tags)), c.Region, c.AccountID, ec2Tags(rt.Tags)),
				VPCID:  aws.ToString(rt.VpcId),
				Routes: routes,
			}
			// Wire subnet default route tables from associations.
			for _, assoc := range rt.Associations {
				if assoc.SubnetId != nil && assoc.Main != nil && !*assoc.Main {
					if sub, ok := snap.Subnets[aws.ToString(assoc.SubnetId)]; ok {
						sub.RouteTableID = id
					}
				}
			}
		}
	}
	return nil
}

func mapRoute(r ec2types.Route) model.Route {
	dest := netip.Prefix{}
	if r.DestinationCidrBlock != nil {
		dest, _ = parseCIDR(aws.ToString(r.DestinationCidrBlock))
	}
	route := model.Route{
		Destination:  dest,
		PrefixListID: aws.ToString(r.DestinationPrefixListId),
		State:        string(r.State),
	}
	if r.GatewayId != nil {
		gw := aws.ToString(r.GatewayId)
		route.TargetID = gw
		switch {
		case strings.HasPrefix(gw, "igw-"):
			route.TargetKind = model.TargetInternetGateway
		case strings.HasPrefix(gw, "vgw-"):
			route.TargetKind = model.TargetVirtualGateway
		case strings.HasPrefix(gw, "local"):
			route.TargetKind = model.TargetLocal
		default:
			route.TargetKind = model.TargetUnknown
		}
	}
	if r.NatGatewayId != nil {
		route.TargetKind = model.TargetNATGateway
		route.TargetID = aws.ToString(r.NatGatewayId)
	}
	if r.TransitGatewayId != nil {
		route.TargetKind = model.TargetTransitGateway
		route.TargetID = aws.ToString(r.TransitGatewayId)
	}
	if r.VpcPeeringConnectionId != nil {
		route.TargetKind = model.TargetVPCPeering
		route.TargetID = aws.ToString(r.VpcPeeringConnectionId)
	}
	if r.NetworkInterfaceId != nil {
		route.TargetKind = model.TargetNetworkInterface
		route.TargetID = aws.ToString(r.NetworkInterfaceId)
	}
	if r.GatewayId != nil && aws.ToString(r.GatewayId) == "local" {
		route.TargetKind = model.TargetLocal
	}
	if r.State == ec2types.RouteStateBlackhole {
		route.TargetKind = model.TargetBlackhole
	}
	return route
}

func collectSecurityGroups(ctx context.Context, c *awsx.Clients, snap *model.Snapshot) error {
	p := ec2.NewDescribeSecurityGroupsPaginator(c.EC2, &ec2.DescribeSecurityGroupsInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return err
		}
		for _, sg := range page.SecurityGroups {
			id := aws.ToString(sg.GroupId)
			snap.SecurityGroups[id] = &model.SecurityGroup{
				Meta:    meta(id, "", aws.ToString(sg.GroupName), c.Region, c.AccountID, ec2Tags(sg.Tags)),
				VPCID:   aws.ToString(sg.VpcId),
				Ingress: mapSGRules(sg.IpPermissions),
				Egress:  mapSGRules(sg.IpPermissionsEgress),
			}
		}
	}
	return nil
}

func mapSGRules(perms []ec2types.IpPermission) []model.SGRule {
	var out []model.SGRule
	for _, p := range perms {
		rule := model.SGRule{
			Protocol: parseProtocol(aws.ToString(p.IpProtocol)),
			FromPort: aws.ToInt32(p.FromPort),
			ToPort:   aws.ToInt32(p.ToPort),
		}
		for _, r := range p.IpRanges {
			if r.CidrIp != nil {
				if cidr, err := parseCIDR(aws.ToString(r.CidrIp)); err == nil {
					rule.CIDRs = append(rule.CIDRs, cidr)
				}
			}
		}
		for _, r := range p.Ipv6Ranges {
			if r.CidrIpv6 != nil {
				if cidr, err := parseCIDR(aws.ToString(r.CidrIpv6)); err == nil {
					rule.CIDRs = append(rule.CIDRs, cidr)
				}
			}
		}
		for _, g := range p.UserIdGroupPairs {
			if g.GroupId != nil {
				rule.PeerGroupIDs = append(rule.PeerGroupIDs, aws.ToString(g.GroupId))
			}
		}
		for _, pl := range p.PrefixListIds {
			if pl.PrefixListId != nil {
				rule.PrefixListIDs = append(rule.PrefixListIDs, aws.ToString(pl.PrefixListId))
			}
		}
		out = append(out, rule)
	}
	return out
}

func collectNACLs(ctx context.Context, c *awsx.Clients, snap *model.Snapshot) error {
	p := ec2.NewDescribeNetworkAclsPaginator(c.EC2, &ec2.DescribeNetworkAclsInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return err
		}
		for _, acl := range page.NetworkAcls {
			id := aws.ToString(acl.NetworkAclId)
			nacl := &model.NACL{
				Meta:    meta(id, "", tagName(ec2Tags(acl.Tags)), c.Region, c.AccountID, ec2Tags(acl.Tags)),
				VPCID:   aws.ToString(acl.VpcId),
				Ingress: mapNACLRoutes(acl.Entries, false),
				Egress:  mapNACLRoutes(acl.Entries, true),
			}
			snap.NACLs[id] = nacl
			for _, assoc := range acl.Associations {
				if assoc.SubnetId != nil {
					if sub, ok := snap.Subnets[aws.ToString(assoc.SubnetId)]; ok {
						sub.NACLID = id
					}
				}
			}
		}
	}
	return nil
}

func mapNACLRoutes(entries []ec2types.NetworkAclEntry, egress bool) []model.NACLRule {
	var out []model.NACLRule
	for _, e := range entries {
		if aws.ToBool(e.Egress) != egress {
			continue
		}
		if e.RuleNumber != nil && *e.RuleNumber == 32767 {
			continue // default deny, implicit
		}
		cidr, _ := parseCIDR(aws.ToString(e.CidrBlock))
		if e.Ipv6CidrBlock != nil {
			cidr, _ = parseCIDR(aws.ToString(e.Ipv6CidrBlock))
		}
		var fromPort, toPort int32
		if e.PortRange != nil {
			fromPort = aws.ToInt32(e.PortRange.From)
			toPort = aws.ToInt32(e.PortRange.To)
		} else {
			// ICMP, all-protocol, or port-agnostic rules omit PortRange.
			fromPort, toPort = 0, 65535
		}
		out = append(out, model.NACLRule{
			RuleNumber: aws.ToInt32(e.RuleNumber),
			Protocol:   parseProtocol(aws.ToString(e.Protocol)),
			FromPort:   fromPort,
			ToPort:     toPort,
			CIDR:       cidr,
			Allow:      e.RuleAction == ec2types.RuleActionAllow,
		})
	}
	return out
}

func collectTransitGateways(ctx context.Context, c *awsx.Clients, snap *model.Snapshot) error {
	p := ec2.NewDescribeTransitGatewaysPaginator(c.EC2, &ec2.DescribeTransitGatewaysInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return err
		}
		for _, tgw := range page.TransitGateways {
			id := aws.ToString(tgw.TransitGatewayId)
			var asn int64
			if tgw.Options != nil {
				asn = aws.ToInt64(tgw.Options.AmazonSideAsn)
			}
			snap.TransitGateways[id] = &model.TransitGateway{
				Meta: meta(id, aws.ToString(tgw.TransitGatewayArn), tagName(ec2Tags(tgw.Tags)), c.Region, c.AccountID, ec2Tags(tgw.Tags)),
				ASN:  asn,
			}
		}
	}
	return nil
}

func collectTGWAttachments(ctx context.Context, c *awsx.Clients, snap *model.Snapshot) error {
	p := ec2.NewDescribeTransitGatewayAttachmentsPaginator(c.EC2, &ec2.DescribeTransitGatewayAttachmentsInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return err
		}
		for _, a := range page.TransitGatewayAttachments {
			id := aws.ToString(a.TransitGatewayAttachmentId)
			att := &model.TGWAttachment{
				Meta:             meta(id, aws.ToString(a.TransitGatewayAttachmentId), tagName(ec2Tags(a.Tags)), c.Region, c.AccountID, ec2Tags(a.Tags)),
				TransitGatewayID: aws.ToString(a.TransitGatewayId),
				ResourceID:       aws.ToString(a.ResourceId),
				State:            string(a.State),
			}
			switch a.ResourceType {
			case ec2types.TransitGatewayAttachmentResourceTypeVpc:
				att.Kind = model.AttachVPC
			case ec2types.TransitGatewayAttachmentResourceTypeVpn:
				att.Kind = model.AttachVPN
			case ec2types.TransitGatewayAttachmentResourceTypePeering:
				att.Kind = model.AttachPeering
				att.PeerTGWID = aws.ToString(a.ResourceId)
			case ec2types.TransitGatewayAttachmentResourceTypeDirectConnectGateway:
				att.Kind = model.AttachDirectConnect
			case ec2types.TransitGatewayAttachmentResourceTypeConnect:
				att.Kind = model.AttachConnect
			}
			snap.TGWAttachments[id] = att
		}
	}
	return nil
}

func collectTGWRouteTables(ctx context.Context, c *awsx.Clients, snap *model.Snapshot) error {
	p := ec2.NewDescribeTransitGatewayRouteTablesPaginator(c.EC2, &ec2.DescribeTransitGatewayRouteTablesInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return err
		}
		for _, rt := range page.TransitGatewayRouteTables {
			id := aws.ToString(rt.TransitGatewayRouteTableId)
			tgwRT := &model.TGWRouteTable{
				Meta:             meta(id, aws.ToString(rt.TransitGatewayRouteTableId), tagName(ec2Tags(rt.Tags)), c.Region, c.AccountID, ec2Tags(rt.Tags)),
				TransitGatewayID: aws.ToString(rt.TransitGatewayId),
			}
			// Routes require SearchTransitGatewayRoutes per attachment or static routes API.
			// For v1 collect, fetch associations and static routes via separate calls.
			if routes, assocs, err := tgwRoutes(ctx, c, id); err == nil {
				tgwRT.Routes = routes
				tgwRT.AssociatedAttachments = assocs
			}
			snap.TGWRouteTables[id] = tgwRT
		}
	}
	return nil
}

func tgwRoutes(ctx context.Context, c *awsx.Clients, rtID string) ([]model.Route, []string, error) {
	var routes []model.Route
	var assocs []string

	ap := ec2.NewGetTransitGatewayRouteTableAssociationsPaginator(c.EC2, &ec2.GetTransitGatewayRouteTableAssociationsInput{
		TransitGatewayRouteTableId: aws.String(rtID),
	})
	for ap.HasMorePages() {
		page, err := ap.NextPage(ctx)
		if err != nil {
			return nil, nil, err
		}
		for _, a := range page.Associations {
			assocs = append(assocs, aws.ToString(a.TransitGatewayAttachmentId))
		}
	}

	rp := ec2.NewSearchTransitGatewayRoutesPaginator(c.EC2, &ec2.SearchTransitGatewayRoutesInput{
		TransitGatewayRouteTableId: aws.String(rtID),
		Filters: []ec2types.Filter{{
			Name:   aws.String("type"),
			Values: []string{"static", "propagated"},
		}},
	})
	for rp.HasMorePages() {
		page, err := rp.NextPage(ctx)
		if err != nil {
			return routes, assocs, err
		}
		for _, r := range page.Routes {
			dest, _ := parseCIDR(aws.ToString(r.DestinationCidrBlock))
			route := model.Route{
				Destination: dest,
				State:       string(r.State),
			}
			if len(r.TransitGatewayAttachments) > 0 {
				route.TargetID = aws.ToString(r.TransitGatewayAttachments[0].ResourceId)
			}
			if r.State == ec2types.TransitGatewayRouteStateBlackhole {
				route.TargetKind = model.TargetBlackhole
			} else {
				route.TargetKind = model.TargetAttachment
			}
			routes = append(routes, route)
		}
	}
	return routes, assocs, nil
}

func collectVPCPeerings(ctx context.Context, c *awsx.Clients, snap *model.Snapshot) error {
	p := ec2.NewDescribeVpcPeeringConnectionsPaginator(c.EC2, &ec2.DescribeVpcPeeringConnectionsInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return err
		}
		for _, pcx := range page.VpcPeeringConnections {
			id := aws.ToString(pcx.VpcPeeringConnectionId)
			var reqVPC, accVPC string
			if pcx.RequesterVpcInfo != nil {
				reqVPC = aws.ToString(pcx.RequesterVpcInfo.VpcId)
			}
			if pcx.AccepterVpcInfo != nil {
				accVPC = aws.ToString(pcx.AccepterVpcInfo.VpcId)
			}
			state := ""
			if pcx.Status != nil {
				state = string(pcx.Status.Code)
			}
			snap.VPCPeerings[id] = &model.VPCPeering{
				Meta:           meta(id, "", tagName(ec2Tags(pcx.Tags)), c.Region, c.AccountID, ec2Tags(pcx.Tags)),
				RequesterVPCID: reqVPC,
				AccepterVPCID:  accVPC,
				State:          state,
			}
		}
	}
	return nil
}

func ec2Tags(tags []ec2types.Tag) map[string]string {
	out := map[string]string{}
	for _, t := range tags {
		if t.Key != nil && t.Value != nil {
			out[*t.Key] = *t.Value
		}
	}
	return out
}

func parseProtocol(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || s == "-1" {
		return "any"
	}
	switch s {
	case "1", "icmp":
		return "icmp"
	case "6", "tcp":
		return "tcp"
	case "17", "udp":
		return "udp"
	}
	return strings.ToLower(s)
}

func parseCIDR(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return netip.Prefix{}, fmt.Errorf("empty cidr")
	}
	if !strings.Contains(s, "/") {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return netip.Prefix{}, err
		}
		return netip.PrefixFrom(a, a.BitLen()), nil
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return p.Masked(), nil
}
