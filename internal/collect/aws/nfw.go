package aws

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/networkfirewall"
	nfwtypes "github.com/aws/aws-sdk-go-v2/service/networkfirewall/types"
	"github.com/jajera/aws-netpath/internal/awsx"
	"github.com/jajera/aws-netpath/internal/model"
	"github.com/jajera/aws-netpath/internal/nfw"
)

func collectFirewalls(ctx context.Context, c *awsx.Clients, snap *model.Snapshot) error {
	p := networkfirewall.NewListFirewallsPaginator(c.NFW, &networkfirewall.ListFirewallsInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return err
		}
		for _, summary := range page.Firewalls {
			name := aws.ToString(summary.FirewallName)
			desc, err := c.NFW.DescribeFirewall(ctx, &networkfirewall.DescribeFirewallInput{
				FirewallName: aws.String(name),
			})
			if err != nil {
				return fmt.Errorf("describe firewall %s: %w", name, err)
			}
			fw := desc.Firewall
			id := aws.ToString(fw.FirewallId)
			policyARN := aws.ToString(fw.FirewallPolicyArn)

			subnetIDs := make([]string, 0, len(fw.SubnetMappings))
			endpoints := map[string]string{}
			for _, m := range fw.SubnetMappings {
				sid := aws.ToString(m.SubnetId)
				subnetIDs = append(subnetIDs, sid)
				if m.IPAddressType != "" {
					endpoints[sid] = sid
				}
			}

			snap.Firewalls[id] = &model.Firewall{
				Meta: model.Meta{
					ID:      id,
					ARN:     aws.ToString(fw.FirewallArn),
					Name:    name,
					Region:  c.Region,
					Account: c.AccountID,
				},
				VPCID:             aws.ToString(fw.VpcId),
				PolicyARN:         policyARN,
				SubnetIDs:         subnetIDs,
				EndpointsBySubnet: endpoints,
			}

			if policyARN != "" {
				if err := collectFirewallPolicy(ctx, c, snap, policyARN); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func collectFirewallPolicy(ctx context.Context, c *awsx.Clients, snap *model.Snapshot, policyARN string) error {
	if _, ok := snap.FirewallPolicies[policyARN]; ok {
		return nil
	}

	out, err := c.NFW.DescribeFirewallPolicy(ctx, &networkfirewall.DescribeFirewallPolicyInput{
		FirewallPolicyArn: aws.String(policyARN),
	})
	if err != nil {
		return fmt.Errorf("describe firewall policy %s: %w", policyARN, err)
	}

	fp := out.FirewallPolicy
	policy := &model.FirewallPolicy{
		Meta: model.Meta{
			ID:      policyARN,
			ARN:     policyARN,
			Name:    aws.ToString(out.FirewallPolicyResponse.FirewallPolicyName),
			Region:  c.Region,
			Account: c.AccountID,
		},
		StatefulDefaultActions:  append([]string(nil), fp.StatefulDefaultActions...),
		StatelessDefaultActions: append([]string(nil), fp.StatelessDefaultActions...),
	}
	if fp.StatefulEngineOptions != nil {
		policy.StatefulRuleOrder = model.RuleOrder(string(fp.StatefulEngineOptions.RuleOrder))
	}

	for _, ref := range fp.StatefulRuleGroupReferences {
		policy.StatefulGroups = append(policy.StatefulGroups, model.RuleGroupRef{
			ARN:      aws.ToString(ref.ResourceArn),
			Priority: int(aws.ToInt32(ref.Priority)),
		})
		if err := collectRuleGroup(ctx, c, snap, aws.ToString(ref.ResourceArn)); err != nil {
			return err
		}
	}

	snap.FirewallPolicies[policyARN] = policy
	return nil
}

func collectRuleGroup(ctx context.Context, c *awsx.Clients, snap *model.Snapshot, arn string) error {
	if arn == "" || snap.RuleGroups[arn] != nil {
		return nil
	}

	out, err := c.NFW.DescribeRuleGroup(ctx, &networkfirewall.DescribeRuleGroupInput{
		RuleGroupArn: aws.String(arn),
	})
	if err != nil {
		return fmt.Errorf("describe rule group %s: %w", arn, err)
	}

	rg := out.RuleGroup
	group := &model.RuleGroup{
		Meta: model.Meta{
			ID:      arn,
			ARN:     arn,
			Name:    aws.ToString(out.RuleGroupResponse.RuleGroupName),
			Region:  c.Region,
			Account: c.AccountID,
		},
		Capacity: int(aws.ToInt32(out.RuleGroupResponse.Capacity)),
	}

	if rg.StatefulRuleOptions != nil {
		group.RuleOrder = model.RuleOrder(string(rg.StatefulRuleOptions.RuleOrder))
	}

	if rg.RulesSource != nil {
		if rg.RulesSource.RulesSourceList != nil {
			group.DomainTargets = append(group.DomainTargets, rg.RulesSource.RulesSourceList.Targets...)
		}
		if rg.RulesSource.RulesString != nil {
			group.RulesString = aws.ToString(rg.RulesSource.RulesString)
		}
		for _, sr := range rg.RulesSource.StatefulRules {
			group.Rules = append(group.Rules, mapStatefulRule(sr))
		}
	}

	if rg.RuleVariables != nil {
		group.RuleVariables = mapIPSetVariables(rg.RuleVariables.IPSets)
		if strings.TrimSpace(group.RulesString) != "" && len(group.Rules) == 0 {
			if expanded, err := nfw.ParseRulesString(group.RulesString, group.RuleVariables); err == nil {
				group.Rules = expanded
			}
		}
	}

	snap.RuleGroups[arn] = group
	return nil
}

func mapStatefulRule(sr nfwtypes.StatefulRule) model.StatefulRule {
	rule := model.StatefulRule{
		Action: strings.ToUpper(string(sr.Action)),
	}
	if sr.Header != nil {
		h := sr.Header
		rule.Protocol = strings.ToUpper(string(h.Protocol))
		rule.Source = aws.ToString(h.Source)
		rule.SourcePort = aws.ToString(h.SourcePort)
		rule.Destination = aws.ToString(h.Destination)
		rule.DestinationPort = aws.ToString(h.DestinationPort)
		rule.Direction = model.Direction(string(h.Direction))
	}
	for _, opt := range sr.RuleOptions {
		if opt.Keyword != nil && strings.EqualFold(aws.ToString(opt.Keyword), "sid") && len(opt.Settings) > 0 {
			rule.SID = opt.Settings[0]
		}
	}
	return rule
}

func mapIPSetVariables(sets map[string]nfwtypes.IPSet) map[string][]string {
	if len(sets) == 0 {
		return nil
	}
	out := make(map[string][]string, len(sets))
	for name, set := range sets {
		out[name] = append([]string(nil), set.Definition...)
	}
	return out
}
