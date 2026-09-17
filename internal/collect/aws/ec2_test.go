package aws

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func TestMapNACLRoutesNilPortRange(t *testing.T) {
	entries := []ec2types.NetworkAclEntry{
		{
			RuleNumber: aws.Int32(100),
			Protocol:   aws.String("1"), // ICMP
			Egress:     aws.Bool(false),
			CidrBlock:  aws.String("10.0.0.0/8"),
			RuleAction: ec2types.RuleActionAllow,
			PortRange:  nil,
		},
	}
	rules := mapNACLRoutes(entries, false)
	if len(rules) != 1 {
		t.Fatalf("got %d rules, want 1", len(rules))
	}
	if rules[0].FromPort != 0 || rules[0].ToPort != 65535 {
		t.Errorf("ports = %d-%d, want 0-65535 for nil PortRange", rules[0].FromPort, rules[0].ToPort)
	}
}
