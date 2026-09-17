// Package awsx builds AWS SDK clients from shared config profiles.
package awsx

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/networkfirewall"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

const defaultRoleSession = "aws-netpath-collect"

// Clients holds regional AWS service clients for one account.
type Clients struct {
	AccountID string
	Profile   string
	Region    string
	Config    aws.Config
	EC2       *ec2.Client
	NFW       *networkfirewall.Client
	STS       *sts.Client
}

// OpenOptions configures client creation for one account and region.
type OpenOptions struct {
	Profile         string
	Region          string
	AssumeRole      string
	RoleSessionName string
}

// Open loads credentials from Profile, optionally assumes AssumeRole, and
// returns clients scoped to Region.
func Open(ctx context.Context, opts OpenOptions) (*Clients, error) {
	if opts.Profile == "" {
		return nil, fmt.Errorf("profile is required")
	}
	if opts.Region == "" {
		return nil, fmt.Errorf("region is required")
	}

	loadOpts := []func(*config.LoadOptions) error{
		config.WithSharedConfigProfile(opts.Profile),
		config.WithRegion(opts.Region),
	}
	cfg, err := config.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return nil, fmt.Errorf("load aws config profile %q: %w", opts.Profile, err)
	}

	stsClient := sts.NewFromConfig(cfg)
	if opts.AssumeRole != "" {
		sessionName := opts.RoleSessionName
		if sessionName == "" {
			sessionName = defaultRoleSession
		}
		cfg.Credentials = stscreds.NewAssumeRoleProvider(stsClient, opts.AssumeRole, func(o *stscreds.AssumeRoleOptions) {
			o.RoleSessionName = sessionName
		})
	}

	idOut, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, fmt.Errorf("sts GetCallerIdentity: %w", err)
	}
	accountID := aws.ToString(idOut.Account)

	return &Clients{
		AccountID: accountID,
		Profile:   opts.Profile,
		Region:    opts.Region,
		Config:    cfg,
		EC2:       ec2.NewFromConfig(cfg),
		NFW:       networkfirewall.NewFromConfig(cfg),
		STS:       stsClient,
	}, nil
}

// WithTimeout wraps ctx with a collection deadline.
func WithTimeout(ctx context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	if d <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, d)
}
