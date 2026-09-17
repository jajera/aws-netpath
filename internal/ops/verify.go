package ops

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/jajera/aws-netpath/internal/awsx"
	"github.com/jajera/aws-netpath/internal/config"
	"github.com/jajera/aws-netpath/internal/model"
	"github.com/jajera/aws-netpath/internal/verify"
)

// VerifyRequest cross-checks the engine's verdict against AWS Reachability
// Analyzer.
//
// Reachability Analyzer analyses are billable and single-region, so the AWS side
// is skipped for cross-region and ICMP flows and the comparison is reported as
// inconclusive rather than guessed at.
type VerifyRequest struct {
	SnapshotPath string
	ConfigPath   string
	Profile      string
	Region       string
	From         string
	To           string
	Proto        string
	Port         int
	Timeout      time.Duration
	// SkipAWS evaluates the model only, making no AWS API call.
	SkipAWS bool
	// Analyzer overrides the Reachability Analyzer client. When nil and SkipAWS
	// is false, one is opened from Profile or ConfigPath. Supplying it lets a
	// caller drive the comparison without credentials.
	Analyzer verify.Analyzer
}

// Verify runs the offline query, then compares it against Reachability Analyzer
// when a single-region analysis can cover the flow.
func Verify(ctx context.Context, req VerifyRequest) (*verify.Result, error) {
	if err := requireFields(
		requiredField{"snapshot", req.SnapshotPath},
		requiredField{"from", req.From},
		requiredField{"to", req.To},
	); err != nil {
		return nil, err
	}

	proto, err := parseProtoPort(req.Proto, req.Port)
	if err != nil {
		return nil, err
	}

	src, dst, err := parseEndpoints(req.From, req.To)
	if err != nil {
		return nil, err
	}

	snap, err := loadSnapshot(req.SnapshotPath)
	if err != nil {
		return nil, err
	}

	opts := verify.Options{
		Snapshot: snap,
		SrcIP:    src,
		DstIP:    dst,
		Proto:    proto,
		Port:     req.Port,
		Region:   req.Region,
		Timeout:  req.Timeout,
		SkipAWS:  req.SkipAWS,
		Analyzer: req.Analyzer,
	}

	if !req.SkipAWS && opts.Analyzer == nil {
		analyzer, region, err := openAnalyzer(ctx, req, snap, src)
		if err != nil {
			return nil, err
		}
		if opts.Region == "" {
			opts.Region = region
		}
		opts.Analyzer = analyzer
	}

	return verify.Run(ctx, opts)
}

// AWSError marks a failure to reach AWS, as distinct from a bad request. The
// CLI labels these differently so an expired login is not mistaken for a usage
// mistake.
type AWSError struct{ Err error }

func (e *AWSError) Error() string { return e.Err.Error() }
func (e *AWSError) Unwrap() error { return e.Err }

// openAnalyzer resolves credentials for the flow's source region and opens a
// Reachability Analyzer client.
func openAnalyzer(ctx context.Context, req VerifyRequest, snap *model.Snapshot, src netip.Addr) (verify.Analyzer, string, error) {
	profile, region, assumeRole, err := resolveAWSScope(req.ConfigPath, req.Profile, req.Region, snap, src)
	if err != nil {
		return nil, "", err
	}

	wantRegion := req.Region
	if wantRegion == "" {
		wantRegion = region
	}

	clients, err := awsx.Open(ctx, awsx.OpenOptions{
		Profile:    profile,
		Region:     wantRegion,
		AssumeRole: assumeRole,
	})
	if err != nil {
		return nil, "", &AWSError{Err: err}
	}
	return &verify.EC2Analyzer{Client: clients.EC2}, region, nil
}

// resolveAWSScope decides which profile and region to analyse in. An explicit
// profile wins; otherwise the config file supplies the profile for the region
// the source address sits in.
func resolveAWSScope(configPath, profile, region string, snap *model.Snapshot, src netip.Addr) (prof, reg, assume string, err error) {
	if profile != "" {
		return profile, region, "", nil
	}
	if configPath != "" {
		cfg, err := config.Load(configPath)
		if err != nil {
			return "", "", "", err
		}
		_, srcRegion, ok := verify.SubnetForAddr(snap, src)
		if !ok && region == "" {
			return "", "", "", fmt.Errorf("--profile or --region required when source IP is not in snapshot")
		}
		wantRegion := region
		if wantRegion == "" {
			wantRegion = srcRegion
		}
		for _, t := range cfg.Targets() {
			if t.Region == wantRegion {
				return t.Profile, wantRegion, t.AssumeRole, nil
			}
		}
		return "", "", "", fmt.Errorf("no account in config for region %s", wantRegion)
	}
	return "", "", "", fmt.Errorf("--profile or --config is required for AWS comparison")
}
