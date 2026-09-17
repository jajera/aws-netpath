package verify

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// AnalysisRequest is input for one Reachability Analyzer run.
type AnalysisRequest struct {
	Source          string
	Destination     string
	SourceIP        string
	DestinationIP   string
	Protocol        types.Protocol
	DestinationPort int32
	Tag             string
}

// AnalysisResponse is the outcome of one Reachability Analyzer run.
type AnalysisResponse struct {
	Reachable      *bool
	AnalysisID     string
	PathID         string
	Status         types.AnalysisStatus
	StatusMessage  string
	WarningMessage string
}

// Analyzer runs AWS VPC Reachability Analyzer.
type Analyzer interface {
	Analyze(ctx context.Context, req AnalysisRequest) (*AnalysisResponse, error)
}

// EC2Analyzer implements Analyzer with the EC2 API.
type EC2Analyzer struct {
	Client *ec2.Client
}

// Analyze creates a path, runs an analysis, polls for completion, and deletes the path.
func (a *EC2Analyzer) Analyze(ctx context.Context, req AnalysisRequest) (*AnalysisResponse, error) {
	if a == nil || a.Client == nil {
		return nil, fmt.Errorf("ec2 client is required")
	}
	token := fmt.Sprintf("aws-netpath-%d", time.Now().UnixNano())
	tag := req.Tag
	if tag == "" {
		tag = "aws-netpath-verify"
	}

	createOut, err := a.Client.CreateNetworkInsightsPath(ctx, &ec2.CreateNetworkInsightsPathInput{
		ClientToken:     aws.String(token),
		Source:          aws.String(req.Source),
		Destination:     aws.String(req.Destination),
		SourceIp:        aws.String(req.SourceIP),
		DestinationIp:   aws.String(req.DestinationIP),
		Protocol:        req.Protocol,
		DestinationPort: aws.Int32(req.DestinationPort),
		TagSpecifications: []types.TagSpecification{
			{
				ResourceType: types.ResourceTypeNetworkInsightsPath,
				Tags: []types.Tag{
					{Key: aws.String("aws-netpath"), Value: aws.String(tag)},
				},
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("create network insights path: %w", err)
	}
	pathID := aws.ToString(createOut.NetworkInsightsPath.NetworkInsightsPathId)
	defer func() {
		_, _ = a.Client.DeleteNetworkInsightsPath(context.Background(), &ec2.DeleteNetworkInsightsPathInput{
			NetworkInsightsPathId: aws.String(pathID),
		})
	}()

	startOut, err := a.Client.StartNetworkInsightsAnalysis(ctx, &ec2.StartNetworkInsightsAnalysisInput{
		NetworkInsightsPathId: aws.String(pathID),
		TagSpecifications: []types.TagSpecification{
			{
				ResourceType: types.ResourceTypeNetworkInsightsAnalysis,
				Tags: []types.Tag{
					{Key: aws.String("aws-netpath"), Value: aws.String(tag)},
				},
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("start network insights analysis: %w", err)
	}
	analysisID := aws.ToString(startOut.NetworkInsightsAnalysis.NetworkInsightsAnalysisId)

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(2 * time.Minute)
	}
	for time.Now().Before(deadline) {
		desc, err := a.Client.DescribeNetworkInsightsAnalyses(ctx, &ec2.DescribeNetworkInsightsAnalysesInput{
			NetworkInsightsAnalysisIds: []string{analysisID},
		})
		if err != nil {
			return nil, fmt.Errorf("describe network insights analysis: %w", err)
		}
		if len(desc.NetworkInsightsAnalyses) == 0 {
			return nil, fmt.Errorf("analysis %s not found", analysisID)
		}
		analysis := desc.NetworkInsightsAnalyses[0]
		switch analysis.Status {
		case types.AnalysisStatusSucceeded:
			reachable := analysis.NetworkPathFound
			return &AnalysisResponse{
				Reachable:      reachable,
				AnalysisID:     analysisID,
				PathID:         pathID,
				Status:         analysis.Status,
				StatusMessage:  aws.ToString(analysis.StatusMessage),
				WarningMessage: aws.ToString(analysis.WarningMessage),
			}, nil
		case types.AnalysisStatusFailed:
			return &AnalysisResponse{
				Reachable:     nil,
				AnalysisID:    analysisID,
				PathID:        pathID,
				Status:        analysis.Status,
				StatusMessage: aws.ToString(analysis.StatusMessage),
			}, fmt.Errorf("analysis failed: %s", aws.ToString(analysis.StatusMessage))
		case types.AnalysisStatusRunning:
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(2 * time.Second):
			}
		default:
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(2 * time.Second):
			}
		}
	}
	return nil, fmt.Errorf("analysis %s timed out", analysisID)
}
