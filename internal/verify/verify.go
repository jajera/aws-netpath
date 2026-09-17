package verify

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/jajera/aws-netpath/internal/flow"
	"github.com/jajera/aws-netpath/internal/model"
	"github.com/jajera/aws-netpath/internal/query"
)

// Options configures a verify run.
type Options struct {
	Snapshot *model.Snapshot
	SrcIP    netip.Addr
	DstIP    netip.Addr
	Proto    flow.Protocol
	Port     int

	// AWS credentials scope for Reachability Analyzer (single region).
	Profile    string
	Region     string
	AssumeRole string
	Timeout    time.Duration

	// Analyzer runs the AWS side. When nil and AWS is required, Run returns an error.
	Analyzer Analyzer
	// SkipAWS evaluates the model only (for tests or when cross-region).
	SkipAWS bool
}

// AWSOutcome holds Reachability Analyzer results when run.
type AWSOutcome struct {
	Region              string `json:"region"`
	SourceVPC           string `json:"source_vpc,omitempty"`
	DestinationVPC      string `json:"destination_vpc,omitempty"`
	SourceResource      string `json:"source_resource,omitempty"`
	DestinationResource string `json:"destination_resource,omitempty"`
	Reachable           *bool  `json:"reachable,omitempty"`
	AnalysisID          string `json:"analysis_id,omitempty"`
	Status              string `json:"status,omitempty"`
	StatusMessage       string `json:"status_message,omitempty"`
	WarningMessage      string `json:"warning_message,omitempty"`
	Skipped             bool   `json:"skipped,omitempty"`
	SkipReason          string `json:"skip_reason,omitempty"`
}

// Result compares offline model vs AWS Reachability Analyzer.
type Result struct {
	Flow      flow.Slice    `json:"flow"`
	Model     *query.Result `json:"model"`
	AWS       *AWSOutcome   `json:"aws,omitempty"`
	Agreement Agreement     `json:"agreement"`
	Detail    string        `json:"detail"`
	// Caveats are what this cross-check does not cover: the cost it incurs, the
	// direction the analyser did not evaluate, the region boundary no single run
	// crosses. Requirements 13.4 and 13.5.
	Caveats []Caveat `json:"caveats,omitempty"`
	Notes   []string `json:"notes,omitempty"`
}

// Run evaluates the model, optionally cross-checks with AWS, and states what the
// cross-check does not cover.
//
// The caveats are attached here rather than inside the comparison because every
// branch of it earns them: an analysis that ran, one skipped for a region
// boundary, and one skipped by request all leave the same things unsaid, and a
// caveat appended per branch is a caveat one new branch will forget.
func Run(ctx context.Context, opts Options) (*Result, error) {
	res, err := run(ctx, opts)
	if err != nil || res == nil {
		return res, err
	}
	res.Caveats = caveats(opts, res)
	return res, nil
}

func run(ctx context.Context, opts Options) (*Result, error) {
	if opts.Snapshot == nil {
		return nil, fmt.Errorf("snapshot is required")
	}
	if !opts.SrcIP.IsValid() || !opts.DstIP.IsValid() {
		return nil, fmt.Errorf("source and destination IP addresses are required")
	}
	if opts.Proto == flow.ProtoICMP {
		return nil, fmt.Errorf("reachability analyzer supports tcp and udp only (not icmp)")
	}
	if opts.Proto.HasPorts() && (opts.Port < 1 || opts.Port > 65535) {
		return nil, fmt.Errorf("port is required for %s", opts.Proto)
	}

	slice := buildSlice(opts)
	modelRes, err := query.Run(query.Options{
		Snapshot: opts.Snapshot,
		SrcIP:    opts.SrcIP,
		DstIP:    opts.DstIP,
		Proto:    opts.Proto,
		Port:     opts.Port,
	})
	if err != nil {
		return nil, err
	}

	res := &Result{
		Flow:  slice,
		Model: modelRes,
		Notes: append([]string(nil), modelRes.Notes...),
	}

	if opts.SkipAWS {
		res.AWS = &AWSOutcome{Skipped: true, SkipReason: "skipped by request"}
		res.Agreement, res.Detail = CompareVerdict(modelRes.Verdict, nil)
		res.Notes = append(res.Notes, "AWS comparison skipped")
		return res, nil
	}

	srcVPC, _, srcOK := SubnetForAddr(opts.Snapshot, opts.SrcIP)
	dstVPC, _, dstOK := SubnetForAddr(opts.Snapshot, opts.DstIP)
	span := spanFor(opts)
	region := span.Scope
	if region == "" {
		res.AWS = &AWSOutcome{Skipped: true, SkipReason: "could not determine AWS region for source"}
		res.Agreement, res.Detail = CompareVerdict(modelRes.Verdict, nil)
		res.Notes = append(res.Notes, "AWS comparison skipped: source IP not in snapshot subnets")
		return res, nil
	}

	// No analysis is attempted once more than one region is in play, and the
	// boundary is checked before the endpoints are: an analysis scoped away from
	// the path is billable, answers about a region the flow may not touch, and
	// reports that answer under the flow that was asked about. Refusing to run it
	// is the only way the result cannot be read as covering the path. Requirement
	// 13.5.
	if span.Crosses() {
		res.AWS = &AWSOutcome{
			Region:         span.Scope,
			SourceVPC:      srcVPC,
			DestinationVPC: dstVPC,
			Skipped:        true,
			SkipReason:     span.skipReason(),
		}
		res.Agreement, _ = CompareVerdict(modelRes.Verdict, nil)
		res.Detail = span.detail()
		res.Notes = append(res.Notes, "AWS comparison skipped: no single Reachability Analyzer run covers this cross-region path")
		return res, nil
	}

	if !srcOK || !dstOK {
		res.AWS = &AWSOutcome{
			Region:     region,
			Skipped:    true,
			SkipReason: "source or destination IP not in snapshot subnets (AWS needs VPC scope)",
		}
		res.Agreement, res.Detail = CompareVerdict(modelRes.Verdict, nil)
		res.Notes = append(res.Notes, "AWS comparison skipped: endpoint outside collected subnets")
		return res, nil
	}

	if opts.Analyzer == nil {
		return nil, fmt.Errorf("AWS analyzer is required (set Profile and Region)")
	}

	endpoints := ResolveRAEndpoints(opts.Snapshot, opts.SrcIP, opts.DstIP)
	if endpoints.SkipReason != "" {
		res.AWS = &AWSOutcome{
			Region:         region,
			SourceVPC:      srcVPC,
			DestinationVPC: dstVPC,
			Skipped:        true,
			SkipReason:     endpoints.SkipReason,
		}
		res.Agreement, res.Detail = CompareVerdict(modelRes.Verdict, nil)
		res.Notes = append(res.Notes, "AWS comparison skipped: "+endpoints.SkipReason)
		return res, nil
	}

	proto, err := ec2Protocol(opts.Proto)
	if err != nil {
		return nil, err
	}

	awsCtx := ctx
	if opts.Timeout > 0 {
		var cancel context.CancelFunc
		awsCtx, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}

	awsRes, err := opts.Analyzer.Analyze(awsCtx, AnalysisRequest{
		Source:          endpoints.Source,
		Destination:     endpoints.Destination,
		SourceIP:        opts.SrcIP.String(),
		DestinationIP:   opts.DstIP.String(),
		Protocol:        proto,
		DestinationPort: int32(opts.Port),
	})
	if err != nil {
		res.AWS = &AWSOutcome{
			Region:              region,
			SourceVPC:           srcVPC,
			DestinationVPC:      dstVPC,
			SourceResource:      endpoints.Source,
			DestinationResource: endpoints.Destination,
			Status:              string(types.AnalysisStatusFailed),
			StatusMessage:       err.Error(),
			Skipped:             true,
			SkipReason:          "AWS analysis failed",
		}
		res.Agreement = AgreementInconclusive
		res.Detail = err.Error()
		return res, nil
	}

	res.AWS = &AWSOutcome{
		Region:              region,
		SourceVPC:           srcVPC,
		DestinationVPC:      dstVPC,
		SourceResource:      endpoints.Source,
		DestinationResource: endpoints.Destination,
		Reachable:           awsRes.Reachable,
		AnalysisID:          awsRes.AnalysisID,
		Status:              string(awsRes.Status),
		StatusMessage:       awsRes.StatusMessage,
		WarningMessage:      awsRes.WarningMessage,
	}
	res.Agreement, res.Detail = CompareVerdict(modelRes.Verdict, awsRes.Reachable)
	if awsRes.WarningMessage != "" {
		res.Notes = append(res.Notes, "AWS warning: "+awsRes.WarningMessage)
	}
	res.Notes = append(res.Notes, "Reachability Analyzer does not model Network Firewall domain lists, Suricata rules, or cross-region paths completely")
	return res, nil
}

func buildSlice(opts Options) flow.Slice {
	src := flow.NewPrefixSet(netip.PrefixFrom(opts.SrcIP, opts.SrcIP.BitLen()))
	dst := flow.NewPrefixSet(netip.PrefixFrom(opts.DstIP, opts.DstIP.BitLen()))
	ports := flow.AllPorts()
	if opts.Proto.HasPorts() && opts.Port > 0 {
		ports = flow.SinglePort(uint16(opts.Port))
	}
	return flow.NewSlice(src, dst, opts.Proto, ports)
}

func ec2Protocol(p flow.Protocol) (types.Protocol, error) {
	switch p {
	case flow.ProtoTCP:
		return types.ProtocolTcp, nil
	case flow.ProtoUDP:
		return types.ProtocolUdp, nil
	default:
		return "", fmt.Errorf("unsupported protocol for AWS: %s", p)
	}
}
