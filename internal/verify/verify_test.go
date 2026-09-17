package verify

import (
	"context"
	"net/netip"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/jajera/aws-netpath/internal/flow"
	"github.com/jajera/aws-netpath/internal/model"
	"github.com/jajera/aws-netpath/internal/query"
	"github.com/jajera/aws-netpath/internal/snapshot"
)

func TestCompareVerdict(t *testing.T) {
	trueVal := true
	falseVal := false

	tests := []struct {
		name      string
		model     query.Verdict
		aws       *bool
		wantAgree Agreement
	}{
		{"both permit", query.VerdictPermitted, &trueVal, AgreementMatch},
		{"both block", query.VerdictBlocked, &falseVal, AgreementMatch},
		{"model permits aws blocks", query.VerdictPermitted, &falseVal, AgreementMismatch},
		{"model blocks aws permits", query.VerdictBlocked, &trueVal, AgreementMismatch},
		{"aws nil", query.VerdictPermitted, nil, AgreementInconclusive},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := CompareVerdict(tt.model, tt.aws)
			if got != tt.wantAgree {
				t.Fatalf("CompareVerdict() = %s, want %s", got, tt.wantAgree)
			}
		})
	}
}

func TestRunSkipsCrossRegionAWS(t *testing.T) {
	snap := loadFixture(t, "../query/testdata/default-action-pass.json")
	res, err := Run(t.Context(), Options{
		Snapshot: snap,
		SrcIP:    mustAddr(t, "10.30.32.10"),
		DstIP:    mustAddr(t, "10.30.192.10"),
		Proto:    mustProto(t, "tcp"),
		Port:     443,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.AWS == nil || !res.AWS.Skipped {
		t.Fatalf("expected AWS skipped for cross-region, got %+v", res.AWS)
	}
	if res.Agreement != AgreementInconclusive {
		t.Fatalf("agreement = %s, want INCONCLUSIVE when AWS skipped", res.Agreement)
	}
	if res.Model.Verdict != query.VerdictPermitted {
		t.Fatalf("model verdict = %s, want PERMITTED", res.Model.Verdict)
	}
}

func TestRunRejectsICMP(t *testing.T) {
	snap := loadFixture(t, "../query/testdata/default-action-pass.json")
	_, err := Run(t.Context(), Options{
		Snapshot: snap,
		SrcIP:    mustAddr(t, "10.30.32.10"),
		DstIP:    mustAddr(t, "10.30.192.10"),
		Proto:    mustProto(t, "icmp"),
	})
	if err == nil {
		t.Fatal("expected error for icmp")
	}
}

type mockAnalyzer struct {
	reachable bool
}

func (m *mockAnalyzer) Analyze(_ context.Context, _ AnalysisRequest) (*AnalysisResponse, error) {
	v := m.reachable
	return &AnalysisResponse{Reachable: &v}, nil
}

func TestRunComparesWithMockAWS(t *testing.T) {
	snap := loadFixture(t, "../query/testdata/double-inspection.json")

	res, err := Run(t.Context(), Options{
		Snapshot: snap,
		SrcIP:    mustAddr(t, "10.30.32.10"),
		DstIP:    mustAddr(t, "10.29.17.10"),
		Proto:    mustProto(t, "tcp"),
		Port:     8080,
		Analyzer: &mockAnalyzer{reachable: false},
		Region:   "us-east-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.AWS == nil || res.AWS.Skipped {
		t.Fatalf("expected AWS run, got %+v", res.AWS)
	}
	if res.AWS.SourceResource == "" || res.AWS.DestinationResource == "" {
		t.Fatalf("expected TGW attachment resources, got src=%q dst=%q", res.AWS.SourceResource, res.AWS.DestinationResource)
	}
}

func TestRunSkipsIntraVPCWithoutENI(t *testing.T) {
	snap := loadFixture(t, "../query/testdata/default-action-pass.json")
	sub := snap.Subnets["subnet-prod-east-a"]
	dup := *sub
	dup.ID = "subnet-prod-east-b"
	dup.CIDR = netip.MustParsePrefix("10.30.33.0/24")
	snap.Subnets[dup.ID] = &dup

	res, err := Run(t.Context(), Options{
		Snapshot: snap,
		SrcIP:    mustAddr(t, "10.30.32.10"),
		DstIP:    mustAddr(t, "10.30.33.10"),
		Proto:    mustProto(t, "tcp"),
		Port:     443,
		Analyzer: &mockAnalyzer{reachable: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.AWS == nil || !res.AWS.Skipped {
		t.Fatal("expected AWS skipped for intra-VPC without ENI")
	}
	if res.Agreement != AgreementInconclusive {
		t.Fatalf("agreement = %s, want INCONCLUSIVE", res.Agreement)
	}
}

func loadFixture(t *testing.T, rel string) *model.Snapshot {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	path := filepath.Join(filepath.Dir(file), rel)
	snap, err := snapshot.Load(path)
	if err != nil {
		t.Fatalf("load fixture: %v", err)
	}
	return snap
}

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func mustProto(t *testing.T, s string) flow.Protocol {
	t.Helper()
	p, err := flow.ParseProtocol(s)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
