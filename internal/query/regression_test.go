package query

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/jajera/aws-netpath/internal/flow"
	"github.com/jajera/aws-netpath/internal/snapshot"
)

// regressionCase is one offline query scenario checked into testdata/.
type regressionCase struct {
	Name                string   `json:"name"`
	Snapshot            string   `json:"snapshot"`
	From                string   `json:"from"`
	To                  string   `json:"to"`
	Proto               string   `json:"proto"`
	Port                int      `json:"port,omitempty"`
	SkipFirewall        bool     `json:"skip_firewall,omitempty"`
	WantVerdict         string   `json:"want_verdict"`
	WantBlockedLayer    string   `json:"want_blocked_layer,omitempty"`
	WantBlockedResource string   `json:"want_blocked_resource,omitempty"`
	WantHopLayers       []string `json:"want_hop_layers,omitempty"`
}

// TestRegression runs fixture snapshots and expected reachability outcomes.
// Run after every change:
//
//	go test ./internal/query/ -run Regression -v
func TestRegression(t *testing.T) {
	cases := loadRegressionCases(t)

	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			snapPath := filepath.Join(testdataDir(t), tc.Snapshot)
			snap, err := snapshot.Load(snapPath)
			if err != nil {
				t.Fatalf("load snapshot: %v", err)
			}

			proto, err := flow.ParseProtocol(tc.Proto)
			if err != nil {
				t.Fatalf("parse proto: %v", err)
			}

			res, err := Run(Options{
				Snapshot:     snap,
				SrcIP:        netip.MustParseAddr(tc.From),
				DstIP:        netip.MustParseAddr(tc.To),
				Proto:        proto,
				Port:         tc.Port,
				SkipFirewall: tc.SkipFirewall,
			})
			if err != nil {
				t.Fatalf("query: %v", err)
			}

			if string(res.Verdict) != tc.WantVerdict {
				t.Fatalf("verdict = %s, want %s\nhops: %s", res.Verdict, tc.WantVerdict, formatHops(res.Hops))
			}

			if tc.WantBlockedLayer != "" || tc.WantBlockedResource != "" {
				if res.BlockedAt == nil {
					t.Fatalf("blocked_at is nil, want layer=%q resource=%q", tc.WantBlockedLayer, tc.WantBlockedResource)
				}
				if tc.WantBlockedLayer != "" && res.BlockedAt.Layer != tc.WantBlockedLayer {
					t.Fatalf("blocked_at.layer = %q, want %q", res.BlockedAt.Layer, tc.WantBlockedLayer)
				}
				if tc.WantBlockedResource != "" && res.BlockedAt.Resource != tc.WantBlockedResource {
					t.Fatalf("blocked_at.resource = %q, want %q", res.BlockedAt.Resource, tc.WantBlockedResource)
				}
			}

			if len(tc.WantHopLayers) > 0 {
				layers := hopLayers(res.Hops)
				if !containsSubsequence(layers, tc.WantHopLayers) {
					t.Fatalf("hop layers = %v, want subsequence %v\nfull path: %s", layers, tc.WantHopLayers, formatHops(res.Hops))
				}
			}
		})
	}
}

func loadRegressionCases(t *testing.T) []regressionCase {
	t.Helper()
	path := filepath.Join(testdataDir(t), "cases.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read cases: %v", err)
	}
	var cases []regressionCase
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatalf("decode cases: %v", err)
	}
	if len(cases) == 0 {
		t.Fatal("no regression cases loaded")
	}
	return cases
}

func testdataDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(file), "testdata")
}

func hopLayers(hops []Hop) []string {
	out := make([]string, len(hops))
	for i, h := range hops {
		out[i] = h.Layer
	}
	return out
}

func containsSubsequence(have, want []string) bool {
	if len(want) == 0 {
		return true
	}
	i := 0
	for _, h := range have {
		if h == want[i] {
			i++
			if i == len(want) {
				return true
			}
		}
	}
	return false
}

func formatHops(hops []Hop) string {
	var b strings.Builder
	for _, h := range hops {
		status := "ALLOW"
		if !h.Allowed {
			status = "DENY"
		}
		b.WriteString("\n  [")
		b.WriteString(status)
		b.WriteString("] ")
		b.WriteString(h.Layer)
		if h.Resource != "" {
			b.WriteString(" ")
			b.WriteString(h.Resource)
		}
		if h.Detail != "" {
			b.WriteString(": ")
			b.WriteString(h.Detail)
		}
	}
	return b.String()
}

// TestRegressionCasesFile documents how many scenarios are locked in.
func TestRegressionCasesFile(t *testing.T) {
	cases := loadRegressionCases(t)
	names := make([]string, len(cases))
	for i, c := range cases {
		names[i] = c.Name
	}
	if !slices.IsSorted(names) {
		t.Errorf("cases.json names should stay sorted for easy diff review:\n%v", names)
	}
}
