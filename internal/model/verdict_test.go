package model

import "testing"

func cite(id string) []Citation {
	return []Citation{{Kind: "route", Identifier: id}}
}

func layerPtr(l Layer) *Layer { return &l }

func TestLayerResultValidate(t *testing.T) {
	tests := []struct {
		name    string
		result  LayerResult
		wantErr bool
	}{
		{
			name:   "pass with citation is valid",
			result: LayerResult{Layer: LayerRoute, Verdict: VerdictPass, Citations: cite("rtb-1111")},
		},
		{
			name:   "abstain with reason needs no citation",
			result: LayerResult{Layer: LayerHostFirewall, Verdict: VerdictAbstain, Reason: "instance is not SSM managed"},
		},
		{
			name:    "abstain without reason is rejected",
			result:  LayerResult{Layer: LayerHostFirewall, Verdict: VerdictAbstain},
			wantErr: true,
		},
		{
			name:    "blocked without citation is rejected",
			result:  LayerResult{Layer: LayerNACL, Verdict: VerdictBlocked},
			wantErr: true,
		},
		{
			name:    "unknown layer is rejected",
			result:  LayerResult{Layer: Layer("dns"), Verdict: VerdictPass, Citations: cite("rtb-1111")},
			wantErr: true,
		},
		{
			name:    "unknown verdict is rejected",
			result:  LayerResult{Layer: LayerRoute, Verdict: LayerVerdict("maybe"), Citations: cite("rtb-1111")},
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.result.Validate()
			if (err != nil) != tc.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestFlowIndexOrdersLayers(t *testing.T) {
	order := FlowOrder()
	for i := 1; i < len(order); i++ {
		if order[i-1].FlowIndex() >= order[i].FlowIndex() {
			t.Fatalf("flow order not ascending at %s -> %s", order[i-1], order[i])
		}
	}
	if got := Layer("dns").FlowIndex(); got != -1 {
		t.Fatalf("FlowIndex() for unknown layer = %d, want -1", got)
	}
	if !LayerHostFirewall.Host() || LayerFirewall.Host() {
		t.Fatal("Host() must distinguish host layers from cloud layers")
	}
}

func TestFlowOrderIsACopy(t *testing.T) {
	order := FlowOrder()
	order[0] = Layer("mutated")
	if FlowOrder()[0] != LayerResolution {
		t.Fatal("FlowOrder() exposed the package-level slice")
	}
}

func TestComputeAuthoritative(t *testing.T) {
	tests := []struct {
		name    string
		verdict Verdict
		want    bool
	}{
		{
			name: "all layers pass",
			verdict: Verdict{Results: []LayerResult{
				{Layer: LayerRoute, Verdict: VerdictPass, Citations: cite("rtb-1111")},
				{Layer: LayerNACL, Verdict: VerdictPass, Citations: cite("acl-1111")},
			}},
			want: true,
		},
		{
			name: "abstention with no blocker found is not authoritative",
			verdict: Verdict{Results: []LayerResult{
				{Layer: LayerRoute, Verdict: VerdictPass, Citations: cite("rtb-1111")},
				{Layer: LayerHostFirewall, Verdict: VerdictAbstain, Reason: "SSM unavailable"},
			}},
		},
		{
			name: "abstention earlier than the blocker is not authoritative",
			verdict: Verdict{
				PrimaryBlocker: layerPtr(LayerHostFirewall),
				Results: []LayerResult{
					{Layer: LayerFirewall, Verdict: VerdictAbstain, Reason: "rule group missing from snapshot"},
					{Layer: LayerHostFirewall, Verdict: VerdictBlocked, Citations: cite("firewall-cmd")},
				},
			},
		},
		{
			name: "abstention after the blocker does not affect the conclusion",
			verdict: Verdict{
				PrimaryBlocker: layerPtr(LayerNACL),
				Results: []LayerResult{
					{Layer: LayerRoute, Verdict: VerdictPass, Citations: cite("rtb-1111")},
					{Layer: LayerNACL, Verdict: VerdictBlocked, Citations: cite("acl-1111")},
					{Layer: LayerHostListener, Verdict: VerdictAbstain, Reason: "SSM unavailable"},
				},
			},
			want: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.verdict.ComputeAuthoritative()
			if got != tc.want {
				t.Fatalf("ComputeAuthoritative() = %v, want %v", got, tc.want)
			}
			if tc.verdict.Authoritative != got {
				t.Fatal("ComputeAuthoritative() did not set the Authoritative field")
			}
		})
	}
}

// TestAbstentionNeverReadsAsPass exercises every Layer as a lone Abstention on
// an otherwise clean path. No such verdict may be authoritative, and the
// Abstention must always be reported separately from the cleared Layers.
func TestAbstentionNeverReadsAsPass(t *testing.T) {
	for _, abstaining := range FlowOrder() {
		t.Run(string(abstaining), func(t *testing.T) {
			v := Verdict{}
			for _, l := range FlowOrder() {
				r := LayerResult{Layer: l, Verdict: VerdictPass, Citations: cite("id-" + string(l))}
				if l == abstaining {
					r = LayerResult{Layer: l, Verdict: VerdictAbstain, Reason: "could not evaluate"}
				}
				v.Results = append(v.Results, r)
			}
			if err := v.Validate(); err != nil {
				t.Fatalf("Validate() = %v, want nil", err)
			}
			if v.ComputeAuthoritative() {
				t.Fatalf("verdict with an unevaluated %s layer must not be authoritative", abstaining)
			}
			if got := len(v.Abstentions()); got != 1 {
				t.Fatalf("Abstentions() returned %d results, want 1", got)
			}
			if got := len(v.ConclusionAffectingAbstentions()); got != 1 {
				t.Fatalf("ConclusionAffectingAbstentions() returned %d results, want 1", got)
			}
		})
	}
}

func TestVerdictValidate(t *testing.T) {
	tests := []struct {
		name    string
		verdict Verdict
		wantErr bool
	}{
		{
			name: "primary plus additional blocker in flow order",
			verdict: Verdict{
				PrimaryBlocker:    layerPtr(LayerNACL),
				AdditionalBlocked: []Layer{LayerHostFirewall},
				Results: []LayerResult{
					{Layer: LayerNACL, Verdict: VerdictBlocked, Citations: cite("acl-1111")},
					{Layer: LayerHostFirewall, Verdict: VerdictBlocked, Citations: cite("firewall-cmd")},
				},
			},
		},
		{
			name: "blocked layer without a primary blocker is rejected",
			verdict: Verdict{Results: []LayerResult{
				{Layer: LayerNACL, Verdict: VerdictBlocked, Citations: cite("acl-1111")},
			}},
			wantErr: true,
		},
		{
			name: "primary blocker later than another blocker is rejected",
			verdict: Verdict{
				PrimaryBlocker:    layerPtr(LayerHostFirewall),
				AdditionalBlocked: []Layer{LayerNACL},
				Results: []LayerResult{
					{Layer: LayerNACL, Verdict: VerdictBlocked, Citations: cite("acl-1111")},
					{Layer: LayerHostFirewall, Verdict: VerdictBlocked, Citations: cite("firewall-cmd")},
				},
			},
			wantErr: true,
		},
		{
			name: "blocked layer missing from additional blockers is rejected",
			verdict: Verdict{
				PrimaryBlocker: layerPtr(LayerNACL),
				Results: []LayerResult{
					{Layer: LayerNACL, Verdict: VerdictBlocked, Citations: cite("acl-1111")},
					{Layer: LayerHostFirewall, Verdict: VerdictBlocked, Citations: cite("firewall-cmd")},
				},
			},
			wantErr: true,
		},
		{
			name: "primary blocker without a blocked result is rejected",
			verdict: Verdict{
				PrimaryBlocker: layerPtr(LayerFirewall),
				Results: []LayerResult{
					{Layer: LayerNACL, Verdict: VerdictPass, Citations: cite("acl-1111")},
				},
			},
			wantErr: true,
		},
		{
			name: "duplicate layer results are rejected",
			verdict: Verdict{Results: []LayerResult{
				{Layer: LayerRoute, Verdict: VerdictPass, Citations: cite("rtb-1111")},
				{Layer: LayerRoute, Verdict: VerdictPass, Citations: cite("rtb-2222")},
			}},
			wantErr: true,
		},
		{
			name: "additional blockers without a primary blocker are rejected",
			verdict: Verdict{
				AdditionalBlocked: []Layer{LayerNACL},
				Results: []LayerResult{
					{Layer: LayerNACL, Verdict: VerdictPass, Citations: cite("acl-1111")},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid layer result propagates",
			verdict: Verdict{Results: []LayerResult{
				{Layer: LayerHostListener, Verdict: VerdictAbstain},
			}},
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.verdict.Validate()
			if (err != nil) != tc.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestVerdictResultLookup(t *testing.T) {
	v := Verdict{Results: []LayerResult{
		{Layer: LayerRoute, Verdict: VerdictPass, Citations: cite("rtb-1111")},
	}}
	if r, ok := v.Result(LayerRoute); !ok || r.Verdict != VerdictPass {
		t.Fatalf("Result(LayerRoute) = %+v, %v", r, ok)
	}
	if _, ok := v.Result(LayerFirewall); ok {
		t.Fatal("Result(LayerFirewall) found a result that was never recorded")
	}
}
