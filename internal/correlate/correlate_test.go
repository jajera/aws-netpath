package correlate

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/jajera/aws-netpath/internal/model"
	"github.com/jajera/aws-netpath/internal/symptom"
)

// --- Fixtures ---------------------------------------------------------------

// evidence is a plausible Citation per Layer. Every emittable pass or block
// needs one (cross-cutting 2), so the helpers below attach one automatically
// rather than each case restating it.
var evidence = map[model.Layer]model.Citation{
	model.LayerResolution:    {Kind: "command", Identifier: "snapshot lookup", Detail: "i-0a1b2c3d4e5f60718"},
	model.LayerRoute:         {Kind: "route", Identifier: "rtb-0a1b2c3d4e5f60718", Detail: "10.0.0.0/8 -> tgw-0a1b2c3d4e5f60718"},
	model.LayerNACL:          {Kind: "nacl", Identifier: "acl-0a1b2c3d4e5f60718", Detail: "entry 100"},
	model.LayerSecurityGroup: {Kind: "security_group", Identifier: "sg-0a1b2c3d4e5f60718", Detail: "ingress tcp/22 from 192.0.2.0/24"},
	model.LayerFirewall:      {Kind: "nfw_rule", Identifier: "nfr-allow-east-west sid 3 (priority 6)"},
	model.LayerReturnPath:    {Kind: "route", Identifier: "tgw-rtb-0a1b2c3d4e5f60718", Detail: "no route for 192.0.2.0/24"},
	model.LayerHostFirewall:  {Kind: "command", Identifier: "firewall-cmd --list-rich-rules", Detail: "source address=192.0.2.0/24 port=22 accept"},
	model.LayerHostListener:  {Kind: "command", Identifier: "ss -tlnp", Detail: "no listener on tcp/22"},
}

func cite(l model.Layer) model.Citation {
	if c, ok := evidence[l]; ok {
		return c
	}
	return model.Citation{Kind: "command", Identifier: string(l) + " evidence"}
}

func pass(l model.Layer) model.LayerResult {
	return model.LayerResult{Layer: l, Verdict: model.VerdictPass, Citations: []model.Citation{cite(l)}}
}

func blocked(l model.Layer) model.LayerResult {
	return model.LayerResult{Layer: l, Verdict: model.VerdictBlocked, Citations: []model.Citation{cite(l)}}
}

func abstain(l model.Layer, reason string) model.LayerResult {
	return model.LayerResult{Layer: l, Verdict: model.VerdictAbstain, Reason: reason}
}

// finding builds a result for an arbitrary verdict, tagging its Citation or
// reason so merged evidence can be told apart.
func finding(l model.Layer, v model.LayerVerdict, tag string) model.LayerResult {
	if v == model.VerdictAbstain {
		return abstain(l, "could not evaluate at "+tag)
	}
	c := cite(l)
	c.Detail = tag
	return model.LayerResult{Layer: l, Verdict: v, Citations: []model.Citation{c}}
}

// cloudLayersPass is the "AWS says yes" half of the motivating incident.
func cloudLayersPass() []model.LayerResult {
	return []model.LayerResult{
		pass(model.LayerResolution),
		pass(model.LayerRoute),
		pass(model.LayerNACL),
		pass(model.LayerSecurityGroup),
		pass(model.LayerFirewall),
	}
}

func layerNames(layers []model.Layer) string {
	out := make([]string, 0, len(layers))
	for _, l := range layers {
		out = append(out, string(l))
	}
	return "[" + strings.Join(out, " ") + "]"
}

func primaryName(p *model.Layer) string {
	if p == nil {
		return "<none>"
	}
	return string(*p)
}

// assertFlowOrder is asserted on every correlated verdict: precedence is only
// meaningful if the results are ordered the way the traffic met them.
func assertFlowOrder(t *testing.T, results []model.LayerResult) {
	t.Helper()
	for i := 1; i < len(results); i++ {
		if results[i-1].Layer.FlowIndex() >= results[i].Layer.FlowIndex() {
			t.Fatalf("results not in flow order at %q -> %q", results[i-1].Layer, results[i].Layer)
		}
	}
}

func assertPrimary(t *testing.T, got *model.Layer, want model.Layer) {
	t.Helper()
	if want == "" {
		if got != nil {
			t.Fatalf("PrimaryBlocker = %q, want none", *got)
		}
		return
	}
	if got == nil {
		t.Fatalf("PrimaryBlocker = none, want %q", want)
	}
	if *got != want {
		t.Fatalf("PrimaryBlocker = %q, want %q", *got, want)
	}
}

// --- Verdict precedence (requirement 14.1, cross-cutting 6) -----------------

// TestPrecedenceSelectsEarliestBlockingLayer is the whole of cross-cutting 6:
// the traffic never reached the later blockers, so naming one of them as the
// cause would send the operator to the wrong place.
func TestPrecedenceSelectsEarliestBlockingLayer(t *testing.T) {
	tests := []struct {
		name           string
		in             []model.LayerResult
		wantPrimary    model.Layer
		wantAdditional []model.Layer
	}{
		{
			name:        "a single blocker is the primary blocker",
			in:          []model.LayerResult{pass(model.LayerRoute), blocked(model.LayerSecurityGroup), pass(model.LayerNACL)},
			wantPrimary: model.LayerSecurityGroup,
		},
		{
			name: "the earliest of several blockers is primary and the rest follow",
			in: []model.LayerResult{
				blocked(model.LayerHostFirewall),
				blocked(model.LayerNACL),
				blocked(model.LayerFirewall),
			},
			wantPrimary:    model.LayerNACL,
			wantAdditional: []model.Layer{model.LayerFirewall, model.LayerHostFirewall},
		},
		{
			name: "input order does not change the outcome",
			in: []model.LayerResult{
				blocked(model.LayerFirewall),
				blocked(model.LayerNACL),
				blocked(model.LayerHostFirewall),
			},
			wantPrimary:    model.LayerNACL,
			wantAdditional: []model.Layer{model.LayerFirewall, model.LayerHostFirewall},
		},
		{
			name:           "no blocker is found when every layer passes",
			in:             cloudLayersPass(),
			wantPrimary:    "",
			wantAdditional: nil,
		},
		{
			name: "an abstention is not a blocker",
			in: []model.LayerResult{
				pass(model.LayerRoute),
				abstain(model.LayerHostFirewall, "instance is not SSM managed"),
			},
			wantPrimary:    "",
			wantAdditional: nil,
		},
		{
			name: "an abstention earlier than a block does not displace the blocker",
			in: []model.LayerResult{
				abstain(model.LayerRoute, "transit gateway policy table not modelled"),
				blocked(model.LayerSecurityGroup),
				blocked(model.LayerHostListener),
			},
			wantPrimary:    model.LayerSecurityGroup,
			wantAdditional: []model.Layer{model.LayerHostListener},
		},
		{
			name:           "no results at all names no blocker",
			in:             nil,
			wantPrimary:    "",
			wantAdditional: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Correlate(Input{Results: tc.in})
			if err != nil {
				t.Fatalf("Correlate() = %v, want nil", err)
			}
			assertPrimary(t, got.PrimaryBlocker, tc.wantPrimary)
			if !slices.Equal(got.AdditionalBlocked, tc.wantAdditional) {
				t.Errorf("AdditionalBlocked = %s, want %s",
					layerNames(got.AdditionalBlocked), layerNames(tc.wantAdditional))
			}
			assertFlowOrder(t, got.Results)
			if err := got.Validate(); err != nil {
				t.Errorf("Validate() = %v, want nil", err)
			}
		})
	}
}

// TestPrecedenceHoldsForEveryCombinationOfVerdicts enumerates every assignment
// of the three verdicts across all eight Layers — 3^8 cases — because
// precedence and authority are claims about the whole space, not about the
// handful of shapes a table can list. Each case checks the three invariants
// together: the earliest blocked Layer is primary, every other blocked Layer is
// listed after it in flow order, and the verdict is authoritative exactly when
// no Abstention sits before the primary blocker.
func TestPrecedenceHoldsForEveryCombinationOfVerdicts(t *testing.T) {
	verdicts := []model.LayerVerdict{model.VerdictPass, model.VerdictBlocked, model.VerdictAbstain}
	flow := model.FlowOrder()

	total := 1
	for range flow {
		total *= len(verdicts)
	}

	for combination := range total {
		assigned := make([]model.LayerVerdict, len(flow))
		in := make([]model.LayerResult, 0, len(flow))
		n := combination
		for i, l := range flow {
			v := verdicts[n%len(verdicts)]
			n /= len(verdicts)
			assigned[i] = v
			in = append(in, finding(l, v, "single evaluation"))
		}

		// Feed the findings in reverse flow order so ordering can only come
		// from the correlator, never from the input.
		slices.Reverse(in)

		got, err := Correlate(Input{Results: in})
		if err != nil {
			t.Fatalf("Correlate(%v) = %v, want nil", assigned, err)
		}

		var wantBlocked []model.Layer
		var wantAbstain []int
		for i, v := range assigned {
			switch v {
			case model.VerdictBlocked:
				wantBlocked = append(wantBlocked, flow[i])
			case model.VerdictAbstain:
				wantAbstain = append(wantAbstain, i)
			}
		}

		assertFlowOrder(t, got.Results)
		if len(got.Results) != len(flow) {
			t.Fatalf("%v: got %d results, want %d", assigned, len(got.Results), len(flow))
		}
		for i, r := range got.Results {
			if r.Verdict != assigned[i] {
				t.Fatalf("%v: layer %q reported %q, want %q", assigned, r.Layer, r.Verdict, assigned[i])
			}
		}

		if len(wantBlocked) == 0 {
			assertPrimary(t, got.PrimaryBlocker, "")
		} else {
			assertPrimary(t, got.PrimaryBlocker, wantBlocked[0])
			if !slices.Equal(got.AdditionalBlocked, wantBlocked[1:]) {
				t.Fatalf("%v: AdditionalBlocked = %s, want %s",
					assigned, layerNames(got.AdditionalBlocked), layerNames(wantBlocked[1:]))
			}
		}

		limit := len(flow)
		if len(wantBlocked) > 0 {
			limit = wantBlocked[0].FlowIndex()
		}
		wantAuthoritative := true
		for _, i := range wantAbstain {
			if i < limit {
				wantAuthoritative = false
				break
			}
		}
		if got.Authoritative != wantAuthoritative {
			t.Fatalf("%v: Authoritative = %t, want %t (primary %s)",
				assigned, got.Authoritative, wantAuthoritative, primaryName(got.PrimaryBlocker))
		}

		if err := got.Validate(); err != nil {
			t.Fatalf("%v: Validate() = %v, want nil", assigned, err)
		}
	}
}

// --- Abstention is not a pass (cross-cutting 1) -----------------------------

// TestAbstainIsNeverAggregatedAsPass covers the double-inspection shape: one
// Layer evaluated at two points. A Layer that passed at one point and could not
// be evaluated at the other has not been cleared, and reporting it as a pass is
// the precise failure the Abstention machinery exists to prevent.
func TestAbstainIsNeverAggregatedAsPass(t *testing.T) {
	verdicts := []model.LayerVerdict{model.VerdictPass, model.VerdictBlocked, model.VerdictAbstain}
	rank := map[model.LayerVerdict]int{model.VerdictPass: 0, model.VerdictAbstain: 1, model.VerdictBlocked: 2}

	for _, first := range verdicts {
		for _, second := range verdicts {
			name := fmt.Sprintf("%s then %s", first, second)
			t.Run(name, func(t *testing.T) {
				in := []model.LayerResult{
					finding(model.LayerFirewall, first, "first inspection point"),
					finding(model.LayerFirewall, second, "second inspection point"),
				}
				got, err := Correlate(Input{Results: in})
				if err != nil {
					t.Fatalf("Correlate() = %v, want nil", err)
				}
				if len(got.Results) != 1 {
					t.Fatalf("got %d results, want the two findings collapsed into one", len(got.Results))
				}

				want := first
				if rank[second] > rank[first] {
					want = second
				}
				merged := got.Results[0]
				if merged.Verdict != want {
					t.Fatalf("merged verdict = %q, want %q", merged.Verdict, want)
				}
				if want != model.VerdictPass && merged.Verdict == model.VerdictPass {
					t.Fatal("a non-pass finding was aggregated into a pass")
				}

				// Every Abstention that contributed keeps its reason, so the
				// report can say which inspection point went unevaluated even
				// when the combined verdict is BLOCKED.
				for _, v := range []model.LayerVerdict{first, second} {
					if v != model.VerdictAbstain {
						continue
					}
					if merged.Reason == "" {
						t.Fatal("merged result carries no reason despite an abstaining finding")
					}
				}
				if err := merged.Validate(); err != nil {
					t.Errorf("merged result is not emittable: %v", err)
				}
			})
		}
	}
}

// TestAbstainAtOneInspectionPointKeepsBothReasons pins the reporting detail:
// two distinct abstention reasons for one Layer are both kept, and identical
// evidence from two points is cited once.
func TestAbstainAtOneInspectionPointKeepsBothReasons(t *testing.T) {
	in := []model.LayerResult{
		abstain(model.LayerFirewall, "domain allowlist rule group"),
		abstain(model.LayerFirewall, "raw suricata rule group"),
	}
	got, err := Correlate(Input{Results: in})
	if err != nil {
		t.Fatalf("Correlate() = %v, want nil", err)
	}
	merged := got.Results[0]
	for _, want := range []string{"domain allowlist rule group", "raw suricata rule group"} {
		if !strings.Contains(merged.Reason, want) {
			t.Errorf("reason %q does not mention %q", merged.Reason, want)
		}
	}

	duplicate := []model.LayerResult{pass(model.LayerFirewall), pass(model.LayerFirewall)}
	got, err = Correlate(Input{Results: duplicate})
	if err != nil {
		t.Fatalf("Correlate() = %v, want nil", err)
	}
	if n := len(got.Results[0].Citations); n != 1 {
		t.Errorf("identical evidence cited %d times, want once", n)
	}
}

// --- Authority rests on the abstentions that matter (requirement 14.6) ------

func TestAbstentionAffectingTheConclusionIsNeverAuthoritative(t *testing.T) {
	tests := []struct {
		name              string
		in                []model.LayerResult
		wantPrimary       model.Layer
		wantAuthoritative bool
		wantAffecting     []model.Layer
	}{
		{
			name:              "every layer evaluated and permitted is authoritative",
			in:                cloudLayersPass(),
			wantPrimary:       "",
			wantAuthoritative: true,
		},
		{
			name: "an unverified layer with no blocker found cannot assert permitted",
			in: append(cloudLayersPass(),
				abstain(model.LayerHostFirewall, "instance is not SSM managed")),
			wantPrimary:       "",
			wantAuthoritative: false,
			wantAffecting:     []model.Layer{model.LayerHostFirewall},
		},
		{
			name: "an abstention earlier than the primary blocker might have blocked first",
			in: []model.LayerResult{
				pass(model.LayerRoute),
				abstain(model.LayerFirewall, "DEFAULT_ACTION_ORDER policy"),
				blocked(model.LayerHostFirewall),
			},
			wantPrimary:       model.LayerHostFirewall,
			wantAuthoritative: false,
			wantAffecting:     []model.Layer{model.LayerFirewall},
		},
		{
			name: "an abstention after the primary blocker changes nothing",
			in: []model.LayerResult{
				pass(model.LayerRoute),
				blocked(model.LayerSecurityGroup),
				abstain(model.LayerHostFirewall, "instance is not SSM managed"),
			},
			wantPrimary:       model.LayerSecurityGroup,
			wantAuthoritative: true,
		},
		{
			name: "the blocking layer abstaining elsewhere still blocks authoritatively",
			in: []model.LayerResult{
				pass(model.LayerRoute),
				blocked(model.LayerFirewall),
				abstain(model.LayerFirewall, "raw suricata rule group"),
			},
			wantPrimary:       model.LayerFirewall,
			wantAuthoritative: true,
		},
		{
			name: "a layer that passed once and abstained once is not cleared",
			in: []model.LayerResult{
				pass(model.LayerFirewall),
				abstain(model.LayerFirewall, "domain allowlist rule group"),
			},
			wantPrimary:       "",
			wantAuthoritative: false,
			wantAffecting:     []model.Layer{model.LayerFirewall},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Correlate(Input{Results: tc.in})
			if err != nil {
				t.Fatalf("Correlate() = %v, want nil", err)
			}
			assertPrimary(t, got.PrimaryBlocker, tc.wantPrimary)
			if got.Authoritative != tc.wantAuthoritative {
				t.Errorf("Authoritative = %t, want %t", got.Authoritative, tc.wantAuthoritative)
			}

			var affecting []model.Layer
			for _, r := range got.ConclusionAffectingAbstentions() {
				affecting = append(affecting, r.Layer)
			}
			if !slices.Equal(affecting, tc.wantAffecting) {
				t.Errorf("ConclusionAffectingAbstentions = %s, want %s",
					layerNames(affecting), layerNames(tc.wantAffecting))
			}
			for _, r := range got.Abstentions() {
				if r.Reason == "" {
					t.Errorf("abstention for layer %q carries no reason", r.Layer)
				}
			}
		})
	}
}

// --- The motivating incident (requirements 8.4, 14.1) -----------------------

// TestCloudLayersPassWithHostFirewallBlockedNamesHostFirewall is the incident
// the project exists for: AWS reports the path clear, and the service is still
// unreachable because the host allowlist omits the source.
func TestCloudLayersPassWithHostFirewallBlockedNamesHostFirewall(t *testing.T) {
	allowlist := model.Citation{
		Kind:       "command",
		Identifier: "firewall-cmd --list-rich-rules",
		Detail:     "rule family=ipv4 source address=192.0.2.0/24 port port=22 protocol=tcp accept",
	}
	in := append(cloudLayersPass(), model.LayerResult{
		Layer:     model.LayerHostFirewall,
		Verdict:   model.VerdictBlocked,
		Citations: []model.Citation{allowlist},
	})

	got, err := Correlate(Input{Symptom: symptom.NoRouteToHost, Results: in})
	if err != nil {
		t.Fatalf("Correlate() = %v, want nil", err)
	}

	assertPrimary(t, got.PrimaryBlocker, model.LayerHostFirewall)
	if len(got.AdditionalBlocked) != 0 {
		t.Errorf("AdditionalBlocked = %s, want none", layerNames(got.AdditionalBlocked))
	}
	if !got.Authoritative {
		t.Error("Authoritative = false, want true: every layer was evaluated")
	}
	// The verdict is only actionable with the allowlist quoted back.
	host, ok := got.Result(model.LayerHostFirewall)
	if !ok {
		t.Fatal("no result recorded for host_firewall")
	}
	if !slices.Contains(host.Citations, allowlist) {
		t.Errorf("host_firewall citations = %+v, want the allowlist entry", host.Citations)
	}
	// The cloud Layers are still reported as cleared rather than dropped: an
	// operator needs to see that AWS was checked and found permissive.
	for _, r := range cloudLayersPass() {
		cleared, ok := got.Result(r.Layer)
		if !ok {
			t.Errorf("no result recorded for cleared layer %q", r.Layer)
			continue
		}
		if cleared.Verdict != model.VerdictPass {
			t.Errorf("layer %q = %q, want pass", r.Layer, cleared.Verdict)
		}
	}
	// A host firewall can drop or reject depending on configuration, so
	// no-route-to-host and a HOST_FIREWALL block agree.
	if len(got.Contradictions) != 0 {
		t.Errorf("Contradictions = %v, want none", got.Contradictions)
	}
}

// --- Blocked return path under a permitted forward path (requirement 7.4) ---

func TestBlockedReturnPathIsPrimaryWhenForwardIsPermitted(t *testing.T) {
	in := append(cloudLayersPass(),
		blocked(model.LayerReturnPath),
		pass(model.LayerHostFirewall),
		pass(model.LayerHostListener),
	)

	got, err := Correlate(Input{Symptom: symptom.ConnectThenStall, Results: in})
	if err != nil {
		t.Fatalf("Correlate() = %v, want nil", err)
	}

	assertPrimary(t, got.PrimaryBlocker, model.LayerReturnPath)
	if len(got.AdditionalBlocked) != 0 {
		t.Errorf("AdditionalBlocked = %s, want none", layerNames(got.AdditionalBlocked))
	}
	if !got.Authoritative {
		t.Error("Authoritative = false, want true")
	}
	// A return path that blocks is exactly how a connect-then-stall arises, so
	// the finding and the symptom agree.
	if len(got.Contradictions) != 0 {
		t.Errorf("Contradictions = %v, want none", got.Contradictions)
	}

	// A blocked forward Layer still takes precedence over the return path,
	// because the traffic never got far enough to come back.
	withForwardBlock := append(in, blocked(model.LayerSecurityGroup))
	got, err = Correlate(Input{Symptom: symptom.ConnectThenStall, Results: withForwardBlock})
	if err != nil {
		t.Fatalf("Correlate() = %v, want nil", err)
	}
	assertPrimary(t, got.PrimaryBlocker, model.LayerSecurityGroup)
	if !slices.Equal(got.AdditionalBlocked, []model.Layer{model.LayerReturnPath}) {
		t.Errorf("AdditionalBlocked = %s, want [return_path]", layerNames(got.AdditionalBlocked))
	}
}

// --- Contradictions are recorded, not resolved (requirement 9.4) ------------

func TestContradictionsAreRecordedWithoutChangingTheVerdict(t *testing.T) {
	tests := []struct {
		name              string
		symptom           symptom.Symptom
		in                []model.LayerResult
		wantPrimary       model.Layer
		wantAuthoritative bool
		wantContradiction string
	}{
		{
			name:              "a symptom with every layer permitted is itself diagnostic",
			symptom:           symptom.ConnectionRefused,
			in:                cloudLayersPass(),
			wantPrimary:       "",
			wantAuthoritative: true,
			wantContradiction: "every evaluated layer permitted the traffic",
		},
		{
			name:    "an unverified layer explains the symptom, so no contradiction is claimed",
			symptom: symptom.ConnectionRefused,
			in: append(cloudLayersPass(),
				abstain(model.LayerHostListener, "instance is not SSM managed")),
			wantPrimary:       "",
			wantAuthoritative: false,
			wantContradiction: "",
		},
		{
			name:              "a RST observed while the blocker discards silently",
			symptom:           symptom.ConnectionRefused,
			in:                []model.LayerResult{pass(model.LayerRoute), blocked(model.LayerSecurityGroup)},
			wantPrimary:       model.LayerSecurityGroup,
			wantAuthoritative: true,
			wantContradiction: "discards silently",
		},
		{
			name:              "silence observed while the blocker replies",
			symptom:           symptom.Timeout,
			in:                []model.LayerResult{pass(model.LayerRoute), blocked(model.LayerHostListener)},
			wantPrimary:       model.LayerHostListener,
			wantAuthoritative: true,
			wantContradiction: "replies",
		},
		{
			name:              "an established connection contradicts a handshake-blocking layer",
			symptom:           symptom.ConnectThenStall,
			in:                []model.LayerResult{pass(model.LayerRoute), blocked(model.LayerNACL)},
			wantPrimary:       model.LayerNACL,
			wantAuthoritative: true,
			wantContradiction: "connection was established",
		},
		{
			name:              "a symptom the blocker already implicates is no contradiction",
			symptom:           symptom.ConnectionRefused,
			in:                []model.LayerResult{pass(model.LayerRoute), blocked(model.LayerHostListener)},
			wantPrimary:       model.LayerHostListener,
			wantAuthoritative: true,
			wantContradiction: "",
		},
		{
			name:              "a silent discard matching a silent blocker is no contradiction",
			symptom:           symptom.Timeout,
			in:                []model.LayerResult{pass(model.LayerRoute), blocked(model.LayerSecurityGroup)},
			wantPrimary:       model.LayerSecurityGroup,
			wantAuthoritative: true,
			wantContradiction: "",
		},
		{
			name:              "a mixed observation is consistent with either behaviour",
			symptom:           symptom.ICMPOKTCPFails,
			in:                []model.LayerResult{pass(model.LayerRoute), blocked(model.LayerFirewall)},
			wantPrimary:       model.LayerFirewall,
			wantAuthoritative: true,
			wantContradiction: "",
		},
		{
			name:              "with no symptom there is nothing to contradict",
			symptom:           symptom.None,
			in:                cloudLayersPass(),
			wantPrimary:       "",
			wantAuthoritative: true,
			wantContradiction: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Correlate(Input{Symptom: tc.symptom, Results: tc.in})
			if err != nil {
				t.Fatalf("Correlate() = %v, want nil", err)
			}

			if tc.wantContradiction == "" {
				if len(got.Contradictions) != 0 {
					t.Errorf("Contradictions = %v, want none", got.Contradictions)
				}
			} else {
				var found bool
				for _, c := range got.Contradictions {
					if strings.Contains(c, tc.wantContradiction) {
						found = true
					}
				}
				if !found {
					t.Errorf("Contradictions = %v, want one mentioning %q", got.Contradictions, tc.wantContradiction)
				}
			}

			// The contradiction is recorded and nothing else moves: the
			// primary blocker, the per-Layer verdicts, and the authority are
			// what they would be with no Symptom supplied.
			assertPrimary(t, got.PrimaryBlocker, tc.wantPrimary)
			if got.Authoritative != tc.wantAuthoritative {
				t.Errorf("Authoritative = %t, want %t", got.Authoritative, tc.wantAuthoritative)
			}

			bare, err := Correlate(Input{Results: tc.in})
			if err != nil {
				t.Fatalf("Correlate() without a symptom = %v, want nil", err)
			}
			if len(bare.Contradictions) != 0 {
				t.Errorf("Contradictions = %v with no symptom, want none", bare.Contradictions)
			}
			if primaryName(got.PrimaryBlocker) != primaryName(bare.PrimaryBlocker) {
				t.Errorf("symptom changed the primary blocker: %s vs %s",
					primaryName(got.PrimaryBlocker), primaryName(bare.PrimaryBlocker))
			}
			if !slices.Equal(got.AdditionalBlocked, bare.AdditionalBlocked) {
				t.Errorf("symptom changed the additional blockers: %s vs %s",
					layerNames(got.AdditionalBlocked), layerNames(bare.AdditionalBlocked))
			}
			if got.Authoritative != bare.Authoritative {
				t.Errorf("symptom changed authority: %t vs %t", got.Authoritative, bare.Authoritative)
			}
			if !slices.EqualFunc(got.Results, bare.Results, func(a, b model.LayerResult) bool {
				return a.Layer == b.Layer && a.Verdict == b.Verdict
			}) {
				t.Error("symptom changed the layer results")
			}
		})
	}
}

// --- Unusable input is refused, not laundered (cross-cutting 1, 2) ----------

func TestCorrelateRejectsFindingsThatMayNotBeEmitted(t *testing.T) {
	tests := []struct {
		name    string
		in      Input
		wantMsg string
	}{
		{
			name:    "an abstention with no reason",
			in:      Input{Results: []model.LayerResult{{Layer: model.LayerHostFirewall, Verdict: model.VerdictAbstain}}},
			wantMsg: "abstain requires a reason",
		},
		{
			name:    "a pass with no citation",
			in:      Input{Results: []model.LayerResult{{Layer: model.LayerRoute, Verdict: model.VerdictPass}}},
			wantMsg: "requires at least one citation",
		},
		{
			name:    "a block with no citation",
			in:      Input{Results: []model.LayerResult{{Layer: model.LayerNACL, Verdict: model.VerdictBlocked}}},
			wantMsg: "requires at least one citation",
		},
		{
			name:    "an unknown layer",
			in:      Input{Results: []model.LayerResult{{Layer: model.Layer("proxy"), Verdict: model.VerdictPass, Citations: []model.Citation{cite(model.LayerRoute)}}}},
			wantMsg: "unknown layer",
		},
		{
			name:    "an unknown verdict",
			in:      Input{Results: []model.LayerResult{{Layer: model.LayerRoute, Verdict: model.LayerVerdict("maybe"), Citations: []model.Citation{cite(model.LayerRoute)}}}},
			wantMsg: "unknown verdict",
		},
		{
			name:    "an unrecognised symptom",
			in:      Input{Symptom: symptom.Symptom("connection-reset"), Results: cloudLayersPass()},
			wantMsg: "unknown symptom",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Correlate(tc.in)
			if err == nil {
				t.Fatalf("Correlate() = %+v, want an error", got)
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Errorf("error %v does not mention %q", err, tc.wantMsg)
			}
		})
	}
}

// A Verdict handed back must not alias the caller's findings, or a caller
// holding on to its input would see the correlated report change underneath it.
func TestCorrelateDoesNotAliasInputCitations(t *testing.T) {
	in := []model.LayerResult{pass(model.LayerRoute)}
	got, err := Correlate(Input{Results: in})
	if err != nil {
		t.Fatalf("Correlate() = %v, want nil", err)
	}
	in[0].Citations[0] = model.Citation{Kind: "route", Identifier: "mutated"}
	if got.Results[0].Citations[0].Identifier == "mutated" {
		t.Error("verdict citations alias the input findings")
	}
}
