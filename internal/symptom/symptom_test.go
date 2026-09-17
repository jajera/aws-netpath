package symptom

import (
	"slices"
	"strings"
	"testing"

	"github.com/jajera/aws-netpath/internal/model"
)

// --- The requirement 9.1 table (requirement 9.1) -----------------------------

// TestRequirement91Table pins the mapping literally rather than reading it back
// out of profiles. A test that iterates the implementation's own map agrees with
// whatever the map says, including after someone quietly drops HOST_FIREWALL
// from connection-refused, which is exactly the regression worth catching.
//
// Candidates here are the table's own order. For the two active-rejection rows
// the table already lists host Layers first, so the requirement 9.2 reordering
// is a no-op on this input; that reordering is asserted separately as a property
// so a future table edit that puts a cloud Layer first is still caught.
func TestRequirement91Table(t *testing.T) {
	tests := []struct {
		name        string
		symptom     Symptom
		mechanism   string
		response    Response
		candidates  []model.Layer
		extraChecks []string
	}{
		{
			name:       "connection refused implicates the listener then the host firewall",
			symptom:    ConnectionRefused,
			mechanism:  "RST returned",
			response:   ResponseActive,
			candidates: []model.Layer{model.LayerHostListener, model.LayerHostFirewall},
		},
		{
			name:       "no route to host implicates the host firewall then network firewall",
			symptom:    NoRouteToHost,
			mechanism:  "ICMP administratively prohibited",
			response:   ResponseActive,
			candidates: []model.Layer{model.LayerHostFirewall, model.LayerFirewall},
		},
		{
			name:       "timeout implicates the silent droppers",
			symptom:    Timeout,
			mechanism:  "packet silently discarded",
			response:   ResponseSilent,
			candidates: []model.Layer{model.LayerSecurityGroup, model.LayerNACL, model.LayerRoute},
		},
		{
			name:        "connect then stall implicates the return path and path MTU",
			symptom:     ConnectThenStall,
			mechanism:   "state or MTU failure",
			response:    ResponseEstablished,
			candidates:  []model.Layer{model.LayerReturnPath},
			extraChecks: []string{"path MTU"},
		},
		{
			name:       "icmp ok tcp fails implicates a port filter on either side",
			symptom:    ICMPOKTCPFails,
			mechanism:  "port-specific filter",
			response:   ResponseMixed,
			candidates: []model.Layer{model.LayerSecurityGroup, model.LayerHostFirewall},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Classify(tc.symptom)
			if err != nil {
				t.Fatalf("Classify(%q) = %v, want nil", tc.symptom, err)
			}
			if got.Symptom != tc.symptom {
				t.Errorf("Symptom = %q, want %q", got.Symptom, tc.symptom)
			}
			if got.Mechanism != tc.mechanism {
				t.Errorf("Mechanism = %q, want %q", got.Mechanism, tc.mechanism)
			}
			if got.Response != tc.response {
				t.Errorf("Response = %q, want %q", got.Response, tc.response)
			}
			if !slices.Equal(got.Candidates, tc.candidates) {
				t.Errorf("Candidates = %v, want %v", got.Candidates, tc.candidates)
			}
			if !slices.Equal(got.ExtraChecks, tc.extraChecks) {
				t.Errorf("ExtraChecks = %v, want %v", got.ExtraChecks, tc.extraChecks)
			}
		})
	}

	// The table has five rows and the classifier must not have grown a sixth
	// without the table above growing with it.
	if got, want := len(Symptoms()), len(tests); got != want {
		t.Errorf("Symptoms() = %d symptoms, want %d pinned by the requirement 9.1 table", got, want)
	}
}

// TestEverySymptomYieldsACandidateLayer is the claim that makes classification
// worth calling at all: no recognised Symptom leaves the operator with nothing
// to check first.
func TestEverySymptomYieldsACandidateLayer(t *testing.T) {
	for _, s := range Symptoms() {
		t.Run(s.String(), func(t *testing.T) {
			c, err := Classify(s)
			if err != nil {
				t.Fatalf("Classify(%q) = %v, want nil", s, err)
			}
			if len(c.Candidates) == 0 {
				t.Fatal("no candidate layers")
			}
			for _, l := range c.Candidates {
				if !l.Valid() {
					t.Errorf("candidate %q is not a defined layer", l)
				}
				if !c.Candidate(l) {
					t.Errorf("Candidate(%q) = false for a listed candidate", l)
				}
			}
			if c.Mechanism == "" {
				t.Error("mechanism is empty")
			}
			if c.Response == "" {
				t.Error("response is empty")
			}
		})
	}
}

// --- Silent discard versus active rejection (requirement 9.2) ---------------

// TestActiveRejectionOrdersHostLayersFirst asserts the ordering as a property of
// the Response rather than of any one row, so it holds for rows added later.
func TestActiveRejectionOrdersHostLayersFirst(t *testing.T) {
	var active int
	for _, s := range Symptoms() {
		c := MustClassify(s)
		if !c.Response.Active() {
			continue
		}
		active++
		t.Run(s.String(), func(t *testing.T) {
			seenCloud := false
			for _, l := range c.Candidates {
				if l.Host() && seenCloud {
					t.Fatalf("host layer %q ordered after a cloud layer in %v", l, c.Candidates)
				}
				if !l.Host() {
					seenCloud = true
				}
			}
			if len(c.CheckOrder) == 0 || !c.CheckOrder[0].Host() {
				t.Fatalf("check order must open on a host layer, got %v", c.CheckOrder)
			}
		})
	}
	if active == 0 {
		t.Fatal("no symptom is classified as an active rejection")
	}
}

// TestSilentDiscardChecksCloudLayersFirst is the other half of the distinction.
// A silent discard was produced by a policy that never replied, so a host probe
// is the wrong first move.
func TestSilentDiscardChecksCloudLayersFirst(t *testing.T) {
	var silent int
	for _, s := range Symptoms() {
		c := MustClassify(s)
		if c.Response != ResponseSilent {
			continue
		}
		silent++
		t.Run(s.String(), func(t *testing.T) {
			for _, l := range c.Candidates {
				if l.Host() {
					t.Errorf("silent discard implicates host layer %q", l)
				}
			}
			if len(c.CheckOrder) == 0 || c.CheckOrder[0].Host() {
				t.Fatalf("check order must open on a cloud layer, got %v", c.CheckOrder)
			}
		})
	}
	if silent == 0 {
		t.Fatal("no symptom is classified as a silent discard")
	}
}

// TestSilentDiscardAndActiveRejectionOrdersDiffer is the point of the whole
// module: if the two classes of Symptom produced the same check order then
// supplying a Symptom would buy the operator nothing.
func TestSilentDiscardAndActiveRejectionOrdersDiffer(t *testing.T) {
	var silent, active []Symptom
	for _, s := range Symptoms() {
		switch c := MustClassify(s); {
		case c.Response == ResponseSilent:
			silent = append(silent, s)
		case c.Response.Active():
			active = append(active, s)
		}
	}
	if len(silent) == 0 || len(active) == 0 {
		t.Fatalf("need both classes to compare, got silent=%v active=%v", silent, active)
	}
	for _, s := range silent {
		for _, a := range active {
			t.Run(s.String()+" vs "+a.String(), func(t *testing.T) {
				sc, ac := MustClassify(s), MustClassify(a)
				if slices.Equal(sc.CheckOrder, ac.CheckOrder) {
					t.Fatalf("identical check order %v", sc.CheckOrder)
				}
				if slices.Equal(sc.Candidates, ac.Candidates) {
					t.Fatalf("identical candidates %v", sc.Candidates)
				}
			})
		}
	}
}

// --- No Symptom means flow order (requirement 9.5) --------------------------

func TestNoSymptomEvaluatesInFlowOrder(t *testing.T) {
	c, err := Classify(None)
	if err != nil {
		t.Fatalf("Classify(None) = %v, want nil", err)
	}
	if want := model.FlowOrder(); !slices.Equal(c.CheckOrder, want) {
		t.Errorf("CheckOrder = %v, want flow order %v", c.CheckOrder, want)
	}
	// Nothing is known, so nothing may be preferred: no candidates, no
	// mechanism, no response to report.
	if len(c.Candidates) != 0 {
		t.Errorf("Candidates = %v, want none", c.Candidates)
	}
	if c.Symptom != None || c.Mechanism != "" || c.Response != "" {
		t.Errorf("classification = %+v, want an empty symptom, mechanism, and response", c)
	}
	if len(c.ExtraChecks) != 0 {
		t.Errorf("ExtraChecks = %v, want none", c.ExtraChecks)
	}
}

// --- Check order invariants -------------------------------------------------

// TestCheckOrderIsFlowOrderPermuted holds the two things a check order must be
// for the caller to rely on it: candidates first, and no Layer silently lost. A
// Symptom narrows the search; it does not excuse skipping a Layer.
func TestCheckOrderIsFlowOrderPermuted(t *testing.T) {
	for _, s := range append(Symptoms(), None) {
		name := s.String()
		if s == None {
			name = "no symptom"
		}
		t.Run(name, func(t *testing.T) {
			c := MustClassify(s)
			if got, want := len(c.CheckOrder), len(model.FlowOrder()); got != want {
				t.Fatalf("CheckOrder has %d layers, want %d: %v", got, want, c.CheckOrder)
			}
			seen := map[model.Layer]bool{}
			for _, l := range c.CheckOrder {
				if !l.Valid() {
					t.Errorf("check order contains undefined layer %q", l)
				}
				if seen[l] {
					t.Errorf("layer %q repeated in check order %v", l, c.CheckOrder)
				}
				seen[l] = true
			}
			if !slices.Equal(c.CheckOrder[:len(c.Candidates)], c.Candidates) {
				t.Errorf("check order %v does not open with candidates %v", c.CheckOrder, c.Candidates)
			}
			// Beyond the candidates the remainder stays in flow order, so the
			// fallback search is still the documented one.
			remainder := c.CheckOrder[len(c.Candidates):]
			for i := 1; i < len(remainder); i++ {
				if remainder[i-1].FlowIndex() >= remainder[i].FlowIndex() {
					t.Fatalf("remainder %v not in flow order at %q -> %q", remainder, remainder[i-1], remainder[i])
				}
			}
		})
	}
}

// A Classification handed to a caller must not be a window onto package state.
// The classifier is used per diagnosis and the caller is free to sort its own
// copy of the order.
func TestClassifyReturnsIndependentSlices(t *testing.T) {
	first := MustClassify(ConnectThenStall)
	first.Candidates[0] = model.Layer("mutated")
	first.CheckOrder[0] = model.Layer("mutated")
	first.ExtraChecks[0] = "mutated"

	second := MustClassify(ConnectThenStall)
	if second.Candidates[0] != model.LayerReturnPath {
		t.Errorf("Candidates leaked package state, got %v", second.Candidates)
	}
	if second.CheckOrder[0] != model.LayerReturnPath {
		t.Errorf("CheckOrder leaked package state, got %v", second.CheckOrder)
	}
	if second.ExtraChecks[0] != "path MTU" {
		t.Errorf("ExtraChecks leaked package state, got %v", second.ExtraChecks)
	}

	order := Symptoms()
	order[0] = Symptom("mutated")
	if Symptoms()[0] != ConnectionRefused {
		t.Error("Symptoms() exposed the package-level slice")
	}
}

// --- Parsing operator input -------------------------------------------------

func TestParse(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    Symptom
		wantErr bool
	}{
		{name: "exact value", input: "connection-refused", want: ConnectionRefused},
		{name: "upper case", input: "CONNECTION-REFUSED", want: ConnectionRefused},
		{name: "mixed case", input: "No-Route-To-Host", want: NoRouteToHost},
		{name: "underscores for hyphens", input: "connect_then_stall", want: ConnectThenStall},
		{name: "spaces for hyphens", input: "icmp ok tcp fails", want: ICMPOKTCPFails},
		{name: "surrounding whitespace", input: "  timeout\n", want: Timeout},
		{name: "empty input yields none", input: "", want: None},
		{name: "whitespace only yields none", input: "   ", want: None},
		{name: "unknown value rejected", input: "connection-reset", wantErr: true},
		{name: "partial value rejected", input: "timeou", wantErr: true},
		{name: "the empty symptom is not a name", input: "none", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Parse(tc.input)
			if (err != nil) != tc.wantErr {
				t.Fatalf("Parse(%q) error = %v, wantErr %v", tc.input, err, tc.wantErr)
			}
			if tc.wantErr {
				// The operator mistyped a flag value; the message has to say
				// what was rejected and what would have been accepted.
				if !strings.Contains(err.Error(), tc.input) {
					t.Errorf("error %v does not name the rejected input %q", err, tc.input)
				}
				for _, s := range Symptoms() {
					if !strings.Contains(err.Error(), s.String()) {
						t.Errorf("error %v does not list %q", err, s)
					}
				}
				return
			}
			if got != tc.want {
				t.Errorf("Parse(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

// Every Symptom the classifier reports must be one Parse accepts back, or help
// text would advertise values the flag refuses.
func TestParseRoundTripsEverySymptom(t *testing.T) {
	for _, s := range Symptoms() {
		t.Run(s.String(), func(t *testing.T) {
			got, err := Parse(s.String())
			if err != nil {
				t.Fatalf("Parse(%q) = %v, want nil", s, err)
			}
			if got != s {
				t.Fatalf("Parse(%q) = %q, want %q", s, got, s)
			}
			if !s.Valid() {
				t.Fatalf("Valid() = false for a listed symptom")
			}
		})
	}
	// None is the absence of a Symptom, not a Symptom.
	if None.Valid() {
		t.Error("None.Valid() = true, want false")
	}
	if Symptom("connection-reset").Valid() {
		t.Error("Valid() = true for an unrecognised symptom")
	}
}

func TestClassifyRejectsUnrecognisedSymptom(t *testing.T) {
	unknown := Symptom("connection-reset")
	_, err := Classify(unknown)
	if err == nil {
		t.Fatal("Classify() error = nil, want an error naming the unknown symptom")
	}
	if !strings.Contains(err.Error(), unknown.String()) {
		t.Errorf("error %v does not name %q", err, unknown)
	}

	defer func() {
		if recover() == nil {
			t.Error("MustClassify() did not panic on an unrecognised symptom")
		}
	}()
	MustClassify(unknown)
}

func TestCandidateReportsMembership(t *testing.T) {
	c := MustClassify(Timeout)
	if !c.Candidate(model.LayerSecurityGroup) {
		t.Error("Candidate(security_group) = false for a timeout")
	}
	if c.Candidate(model.LayerHostListener) {
		t.Error("Candidate(host_listener) = true for a timeout")
	}
	// With no Symptom nothing is a candidate, even though every Layer is still
	// checked.
	none := MustClassify(None)
	for _, l := range model.FlowOrder() {
		if none.Candidate(l) {
			t.Errorf("Candidate(%q) = true with no symptom supplied", l)
		}
	}
}
