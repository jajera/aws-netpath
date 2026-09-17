package host

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/jajera/aws-netpath/internal/model"
)

// Requirement 8.6: every way a host check can fail to run produces an ABSTAIN
// with a reason, on both host Layers, and never a PASS.
func TestAbstainAllCoversBothHostLayersWithAReason(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantText string
	}{
		{
			name:     "instance unmanaged",
			err:      fmt.Errorf("%w: %s is not registered with ssm", ErrUnmanaged, testInstance),
			wantText: "not registered with ssm",
		},
		{
			name:     "command undeliverable",
			err:      fmt.Errorf("%w: ss -tlnp: ssm reported Undeliverable", ErrUndeliverable),
			wantText: "could not be delivered",
		},
		{
			name:     "command timed out",
			err:      fmt.Errorf("%w: ss -tlnp after 30s", ErrCommandTimeout),
			wantText: "did not complete in time",
		},
		{
			name:     "no error supplied",
			err:      nil,
			wantText: "was not probed",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			results := AbstainAll(tc.err)
			if len(results) != len(HostLayers()) {
				t.Fatalf("got %d results, want one per host layer %v", len(results), HostLayers())
			}
			seen := map[model.Layer]bool{}
			for _, r := range results {
				if r.Verdict != model.VerdictAbstain {
					t.Errorf("layer %s verdict = %s, want %s", r.Layer, r.Verdict, model.VerdictAbstain)
				}
				if !strings.Contains(r.Reason, tc.wantText) {
					t.Errorf("layer %s reason = %q, want it to state %q", r.Layer, r.Reason, tc.wantText)
				}
				if err := r.Validate(); err != nil {
					t.Errorf("layer %s result is not emittable: %v", r.Layer, err)
				}
				seen[r.Layer] = true
			}
			for _, layer := range []model.Layer{model.LayerHostFirewall, model.LayerHostListener} {
				if !seen[layer] {
					t.Errorf("layer %s missing from the abstentions", layer)
				}
			}
		})
	}
}

// A single check that could not run abstains on its own Layer, so the other host
// check keeps whatever answer it found.
func TestAbstainCoversOneLayer(t *testing.T) {
	err := fmt.Errorf("%w: firewall-cmd --list-rich-rules after 30s", ErrCommandTimeout)
	got := Abstain(model.LayerHostFirewall, err)

	if got.Layer != model.LayerHostFirewall {
		t.Errorf("Layer = %s, want %s", got.Layer, model.LayerHostFirewall)
	}
	if got.Verdict != model.VerdictAbstain {
		t.Errorf("Verdict = %s, want %s", got.Verdict, model.VerdictAbstain)
	}
	if !strings.Contains(got.Reason, "firewall-cmd --list-rich-rules") {
		t.Errorf("Reason = %q, want it to name the command that did not complete", got.Reason)
	}
	if err := got.Validate(); err != nil {
		t.Errorf("result is not emittable: %v", err)
	}
}

// An Abstention is never aggregated as a pass, and a verdict resting on one is
// not authoritative. This is the property the host Layers exist to preserve: a
// clean cloud path with an unprobed host is not the same answer as all clear.
func TestUnprobedHostLeavesTheVerdictUnauthoritative(t *testing.T) {
	v := &model.Verdict{
		Results: append([]model.LayerResult{
			{Layer: model.LayerRoute, Verdict: model.VerdictPass, Citations: []model.Citation{{Kind: "route", Identifier: "rtb-0aaa"}}},
			{Layer: model.LayerSecurityGroup, Verdict: model.VerdictPass, Citations: []model.Citation{{Kind: "security_group", Identifier: "sg-0bbb"}}},
		}, AbstainAll(fmt.Errorf("%w: %s is not registered with ssm", ErrUnmanaged, testInstance))...),
	}
	if err := v.Validate(); err != nil {
		t.Fatalf("verdict is not emittable: %v", err)
	}
	if v.ComputeAuthoritative() {
		t.Error("verdict is authoritative with both host layers unverified")
	}
	if got := len(v.Abstentions()); got != len(HostLayers()) {
		t.Errorf("abstentions = %d, want %d", got, len(HostLayers()))
	}
	if v.PrimaryBlocker != nil {
		t.Errorf("primary blocker = %v, want none: nothing was shown to block", *v.PrimaryBlocker)
	}
}

// The runner's own errors feed the abstention path unchanged, so an operator sees
// the cause rather than a generic "host not checked".
func TestRunnerErrorsAbstainWithTheCause(t *testing.T) {
	tests := []struct {
		name     string
		stub     *stubSSM
		wantText string
	}{
		{
			name:     "unmanaged instance",
			stub:     &stubSSM{sendErr: &ssmtypes.InvalidInstanceId{Message: aws.String("instance not in a valid state")}},
			wantText: testInstance,
		},
		{
			name: "invocation never completes",
			stub: &stubSSM{steps: []invocationStep{{out: &ssm.GetCommandInvocationOutput{
				Status: ssmtypes.CommandInvocationStatusInProgress,
			}}}},
			wantText: "ss -tlnp",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, _ := newTestRunner(tc.stub, WithTimeout(10*time.Second), WithPollInterval(2*time.Second))
			_, err := r.Run(context.Background(), testInstance, listenerCommand(t))
			if err == nil {
				t.Fatal("Run succeeded, want a failure to abstain on")
			}
			for _, result := range AbstainAll(err) {
				if result.Verdict != model.VerdictAbstain {
					t.Errorf("layer %s verdict = %s, want %s", result.Layer, result.Verdict, model.VerdictAbstain)
				}
				if !strings.Contains(result.Reason, tc.wantText) {
					t.Errorf("layer %s reason = %q, want it to name %q", result.Layer, result.Reason, tc.wantText)
				}
			}
			if !errors.Is(err, ErrUnmanaged) && !errors.Is(err, ErrUndeliverable) && !errors.Is(err, ErrCommandTimeout) {
				t.Errorf("error = %v, want one of the three abstention causes", err)
			}
		})
	}
}
