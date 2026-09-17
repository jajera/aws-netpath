package host

// Abstention for the host Layers.
//
// The whole value of this package is the difference between "the host was checked
// and is fine" and "the host was not checked". An unmanaged instance, an
// undeliverable command, and a command that timed out all leave the host
// unverified, so each produces an ABSTAIN carrying the reason — never a PASS, and
// never a silently missing Layer, which the Formatter would have nothing to
// report and the Correlator would treat as a Layer nobody asked about.

import (
	"fmt"

	"github.com/jajera/aws-netpath/internal/model"
)

// hostLayers are the Layers decided on the host rather than from cloud
// configuration. Both abstain together when nothing can be probed at all.
var hostLayers = []model.Layer{model.LayerHostFirewall, model.LayerHostListener}

// HostLayers returns the Layers a host probe decides, in flow order.
func HostLayers() []model.Layer {
	out := make([]model.Layer, len(hostLayers))
	copy(out, hostLayers)
	return out
}

// Abstain returns the ABSTAIN result for one host Layer, with err as the stated
// reason. Use it when a single check could not run — a command that timed out
// leaves its own Layer unverified while the others still have answers.
func Abstain(layer model.Layer, err error) model.LayerResult {
	return model.LayerResult{
		Layer:   layer,
		Verdict: model.VerdictAbstain,
		Reason:  abstainReason(err),
	}
}

// AbstainAll returns the ABSTAIN result for every host Layer. Use it when no
// check could run: an instance Systems Manager does not manage, or an endpoint it
// could not be reached through, leaves both host Layers unverified for the same
// reason.
func AbstainAll(err error) []model.LayerResult {
	out := make([]model.LayerResult, 0, len(hostLayers))
	for _, layer := range hostLayers {
		out = append(out, Abstain(layer, err))
	}
	return out
}

// abstainReason states what stopped the check. The sentinel errors already name
// the category — unmanaged, undeliverable, timed out — and wrap the instance,
// command, and API error behind it, so the reason is that text with the
// consequence spelled out in front of it. A nil error still yields a reason:
// LayerResult refuses an Abstention without one, and an Abstention that could
// not explain itself is indistinguishable from a silent pass.
func abstainReason(err error) string {
	if err == nil {
		return "host layer unverified: the host was not probed"
	}
	return fmt.Sprintf("host layer unverified: %v", err)
}
