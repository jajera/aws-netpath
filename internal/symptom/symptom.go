// Package symptom turns the error an operator actually saw into a direction to
// investigate.
//
// The client-side failure is the strongest clue available before any
// configuration is read, because different failures are produced by different
// halves of the stack. A RST came from something that received the packet and
// answered. A timeout came from something that received the packet and said
// nothing. "No route to host" on a routable network came from a device that
// chose to reject and reported doing so, which in practice means a host
// firewall.
//
// Classification is a pure function: no AWS call, no Snapshot, no I/O. It maps
// a Symptom to candidate Layers and a check order, and nothing more. Deciding
// what those Layers actually say is the Path_Walker's and the Host_Prober's
// work; reconciling the findings against the Symptom is the Correlator's.
package symptom

import (
	"fmt"
	"strings"

	"github.com/jajera/aws-netpath/internal/model"
)

// Symptom is an observed client-side failure.
type Symptom string

const (
	// ConnectionRefused is a RST returned to the client. The host is reachable
	// and either nothing is listening or the host rejected the connection.
	ConnectionRefused Symptom = "connection-refused"
	// NoRouteToHost is ICMP administratively prohibited on a network that does
	// have a route. Something chose to reject and reported doing so.
	NoRouteToHost Symptom = "no-route-to-host"
	// Timeout is silence: the packet was discarded with no reply.
	Timeout Symptom = "timeout"
	// ConnectThenStall is a completed handshake followed by no progress,
	// characteristic of a state or MTU failure rather than a policy block.
	ConnectThenStall Symptom = "connect-then-stall"
	// ICMPOKTCPFails is ping succeeding while TCP to the port fails, which
	// narrows the cause to a port-specific filter.
	ICMPOKTCPFails Symptom = "icmp-ok-tcp-fails"
)

// None is the absence of a Symptom. Diagnosis proceeds in flow order.
const None Symptom = ""

// Response describes what the far side did with the packet. It is the
// distinction that carries the diagnostic weight, because it separates "a
// policy dropped this" from "a device rejected this".
type Response string

const (
	// ResponseSilent means the packet was discarded without a reply: a security
	// group, a NACL, or a missing route.
	ResponseSilent Response = "silent-discard"
	// ResponseActive means a device chose to reject and said so, by RST or by
	// ICMP administratively prohibited. In practice that is a host.
	ResponseActive Response = "active-rejection"
	// ResponseEstablished means the connection was accepted, so no Layer
	// blocked the handshake. The failure came later.
	ResponseEstablished Response = "established"
	// ResponseMixed means the observation does not settle whether the packet was
	// dropped or rejected, so neither ordering heuristic applies.
	ResponseMixed Response = "mixed"
)

// Active reports whether the far side actively rejected the traffic. Candidate
// Layers are ordered host-first when it did.
func (r Response) Active() bool { return r == ResponseActive }

// Classification is the result of classifying a Symptom.
type Classification struct {
	// Symptom is the Symptom classified, or None when none was supplied.
	Symptom Symptom `json:"symptom,omitempty"`
	// Mechanism describes, in one phrase, how the Symptom is produced. It comes
	// straight from the requirement 9.1 table and exists to be shown to an
	// operator alongside the candidates.
	Mechanism string `json:"mechanism,omitempty"`
	// Response is what the far side did with the packet.
	Response Response `json:"response,omitempty"`
	// Candidates are the Layers the Symptom implicates, most likely first.
	// Empty when no Symptom was supplied.
	Candidates []model.Layer `json:"candidates,omitempty"`
	// CheckOrder is every Layer, candidates first, then the remainder in flow
	// order. With no Symptom it is exactly flow order.
	CheckOrder []model.Layer `json:"check_order"`
	// ExtraChecks names implicated checks that are not Layers, such as path
	// MTU. They belong to the Symptom but have no verdict of their own.
	ExtraChecks []string `json:"extra_checks,omitempty"`
}

// Candidate reports whether l is one of the candidate Layers.
func (c Classification) Candidate(l model.Layer) bool {
	return containsLayer(c.Candidates, l)
}

// profile is the requirement 9.1 table for one Symptom. Candidates are listed
// in the table's order, which is likelihood order rather than flow order:
// for a timeout, a security group is a more common cause than a missing route.
type profile struct {
	mechanism   string
	response    Response
	candidates  []model.Layer
	extraChecks []string
}

var profiles = map[Symptom]profile{
	ConnectionRefused: {
		mechanism:  "RST returned",
		response:   ResponseActive,
		candidates: []model.Layer{model.LayerHostListener, model.LayerHostFirewall},
	},
	NoRouteToHost: {
		mechanism:  "ICMP administratively prohibited",
		response:   ResponseActive,
		candidates: []model.Layer{model.LayerHostFirewall, model.LayerFirewall},
	},
	Timeout: {
		mechanism:  "packet silently discarded",
		response:   ResponseSilent,
		candidates: []model.Layer{model.LayerSecurityGroup, model.LayerNACL, model.LayerRoute},
	},
	ConnectThenStall: {
		mechanism: "state or MTU failure",
		response:  ResponseEstablished,
		// Path MTU is a host check with no Layer of its own, so it is reported
		// as an extra check rather than folded into a Layer that would then
		// carry a verdict it did not earn.
		candidates:  []model.Layer{model.LayerReturnPath},
		extraChecks: []string{"path MTU"},
	},
	ICMPOKTCPFails: {
		mechanism: "port-specific filter",
		// ICMP succeeding proves the host is reachable, but a filter on the
		// port may drop or reject. The observation does not distinguish them.
		response:   ResponseMixed,
		candidates: []model.Layer{model.LayerSecurityGroup, model.LayerHostFirewall},
	},
}

// symptomOrder is the declaration order used when listing Symptoms, so help
// text and error messages are stable.
var symptomOrder = []Symptom{
	ConnectionRefused,
	NoRouteToHost,
	Timeout,
	ConnectThenStall,
	ICMPOKTCPFails,
}

// Symptoms returns every recognised Symptom in a stable order.
func Symptoms() []Symptom {
	out := make([]Symptom, len(symptomOrder))
	copy(out, symptomOrder)
	return out
}

// Valid reports whether s is a recognised Symptom. None is not valid: it is the
// absence of a Symptom, which Classify accepts but which is not a Symptom.
func (s Symptom) Valid() bool {
	_, ok := profiles[s]
	return ok
}

func (s Symptom) String() string { return string(s) }

// Parse converts operator input into a Symptom. Case, surrounding whitespace,
// and underscores or spaces in place of hyphens are all accepted, since the
// value usually arrives from a command line. Empty input yields None so callers
// can pass a flag value through unconditionally.
func Parse(s string) (Symptom, error) {
	normalized := strings.ToLower(strings.TrimSpace(s))
	normalized = strings.NewReplacer("_", "-", " ", "-").Replace(normalized)
	if normalized == "" {
		return None, nil
	}
	candidate := Symptom(normalized)
	if !candidate.Valid() {
		return None, fmt.Errorf("unknown symptom %q: expected one of %s", s, strings.Join(names(), ", "))
	}
	return candidate, nil
}

func names() []string {
	out := make([]string, 0, len(symptomOrder))
	for _, s := range symptomOrder {
		out = append(out, string(s))
	}
	return out
}

// Classify maps a Symptom to its candidate Layers and a check order.
//
// With no Symptom supplied the check order is flow order and there are no
// candidates: nothing is known that would justify preferring one Layer over
// another. With an actively rejected Symptom the candidates are reordered to
// put host Layers first, which inverts the default order and reaches the answer
// in one probe rather than five. For every other Symptom the table's own
// likelihood order stands.
func Classify(s Symptom) (Classification, error) {
	if s == None {
		return Classification{CheckOrder: model.FlowOrder()}, nil
	}
	p, ok := profiles[s]
	if !ok {
		return Classification{}, fmt.Errorf("unknown symptom %q: expected one of %s", s, strings.Join(names(), ", "))
	}

	candidates := hostFirst(p.candidates, p.response.Active())

	return Classification{
		Symptom:     s,
		Mechanism:   p.mechanism,
		Response:    p.response,
		Candidates:  candidates,
		CheckOrder:  checkOrder(candidates),
		ExtraChecks: copyStrings(p.extraChecks),
	}, nil
}

// MustClassify is Classify for a Symptom known to be valid, such as a constant
// declared here. It panics on an unrecognised Symptom, so it is for test and
// initialisation code, not for operator input.
func MustClassify(s Symptom) Classification {
	c, err := Classify(s)
	if err != nil {
		panic(err)
	}
	return c
}

// hostFirst returns layers with host Layers moved ahead of cloud Layers when
// active is true, preserving the relative order within each group. When active
// is false the input order is returned unchanged.
func hostFirst(layers []model.Layer, active bool) []model.Layer {
	if !active {
		return copyLayers(layers)
	}
	out := make([]model.Layer, 0, len(layers))
	for _, l := range layers {
		if l.Host() {
			out = append(out, l)
		}
	}
	for _, l := range layers {
		if !l.Host() {
			out = append(out, l)
		}
	}
	return out
}

// checkOrder returns the candidates followed by every remaining Layer in flow
// order. Candidates are checked first because they are the likely cause; the
// remainder still follows, because a Symptom narrows the search without
// excluding anything.
func checkOrder(candidates []model.Layer) []model.Layer {
	flow := model.FlowOrder()
	out := make([]model.Layer, 0, len(flow)+len(candidates))
	for _, l := range candidates {
		if !containsLayer(out, l) {
			out = append(out, l)
		}
	}
	for _, l := range flow {
		if !containsLayer(out, l) {
			out = append(out, l)
		}
	}
	return out
}

func containsLayer(layers []model.Layer, want model.Layer) bool {
	for _, l := range layers {
		if l == want {
			return true
		}
	}
	return false
}

func copyLayers(in []model.Layer) []model.Layer {
	if in == nil {
		return nil
	}
	out := make([]model.Layer, len(in))
	copy(out, in)
	return out
}

func copyStrings(in []string) []string {
	if in == nil {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}
