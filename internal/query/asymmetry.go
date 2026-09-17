package query

// Asymmetry detection: comparing what the two directions of a flow resolve to.
//
// Routing in AWS is per-direction, so the two directions of one flow can resolve
// to different transit gateways, different attachments, or different gateways
// entirely. Both directions still carry traffic, so no layer blocks and the
// forward walk reports a clean pass. The failure shows up later and elsewhere,
// which is why it is worth stating outright rather than leaving an operator to
// notice that two hop lists do not match.
//
// The comparison is on next hops, not on the resources that decided them. A
// route table is per-direction by design: the source subnet's table and the
// destination subnet's table are different objects and are supposed to be.
// Comparing tables would call every path asymmetric. What the two directions are
// expected to agree on is the set of components they resolve to, which is what
// walkRoutes records on each hop as it goes.
//
// Order is deliberately not compared. The return direction meets the same
// components in the opposite order, so the finding is which components one
// direction traverses and the other does not.
//
// Nothing here decides a verdict. An asymmetric path is a report; whether it
// explains a failure depends on the Symptom the operator observed, and that is
// the Correlator's judgement.

import (
	"fmt"
	"strings"

	"github.com/jajera/aws-netpath/internal/model"
)

// Next-hop kinds that no route target describes. Route targets reuse the
// snapshot's own TargetKind vocabulary.
const (
	// nextHopAttachment is a transit gateway attachment: traffic enters the
	// gateway by one and leaves by another.
	nextHopAttachment = "attachment"
	// nextHopInspectionVPC is a VPC traffic is diverted into for inspection.
	nextHopInspectionVPC = "inspection-vpc"
)

// asymmetryCitationKind is the evidence category for asymmetry findings. A next
// hop is a routing decision, so it is cited as one.
const asymmetryCitationKind = "route"

// NextHop is one forwarding or inspection component a direction resolves to.
type NextHop struct {
	// ID is the component's identifier, and is what the two directions are
	// compared on. Kind is descriptive: the same component can be described
	// differently by two route tables, but its identifier does not change.
	ID   string `json:"id"`
	Kind string `json:"kind,omitempty"`
	// Layer is the hop that resolved to this component, so a difference can be
	// traced back to the decision that produced it.
	Layer  string `json:"layer,omitempty"`
	Detail string `json:"detail,omitempty"`
	// Stateful marks a component that keeps per-connection state, which is what
	// turns an asymmetric path from an oddity into a probable stall.
	Stateful bool `json:"stateful,omitempty"`
}

func (n NextHop) String() string {
	if n.Kind == "" {
		return n.ID
	}
	return fmt.Sprintf("%s (%s)", n.ID, n.Kind)
}

// NextHopDifference is one component only one direction traverses.
type NextHopDifference struct {
	NextHop NextHop `json:"next_hop"`
	// Direction is the direction that traverses it: "forward" or "return".
	Direction string `json:"direction"`
}

// Direction labels used in findings and citations.
const (
	directionForward = "forward"
	directionReturn  = "return"
)

// Asymmetry is the comparison of the two directions' next hops.
type Asymmetry struct {
	// Forward and Return are the components each direction resolves to, in the
	// order that direction meets them. Both are kept whether or not they differ:
	// the pair is the finding, and a citation that named only one side would not
	// let a reader check it.
	Forward []NextHop `json:"forward,omitempty"`
	Return  []NextHop `json:"return,omitempty"`
	// Differences are the components only one direction traverses. Empty means
	// the two directions agree.
	Differences []NextHopDifference `json:"differences,omitempty"`
	// Stateful names the components on either direction that keep
	// per-connection state.
	Stateful []NextHop `json:"stateful,omitempty"`
	Summary  string    `json:"summary,omitempty"`
	// Citations are the evidence, populated only for an asymmetric path: there
	// is no finding to support when the two directions match.
	Citations []model.Citation `json:"citations,omitempty"`
}

// Asymmetric reports whether the two directions resolve to different components.
func (a *Asymmetry) Asymmetric() bool {
	return a != nil && len(a.Differences) > 0
}

// StatefulAsymmetry reports whether an asymmetric path also crosses a component
// that keeps per-connection state. That combination is the one that produces a
// connection which establishes and then stalls.
func (a *Asymmetry) StatefulAsymmetry() bool {
	return a.Asymmetric() && len(a.Stateful) > 0
}

// Observation renders an asymmetric path as a finding the Correlator can weigh
// against the Symptom. A symmetric path produces nothing: there is no finding.
func (a *Asymmetry) Observation() (model.Observation, bool) {
	if !a.Asymmetric() {
		return model.Observation{}, false
	}
	kind := model.ObservationAsymmetric
	if a.StatefulAsymmetry() {
		kind = model.ObservationAsymmetricStateful
	}
	return model.Observation{
		Kind:      kind,
		Layer:     model.LayerReturnPath,
		Summary:   a.Summary,
		Citations: a.Citations,
	}, true
}

// evalAsymmetry compares the forward hops against the return hops.
//
// It returns nil when there is nothing to compare, which is a question about the
// hops rather than about the return verdict. A return direction that was never
// walked has no next hops at all, and calling every forward next hop a
// difference would read a gap in the snapshot as a finding. A blocked return
// direction never reached the components past the block, so the same reading
// applies — and a block is already the stronger statement about the way back.
//
// A return direction that abstained because firewall policy was not evaluated in
// reverse is still compared: that abstention is about policy, while the routing
// was walked to the end and every next hop resolved. Skipping it would drop the
// asymmetry finding on exactly the topology it matters most for, where one
// direction crosses an inspection point and the other does not.
func evalAsymmetry(g *graph, forward []Hop, rp *ReturnPath) *Asymmetry {
	if rp == nil || rp.Blocked() || len(rp.Hops) == 0 {
		return nil
	}

	a := &Asymmetry{
		Forward: nextHops(g, forward),
		Return:  nextHops(g, rp.Path()),
	}
	a.Differences = nextHopDifferences(a.Forward, a.Return)
	a.Stateful = statefulNextHops(a.Forward, a.Return)

	if !a.Asymmetric() {
		a.Summary = symmetricSummary(a.Forward)
		return a
	}

	a.Summary = asymmetrySummary(a)
	a.Citations = asymmetryCitations(a)
	return a
}

// nextHops extracts the components one direction resolves to, in order, with
// repeats collapsed. A component reached twice — a transit gateway route naming
// the attachment that the next hop then delivers through — is one component.
func nextHops(g *graph, hops []Hop) []NextHop {
	var out []NextHop
	seen := make(map[string]bool, len(hops))
	for _, h := range hops {
		if h.NextHop == "" || seen[h.NextHop] {
			continue
		}
		seen[h.NextHop] = true
		out = append(out, NextHop{
			ID:       h.NextHop,
			Kind:     h.NextHopKind,
			Layer:    h.Layer,
			Detail:   h.Detail,
			Stateful: g.statefulNextHop(h),
		})
	}
	return out
}

// nextHopDifferences returns the components present in one direction and absent
// from the other, forward-only differences first.
func nextHopDifferences(forward, ret []NextHop) []NextHopDifference {
	var out []NextHopDifference
	for _, n := range missingFrom(forward, ret) {
		out = append(out, NextHopDifference{NextHop: n, Direction: directionForward})
	}
	for _, n := range missingFrom(ret, forward) {
		out = append(out, NextHopDifference{NextHop: n, Direction: directionReturn})
	}
	return out
}

// missingFrom returns the members of from whose identifier does not appear in
// other.
func missingFrom(from, other []NextHop) []NextHop {
	present := make(map[string]bool, len(other))
	for _, n := range other {
		present[n.ID] = true
	}
	var out []NextHop
	for _, n := range from {
		if !present[n.ID] {
			out = append(out, n)
		}
	}
	return out
}

// statefulNextHops returns the stateful components either direction traverses.
func statefulNextHops(forward, ret []NextHop) []NextHop {
	var out []NextHop
	seen := map[string]bool{}
	for _, n := range append(append([]NextHop(nil), forward...), ret...) {
		if !n.Stateful || seen[n.ID] {
			continue
		}
		seen[n.ID] = true
		out = append(out, n)
	}
	return out
}

// statefulNextHop reports whether the component this hop forwards through keeps
// per-connection state, so that a response arriving by another path has no state
// to match against.
//
// Network Firewall inspects statefully, and each firewall endpoint keeps its own
// state, so both an inspection VPC and a firewall endpoint named directly by a
// route table count. A NAT gateway keeps a translation table, which is state
// under another name. Everything else on a path — route tables, transit
// gateways, attachments — forwards without keeping any. Security groups are
// stateful but attach to an interface rather than sitting on the path between
// the endpoints, so they are symmetric by construction and are not part of this.
func (g *graph) statefulNextHop(h Hop) bool {
	switch h.NextHopKind {
	case nextHopInspectionVPC, string(model.TargetNATGateway):
		return true
	}
	return g.firewallForEndpoint(h.NextHop) != nil
}

// symmetricSummary states that the two directions agree. A flow inside one VPC
// resolves to no next hop in either direction, because a local route names
// address space rather than a device, so there is nothing to disagree about.
func symmetricSummary(hops []NextHop) string {
	if len(hops) == 0 {
		return "forward and return directions traverse no gateway: both resolve locally"
	}
	return fmt.Sprintf("forward and return directions resolve to the same next hops (%s)", nextHopList(hops))
}

// asymmetrySummary states the finding in the terms an operator can act on: what
// differs, and whether anything on the path cares.
func asymmetrySummary(a *Asymmetry) string {
	var b strings.Builder
	fmt.Fprintf(&b, "forward and return directions resolve to different next hops: forward traverses %s, return traverses %s",
		nextHopList(a.Forward), nextHopList(a.Return))

	if forwardOnly := differencesFor(a, directionForward); len(forwardOnly) > 0 {
		fmt.Fprintf(&b, "; only the forward direction traverses %s", nextHopList(forwardOnly))
	}
	if returnOnly := differencesFor(a, directionReturn); len(returnOnly) > 0 {
		fmt.Fprintf(&b, "; only the return direction traverses %s", nextHopList(returnOnly))
	}

	if !a.StatefulAsymmetry() {
		return b.String()
	}
	fmt.Fprintf(&b, "; the path crosses stateful %s, so the response returns through a device other than the one holding the connection state and the connection can establish and then stall",
		nextHopList(a.Stateful))
	return b.String()
}

// asymmetryCitations cites both directions.
//
// Every next hop on both sides is cited, not only the ones that differ:
// requirement 7.2 is that the finding names both next hops, and a difference is
// only meaningful next to what the other direction resolved to instead. The
// differences are then cited again on their own, each naming what the opposite
// direction did, so a single citation carries the whole comparison.
func asymmetryCitations(a *Asymmetry) []model.Citation {
	out := make([]model.Citation, 0, len(a.Forward)+len(a.Return)+len(a.Differences))
	out = append(out, directionCitations(directionForward, a.Forward)...)
	out = append(out, directionCitations(directionReturn, a.Return)...)

	for _, d := range a.Differences {
		opposite, counterparts := directionReturn, a.Return
		if d.Direction == directionReturn {
			opposite, counterparts = directionForward, a.Forward
		}
		out = append(out, model.Citation{
			Kind:       asymmetryCitationKind,
			Identifier: d.NextHop.ID,
			Detail: fmt.Sprintf("%s next hop %s has no counterpart in the %s direction, which resolves to %s",
				d.Direction, d.NextHop, opposite, nextHopList(counterparts)),
		})
	}
	return out
}

func directionCitations(direction string, hops []NextHop) []model.Citation {
	out := make([]model.Citation, 0, len(hops))
	for _, n := range hops {
		detail := fmt.Sprintf("%s next hop at %s: %s", direction, n.Layer, n.Detail)
		if n.Stateful {
			detail += " (stateful)"
		}
		out = append(out, model.Citation{
			Kind:       asymmetryCitationKind,
			Identifier: n.ID,
			Detail:     detail,
		})
	}
	return out
}

func differencesFor(a *Asymmetry, direction string) []NextHop {
	var out []NextHop
	for _, d := range a.Differences {
		if d.Direction == direction {
			out = append(out, d.NextHop)
		}
	}
	return out
}

// nextHopList renders components for a human-readable finding.
func nextHopList(hops []NextHop) string {
	if len(hops) == 0 {
		return "no next hop"
	}
	parts := make([]string, 0, len(hops))
	for _, n := range hops {
		parts = append(parts, n.String())
	}
	return strings.Join(parts, " → ")
}
