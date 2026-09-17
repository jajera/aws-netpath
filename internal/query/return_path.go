package query

// Return path evaluation: the destination-to-source direction walked as a Flow
// in its own right rather than inferred from the forward result.
//
// Routing in AWS is per-direction. Subnet route tables, transit gateway route
// tables, and attachment associations are each one-way, so a forward path that
// reaches the destination says nothing about whether the response can come
// back. An asymmetric pair presents as a connect-then-stall rather than a clean
// block, which is exactly the failure worth a second walk.
//
// This covers the routing half of the return direction. The stateless reverse
// NACL check stays in evalReturnNACL, evaluated inline with the forward walk
// because that is the Path_Walker's job; both directions share the single
// reverse Flow built here by returnFlow, so there is one definition of what the
// return direction is.
//
// Firewall policy is deliberately not re-evaluated backwards. Network Firewall
// stateful inspection permits the response to an already permitted flow, and
// the client ephemeral port is unknown, so evaluating the reverse Flow against
// the policy would manufacture a drop that does not happen. Where the reverse
// path crosses an inspection point the layer abstains and names it, rather than
// reporting a pass through a firewall it never evaluated.

import (
	"fmt"
	"strings"

	"github.com/jajera/aws-netpath/internal/flow"
	"github.com/jajera/aws-netpath/internal/model"
)

// returnCitationKind is the evidence category for return-path findings: every
// hop a reverse walk reports is a routing decision.
const returnCitationKind = "route"

// ReturnPath is the reverse direction evaluated as a distinct Flow.
type ReturnPath struct {
	// Flow is the reverse Flow: the forward destination as source, the forward
	// source as destination. For TCP and UDP its destination ports are every
	// port, because the client ephemeral port is not knowable from
	// configuration.
	Flow flow.Slice `json:"flow"`
	// Result is the RETURN_PATH layer outcome: a pass or a block with the
	// routing evidence, or an abstention naming what could not be evaluated.
	Result model.LayerResult `json:"result"`
	// Hops are the reverse hops in the order return traffic meets them. Their
	// layer names match the forward hops so the two directions can be compared
	// next hop by next hop.
	Hops []Hop `json:"hops,omitempty"`
	// BlockedAt is the reverse hop that dropped the return traffic, if any.
	BlockedAt *Hop `json:"blocked_at,omitempty"`
	// Asymmetry compares this direction's next hops against the forward
	// direction's. It is nil when there was nothing to compare: a return
	// direction that abstained or was blocked never resolved a full set of next
	// hops.
	Asymmetry *Asymmetry `json:"asymmetry,omitempty"`
	Notes     []string   `json:"notes,omitempty"`
}

// Blocked reports whether the return direction is blocked.
func (r *ReturnPath) Blocked() bool {
	return r != nil && r.Result.Verdict == model.VerdictBlocked
}

// Path returns the reverse hops including the blocking hop, which a walk may
// report without having appended it.
func (r *ReturnPath) Path() []Hop {
	if r == nil {
		return nil
	}
	if r.BlockedAt == nil || hopRecorded(r.Hops, *r.BlockedAt) {
		return r.Hops
	}
	return append(append([]Hop(nil), r.Hops...), *r.BlockedAt)
}

// returnFlow builds the reverse of a forward Flow, with the note explaining the
// one thing configuration cannot tell us about it.
//
// The response to a TCP or UDP connection arrives at the client's ephemeral
// port, chosen at connect time and absent from any configuration. Treating the
// reverse destination ports as every port is the only honest choice: narrowing
// them would invent a value, and a rule keyed on one port would then be read as
// deciding traffic it may never see.
func returnFlow(s flow.Slice) (flow.Slice, []string) {
	rev := flow.NewSlice(s.Dst, s.Src, s.Proto, s.DstPorts)
	if !s.Proto.HasPorts() {
		return rev, nil
	}
	rev.DstPorts = flow.AllPorts()
	return rev, []string{"return direction uses any destination port for TCP/UDP (client ephemeral port unknown)"}
}

// evalReturnPath walks the reverse Flow from the forward destination back to the
// forward source. srcSub is the forward source subnet, which Run has already
// established; dstSub and dstKnown describe the forward destination.
//
// The forward verdict is left alone: reporting a blocked return direction as
// the primary blocker is the Correlator's decision, not this walk's.
func evalReturnPath(g *graph, opts Options, forward flow.Slice, srcSub, dstSub *model.Subnet, dstKnown bool) *ReturnPath {
	rev, notes := returnFlow(forward)
	rp := &ReturnPath{Flow: rev, Notes: notes}

	// The reverse walk starts from the forward destination's route table. With
	// no such subnet in the snapshot there is nothing to walk, so the layer
	// abstains: an unwalkable return direction is not a working one.
	if !dstKnown || dstSub == nil {
		if ext, ok := g.externalForAddr(opts.DstIP); ok {
			rp.Result = returnAbstain(fmt.Sprintf(
				"destination %s belongs to declared external network %s, whose routing is not in the snapshot, so the return direction could not be walked",
				opts.DstIP, externalLabel(ext)), nil)
			return rp
		}
		rp.Result = returnAbstain(fmt.Sprintf(
			"destination %s is not in any collected subnet, so the return direction has no route table to walk; re-collect with the account owning that address",
			opts.DstIP), nil)
		return rp
	}

	var skipped []string
	w := &pathWalker{g: g, slice: rev, skipFirewall: true, skippedFirewalls: &skipped}
	rp.Hops, rp.BlockedAt = walkRoutes(w, dstSub, srcSub, false, opts.SrcIP)

	cites := returnCitations(rp.Path())
	if len(cites) == 0 {
		cites = []model.Citation{{
			Kind: returnCitationKind, Identifier: dstSub.ID,
			Detail: fmt.Sprintf("return path from %s", opts.DstIP),
		}}
	}

	switch {
	case rp.BlockedAt != nil:
		// A block stands whatever went unevaluated: an inspection point cannot
		// un-drop traffic the routing already discarded.
		rp.Result = model.LayerResult{
			Layer: model.LayerReturnPath, Verdict: model.VerdictBlocked, Citations: cites,
		}
	case len(skipped) > 0:
		rp.Result = returnAbstain(fmt.Sprintf(
			"return routing reaches %s, but firewall policy was not evaluated in the reverse direction at %s: stateful inspection permits the response to an already permitted flow, and the client ephemeral port is unknown, so a reverse-direction firewall verdict would not be authoritative",
			opts.SrcIP, strings.Join(skipped, ", ")), cites)
	default:
		rp.Result = model.LayerResult{
			Layer: model.LayerReturnPath, Verdict: model.VerdictPass, Citations: cites,
		}
	}
	return rp
}

// returnAbstain builds a RETURN_PATH abstention. The reason is mandatory: an
// abstention without one is indistinguishable from a return direction that
// works.
func returnAbstain(reason string, citations []model.Citation) model.LayerResult {
	return model.LayerResult{
		Layer:     model.LayerReturnPath,
		Verdict:   model.VerdictAbstain,
		Citations: citations,
		Reason:    reason,
	}
}

// returnCitations turns reverse hops into evidence. Every hop is cited, not just
// the deciding one, because the next hops themselves are the finding: they are
// what a forward path is compared against.
func returnCitations(hops []Hop) []model.Citation {
	out := make([]model.Citation, 0, len(hops))
	for _, h := range hops {
		out = append(out, model.Citation{
			Kind:       returnCitationKind,
			Identifier: hopIdentifier(h),
			Detail:     fmt.Sprintf("return %s: %s", h.Layer, hopDetail(h)),
		})
	}
	return out
}

func hopIdentifier(h Hop) string {
	if h.Resource != "" {
		return h.Resource
	}
	return h.Layer
}

func hopDetail(h Hop) string {
	if h.Detail != "" {
		return h.Detail
	}
	return allowDeny(h.Allowed)
}

// hopRecorded reports whether hops already contains want. Hops carry a citation
// slice, so they are compared on the fields that identify a decision.
func hopRecorded(hops []Hop, want Hop) bool {
	for _, h := range hops {
		if h.Layer == want.Layer && h.Resource == want.Resource && h.Detail == want.Detail {
			return true
		}
	}
	return false
}

func externalLabel(ext *model.ExternalNetwork) string {
	if ext.Name != "" {
		return ext.Name
	}
	return ext.ID
}
