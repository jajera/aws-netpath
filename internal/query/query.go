// Package query walks a collected snapshot to decide whether a flow can reach
// its destination, checking routes, NACLs, and network firewalls along the way.
package query

import (
	"fmt"
	"net/netip"

	"github.com/jajera/aws-netpath/internal/flow"
	"github.com/jajera/aws-netpath/internal/model"
	"github.com/jajera/aws-netpath/internal/nfw"
)

// Verdict is the overall reachability outcome.
type Verdict string

const (
	VerdictPermitted Verdict = "PERMITTED"
	VerdictBlocked   Verdict = "BLOCKED"
	VerdictUnknown   Verdict = "UNKNOWN" // address space not in snapshot — not a network verdict
)

// Options configures a query.
type Options struct {
	Snapshot *model.Snapshot
	SrcIP    netip.Addr
	DstIP    netip.Addr
	Proto    flow.Protocol
	Port     int // 0 for icmp
	// SkipFirewall skips NFW evaluation (route-only mode).
	SkipFirewall bool
}

// Result is the outcome of a end-to-end query.
type Result struct {
	Flow      flow.Slice   `json:"flow"`
	Verdict   Verdict      `json:"verdict"`
	Hops      []Hop        `json:"hops,omitempty"`
	Firewalls []nfw.Result `json:"firewalls,omitempty"`
	BlockedAt *Hop         `json:"blocked_at,omitempty"`
	// Abstentions are the layers that could not be authoritatively evaluated,
	// each with the reason. They are reported separately from the hops so that
	// "could not check" is never read as "checked and fine".
	Abstentions []model.LayerResult `json:"abstentions,omitempty"`
	// ReturnPath is the destination-to-source direction evaluated as a distinct
	// Flow. It is nil when the forward walk stopped before reaching it, since a
	// forward block is the earlier finding in flow order.
	ReturnPath *ReturnPath `json:"return_path,omitempty"`
	Notes      []string    `json:"notes,omitempty"`
}

// LayerTGWRoute is the hop layer the walker records for a transit gateway route
// table decision.
//
// It is named rather than left as a literal because a caller outside this package
// has to recognise it: Reachability Analyzer evaluates TCP over a transit gateway
// route table in the forward direction only, and the Verifier can only state that
// caveat if it can tell that the path met one.
const LayerTGWRoute = "tgw-route"

// Hop is one step in the forward path with a layer decision.
type Hop struct {
	Layer    string `json:"layer"`
	Region   string `json:"region,omitempty"`
	Resource string `json:"resource,omitempty"`
	Detail   string `json:"detail,omitempty"`
	Allowed  bool   `json:"allowed"`
	// NextHop is the component this hop forwards through: the transit gateway a
	// route resolves to, the attachment traffic enters by, the inspection VPC it
	// is diverted into. It is empty for a hop that decides policy rather than
	// forwarding, and for a hop that resolved to nothing.
	//
	// It is recorded separately from Resource because Resource is the thing that
	// made the decision — usually a route table — and a route table is
	// per-direction by design. The next hop it resolves to is the part the two
	// directions are expected to agree on, which is what makes asymmetry
	// detectable.
	NextHop string `json:"next_hop,omitempty"`
	// NextHopKind categorises NextHop: a route target kind from the snapshot, or
	// one of the component kinds a route target does not describe. It is
	// descriptive only; components are compared by identifier.
	NextHopKind string `json:"next_hop_kind,omitempty"`
	// Citations are the evidence behind the decision: the resource IDs and the
	// rules that decided this hop.
	Citations []model.Citation `json:"citations,omitempty"`
}

// Path returns the forward hops including the blocking hop, which a walk may
// report without having appended it.
func (r *Result) Path() []Hop {
	if r.BlockedAt == nil || hopRecorded(r.Hops, *r.BlockedAt) {
		return r.Hops
	}
	return append(append([]Hop(nil), r.Hops...), *r.BlockedAt)
}

// Authoritative reports whether the verdict rests on a fully evaluated path.
//
// A block stands regardless of what abstained: an allow-only layer cannot
// un-block traffic another layer already dropped, though an earlier abstention
// may mean some other layer blocked it first. A permit is authoritative only
// when nothing abstained, because any unevaluated layer might have blocked.
func (r *Result) Authoritative() bool {
	return r.Verdict == VerdictBlocked || len(r.Abstentions) == 0
}

// Run evaluates connectivity from source to destination.
func Run(opts Options) (*Result, error) {
	if opts.Snapshot == nil {
		return nil, fmt.Errorf("snapshot is required")
	}
	if !opts.SrcIP.IsValid() || !opts.DstIP.IsValid() {
		return nil, fmt.Errorf("source and destination IP addresses are required")
	}

	slice := buildSlice(opts)
	g := newGraph(opts.Snapshot)
	res := &Result{Flow: slice, Verdict: VerdictPermitted}

	srcSub, srcOK := g.subnetForAddr(opts.SrcIP)
	if !srcOK {
		res.Verdict = VerdictUnknown
		res.BlockedAt = &Hop{
			Layer: "snapshot", Detail: fmt.Sprintf("source %s is not in any collected subnet (re-collect with the owning account, or ping proves live connectivity)", opts.SrcIP),
			Allowed: false,
		}
		res.Hops = append(res.Hops, *res.BlockedAt)
		res.Notes = append(res.Notes, "verdict UNKNOWN does not mean the network blocks this flow")
		return res, nil
	}

	dstSub, dstOK := g.subnetForAddr(opts.DstIP)
	dstExternal := false
	if !dstOK {
		if ext, ok := g.externalForAddr(opts.DstIP); ok {
			dstExternal = true
			res.Hops = append(res.Hops, Hop{
				Layer: "destination", Resource: ext.Name,
				Detail: fmt.Sprintf("declared external %s", opts.DstIP), Allowed: true,
			})
		} else {
			res.Notes = append(res.Notes, fmt.Sprintf("destination %s not in snapshot subnets; evaluating routing only", opts.DstIP))
		}
	}

	// Source security group egress. Evaluated before the source NACL, in the
	// order traffic leaving an interface actually meets them.
	srcSGHop, srcSGAbstain := evalEndpointSG(g, g.eniForAddr(opts.SrcIP), opts.SrcIP, slice, true)
	if res.record(srcSGHop, srcSGAbstain) {
		return res, nil
	}

	// Source NACL egress
	if hop := evalNACL(g.nacl(srcSub.NACLID), slice, true); hop != nil {
		res.Hops = append(res.Hops, *hop)
		if !hop.Allowed {
			res.Verdict = VerdictBlocked
			res.BlockedAt = hop
			return res, nil
		}
	}

	// Routing forward path
	w := &pathWalker{
		g: g, slice: slice, skipFirewall: opts.SkipFirewall, firewalls: &res.Firewalls,
	}
	routeHops, blocked := walkRoutes(w, srcSub, dstSub, dstExternal, opts.DstIP)
	res.Hops = append(res.Hops, routeHops...)
	if blocked != nil {
		res.Verdict = VerdictBlocked
		res.BlockedAt = blocked
		return res, nil
	}

	// Destination NACL ingress
	if dstOK {
		if hop := evalNACL(g.nacl(dstSub.NACLID), slice, false); hop != nil {
			res.Hops = append(res.Hops, *hop)
			if !hop.Allowed {
				res.Verdict = VerdictBlocked
				res.BlockedAt = hop
				return res, nil
			}
		}

		// Destination security group ingress.
		dstSGHop, dstSGAbstain := evalEndpointSG(g, g.eniForAddr(opts.DstIP), opts.DstIP, slice, false)
		if res.record(dstSGHop, dstSGAbstain) {
			return res, nil
		}
	} else {
		// The destination is outside the snapshot, so routing is all that can
		// be evaluated. Destination-side policy abstains rather than being
		// treated as absent.
		res.record(nil, sgAbstain(fmt.Sprintf(
			"destination %s lies outside the snapshot, so its security groups were not evaluated",
			opts.DstIP), nil))
	}

	// Return path: the reverse direction walked as a Flow of its own, because
	// routing is per-direction and a forward path says nothing about the way
	// back.
	res.ReturnPath = evalReturnPath(g, opts, slice, srcSub, dstSub, dstOK)
	// Compared against the forward hops recorded so far, which is every
	// forwarding decision the flow made: the reverse NACL below is a policy
	// check, not a next hop.
	res.ReturnPath.Asymmetry = evalAsymmetry(g, res.Hops, res.ReturnPath)
	res.recordReturn(res.ReturnPath)

	// Return-path NACL (stateless reverse direction), on the same reverse Flow.
	if hop := evalReturnNACL(g, srcSub, dstSub, dstOK, res.ReturnPath.Flow); hop != nil {
		res.Hops = append(res.Hops, *hop)
		if !hop.Allowed {
			res.Verdict = VerdictBlocked
			res.BlockedAt = hop
			return res, nil
		}
	}

	if !res.Authoritative() {
		res.Notes = append(res.Notes, fmt.Sprintf("verdict %s is not authoritative: %d layer(s) abstained", res.Verdict, len(res.Abstentions)))
	}
	return res, nil
}

// record files one layer outcome. Exactly one of hop and abstain is expected to
// be set; a nil pair records nothing. It reports whether the walk should stop,
// which happens only when the hop blocked the flow.
func (r *Result) record(hop *Hop, abstain *model.LayerResult) bool {
	if abstain != nil {
		r.Abstentions = append(r.Abstentions, *abstain)
	}
	if hop == nil {
		return false
	}
	r.Hops = append(r.Hops, *hop)
	if hop.Allowed {
		return false
	}
	r.Verdict = VerdictBlocked
	r.BlockedAt = hop
	return true
}

// recordReturn files the return-direction outcome.
//
// An abstention joins the abstention list, so a return direction that could not
// be walked is never read as one that works, and the verdict stops being
// authoritative. A blocked return direction is stated as a note and left out of
// the forward verdict: forward packets still arrive, and promoting the return
// direction to primary blocker is the Correlator's call.
//
// An asymmetric path is a note and nothing more. Both directions carry traffic,
// so there is no verdict to change; whether the asymmetry explains a failure
// depends on the Symptom, which this walk does not see.
func (r *Result) recordReturn(rp *ReturnPath) {
	if rp == nil {
		return
	}
	r.Notes = append(r.Notes, rp.Notes...)
	if rp.Asymmetry.Asymmetric() {
		r.Notes = append(r.Notes, rp.Asymmetry.Summary)
		// The comparison is evidence for the return direction, so it is cited
		// there: a consumer reading the RETURN_PATH finding sees both next hops
		// without having to reach into the walk.
		rp.Result.Citations = append(rp.Result.Citations, rp.Asymmetry.Citations...)
	}
	switch rp.Result.Verdict {
	case model.VerdictAbstain:
		r.Abstentions = append(r.Abstentions, rp.Result)
	case model.VerdictBlocked:
		detail := "no return route"
		if rp.BlockedAt != nil {
			detail = fmt.Sprintf("%s %s: %s", rp.BlockedAt.Layer, rp.BlockedAt.Resource, rp.BlockedAt.Detail)
		}
		r.Notes = append(r.Notes, fmt.Sprintf(
			"return direction is blocked at %s; the forward verdict does not account for the response path", detail))
	}
}

func buildSlice(opts Options) flow.Slice {
	src := flow.NewPrefixSet(netip.PrefixFrom(opts.SrcIP, opts.SrcIP.BitLen()))
	dst := flow.NewPrefixSet(netip.PrefixFrom(opts.DstIP, opts.DstIP.BitLen()))
	ports := flow.AllPorts()
	if opts.Proto.HasPorts() && opts.Port > 0 {
		ports = flow.SinglePort(uint16(opts.Port))
	}
	return flow.NewSlice(src, dst, opts.Proto, ports)
}

func intersectsSlice(set flow.Set, q flow.Slice) bool {
	for _, s := range set.Slices {
		if s.Proto != q.Proto && s.Proto != flow.ProtoAny && q.Proto != flow.ProtoAny {
			continue
		}
		if !s.Src.Intersect(q.Src).IsEmpty() && !s.Dst.Intersect(q.Dst).IsEmpty() {
			if !q.Proto.HasPorts() || !s.DstPorts.Intersect(q.DstPorts).IsEmpty() {
				return true
			}
		}
	}
	return false
}
