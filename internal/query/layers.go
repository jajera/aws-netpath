package query

// The seam between the path walk and the Correlator.
//
// The walk reports hops, which are AWS-shaped: a subnet route table, a transit
// gateway attachment, an inspection VPC hand-off. The Correlator reasons about
// Layers, which are decision-shaped and ordered along a Flow. This file is the
// only place that maps one onto the other.
//
// Nothing here decides precedence, aggregates a layer, or promotes a finding.
// That logic lives in the Correlator and stays there: a blocked return direction
// under a permitted forward direction becomes the primary blocker because
// RETURN_PATH is the earliest blocking Layer in flow order, and re-deriving that
// here would give the same conclusion a second implementation to disagree with.

import (
	"fmt"

	"github.com/jajera/aws-netpath/internal/model"
)

// LayerResults projects the walk onto the Layer findings the Correlator consumes.
//
// Several findings for one Layer are expected and are left as they are: a flow
// crossing two inspection points produces two firewall findings, and a path with
// six routing decisions produces six route findings. Collapsing them into one
// verdict per Layer is aggregation, which the Correlator does.
func (r *Result) LayerResults() []model.LayerResult {
	var out []model.LayerResult

	for _, h := range r.Path() {
		if res, ok := hopLayerResult(h); ok {
			out = append(out, res)
		}
	}

	// A return direction that abstained is already on the abstention list, since
	// that is how the walk stops a permitted verdict resting on it from reading
	// as authoritative. The return finding is emitted once, from the return path
	// itself, so the same abstention does not arrive twice under one Layer.
	for _, a := range r.Abstentions {
		if a.Layer == model.LayerReturnPath {
			continue
		}
		out = append(out, a)
	}

	if r.ReturnPath != nil {
		out = append(out, r.ReturnPath.Result)
	}
	return out
}

// Observations returns the findings that carry no verdict of their own.
func (r *Result) Observations() []model.Observation {
	if r.ReturnPath == nil {
		return nil
	}
	if o, ok := r.ReturnPath.Asymmetry.Observation(); ok {
		return []model.Observation{o}
	}
	return nil
}

// hopLayerResult turns one hop into a Layer finding. The second return value is
// false for a hop that belongs to no Layer.
func hopLayerResult(h Hop) (model.LayerResult, bool) {
	// A hop reporting that an address is outside the snapshot is not a network
	// decision: nothing blocked the traffic, the tool simply cannot see that
	// address space. Reporting it as a blocked Layer would turn missing
	// collection into a network finding, so it abstains and says why.
	if h.Layer == hopLayerSnapshot {
		return model.LayerResult{
			Layer:   model.LayerResolution,
			Verdict: model.VerdictAbstain,
			Reason:  h.Detail,
		}, true
	}

	layer, ok := hopLayer(h.Layer)
	if !ok {
		return model.LayerResult{}, false
	}

	verdict := model.VerdictBlocked
	if h.Allowed {
		verdict = model.VerdictPass
	}
	return model.LayerResult{
		Layer:     layer,
		Verdict:   verdict,
		Citations: hopCitations(h),
	}, true
}

// hopLayerSnapshot is the pseudo-layer a walk reports when an endpoint address is
// not in the snapshot at all.
const hopLayerSnapshot = "snapshot"

// hopLayer maps a walk hop onto the Layer the Correlator reasons about.
//
// Every forwarding hop is a ROUTE decision. A subnet route table, a transit
// gateway route table, an attachment, and an inspection VPC hand-off are all
// steps in resolving where the packet goes next, and an operator who is told
// "route" then reads the hops to find out which one.
//
// The reverse NACL is RETURN_PATH rather than NACL, deliberately. It is the
// stateless return direction evaluated on the reverse Flow; reporting it as NACL
// would place it before the forward Layers in flow order and read as the forward
// NACL having dropped traffic that in fact left the source cleanly.
func hopLayer(layer string) (model.Layer, bool) {
	switch layer {
	case "route", "tgw", "tgw-route", "tgw-peering", "inspection-vpc":
		return model.LayerRoute, true
	case "nacl":
		return model.LayerNACL, true
	case "nacl-return":
		return model.LayerReturnPath, true
	case "sg":
		return model.LayerSecurityGroup, true
	case "firewall":
		return model.LayerFirewall, true
	case "destination":
		return model.LayerResolution, true
	default:
		return "", false
	}
}

// hopCitationKind maps a hop onto the Citation vocabulary.
func hopCitationKind(layer string) string {
	switch layer {
	case "nacl", "nacl-return":
		return "nacl"
	case "sg":
		return sgCitationKind
	case "firewall":
		return "nfw_rule"
	default:
		return returnCitationKind
	}
}

// hopCitations is the evidence for a hop. A hop that carries its own citations
// keeps them; the rest are cited on the resource that decided them, because a
// finding without a citation is not emittable and a routing decision always has
// a resource behind it.
func hopCitations(h Hop) []model.Citation {
	if len(h.Citations) > 0 {
		return h.Citations
	}
	identifier := h.Resource
	if identifier == "" {
		identifier = h.Layer
	}
	return []model.Citation{{
		Kind:       hopCitationKind(h.Layer),
		Identifier: identifier,
		Detail:     fmt.Sprintf("%s: %s", h.Layer, hopDetail(h)),
	}}
}
