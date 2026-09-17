package query

import (
	"fmt"

	"github.com/jajera/aws-netpath/internal/flow"
	"github.com/jajera/aws-netpath/internal/model"
	"github.com/jajera/aws-netpath/internal/nfw"
)

func (w *pathWalker) evalFirewall(hops []Hop, fw *model.Firewall) ([]Hop, *Hop) {
	policy := w.g.snap.FirewallPolicies[fw.PolicyARN]
	if policy == nil {
		h := Hop{Layer: "firewall", Region: fw.Region, Resource: fw.Name, Detail: "policy missing from snapshot", Allowed: false}
		return append(hops, h), &h
	}
	nfwRes, err := nfw.Evaluate(policy, w.g.snap.RuleGroups, w.slice)
	if err != nil {
		h := Hop{Layer: "firewall", Region: fw.Region, Resource: fw.Name, Detail: err.Error(), Allowed: false}
		return append(hops, h), &h
	}
	nfwRes.Firewall = fw.Name
	nfwRes.Region = fw.Region
	if w.firewalls != nil {
		*w.firewalls = append(*w.firewalls, nfwRes)
	}

	permitted := intersectsSlice(nfwRes.Permitted(), w.slice)
	denied := intersectsSlice(nfwRes.Denied(), w.slice)
	hop := Hop{
		Layer: "firewall", Region: fw.Region, Resource: fw.Name,
		Allowed: permitted && !denied,
	}
	if hop.Allowed {
		hop.Detail = "permitted by policy"
		for _, d := range nfwRes.Decisions {
			if d.Verdict == nfw.Pass && intersectsSlice(flow.NewSet(d.Slice), w.slice) {
				hop.Detail = d.Rule.String()
				break
			}
		}
	} else {
		for _, d := range nfwRes.Decisions {
			if d.Verdict == nfw.Drop && intersectsSlice(flow.NewSet(d.Slice), w.slice) {
				if d.ByDefault {
					hop.Detail = fmt.Sprintf("default action %s", d.Rule.Action)
				} else {
					hop.Detail = d.Rule.String()
				}
				break
			}
		}
		if hop.Detail == "" {
			hop.Detail = "denied by policy"
		}
	}
	hops = append(hops, hop)
	if !hop.Allowed {
		return hops, &hop
	}
	return hops, nil
}
