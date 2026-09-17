package ops

import (
	"fmt"
	"sort"
	"strings"

	"github.com/jajera/aws-netpath/internal/flow"
	"github.com/jajera/aws-netpath/internal/model"
	"github.com/jajera/aws-netpath/internal/nfw"
)

// FirewallRequest evaluates a flow against firewall policy alone, leaving
// routing aside.
type FirewallRequest struct {
	SnapshotPath string
	From         string
	To           string
	Proto        string
	// Ports accepts a set, such as "443" or "80-443" or "22,443", because a
	// rule matching part of the set splits the flow rather than deciding it.
	Ports string
	// Only restricts evaluation to firewalls whose name or ID contains this
	// substring. Empty evaluates every firewall in the snapshot.
	Only string
}

// FirewallResult holds the evaluated flow alongside one result per firewall.
// The flow is carried because a caller rendering the result needs the question
// as well as the answers.
type FirewallResult struct {
	Flow    flow.Slice   `json:"flow"`
	Results []nfw.Result `json:"results"`
}

// Blocked reports whether any firewall denied part of the flow.
func (r *FirewallResult) Blocked() bool {
	for _, res := range r.Results {
		if !res.Denied().IsEmpty() {
			return true
		}
	}
	return false
}

// Authoritative reports whether every rule group on the path could be
// evaluated. A single abstention makes the verdict non-authoritative, because
// the unevaluated group might have decided the flow.
func (r *FirewallResult) Authoritative() bool {
	for _, res := range r.Results {
		if len(res.Abstentions) > 0 {
			return false
		}
	}
	return true
}

// Firewall evaluates a flow against the firewall policies in a snapshot.
func Firewall(req FirewallRequest) (*FirewallResult, error) {
	if err := requireFields(
		requiredField{"snapshot", req.SnapshotPath},
		requiredField{"from", req.From},
		requiredField{"to", req.To},
	); err != nil {
		return nil, err
	}

	traffic, err := buildSlice(req.From, req.To, req.Proto, req.Ports)
	if err != nil {
		return nil, err
	}

	snap, err := loadSnapshot(req.SnapshotPath)
	if err != nil {
		return nil, err
	}

	results, err := evaluateAll(snap, traffic, req.Only)
	if err != nil {
		return nil, err
	}
	if len(results) == 0 {
		return nil, fmt.Errorf("no firewalls in the snapshot matched")
	}

	return &FirewallResult{Flow: traffic, Results: results}, nil
}

// evaluateAll runs the flow through every firewall in the snapshot, in a stable
// order so output can be diffed between runs.
func evaluateAll(snap *model.Snapshot, traffic flow.Slice, only string) ([]nfw.Result, error) {
	ids := make([]string, 0, len(snap.Firewalls))
	for id := range snap.Firewalls {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	var out []nfw.Result
	for _, id := range ids {
		fw := snap.Firewalls[id]
		if only != "" && !strings.Contains(fw.Name, only) && !strings.Contains(fw.ID, only) {
			continue
		}

		policy, ok := snap.FirewallPolicies[fw.PolicyARN]
		if !ok {
			return nil, fmt.Errorf("firewall %s references policy %s, which is not in the snapshot", fw.Name, fw.PolicyARN)
		}

		res, err := nfw.Evaluate(policy, snap.RuleGroups, traffic)
		if err != nil {
			return nil, fmt.Errorf("firewall %s: %w", fw.Name, err)
		}
		res.Firewall = DisplayName(fw.Name, fw.ID)
		if res.Region == "" {
			res.Region = fw.Region
		}
		out = append(out, res)
	}
	return out, nil
}
