package query

import (
	"github.com/jajera/aws-netpath/internal/flow"
	"github.com/jajera/aws-netpath/internal/model"
	"github.com/jajera/aws-netpath/internal/nfw"
)

// pathWalker carries per-query state through a route walk.
type pathWalker struct {
	g            *graph
	slice        flow.Slice
	skipFirewall bool
	firewalls    *[]nfw.Result
	// skippedFirewalls names the inspection points the walk crossed without
	// evaluating their policy. The return-path walk supplies it so it can
	// abstain rather than report a clean pass through a firewall it never
	// evaluated; a nil pointer records nothing.
	skippedFirewalls *[]string
}

// recordSkippedFirewall notes an inspection point the walk crossed without
// evaluating.
func (w *pathWalker) recordSkippedFirewall(fw *model.Firewall) {
	if w.skippedFirewalls == nil || fw == nil {
		return
	}
	name := fw.Name
	if name == "" {
		name = fw.ID
	}
	for _, seen := range *w.skippedFirewalls {
		if seen == name {
			return
		}
	}
	*w.skippedFirewalls = append(*w.skippedFirewalls, name)
}
