package query

import (
	"github.com/jajera/aws-netpath/internal/flow"
	"github.com/jajera/aws-netpath/internal/model"
)

// evalReturnNACL checks whether response traffic can return past the stateless
// NACLs. reverse is the reverse Flow built by returnFlow, shared with the
// return-path walk so both halves of the return direction are asking about the
// same traffic.
//
// Security groups need no equivalent: they are stateful, so the response to a
// permitted flow needs no rule of its own. NACLs are not, which is why the
// reverse direction is evaluated here rule by rule.
func evalReturnNACL(g *graph, srcSub, dstSub *model.Subnet, dstKnown bool, reverse flow.Slice) *Hop {
	if dstKnown && dstSub != nil {
		if hop := evalNACL(g.nacl(dstSub.NACLID), reverse, true); hop != nil {
			hop.Layer = "nacl-return"
			hop.Detail = "return: " + hop.Detail
			if !hop.Allowed {
				return hop
			}
		}
	}

	if hop := evalNACL(g.nacl(srcSub.NACLID), reverse, false); hop != nil {
		hop.Layer = "nacl-return"
		hop.Detail = "return: " + hop.Detail
		if !hop.Allowed {
			return hop
		}
	}
	return nil
}
