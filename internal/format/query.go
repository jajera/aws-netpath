package format

// Projecting a reachability walk onto the same three sections.
//
// The slots hold what a walk found — the hop that stopped the traffic, the hops
// that let it through, the layers that could not be read — in the order every
// other report uses, so a reader who learned the layout on a diagnosis meets the
// answer, then what has been ruled out, then what could not be established.
//
// The cleared hops carry no citations. A walk that reached its destination met a
// route table, two security groups, two NACLs, and a firewall on the way, and each
// of them cites the rule it matched; that is the right depth for a diagnosis and
// the wrong depth for "does this get through", where the reader wants the route
// the traffic took. The evidence is not lost — the hop's own detail names the
// resource and what it decided, and the blocking hop, the abstentions, and every
// firewall decision keep their citations in full.
//
// The return direction and the firewall decisions are their own sections rather
// than being folded into the forward walk. The reverse direction is a distinct
// Flow — asymmetry through a stateful component is a stall rather than a block —
// and a report that mixed the two would leave a reader unable to tell which
// direction a hop belonged to.

import (
	"fmt"
	"strings"

	"github.com/jajera/aws-netpath/internal/model"
	"github.com/jajera/aws-netpath/internal/nfw"
	"github.com/jajera/aws-netpath/internal/query"
)

// KindQuery names a reachability walk in the JSON output.
const KindQuery Kind = "query"

// Outcome strings for a walk.
const (
	// outcomeNoWalk is what an absent result says, rather than a permit it did
	// not earn.
	outcomeNoWalk = "NO PATH WALKED"
	// outcomeUnknown is the verdict that is not a network verdict. Requirement
	// 6.4: an address outside every collected subnet means no path was walked, and
	// the fix is a re-collection rather than a policy change.
	outcomeUnknown = "UNKNOWN — the address is not in any collected subnet, so no path was walked"
)

// FromQuery projects a reachability walk onto a Report.
func FromQuery(q *query.Result) Report {
	if q == nil {
		return Report{Kind: KindQuery, Outcome: outcomeNoWalk}
	}

	r := Report{
		Kind:          KindQuery,
		Flow:          q.Flow.String(),
		Outcome:       queryOutcome(q),
		Authoritative: q.Authoritative(),
		Notes:         dedupe(q.Notes),
	}
	path := q.Path()
	r.Finding = blockingHopSection(q)
	r.Cleared = clearedHopSection(path)
	r.Unresolved = walkAbstentionSection(q.Abstentions)
	r.Extra = walkExtras(q)
	if !r.Authoritative {
		r.Notice = notEvaluatedLayers(q.Abstentions)
	}
	return r
}

// queryOutcome states the verdict in one line, naming the hop where a block was
// decided.
func queryOutcome(q *query.Result) string {
	switch {
	case q.Verdict == query.VerdictUnknown:
		return outcomeUnknown
	case q.Verdict != query.VerdictBlocked:
		return outcomePermitted
	case q.BlockedAt != nil:
		return fmt.Sprintf(outcomeBlocked, hopSubject(*q.BlockedAt))
	default:
		return fmt.Sprintf(outcomeBlocked, "an unnamed hop")
	}
}

// blockingHopSection is section one: the hop that stopped the traffic, with the
// resource and the rule behind it.
func blockingHopSection(q *query.Result) *Section {
	if q.BlockedAt == nil {
		return &Section{
			Title: "blocking hop",
			Note:  "no hop was shown to block this flow",
		}
	}
	blocked := *q.BlockedAt
	s := &Section{Title: fmt.Sprintf("blocking hop — %s", blocked.Layer)}
	s.add(hopRow(blocked))
	s.add(citationRows(blocked.Citations)...)
	return s
}

// clearedHopSection is section two: the hops that let the traffic through, one
// row each.
func clearedHopSection(path []query.Hop) *Section {
	s := &Section{Title: "cleared hops"}
	for _, h := range path {
		if h.Allowed {
			s.add(hopRow(h))
		}
	}
	if len(s.Rows) == 0 {
		s.Note = "no hop was evaluated as permitting this flow"
		return s
	}
	s.Note = "rule citations omitted: use diagnose for the evidence behind a hop that cleared"
	return s
}

// walkAbstentionSection is section three: the layers the walk could not evaluate,
// with their reasons and the evidence the reason rests on.
func walkAbstentionSection(abstentions []model.LayerResult) *Section {
	s := &Section{Title: "abstentions"}
	for _, res := range sortResults(abstentions) {
		s.add(layerRows(res)...)
	}
	if len(s.Rows) == 0 {
		s.Note = "no layer abstained"
		return s
	}
	s.Note = "a layer that could not be evaluated is never reported as a pass"
	return s
}

// walkExtras renders the findings that sit outside the forward walk: the reverse
// direction, and the firewall policy each inspection point applied.
func walkExtras(q *query.Result) []Section {
	var out []Section
	if s, ok := returnPathSection(q.ReturnPath); ok {
		out = append(out, s)
	}
	if s, ok := firewallDecisionSection(q.Firewalls); ok {
		out = append(out, s)
	}
	return out
}

// returnPathSection renders the reverse direction as its own Flow.
//
// The asymmetry finding leads the note rather than the rows, because asymmetry is
// a property of the pair of directions rather than of any one hop: requirement 7.3
// asks for an asymmetric path through a stateful component to be flagged as the
// probable cause of a stall, and that is a statement about the section.
func returnPathSection(rp *query.ReturnPath) (Section, bool) {
	if rp == nil {
		return Section{}, false
	}

	s := Section{Title: fmt.Sprintf("return path — %s", rp.Flow)}
	s.add(Row{
		Layer:   string(rp.Result.Layer),
		Verdict: verdictLabel(rp.Result.Verdict),
		Detail:  rp.Result.Reason,
	})
	for _, h := range rp.Path() {
		s.add(hopRow(h))
	}
	if a := rp.Asymmetry; a.Asymmetric() {
		s.add(citationRows(a.Citations)...)
		s.Note = a.Summary
		if a.StatefulAsymmetry() {
			s.Note = a.Summary + "; the path crosses a component that keeps per-connection state, which is the combination that establishes a connection and then stalls it"
		}
	}
	return s, true
}

// firewallDecisionSection renders every firewall decision the walk met, with the
// rule behind it. Requirement 14.4, kept out of the forward hops so a walk with
// two inspection points reads as two policies rather than as one long path.
func firewallDecisionSection(results []nfw.Result) (Section, bool) {
	if len(results) == 0 {
		return Section{}, false
	}

	s := Section{Title: "firewall policy"}
	for _, res := range results {
		s.add(decisionRows(res, nfw.Drop)...)
		s.add(decisionRows(res, nfw.Pass)...)
		s.add(firewallAbstentionRows(res)...)
	}
	if len(s.Rows) == 0 {
		return Section{}, false
	}
	return s, true
}

// hopRow renders one hop: the layer that decided, the resource that decided it,
// and what it decided.
func hopRow(h query.Hop) Row {
	verdict := labelDeny
	if h.Allowed {
		verdict = labelAllow
	}
	return Row{
		Layer:   h.Layer,
		Verdict: verdict,
		Subject: hopSubject(h),
		Detail:  hopDetail(h),
	}
}

// hopSubject identifies a hop the way an operator would look it up: the resource
// that decided, in the region it lives in.
func hopSubject(h query.Hop) string {
	subject := h.Resource
	if subject == "" {
		subject = h.Layer
	}
	if h.Region != "" {
		return fmt.Sprintf("%s (%s)", subject, h.Region)
	}
	return subject
}

// hopDetail describes what a hop decided, and where it forwarded to.
//
// The next hop is appended rather than left to the citations because it is the
// part the two directions are expected to agree on, and a reader comparing the
// forward and return sections by eye needs it on the row.
func hopDetail(h query.Hop) string {
	if h.NextHop == "" {
		return h.Detail
	}
	via := fmt.Sprintf("via %s", h.NextHop)
	if h.Detail == "" {
		return via
	}
	return fmt.Sprintf("%s (%s)", h.Detail, via)
}

// notEvaluatedLayers states why a walk's verdict cannot be relied on.
// Requirement 14.6. It names the layers and their reasons, because the reader's
// next move is to go and evaluate whichever one could not be read.
func notEvaluatedLayers(abstentions []model.LayerResult) string {
	if len(abstentions) == 0 {
		return "this verdict is not authoritative: it rests on a layer that could not be evaluated"
	}
	parts := make([]string, 0, len(abstentions))
	for _, res := range sortResults(abstentions) {
		parts = append(parts, fmt.Sprintf("%s (%s)", res.Layer, res.Reason))
	}
	return fmt.Sprintf("this verdict is not authoritative: it rests on %s — %s; a layer that could not be evaluated may be the one blocking this flow",
		abstentionCount(len(parts)), strings.Join(parts, "; "))
}
