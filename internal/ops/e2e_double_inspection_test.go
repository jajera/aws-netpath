package ops

// Two inspection points on one flow, from the inherited snapshot to the rendered
// report.
//
// internal/query's regression cases already pin the end-to-end verdict for this
// fixture: tcp/443 from the east spoke to the west edge VPC comes back BLOCKED at
// nfw-prod-usw2. That assertion is satisfied by a walk that reported one firewall
// verdict, and requirement 5.6 asks for two. The failure it cannot see is the
// aggregation: a walk that folded both inspection points into the single verdict
// that decided the flow would keep every regression case green while telling an
// operator that "the firewall dropped it" — leaving them to work out for
// themselves which of the two firewalls on a cross-region path they should be
// reading, and whether the other one had already passed the traffic.
//
// So what this adds is the pair. Both points are crossed, each reports its own
// verdict, the two verdicts differ, each carries the policy that produced it, and
// the pair survives the projection onto the Formatter and the rendering out of it.
//
// The topology is the inherited example rather than one authored here: an east
// spoke, an inspection VPC either side of a transit gateway peering, and a west
// edge VPC. The east policy passes tcp/443 by a rule that names it; the west
// policy carries no rule for it and drops it by default action. That asymmetry is
// what makes a pass and a drop on one flow observable at all.

import (
	"strings"
	"testing"

	"github.com/jajera/aws-netpath/internal/format"
	"github.com/jajera/aws-netpath/internal/nfw"
	"github.com/jajera/aws-netpath/internal/query"
)

// The inherited double-inspection fixture and the flow that crosses both of its
// inspection points: an address in the east spoke to one in the west edge VPC,
// on the port the east policy names and the west policy does not.
const (
	twoPointFixture = "../query/testdata/double-inspection.json"
	twoPointSrc     = "10.30.32.10"
	twoPointDst     = "10.30.192.10"
	twoPointPort    = 443
)

// The two inspection points, in the order the flow meets them. Named because
// every assertion here is about telling them apart: a verdict attributed to the
// wrong firewall sends an operator to the wrong region.
const (
	firstFirewall        = "nfw-prod-use1"
	firstFirewallRegion  = "us-east-1"
	secondFirewall       = "nfw-prod-usw2"
	secondFirewallRegion = "us-west-2"
)

// Requirement 5.6: a flow crossing two inspection points gets a verdict at each.
// The first passes it, the second drops it, and both verdicts are cited with the
// policy behind them — in the result and in the report.
//
// Validates: Requirements 5.6, 14.4
func TestDoubleInspectionReportsAVerdictAtEachPoint(t *testing.T) {
	res, err := Query(QueryRequest{
		SnapshotPath: twoPointFixture,
		From:         twoPointSrc,
		To:           twoPointDst,
		Proto:        "tcp",
		Port:         twoPointPort,
	})
	if err != nil {
		t.Fatalf("Query() error = %v", err)
	}

	// The premise first. "A verdict for each" is only a claim about two inspection
	// points if the flow actually crossed two, and the walk is what establishes
	// that: two firewall hops, in two regions, on the way to one destination.
	var crossed []query.Hop
	for _, h := range res.Path() {
		if h.Layer == "firewall" {
			crossed = append(crossed, h)
		}
	}
	if len(crossed) != 2 {
		t.Fatalf("the walk crossed %d inspection point(s), want 2:\n%s", len(crossed), renderReport(t, QueryReport(res), format.ModeText))
	}
	if crossed[0].Resource != firstFirewall || crossed[1].Resource != secondFirewall {
		t.Fatalf("inspection points crossed = %s then %s, want %s then %s",
			crossed[0].Resource, crossed[1].Resource, firstFirewall, secondFirewall)
	}
	if crossed[0].Region == crossed[1].Region {
		t.Errorf("both inspection points are in %s; this fixture places one either side of a region boundary", crossed[0].Region)
	}

	// One evaluation per point, not one for the flow. A single result here is the
	// aggregation requirement 5.6 forbids, and it is the failure this test exists
	// for: the walk would still report BLOCKED, and the pass at the first firewall
	// would be gone.
	if len(res.Firewalls) != 2 {
		t.Fatalf("%d firewall verdict(s) for a flow crossing two inspection points, want 2: %+v", len(res.Firewalls), res.Firewalls)
	}
	first := firewallResult(t, res.Firewalls, firstFirewall)
	second := firewallResult(t, res.Firewalls, secondFirewall)
	if first.Region != firstFirewallRegion || second.Region != secondFirewallRegion {
		t.Errorf("verdict regions = %s and %s, want %s and %s", first.Region, second.Region, firstFirewallRegion, secondFirewallRegion)
	}
	if first.Policy == second.Policy {
		t.Errorf("both verdicts name policy %q; two inspection points apply two policies", first.Policy)
	}

	// The first passes. Asserted on both halves of the evaluation, because a
	// verdict that permitted some of the traffic and dropped the rest is not a
	// pass, and only the drop set can say so.
	if !first.Denied().IsEmpty() {
		t.Errorf("%s denied part of the flow: %s", firstFirewall, first.Denied().String())
	}
	if first.Permitted().IsEmpty() {
		t.Errorf("%s permitted none of the flow, so it reported no pass to cite", firstFirewall)
	}

	// The second drops it, and the flow stops there rather than at some later
	// layer that would leave the second point's verdict unexplained.
	if second.Denied().IsEmpty() {
		t.Errorf("%s denied none of the flow: %+v", secondFirewall, second.Decisions)
	}
	if res.Verdict != query.VerdictBlocked {
		t.Errorf("verdict = %s, want %s at the second inspection point", res.Verdict, query.VerdictBlocked)
	}
	if res.BlockedAt == nil || res.BlockedAt.Resource != secondFirewall {
		t.Errorf("blocked at %+v, want %s", res.BlockedAt, secondFirewall)
	}

	// And the two verdicts differ. The pair is the finding: two points reported
	// separately but with the same verdict would satisfy every assertion above
	// while hiding the one thing an operator needs, which is that the traffic got
	// through the first firewall and died at the second.
	firstVerdict, secondVerdict := first.LayerResult().Verdict, second.LayerResult().Verdict
	if firstVerdict == secondVerdict {
		t.Errorf("both inspection points reported %s; this flow passes %s and is dropped by %s",
			firstVerdict, firstFirewall, secondFirewall)
	}

	// Requirement 14.4 on the citation the first point produced: a rule decided
	// this traffic, so the rule group, its priority, and its SID are all on the
	// evidence an operator would go and read.
	pass := decision(t, first, nfw.Pass)
	if pass.ByDefault {
		t.Fatalf("%s passed the flow by default action, so the fixture provides no rule to cite: %+v", firstFirewall, pass)
	}
	for _, part := range []struct {
		name, value string
	}{
		{"rule group", pass.Rule.GroupName},
		{"SID", pass.Rule.SID},
	} {
		if part.value == "" {
			t.Errorf("the citation at %s carries no %s: %+v", firstFirewall, part.name, pass.Rule)
		}
	}
	if pass.Rule.Priority <= 0 {
		t.Errorf("the citation at %s carries no priority: %+v", firstFirewall, pass.Rule)
	}
	// All three in the identifier a report renders, rather than only in the fields
	// behind it. A citation is evidence to the extent that the reader can look it
	// up, and the reader gets the rendered string.
	identifier := pass.Citation().Identifier
	for _, want := range []string{pass.Rule.GroupName, "sid " + pass.Rule.SID, "priority"} {
		if !strings.Contains(identifier, want) {
			t.Errorf("citation %q at %s omits %q", identifier, firstFirewall, want)
		}
	}

	// Requirement 5.3 on the second: no rule named this traffic, so the policy
	// default action is the evidence, and it is called what it is. "Dropped by the
	// default action" and "dropped by a rule" send an operator to different places
	// in the policy.
	drop := decision(t, second, nfw.Drop)
	if !drop.ByDefault {
		t.Errorf("%s dropped the flow by rule %+v; this fixture drops it by default action", secondFirewall, drop.Rule)
	}
	if detail := drop.Citation().Detail; !strings.Contains(detail, "default action") {
		t.Errorf("the citation at %s does not name the policy default action: %q", secondFirewall, detail)
	}

	// The projection. Requirement 14.4 is a claim about the Formatter, so the
	// evidence has to arrive at it: one row per point, each with its own verdict
	// and its own policy citation, in a section of their own rather than folded
	// into the forward hops.
	report := QueryReport(res)
	policy := extraSection(t, report, "firewall policy")
	if len(policy.Rows) != 2 {
		t.Fatalf("the firewall policy section has %d row(s) for two inspection points: %+v", len(policy.Rows), policy.Rows)
	}
	for i, want := range []struct {
		firewall string
		verdict  string
	}{
		{firstFirewall, "ALLOW"},
		{secondFirewall, "DENY"},
	} {
		row := policy.Rows[i]
		if row.Layer != want.firewall || row.Verdict != want.verdict {
			t.Errorf("firewall policy row %d = %s %s, want %s %s", i, row.Layer, row.Verdict, want.firewall, want.verdict)
		}
		if row.Subject == "" {
			t.Errorf("the row for %s carries no policy citation: %+v", want.firewall, row)
		}
	}
	if got := policy.Rows[0].Subject; !strings.Contains(got, pass.Rule.GroupName) || !strings.Contains(got, pass.Rule.SID) {
		t.Errorf("the row for %s cites %q, want the rule group and SID that decided the traffic", firstFirewall, got)
	}

	// And out the other side. A projection that carried both verdicts and a
	// renderer that printed one would leave the operator reading a single firewall
	// verdict, which is the outcome every assertion above is guarding against.
	for _, mode := range []format.Mode{format.ModeText, format.ModeMarkdown, format.ModeJSON} {
		t.Run(string(mode), func(t *testing.T) {
			got := renderReport(t, report, mode)
			for _, want := range []string{firstFirewall, secondFirewall} {
				if !strings.Contains(got, want) {
					t.Errorf("the %s rendering does not name %s:\n%s", mode, want, got)
				}
			}
			// The rule the first point applied is in the rendering, whichever
			// format the reader asked for: requirement 14.3 lets them choose, and
			// 14.4 does not vary with the choice.
			if !strings.Contains(got, pass.Rule.GroupName) {
				t.Errorf("the %s rendering omits the rule group that passed the flow at %s:\n%s", mode, firstFirewall, got)
			}
		})
	}

	// Scoped to the section that holds the pair, on the default rendering. A
	// whole-report search would be satisfied by the two verdicts appearing
	// anywhere — including by the blocking hop and a cleared hop, which is the
	// aggregated reading this section exists to replace.
	section := textSection(t, renderReport(t, report, format.ModeText), "firewall policy")
	if !strings.Contains(section, "[ALLOW] "+firstFirewall) {
		t.Errorf("the firewall policy section does not report a pass at %s:\n%s", firstFirewall, section)
	}
	if !strings.Contains(section, "[DENY ] "+secondFirewall) {
		t.Errorf("the firewall policy section does not report a drop at %s:\n%s", secondFirewall, section)
	}
	if got := strings.Count(section, "[ALLOW]") + strings.Count(section, "[DENY "); got != 2 {
		t.Errorf("the firewall policy section carries %d verdict(s), want one per inspection point:\n%s", got, section)
	}
}

// firewallResult returns the verdict one named inspection point reported. A
// lookup by name rather than by position, because "the second firewall dropped
// it" is a claim about a firewall and not about a slice index.
func firewallResult(t *testing.T, results []nfw.Result, firewall string) nfw.Result {
	t.Helper()
	for _, res := range results {
		if res.Firewall == firewall {
			return res
		}
	}
	t.Fatalf("no verdict was reported for %s: %+v", firewall, results)
	return nfw.Result{}
}

// decision returns the first decision one firewall reached with the given
// verdict, so an assertion about the evidence can name the rule behind it.
func decision(t *testing.T, res nfw.Result, want nfw.Verdict) nfw.Decision {
	t.Helper()
	for _, d := range res.Decisions {
		if d.Verdict == want {
			return d
		}
	}
	t.Fatalf("%s recorded no %s decision: %+v", res.Firewall, want, res.Decisions)
	return nfw.Decision{}
}

// extraSection returns one of a report's extra sections by title.
func extraSection(t *testing.T, report format.Report, title string) format.Section {
	t.Helper()
	for _, s := range report.Extra {
		if s.Title == title {
			return s
		}
	}
	t.Fatalf("the report carries no %q section: %+v", title, report.Extra)
	return format.Section{}
}
