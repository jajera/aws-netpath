package diffsnap

// Diff tests.
//
// Every identifier is a placeholder and every address is RFC 1918 or RFC 5737
// documentation space, so a fixture can never carry an environment detail out of
// the repository.
//
// The fixtures are built by mutating a copy of one base Snapshot rather than by
// writing two Snapshots out in full. A diff test whose two sides are written
// independently tends to differ in ways the author did not intend, and then it
// passes for the wrong reason.

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/jajera/aws-netpath/internal/model"
)

// Placeholder scopes. Two accounts and two regions, because grouping is what
// requirement 11.2 asks for and a single-scoped fixture cannot show it.
const (
	accountA = "111122223333"
	accountB = "444455556666"
	regionA  = "ap-southeast-2"
	regionB  = "us-east-1"
)

const (
	vpcA      = "vpc-0aaa1111bbbb2222c"
	vpcB      = "vpc-0ddd3333eeee4444f"
	subnetA   = "subnet-0123456789abcdef0"
	subnetB   = "subnet-0fedcba9876543210"
	sgA       = "sg-0111111111111111a"
	routeTblA = "rtb-0aaa1111bbbb2222c"
)

var (
	capturedBefore = time.Date(2025, 3, 1, 9, 0, 0, 0, time.UTC)
	capturedAfter  = time.Date(2025, 3, 8, 9, 0, 0, 0, time.UTC)
)

func meta(id, name, account, region string) model.Meta {
	return model.Meta{ID: id, Name: name, Account: account, Region: region}
}

func prefix(s string) netip.Prefix { return netip.MustParsePrefix(s) }

// baseSnapshot is the earlier collection: two VPCs in two accounts and regions,
// with a subnet, a route table, and a security group in the first.
func baseSnapshot() *model.Snapshot {
	s := model.NewSnapshot()
	s.SchemaVersion = model.SchemaVersion
	s.CapturedAt = capturedBefore
	s.Accounts = []string{accountA, accountB}
	s.Regions = []string{regionA, regionB}

	s.VPCs[vpcA] = &model.VPC{
		Meta:  meta(vpcA, "app-vpc", accountA, regionA),
		CIDRs: []netip.Prefix{prefix("10.0.0.0/16")},
	}
	s.VPCs[vpcB] = &model.VPC{
		Meta:  meta(vpcB, "hub-vpc", accountB, regionB),
		CIDRs: []netip.Prefix{prefix("10.1.0.0/16")},
	}
	s.Subnets[subnetA] = &model.Subnet{
		Meta:         meta(subnetA, "app-a", accountA, regionA),
		VPCID:        vpcA,
		CIDR:         prefix("10.0.1.0/24"),
		RouteTableID: routeTblA,
	}
	s.RouteTables[routeTblA] = &model.RouteTable{
		Meta:  meta(routeTblA, "app-rt", accountA, regionA),
		VPCID: vpcA,
		Routes: []model.Route{
			{Destination: prefix("10.0.0.0/16"), TargetKind: model.TargetLocal},
		},
	}
	s.SecurityGroups[sgA] = &model.SecurityGroup{
		Meta:  meta(sgA, "app-sg", accountA, regionA),
		VPCID: vpcA,
		Ingress: []model.SGRule{{
			Protocol: "tcp", FromPort: 443, ToPort: 443,
			CIDRs: []netip.Prefix{prefix("10.0.2.0/24")},
		}},
	}
	return s
}

// later returns the base Snapshot with mutate applied, standing in for a
// collection taken after a change.
func later(t *testing.T, mutate func(*model.Snapshot)) *model.Snapshot {
	t.Helper()
	s := baseSnapshot()
	s.CapturedAt = capturedAfter
	if mutate != nil {
		mutate(s)
	}
	return s
}

func diff(t *testing.T, from, to *model.Snapshot) *Result {
	t.Helper()
	res, err := Snapshots(from, to)
	if err != nil {
		t.Fatalf("Snapshots() error = %v", err)
	}
	return res
}

// changes flattens the result in report order, which is the order a reader meets
// them in.
func changes(r *Result) []Change {
	var out []Change
	for _, g := range r.Groups {
		out = append(out, g.Changes...)
	}
	return out
}

// TestSnapshotsReportsAddedRemovedAndModified is requirement 11.1: given two
// Snapshots, report what appeared, what disappeared, and what was altered in
// place.
//
// Modification is asserted down to the field, because "the subnet changed" is not
// something an operator can act on, and because a diff that reports a
// modification without naming a field is one that could be comparing anything.
func TestSnapshotsReportsAddedRemovedAndModified(t *testing.T) {
	type want struct {
		kind   Kind
		typ    string
		id     string
		fields []string
	}

	cases := []struct {
		name   string
		mutate func(*model.Snapshot)
		want   []want
	}{
		{
			name: "a new subnet is added",
			mutate: func(s *model.Snapshot) {
				s.Subnets[subnetB] = &model.Subnet{
					Meta:  meta(subnetB, "app-b", accountA, regionA),
					VPCID: vpcA,
					CIDR:  prefix("10.0.2.0/24"),
				}
			},
			want: []want{{kind: KindAdded, typ: TypeSubnet, id: subnetB}},
		},
		{
			name:   "a deleted security group is removed",
			mutate: func(s *model.Snapshot) { delete(s.SecurityGroups, sgA) },
			want:   []want{{kind: KindRemoved, typ: TypeSecurityGroup, id: sgA}},
		},
		{
			name: "a widened security group rule is modified",
			mutate: func(s *model.Snapshot) {
				s.SecurityGroups[sgA].Ingress[0].CIDRs = []netip.Prefix{prefix("0.0.0.0/0")}
			},
			want: []want{{kind: KindModified, typ: TypeSecurityGroup, id: sgA, fields: []string{"ingress"}}},
		},
		{
			name: "a re-pointed route is modified",
			mutate: func(s *model.Snapshot) {
				s.RouteTables[routeTblA].Routes = append(s.RouteTables[routeTblA].Routes, model.Route{
					Destination: prefix("10.1.0.0/16"),
					TargetKind:  model.TargetTransitGateway,
					TargetID:    "tgw-0abc1234def567890",
				})
			},
			want: []want{{kind: KindModified, typ: TypeRouteTable, id: routeTblA, fields: []string{"routes"}}},
		},
		{
			name: "a renamed and retagged resource is modified in both fields",
			mutate: func(s *model.Snapshot) {
				s.VPCs[vpcA].Name = "app-vpc-renamed"
				s.VPCs[vpcA].Tags = map[string]string{"Environment": "test"}
			},
			want: []want{{kind: KindModified, typ: TypeVPC, id: vpcA, fields: []string{"name", "tags"}}},
		},
		{
			name: "a replaced resource is both a removal and an addition",
			mutate: func(s *model.Snapshot) {
				delete(s.Subnets, subnetA)
				s.Subnets[subnetB] = &model.Subnet{
					Meta:  meta(subnetB, "app-b", accountA, regionA),
					VPCID: vpcA,
					CIDR:  prefix("10.0.1.0/24"),
				}
			},
			want: []want{
				{kind: KindAdded, typ: TypeSubnet, id: subnetB},
				{kind: KindRemoved, typ: TypeSubnet, id: subnetA},
			},
		},
		{
			name:   "an unchanged collection reports nothing",
			mutate: nil,
			want:   nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := diff(t, baseSnapshot(), later(t, tc.mutate))
			got := changes(res)
			if len(got) != len(tc.want) {
				t.Fatalf("got %d changes, want %d: %+v", len(got), len(tc.want), got)
			}
			for i, w := range tc.want {
				c := got[i]
				if c.Kind != w.kind || c.Type != w.typ || c.ID != w.id {
					t.Errorf("change %d = %s %s %s, want %s %s %s",
						i, c.Kind, c.Type, c.ID, w.kind, w.typ, w.id)
				}
				if c.Summary == "" {
					t.Errorf("change %d carries no summary: %+v", i, c)
				}
				assertFields(t, c, w.fields)
			}
			if res.Changed() != (len(tc.want) > 0) {
				t.Errorf("Changed() = %v with %d changes", res.Changed(), len(tc.want))
			}
		})
	}
}

// assertFields checks that a modification names exactly the fields that differ,
// and that any other kind of change names none: an addition has no before value
// to report a field against.
func assertFields(t *testing.T, c Change, want []string) {
	t.Helper()
	if len(c.Fields) != len(want) {
		t.Fatalf("%s %s reports %d changed fields, want %d: %+v", c.Kind, c.ID, len(c.Fields), len(want), c.Fields)
	}
	for i, name := range want {
		f := c.Fields[i]
		if f.Field != name {
			t.Errorf("changed field %d = %q, want %q", i, f.Field, name)
		}
		if f.Before == f.After {
			t.Errorf("field %q is reported as changed with identical values %q", f.Field, f.Before)
		}
	}
}

// TestSnapshotsGroupsByTypeAccountAndRegion is requirement 11.2. A change in the
// account nobody was looking at is the one worth surfacing, so the account and
// region a change belongs to is part of the report rather than something a reader
// has to look up.
func TestSnapshotsGroupsByTypeAccountAndRegion(t *testing.T) {
	res := diff(t, baseSnapshot(), later(t, func(s *model.Snapshot) {
		// One addition in each account, and one modification alongside the
		// addition in the first, so a group carries two kinds.
		s.Subnets[subnetB] = &model.Subnet{
			Meta:  meta(subnetB, "app-b", accountA, regionA),
			VPCID: vpcA, CIDR: prefix("10.0.2.0/24"),
		}
		delete(s.Subnets, subnetA)
		s.VPCs[vpcB].CIDRs = append(s.VPCs[vpcB].CIDRs, prefix("10.2.0.0/16"))
	}))

	want := map[string]struct {
		added, removed, modified int
	}{
		"subnet — " + accountA + " / " + regionA: {added: 1, removed: 1},
		"vpc — " + accountB + " / " + regionB:    {modified: 1},
	}

	got := map[string]struct {
		added, removed, modified int
	}{}
	for _, g := range res.ChangedGroups() {
		got[g.Label()] = struct{ added, removed, modified int }{g.Added, g.Removed, g.Modified}
		for _, c := range g.Changes {
			if c.Account != g.Account || c.Region != g.Region {
				t.Errorf("change %s is in group %s but reports %s / %s", c.ID, g.Label(), c.Account, c.Region)
			}
			if c.Type != g.Type {
				t.Errorf("change %s is of type %s in a group of %s", c.ID, c.Type, g.Type)
			}
		}
	}

	if len(got) != len(want) {
		t.Fatalf("got %d changed groups, want %d: %+v", len(got), len(want), got)
	}
	for label, counts := range want {
		if got[label] != counts {
			t.Errorf("group %s = %+v, want %+v", label, got[label], counts)
		}
	}

	// The scopes that changed nothing are still named, with their resources
	// counted rather than listed.
	for _, g := range res.UnchangedGroups() {
		if g.Unchanged == 0 || g.Changed() {
			t.Errorf("group %s is reported as unchanged with %d resources and %d changes", g.Label(), g.Unchanged, len(g.Changes))
		}
	}
}

// TestSnapshotsIsDeterministic pins the ordering. The Snapshot's resources live in
// maps, so a diff that emitted them in iteration order would render differently on
// every run and no two diffs of the same pair could be compared.
func TestSnapshotsIsDeterministic(t *testing.T) {
	mutate := func(s *model.Snapshot) {
		s.Subnets[subnetB] = &model.Subnet{
			Meta:  meta(subnetB, "app-b", accountA, regionA),
			VPCID: vpcA, CIDR: prefix("10.0.2.0/24"),
		}
		delete(s.SecurityGroups, sgA)
		s.VPCs[vpcA].CIDRs = append(s.VPCs[vpcA].CIDRs, prefix("10.3.0.0/16"))
		s.VPCs[vpcB].Name = "hub-vpc-renamed"
		s.RouteTables[routeTblA].Routes = nil
	}

	first := encodeResult(t, diff(t, baseSnapshot(), later(t, mutate)))
	for i := 0; i < 20; i++ {
		if got := encodeResult(t, diff(t, baseSnapshot(), later(t, mutate))); got != first {
			t.Fatalf("run %d differs from the first:\n--- run %d ---\n%s\n--- first ---\n%s", i, i, got, first)
		}
	}

	// Within a group: additions, then removals, then modifications, and by
	// identifier inside each.
	res := diff(t, baseSnapshot(), later(t, mutate))
	for _, g := range res.ChangedGroups() {
		for i := 1; i < len(g.Changes); i++ {
			prev, cur := g.Changes[i-1], g.Changes[i]
			switch {
			case prev.Kind.order() > cur.Kind.order():
				t.Errorf("group %s reports %s before %s", g.Label(), prev.Kind, cur.Kind)
			case prev.Kind == cur.Kind && prev.ID > cur.ID:
				t.Errorf("group %s reports %s before %s", g.Label(), prev.ID, cur.ID)
			}
		}
	}
}

func encodeResult(t *testing.T, r *Result) string {
	t.Helper()
	raw, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	return string(raw)
}

// TestSnapshotsReportsIncompleteness is requirement 11.3 and its close relative.
//
// Differing schema versions mean a field one build records and the other does not
// cannot be told apart from a field that changed, and a collection error means a
// resource absent from a Snapshot may be one that could not be read rather than
// one that was deleted. Both are stated; neither stops the comparison, because a
// diff that refuses to run is no more complete than one that says what it could
// not establish.
func TestSnapshotsReportsIncompleteness(t *testing.T) {
	cases := []struct {
		name         string
		from         func(*model.Snapshot)
		to           func(*model.Snapshot)
		wantComplete bool
		wantSubjects []string
	}{
		{
			name:         "same version, no errors",
			wantComplete: true,
		},
		{
			name:         "the later snapshot was written by a newer build",
			to:           func(s *model.Snapshot) { s.SchemaVersion = model.SchemaVersion + 1 },
			wantComplete: false,
			wantSubjects: []string{"schema version"},
		},
		{
			name:         "the earlier snapshot was written by an older build",
			from:         func(s *model.Snapshot) { s.SchemaVersion = model.SchemaVersion - 1 },
			wantComplete: false,
			wantSubjects: []string{"schema version"},
		},
		{
			name: "a resource could not be read on one side",
			to: func(s *model.Snapshot) {
				s.CollectionErrors = []model.CollectionError{{
					Account: accountB, Region: regionB,
					Resource: "security_groups", Err: "access denied",
				}}
			},
			wantComplete: false,
			wantSubjects: []string{"collection errors"},
		},
		{
			name: "both at once",
			from: func(s *model.Snapshot) { s.SchemaVersion = model.SchemaVersion - 1 },
			to: func(s *model.Snapshot) {
				s.CollectionErrors = []model.CollectionError{{Resource: "vpcs", Err: "throttled"}}
			},
			wantComplete: false,
			wantSubjects: []string{"schema version", "collection errors"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			from := baseSnapshot()
			if tc.from != nil {
				tc.from(from)
			}
			res := diff(t, from, later(t, tc.to))

			if res.Complete != tc.wantComplete {
				t.Errorf("Complete = %v, want %v (caveats %+v)", res.Complete, tc.wantComplete, res.Caveats)
			}
			if len(res.Caveats) != len(tc.wantSubjects) {
				t.Fatalf("got %d caveats, want %d: %+v", len(res.Caveats), len(tc.wantSubjects), res.Caveats)
			}
			for i, subject := range tc.wantSubjects {
				if res.Caveats[i].Subject != subject {
					t.Errorf("caveat %d subject = %q, want %q", i, res.Caveats[i].Subject, subject)
				}
				if res.Caveats[i].Summary == "" {
					t.Errorf("caveat %q states no reason", subject)
				}
			}
		})
	}
}

// The schema version notice names both versions, so an operator can tell which
// side to recapture.
func TestSchemaMismatchNamesBothVersions(t *testing.T) {
	from := baseSnapshot()
	from.SchemaVersion = 1
	to := later(t, func(s *model.Snapshot) { s.SchemaVersion = 2 })

	res := diff(t, from, to)
	if len(res.Caveats) != 1 {
		t.Fatalf("got %d caveats, want 1: %+v", len(res.Caveats), res.Caveats)
	}
	summary := res.Caveats[0].Summary
	for _, want := range []string{"version 1", "version 2", FromLabel, ToLabel, "may be incomplete"} {
		if !strings.Contains(summary, want) {
			t.Errorf("the schema caveat omits %q: %s", want, summary)
		}
	}
	if res.From.SchemaVersion != 1 || res.To.SchemaVersion != 2 {
		t.Errorf("summaries report versions %d and %d, want 1 and 2", res.From.SchemaVersion, res.To.SchemaVersion)
	}
}

// An unchanged pair counts what it compared and says so, rather than rendering as
// an empty report that could equally mean nothing was read.
func TestIdenticalSnapshotsAreCountedAndStated(t *testing.T) {
	res := diff(t, baseSnapshot(), later(t, nil))

	if res.Changed() {
		t.Errorf("identical snapshots reported %d added, %d removed, %d modified", res.Added, res.Removed, res.Modified)
	}
	if want := countResources(baseSnapshot()); res.Unchanged != want {
		t.Errorf("Unchanged = %d, want %d", res.Unchanged, want)
	}
	if len(res.Notes) == 0 {
		t.Error("an unchanged diff carries no note saying so")
	}
	if len(res.ChangedGroups()) != 0 {
		t.Errorf("an unchanged diff reports %d changed groups", len(res.ChangedGroups()))
	}
}

// A single changed field is quoted with both values: that is the whole answer, and
// an operator should not have to open the JSON for it.
func TestSingleFieldChangeQuotesBothValues(t *testing.T) {
	res := diff(t, baseSnapshot(), later(t, func(s *model.Snapshot) {
		s.VPCs[vpcA].Name = "app-vpc-renamed"
	}))

	got := changes(res)
	if len(got) != 1 {
		t.Fatalf("got %d changes, want 1: %+v", len(got), got)
	}
	for _, want := range []string{"name changed", "app-vpc", "app-vpc-renamed"} {
		if !strings.Contains(got[0].Summary, want) {
			t.Errorf("the summary omits %q: %s", want, got[0].Summary)
		}
	}
}

// Comparing against nothing is an error rather than a diff in which everything was
// added: that reads like a collection and is not one.
func TestSnapshotsRequiresBothSides(t *testing.T) {
	for _, tc := range []struct {
		name     string
		from, to *model.Snapshot
	}{
		{"neither", nil, nil},
		{"no earlier snapshot", nil, baseSnapshot()},
		{"no later snapshot", baseSnapshot(), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Snapshots(tc.from, tc.to); err == nil {
				t.Error("Snapshots() returned no error")
			}
		})
	}
}

// A resource the collector could not scope is grouped rather than dropped: an
// older Snapshot carries no account or region on some resources, and losing its
// changes would make the diff quietly wrong.
func TestUnscopedResourcesAreGrouped(t *testing.T) {
	from := model.NewSnapshot()
	from.CapturedAt = capturedBefore
	to := model.NewSnapshot()
	to.CapturedAt = capturedAfter
	to.VPCs[vpcA] = &model.VPC{
		Meta:  model.Meta{ID: vpcA},
		CIDRs: []netip.Prefix{prefix("10.0.0.0/16")},
	}

	res := diff(t, from, to)
	groups := res.ChangedGroups()
	if len(groups) != 1 {
		t.Fatalf("got %d changed groups, want 1: %+v", len(groups), groups)
	}
	if got, want := groups[0].Label(), TypeVPC+" — "+unscoped; got != want {
		t.Errorf("group label = %q, want %q", got, want)
	}
}
