package format

// Snapshot diff rendering tests, and the fixture the goldens are cut from.
//
// The fixture is produced by the real differ rather than assembled by hand, so a
// change to what a diff reports shows up here as a rendering that no longer makes
// sense rather than as a fixture that quietly stopped resembling the output.
//
// Every identifier is a placeholder and every address is RFC 1918 space.

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/jajera/aws-netpath/internal/diffsnap"
	"github.com/jajera/aws-netpath/internal/model"
)

const (
	diffAccountA = "111122223333"
	diffAccountB = "444455556666"
	diffRegionA  = "us-west-2"
	diffRegionB  = "us-east-1"
)

// snapshotDiff is a week between two collections: a subnet added and a security
// group removed in one account, a hub VPC widened in another, and the later file
// written by a newer build — which is the ordinary shape of a diff an operator
// runs after an incident, caveat included.
func snapshotDiff(t *testing.T) *diffsnap.Result {
	t.Helper()
	before := diffSnapshotFixture(time.Date(2025, 3, 1, 9, 0, 0, 0, time.UTC))
	after := diffSnapshotFixture(time.Date(2025, 3, 8, 9, 0, 0, 0, time.UTC))

	after.SchemaVersion = model.SchemaVersion + 1
	after.Subnets["subnet-0fedcba9876543210"] = &model.Subnet{
		Meta: model.Meta{
			ID: "subnet-0fedcba9876543210", Name: "app-b",
			Account: diffAccountA, Region: diffRegionA,
		},
		VPCID: "vpc-0aaa1111bbbb2222c",
		CIDR:  netip.MustParsePrefix("10.0.2.0/24"),
	}
	delete(after.SecurityGroups, "sg-0111111111111111a")
	after.VPCs["vpc-0ddd3333eeee4444f"].CIDRs = append(
		after.VPCs["vpc-0ddd3333eeee4444f"].CIDRs, netip.MustParsePrefix("10.2.0.0/16"))

	res, err := diffsnap.Snapshots(before, after)
	if err != nil {
		t.Fatalf("diffsnap.Snapshots: %v", err)
	}
	return res
}

// unchangedSnapshotDiff is the answer an operator hopes for and has to be able to
// read: nothing changed, and the report says so rather than rendering empty.
func unchangedSnapshotDiff(t *testing.T) *diffsnap.Result {
	t.Helper()
	res, err := diffsnap.Snapshots(
		diffSnapshotFixture(time.Date(2025, 3, 1, 9, 0, 0, 0, time.UTC)),
		diffSnapshotFixture(time.Date(2025, 3, 8, 9, 0, 0, 0, time.UTC)),
	)
	if err != nil {
		t.Fatalf("diffsnap.Snapshots: %v", err)
	}
	return res
}

func diffSnapshotFixture(capturedAt time.Time) *model.Snapshot {
	s := model.NewSnapshot()
	s.SchemaVersion = model.SchemaVersion
	s.CapturedAt = capturedAt
	s.Accounts = []string{diffAccountA, diffAccountB}
	s.Regions = []string{diffRegionA, diffRegionB}

	s.VPCs["vpc-0aaa1111bbbb2222c"] = &model.VPC{
		Meta: model.Meta{
			ID: "vpc-0aaa1111bbbb2222c", Name: "app-vpc",
			Account: diffAccountA, Region: diffRegionA,
		},
		CIDRs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/16")},
	}
	s.VPCs["vpc-0ddd3333eeee4444f"] = &model.VPC{
		Meta: model.Meta{
			ID: "vpc-0ddd3333eeee4444f", Name: "hub-vpc",
			Account: diffAccountB, Region: diffRegionB,
		},
		CIDRs: []netip.Prefix{netip.MustParsePrefix("10.1.0.0/16")},
	}
	s.Subnets["subnet-0123456789abcdef0"] = &model.Subnet{
		Meta: model.Meta{
			ID: "subnet-0123456789abcdef0", Name: "app-a",
			Account: diffAccountA, Region: diffRegionA,
		},
		VPCID: "vpc-0aaa1111bbbb2222c",
		CIDR:  netip.MustParsePrefix("10.0.1.0/24"),
	}
	s.SecurityGroups["sg-0111111111111111a"] = &model.SecurityGroup{
		Meta: model.Meta{
			ID: "sg-0111111111111111a", Name: "app-sg",
			Account: diffAccountA, Region: diffRegionA,
		},
		VPCID: "vpc-0aaa1111bbbb2222c",
		Ingress: []model.SGRule{{
			Protocol: "tcp", FromPort: 443, ToPort: 443,
			CIDRs: []netip.Prefix{netip.MustParsePrefix("10.0.2.0/24")},
		}},
	}
	return s
}

// The three sections hold for a diff too, in the same order and present when
// empty: the changes, the scopes where nothing changed, and what could not be
// compared. Requirements 11.1 and 11.2 in the first, 11.3 in the third.
func TestSnapshotDiffRendersTheThreeSections(t *testing.T) {
	cases := []struct {
		name    string
		report  Report
		mode    Mode
		ordered []string
	}{
		{"changed text", FromSnapshotDiff(snapshotDiff(t)), ModeText,
			[]string{"changes:", "unchanged:", "incomplete comparisons:"}},
		{"changed markdown", FromSnapshotDiff(snapshotDiff(t)), ModeMarkdown,
			[]string{"## changes", "## unchanged", "## incomplete comparisons"}},
		{"unchanged text", FromSnapshotDiff(unchangedSnapshotDiff(t)), ModeText,
			[]string{"changes:", "unchanged:", "incomplete comparisons:"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := render(t, tc.report, Options{Mode: tc.mode})
			at := -1
			for _, want := range tc.ordered {
				i := strings.Index(got, want)
				if i < 0 {
					t.Fatalf("section %q is missing:\n%s", want, got)
				}
				if i < at {
					t.Fatalf("section %q is out of order:\n%s", want, got)
				}
				at = i
			}
		})
	}
}

// Requirement 11.1 and 11.2 through the renderer: every change is on the page,
// under a heading naming its resource type, account, and region.
func TestSnapshotDiffRendersEveryChangeUnderItsGroup(t *testing.T) {
	diff := snapshotDiff(t)
	got := render(t, FromSnapshotDiff(diff), Options{Mode: ModeText})

	for _, want := range []string{
		"[ADDED] subnet — " + diffAccountA + " / " + diffRegionA,
		"subnet-0fedcba9876543210",
		"[REMOVED] security_group — " + diffAccountA + " / " + diffRegionA,
		"sg-0111111111111111a",
		"[MODIFIED] vpc — " + diffAccountB + " / " + diffRegionB,
		"vpc-0ddd3333eeee4444f",
		"verdict: CHANGED: 1 added, 1 removed, 1 modified",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the rendering omits %q:\n%s", want, got)
		}
	}

	// Nothing the differ found may be dropped on the way to the page.
	for _, g := range diff.ChangedGroups() {
		for _, c := range g.Changes {
			if !strings.Contains(got, c.ID) {
				t.Errorf("change %s %s is missing from the rendering:\n%s", c.Kind, c.ID, got)
			}
		}
	}
}

// Requirement 11.3: differing schema versions are reported as a comparison that
// may be incomplete, in all three renderings, through the same banner a verdict
// resting on an abstention carries.
func TestSnapshotDiffStatesPossibleIncompleteness(t *testing.T) {
	report := FromSnapshotDiff(snapshotDiff(t))
	if report.Authoritative {
		t.Fatal("a diff across schema versions rendered as a complete comparison")
	}

	text := render(t, report, Options{Mode: ModeText})
	if !strings.Contains(text, "!! this comparison may be incomplete") {
		t.Errorf("the text rendering carries no notice:\n%s", text)
	}
	if !strings.Contains(text, "schema version") {
		t.Errorf("the text rendering does not name the schema version as the reason:\n%s", text)
	}
	if md := render(t, report, Options{Mode: ModeMarkdown}); !strings.Contains(md, "> **Not authoritative.** this comparison may be incomplete") {
		t.Errorf("the markdown rendering carries no notice:\n%s", md)
	}
	if js := render(t, report, Options{Mode: ModeJSON}); !strings.Contains(js, `"authoritative": false`) {
		t.Errorf("the json rendering does not report the comparison as incomplete:\n%s", js)
	}
}

// A diff that found nothing says so in the outcome line rather than leaving a
// reader to infer it from an empty section.
func TestUnchangedSnapshotDiffStatesNoChange(t *testing.T) {
	report := FromSnapshotDiff(unchangedSnapshotDiff(t))
	if report.Outcome != outcomeNoChange {
		t.Errorf("Outcome = %q, want %q", report.Outcome, outcomeNoChange)
	}
	if !report.Authoritative {
		t.Errorf("a diff of two same-version snapshots with no collection errors rendered as incomplete: %s", report.Notice)
	}

	got := render(t, report, Options{Mode: ModeText})
	if !strings.Contains(got, "verdict: "+outcomeNoChange) {
		t.Errorf("the rendering does not lead with the outcome:\n%s", got)
	}
	if !strings.Contains(got, "no resource was added, removed, or modified") {
		t.Errorf("the rendering does not state that nothing changed:\n%s", got)
	}
}

// A nil diff renders rather than panicking: the CLI maps an error to an exit code
// and may still be asked to print something.
func TestNilSnapshotDiffRenders(t *testing.T) {
	report := FromSnapshotDiff(nil)
	if report.Kind != KindSnapshotDiff {
		t.Errorf("Kind = %q, want %q", report.Kind, KindSnapshotDiff)
	}
	if _, err := renderErr(report); err != nil {
		t.Errorf("rendering a nil diff: %v", err)
	}
}

func renderErr(r Report) (string, error) {
	var b strings.Builder
	err := Write(&b, r, Options{})
	return b.String(), err
}
