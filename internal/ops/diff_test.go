package ops

// The diff operation, from two files on disk to a rendered report.
//
// The differ's own tests work on Snapshots already in memory, so they cannot
// catch an operation that reads the wrong file, refuses one it should have read,
// or drops the caveat on the way to the Formatter. These go through the door the
// CLI and the MCP server will use.

import (
	"errors"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jajera/aws-netpath/internal/format"
	"github.com/jajera/aws-netpath/internal/model"
	"github.com/jajera/aws-netpath/internal/snapshot"
)

const (
	diffVPCID    = "vpc-0aaa1111bbbb2222c"
	diffSubnetID = "subnet-0123456789abcdef0"
	diffAddedID  = "subnet-0fedcba9876543210"
	diffAccount  = "111122223333"
	diffRegion   = "ap-southeast-2"
)

// diffFixture is a small collection: one VPC and one subnet in one scope.
func diffFixture(capturedAt time.Time) *model.Snapshot {
	s := model.NewSnapshot()
	s.SchemaVersion = model.SchemaVersion
	s.CapturedAt = capturedAt
	s.VPCs[diffVPCID] = &model.VPC{
		Meta:  model.Meta{ID: diffVPCID, Name: "app-vpc", Account: diffAccount, Region: diffRegion},
		CIDRs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/16")},
	}
	s.Subnets[diffSubnetID] = &model.Subnet{
		Meta:  model.Meta{ID: diffSubnetID, Name: "app-a", Account: diffAccount, Region: diffRegion},
		VPCID: diffVPCID,
		CIDR:  netip.MustParsePrefix("10.0.1.0/24"),
	}
	return s
}

// writeSnapshot saves a Snapshot to a temporary file and returns its path.
func writeSnapshot(t *testing.T, name string, s *model.Snapshot) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := snapshot.Save(path, s); err != nil {
		t.Fatalf("save %s: %v", name, err)
	}
	return path
}

// Requirements 11.1 and 11.2 through the operation: two files in, the added
// resource out, grouped by type, account, and region.
func TestDiffSnapshotFromFiles(t *testing.T) {
	before := diffFixture(time.Date(2025, 3, 1, 9, 0, 0, 0, time.UTC))
	after := diffFixture(time.Date(2025, 3, 8, 9, 0, 0, 0, time.UTC))
	after.Subnets[diffAddedID] = &model.Subnet{
		Meta:  model.Meta{ID: diffAddedID, Name: "app-b", Account: diffAccount, Region: diffRegion},
		VPCID: diffVPCID,
		CIDR:  netip.MustParsePrefix("10.0.2.0/24"),
	}

	res, err := DiffSnapshot(DiffSnapshotRequest{
		FromPath: writeSnapshot(t, "before.json", before),
		ToPath:   writeSnapshot(t, "after.json", after),
	})
	if err != nil {
		t.Fatalf("DiffSnapshot() error = %v", err)
	}
	if !res.Changed() {
		t.Fatal("an added subnet produced no change")
	}

	groups := res.Diff.ChangedGroups()
	if len(groups) != 1 {
		t.Fatalf("got %d changed groups, want 1: %+v", len(groups), groups)
	}
	if got, want := groups[0].Label(), "subnet — "+diffAccount+" / "+diffRegion; got != want {
		t.Errorf("group label = %q, want %q", got, want)
	}
	if !res.Diff.Complete {
		t.Errorf("a diff of two current-version snapshots is reported as incomplete: %+v", res.Diff.Caveats)
	}

	got := renderReport(t, res.Report(), format.ModeText)
	for _, want := range []string{
		"before snapshot: captured 2025-03-01T09:00:00Z",
		"after snapshot: captured 2025-03-08T09:00:00Z",
		"verdict: CHANGED: 1 added, 0 removed, 0 modified",
		diffAddedID,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the rendering omits %q:\n%s", want, got)
		}
	}
}

// Requirement 11.3 end to end. A Snapshot written by another build is read rather
// than refused — comparing collections from either side of a change is exactly
// when a version difference turns up — and the report says the comparison may be
// incomplete.
func TestDiffSnapshotAcrossSchemaVersionsIsReadAndCaveated(t *testing.T) {
	before := diffFixture(time.Date(2025, 3, 1, 9, 0, 0, 0, time.UTC))
	after := diffFixture(time.Date(2025, 3, 8, 9, 0, 0, 0, time.UTC))
	after.SchemaVersion = model.SchemaVersion + 1

	fromPath := writeSnapshot(t, "before.json", before)
	toPath := writeSnapshot(t, "after.json", after)

	// The evaluating operations refuse the same file, which is the distinction
	// worth pinning: a diff states its uncertainty, a verdict cannot.
	if _, err := loadSnapshot(toPath); err == nil {
		t.Error("loadSnapshot accepted an unsupported schema version")
	}

	res, err := DiffSnapshot(DiffSnapshotRequest{FromPath: fromPath, ToPath: toPath})
	if err != nil {
		t.Fatalf("DiffSnapshot() error = %v", err)
	}
	if res.Diff.Complete {
		t.Fatal("a diff across schema versions is reported as complete")
	}
	if len(res.Diff.Caveats) != 1 || res.Diff.Caveats[0].Subject != "schema version" {
		t.Fatalf("caveats = %+v, want one naming the schema version", res.Diff.Caveats)
	}

	report := res.Report()
	if report.Authoritative {
		t.Error("the report claims a complete comparison")
	}
	if got := renderReport(t, report, format.ModeText); !strings.Contains(got, "may be incomplete") {
		t.Errorf("the rendering does not state that the comparison may be incomplete:\n%s", got)
	}
}

// Validation names the field at fault, in a fixed order, so an invocation with
// several problems always reports the same one first.
func TestDiffSnapshotValidation(t *testing.T) {
	path := writeSnapshot(t, "snapshot.json", diffFixture(time.Now().UTC()))

	cases := []struct {
		name      string
		req       DiffSnapshotRequest
		wantField string
	}{
		{"neither side", DiffSnapshotRequest{}, "from"},
		{"no earlier snapshot", DiffSnapshotRequest{ToPath: path}, "from"},
		{"no later snapshot", DiffSnapshotRequest{FromPath: path}, "to"},
		{"unreadable file", DiffSnapshotRequest{FromPath: path, ToPath: filepath.Join(t.TempDir(), "absent.json")}, "to"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DiffSnapshot(tc.req)
			if err == nil {
				t.Fatal("DiffSnapshot() returned no error")
			}
			var fe *FieldError
			if !errors.As(err, &fe) {
				t.Fatalf("error %v is not a *FieldError", err)
			}
			if fe.Field != tc.wantField {
				t.Errorf("error names field %q, want %q", fe.Field, tc.wantField)
			}
		})
	}
}

// A nil result renders rather than panicking, as the other operations' do.
func TestNilDiffResultRenders(t *testing.T) {
	var res *DiffSnapshotResult
	if got := res.Report().Kind; got != format.KindSnapshotDiff {
		t.Errorf("nil diff report kind = %q, want %q", got, format.KindSnapshotDiff)
	}
	if res.Changed() {
		t.Error("a nil result reports a change")
	}
}
