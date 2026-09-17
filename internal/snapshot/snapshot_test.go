package snapshot

// Save's directory handling.
//
// The default output path is snapshots/snapshot.json — a directory that exists in
// .gitignore but not necessarily on disk. os.Create does not create parents, so
// without the mkdir in Save the first collect in a fresh clone fails with ENOENT
// after every AWS call has already been paid for. These tests pin that the
// directory is made, at whatever depth the path names, and that what lands there
// reads back as the snapshot that went in.

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jajera/aws-netpath/internal/model"
)

// fixture is a minimal snapshot carrying enough to tell a successful round trip
// from an empty file: a schema version Read insists on, and one identifiable VPC.
func fixture() *model.Snapshot {
	s := model.NewSnapshot()
	s.CapturedAt = time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	s.Accounts = []string{"111122223333"}
	s.Regions = []string{"us-east-1"}
	s.VPCs["vpc-aaa"] = &model.VPC{
		Meta:  model.Meta{ID: "vpc-aaa", Region: "us-east-1", Account: "111122223333"},
		CIDRs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/16")},
	}
	return s
}

func TestSaveCreatesMissingParentDirectories(t *testing.T) {
	cases := []struct {
		name string
		// rel is the output path relative to a fresh temporary directory, so no
		// part of it exists before Save runs.
		rel string
	}{
		{
			name: "the new default, one level down",
			rel:  filepath.Join("snapshots", "snapshot.json"),
		},
		{
			name: "a nested --output the operator chose",
			rel:  filepath.Join("out", "2024-01-02", "prod", "snapshot.json"),
		},
		{
			name: "no directory component at all",
			rel:  "snapshot.json",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), tc.rel)

			if err := Save(path, fixture()); err != nil {
				t.Fatalf("Save(%s) = %v, want the parent directory created", tc.rel, err)
			}

			// Readable back, not merely present: a truncated or unflushed write
			// would still leave a file on disk.
			got, err := Load(path)
			if err != nil {
				t.Fatalf("Load(%s) = %v, want the snapshot Save wrote", tc.rel, err)
			}
			if _, ok := got.VPCs["vpc-aaa"]; !ok {
				t.Errorf("loaded snapshot has vpcs %v, want the one that was saved", got.VPCs)
			}
			if !got.CapturedAt.Equal(fixture().CapturedAt) {
				t.Errorf("captured_at = %v, want %v", got.CapturedAt, fixture().CapturedAt)
			}
		})
	}
}

// Save must not loosen the permissions of the snapshot itself. The directory is
// created for convenience; the file stays whatever os.Create gives it, because a
// snapshot is an unsanitised model of a real network.
func TestSaveLeavesTheSnapshotFileModeAlone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snapshots", "snapshot.json")
	if err := Save(path, fixture()); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm&0o111 != 0 {
		t.Errorf("snapshot mode = %v, want no execute bits", perm)
	}
}

// A path whose parent cannot be created is an error naming the path, not a panic
// and not a silently skipped write. Here the parent is an existing regular file,
// so MkdirAll has nowhere to put the directory.
func TestSaveReportsAnUncreatableParent(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "snapshots")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0o644); err != nil {
		t.Fatal(err)
	}

	err := Save(filepath.Join(blocker, "snapshot.json"), fixture())
	if err == nil {
		t.Fatal("Save into a path under a regular file succeeded, want an error")
	}
	if !strings.Contains(err.Error(), "snapshots") {
		t.Errorf("error %q does not name the path it failed on", err)
	}
}
