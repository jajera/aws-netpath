// Package snapshot reads and writes captured network models.
//
// Snapshots are ordinary JSON files. That is deliberate: they can be archived,
// diffed between dates, and read by someone who has no access to the account they
// came from. Committing one is the exception — nothing here sanitises a snapshot,
// so it stays an unredacted model of a real network, which is why the default
// output path lands inside a gitignored directory.
package snapshot

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/jajera/aws-netpath/internal/model"
)

// Save writes a snapshot as indented JSON.
//
// The parent directory is created if it does not exist. That belongs here rather
// than in the caller because Save is the single funnel for writing a snapshot:
// the default output path is now snapshots/snapshot.json, a directory git ignores
// wholesale, and doing the mkdir here makes any nested --output path work too
// instead of only the one the default happens to name.
func Save(path string, s *model.Snapshot) error {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create snapshot directory %s: %w", dir, err)
		}
	}

	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create snapshot %s: %w", path, err)
	}
	defer f.Close()

	if err := Write(f, s); err != nil {
		return err
	}
	return f.Close()
}

// Write encodes a snapshot to w.
func Write(w io.Writer, s *model.Snapshot) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(s); err != nil {
		return fmt.Errorf("encode snapshot: %w", err)
	}
	return nil
}

// Load reads a snapshot and rejects formats this build cannot interpret.
func Load(path string) (*model.Snapshot, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open snapshot %s: %w", path, err)
	}
	defer f.Close()
	return Read(f)
}

// Read decodes a snapshot from r, rejecting a schema version this build cannot
// interpret. Evaluating a misread snapshot would produce verdicts about a network
// that was never collected, so the error is the only safe outcome.
func Read(r io.Reader) (*model.Snapshot, error) {
	s, err := ReadAny(r)
	if err != nil {
		return nil, err
	}
	if s.SchemaVersion != model.SchemaVersion {
		return nil, fmt.Errorf(
			"snapshot schema version %d is not supported by this build (expected %d); recapture it with aws-netpath collect",
			s.SchemaVersion, model.SchemaVersion)
	}
	return s, nil
}

// LoadAny reads a snapshot whatever schema version it carries.
//
// It exists for the diff, and only for the diff. Comparing a collection from
// before a change against one from after it is the case where a version
// difference is ordinary — one file was written by an older build — and refusing
// to read it would withhold the answer precisely when it is wanted. Requirement
// 11.3 takes the other route: read both, compare what lines up, and report that
// the comparison may be incomplete.
//
// Nothing that evaluates a path may use this. A field this build reads differently
// from the build that wrote the file is a wrong answer in a diff and a wrong
// verdict everywhere else, and only one of those states its own uncertainty.
func LoadAny(path string) (*model.Snapshot, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open snapshot %s: %w", path, err)
	}
	defer f.Close()
	return ReadAny(f)
}

// ReadAny decodes a snapshot from r without checking its schema version.
func ReadAny(r io.Reader) (*model.Snapshot, error) {
	var s model.Snapshot
	if err := json.NewDecoder(r).Decode(&s); err != nil {
		return nil, fmt.Errorf("decode snapshot: %w", err)
	}
	return &s, nil
}
