package ops

// The diff operation: two collections, one question.
//
// Everything else here answers a question about a network. This answers a question
// about two answers: what is different now. It is the cheapest operation in the
// tool — no walk, no policy evaluation, no API call — and often the fastest route
// to a cause, because the operator usually knows what broke and needs to find out
// what moved.
//
// Both Snapshots are read without enforcing the schema version, which is the one
// place in this package where that is allowed. A collection from before a change
// and one from after it may well have been written by different builds, and
// refusing to read the older file would withhold the answer exactly when it is
// wanted. Requirement 11.3 takes the other route: read both, compare what lines
// up, and report that the comparison may be incomplete. Nothing that evaluates a
// path may do this — a version difference there is a wrong verdict rather than a
// stated caveat.

import (
	"github.com/jajera/aws-netpath/internal/diffsnap"
	"github.com/jajera/aws-netpath/internal/model"
	"github.com/jajera/aws-netpath/internal/snapshot"
)

// DiffSnapshotRequest asks what changed between two Snapshots.
type DiffSnapshotRequest struct {
	// FromPath and ToPath locate the earlier and later Snapshots. The in-memory
	// fields take precedence when both are given, which is what the tests and the
	// MCP server use.
	FromPath string
	ToPath   string
	From     *model.Snapshot
	To       *model.Snapshot
}

// DiffSnapshotResult is what changed.
type DiffSnapshotResult struct {
	Diff *diffsnap.Result `json:"diff"`
}

// Changed reports whether anything differs between the two Snapshots.
func (r *DiffSnapshotResult) Changed() bool { return r != nil && r.Diff.Changed() }

// Established reports whether the two Snapshots could be compared in full.
//
// False is requirement 11.3's outcome: differing schema versions mean a field one
// side records and the other does not cannot be told apart from a field that
// changed, so "nothing changed" was not established. Exposed for the CLI's
// exit-code mapping.
func (r *DiffSnapshotResult) Established() bool {
	return r != nil && r.Diff != nil && r.Diff.Complete
}

// DiffSnapshot compares two Snapshots and reports the resources added, removed,
// and modified, grouped by type and by account and region.
//
// Validation order is fixed — the earlier Snapshot, then the later one — so an
// invocation missing both always reports the same one first.
func DiffSnapshot(req DiffSnapshotRequest) (*DiffSnapshotResult, error) {
	from, err := diffSide("from", req.From, req.FromPath)
	if err != nil {
		return nil, err
	}
	to, err := diffSide("to", req.To, req.ToPath)
	if err != nil {
		return nil, err
	}

	diff, err := diffsnap.Snapshots(from, to)
	if err != nil {
		return nil, err
	}
	return &DiffSnapshotResult{Diff: diff}, nil
}

// diffSide resolves one side of the comparison, naming the field at fault. An
// already-loaded Snapshot is taken as given: it came through the same door.
func diffSide(field string, snap *model.Snapshot, path string) (*model.Snapshot, error) {
	if snap != nil {
		return snap, nil
	}
	if path == "" {
		return nil, missingField(field)
	}
	loaded, err := snapshot.LoadAny(path)
	if err != nil {
		return nil, badField(field, err)
	}
	return loaded, nil
}
