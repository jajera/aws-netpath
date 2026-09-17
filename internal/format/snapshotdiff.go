package format

// Projecting a snapshot diff onto the same three sections.
//
// The slots hold what a diff found — the resources that changed, the groups where
// nothing did, and the reasons the comparison may be incomplete — in the order
// every other report uses. A reader who learned the layout on a diagnosis meets
// the answer, then what has been ruled out, then what could not be established,
// and does not have to learn a second layout for a second command.
//
// Changes are grouped twice over. Requirement 11.2 asks for resource type,
// account, and region, and the rows add the change kind to that, so a group's
// additions, removals, and modifications each get their own heading. The row shape
// this produces — one heading carrying the group and the kind, one row per
// resource beneath it — is the shape the renderers already know: the text output
// prints the heading once and indents the evidence, and the markdown table folds
// the heading into the rows so no cell is spent repeating it.

import (
	"fmt"
	"time"

	"github.com/jajera/aws-netpath/internal/diffsnap"
)

// Row-level labels for a snapshot diff. They are the diff's own vocabulary:
// nothing here passed or was blocked.
const (
	labelAdded     = "ADDED"
	labelRemoved   = "REMOVED"
	labelModified  = "MODIFIED"
	labelUnchanged = "SAME"
)

// Outcome strings for a diff.
const (
	outcomeNoChange = "NO CHANGE"
	outcomeChanged  = "CHANGED: %s"
)

// FromSnapshotDiff projects a snapshot diff onto a Report.
func FromSnapshotDiff(d *diffsnap.Result) Report {
	if d == nil {
		return Report{Kind: KindSnapshotDiff, Outcome: outcomeNoDiff}
	}

	r := Report{
		Kind:          KindSnapshotDiff,
		Subjects:      []string{snapshotSubject(d.From), snapshotSubject(d.To)},
		Authoritative: d.Complete,
		Notes:         dedupe(d.Notes),
	}
	r.Outcome, r.Finding = changeSection(d)
	r.Cleared = unchangedSection(d)
	r.Unresolved = caveatSection(d)
	if !d.Complete {
		r.Notice = mayBeIncomplete(d)
	}
	return r
}

// snapshotSubject identifies one side: when it was captured, what wrote it, and
// how much it holds. The size is there because a diff against a Snapshot that
// collected a tenth as many resources is a collection difference wearing a
// configuration difference's clothes.
func snapshotSubject(s diffsnap.SnapshotSummary) string {
	out := fmt.Sprintf("%s snapshot: captured %s, schema version %d, %d resources",
		s.Label, s.CapturedAt.UTC().Format(time.RFC3339), s.SchemaVersion, s.Resources)
	if s.CollectionErrors > 0 {
		out += fmt.Sprintf(", %d collection errors", s.CollectionErrors)
	}
	return out
}

// changeSection is section one: what differs, grouped by type, account, region,
// and kind.
func changeSection(d *diffsnap.Result) (outcome string, s *Section) {
	s = &Section{Title: "changes"}
	for _, g := range d.ChangedGroups() {
		for _, kind := range []struct {
			kind  diffsnap.Kind
			label string
		}{
			{diffsnap.KindAdded, labelAdded},
			{diffsnap.KindRemoved, labelRemoved},
			{diffsnap.KindModified, labelModified},
		} {
			rows := changeRows(g, kind.kind)
			if len(rows) == 0 {
				continue
			}
			s.add(Row{Layer: g.Label(), Verdict: kind.label})
			s.add(rows...)
		}
	}

	if len(s.Rows) == 0 {
		s.Note = fmt.Sprintf("no resource was added, removed, or modified between the %s and %s snapshots",
			d.From.Label, d.To.Label)
		return outcomeNoChange, s
	}
	s.Note = fmt.Sprintf("grouped by resource type, account, and region; %s", counts(d))
	return fmt.Sprintf(outcomeChanged, counts(d)), s
}

// changeRows renders one group's changes of one kind, each resource on its own
// row: the identifier is what an operator pastes into a console, and the summary
// is what changed about it.
func changeRows(g diffsnap.Group, kind diffsnap.Kind) []Row {
	var out []Row
	for _, c := range g.Changes {
		if c.Kind != kind {
			continue
		}
		out = append(out, Row{Subject: c.ID, Detail: c.Summary})
	}
	return out
}

// unchangedSection is section two: the groups where nothing changed, named and
// counted only.
//
// It is the diff's equivalent of the Layers a diagnosis cleared. "Nothing changed
// in this account and region" is a finding an operator acts on — it is the half of
// the estate they can stop looking at — and listing the resources behind it would
// bury the changes above.
func unchangedSection(d *diffsnap.Result) *Section {
	s := &Section{Title: "unchanged"}
	for _, g := range d.UnchangedGroups() {
		s.add(Row{Layer: fmt.Sprintf("%s (%d)", g.Label(), g.Unchanged), Verdict: labelUnchanged})
	}
	if len(s.Rows) == 0 {
		s.Note = "no resource type was found identical in both snapshots"
		return s
	}
	s.Note = fmt.Sprintf("%d resources are identical in both snapshots; a diff reports changes only", d.Unchanged)
	return s
}

// caveatSection is section three: what this diff could not establish.
// Requirement 11.3 lands here.
func caveatSection(d *diffsnap.Result) *Section {
	s := &Section{Title: "incomplete comparisons"}
	for _, c := range d.Caveats {
		s.add(Row{Layer: c.Subject, Verdict: labelIncomplete, Detail: c.Summary})
	}
	if len(s.Rows) == 0 {
		s.Note = "both snapshots were written at the same schema version with no collection errors, so every resource either holds was compared"
	}
	return s
}

// mayBeIncomplete states why the diff is not a complete account of what changed.
// Requirement 11.3 asks for exactly this to be reported, and the banner the
// Formatter already carries for a non-authoritative verdict is where a reader
// will see it.
func mayBeIncomplete(d *diffsnap.Result) string {
	subjects := make([]string, 0, len(d.Caveats))
	for _, c := range d.Caveats {
		subjects = append(subjects, c.Subject)
	}
	if len(subjects) == 0 {
		return "this comparison may be incomplete"
	}
	return fmt.Sprintf("this comparison may be incomplete: %s", joinList(subjects))
}

// counts renders the totals in the order the sections use them.
func counts(d *diffsnap.Result) string {
	return fmt.Sprintf("%d added, %d removed, %d modified", d.Added, d.Removed, d.Modified)
}
