package format

// Projecting a collection run onto the report layout.
//
// A collection is the one operation that reports no finding. Nothing was walked
// and no layer decided anything, so the three-section shape is filled the way the
// diff and the cross-check fill it: with the slots that apply and none of the ones
// that do not. There is no "cleared layers" section here, because there were no
// layers, and a section saying so would be teaching a reader something untrue.
//
// What the report has to carry is the one thing every later answer depends on:
// whether the collection is complete. Requirement 2.5 records a failed scope in
// the snapshot rather than failing the run, which is right — one unreadable
// account should not cost the rest — but it means a snapshot can be missing a
// resource type that a later query would have evaluated. A layer missing from the
// snapshot abstains rather than passing, so an incomplete collection propagates
// into every verdict drawn from it. That is the same claim requirement 14.6 makes
// about an abstention, so it is stated the same way, through the banner a reader
// cannot miss.
//
// The Snapshot itself is not projected. It is a large document the other
// operations read from disk, and a report restating it would spend a reader's
// whole budget on data no question needs in a message.

import (
	"fmt"
	"sort"
)

// KindCollection names a collection run in the JSON output.
const KindCollection Kind = "collection"

// Collection is a collection run as the Formatter consumes it.
//
// It is a projection rather than the operation's own result because that result
// carries the Snapshot and reaches the AWS SDK through the collectors, and a
// renderer has no business carrying either.
type Collection struct {
	// OutputPath is where the snapshot was written, empty when it was not.
	OutputPath string
	// Targets counts the account and region pairs attempted.
	Targets int
	// Errors counts the scopes or resource types that could not be read.
	Errors int
	// Complete is false when anything failed to collect.
	Complete bool
	// Counts is what was collected, by resource type.
	Counts map[string]int
}

// Outcome strings for a collection.
const (
	outcomeNoCollection = "NOTHING COLLECTED"
	outcomeCollected    = "COLLECTED %s"
	outcomePartial      = "PARTIALLY COLLECTED %s"
)

// collectionIncomplete states what a partial collection means for everything read
// from it afterwards. Requirement 2.5.
const collectionIncomplete = "this collection is partial: an account or resource type could not be read, and a layer missing from the snapshot abstains rather than passing, so a verdict drawn from this snapshot is weaker than one drawn from a complete collection"

// FromCollection projects a collection run onto a Report.
func FromCollection(c Collection) Report {
	if c.Targets == 0 && len(c.Counts) == 0 {
		return Report{Kind: KindCollection, Outcome: outcomeNoCollection}
	}

	r := Report{
		Kind:          KindCollection,
		Outcome:       collectionOutcome(c),
		Authoritative: c.Complete,
	}
	if c.OutputPath != "" {
		r.Subjects = []string{fmt.Sprintf("snapshot: %s", c.OutputPath)}
	}
	r.Finding = collectedSection(c.Counts)
	r.Unresolved = collectionErrorSection(c)
	if !c.Complete {
		r.Notice = collectionIncomplete
	}
	return r
}

// collectionOutcome states what was attempted and whether all of it was read.
func collectionOutcome(c Collection) string {
	if c.Complete {
		return fmt.Sprintf(outcomeCollected, targetCount(c.Targets))
	}
	return fmt.Sprintf(outcomePartial, targetCount(c.Targets))
}

// collectedSection is what the snapshot holds, by resource type.
//
// The counts are the answer to the question a caller asks next — is there enough
// here to query — and they are the cheapest possible form of it: an empty
// firewalls count explains an abstention a later query would otherwise report
// without a cause.
func collectedSection(counts map[string]int) *Section {
	s := &Section{Title: "collected"}
	types := make([]string, 0, len(counts))
	for name := range counts {
		types = append(types, name)
	}
	sort.Strings(types)
	for _, name := range types {
		s.add(Row{Layer: name, Detail: fmt.Sprintf("%d", counts[name])})
	}
	if len(s.Rows) == 0 {
		s.Note = "the snapshot holds no resources"
	}
	return s
}

// collectionErrorSection is what could not be read.
//
// The failures themselves are in the snapshot rather than in this result — the
// collectors record them there so a later query can cite them — so this section
// counts them and says where to look. A count with nowhere to go would be a
// finding an operator cannot act on.
func collectionErrorSection(c Collection) *Section {
	if c.Complete {
		return &Section{
			Title: "collection errors",
			Note:  "every account, region, and resource type asked for was read",
		}
	}
	s := &Section{Title: "collection errors"}
	s.add(Row{
		Layer:   "collection",
		Verdict: labelIncomplete,
		Detail:  fmt.Sprintf("%s could not be read", errorCount(c.Errors)),
	})
	s.Note = "the failures are recorded in the snapshot, under collection_errors"
	return s
}

func targetCount(n int) string {
	if n == 1 {
		return "1 account and region"
	}
	return fmt.Sprintf("%d account and region pairs", n)
}

func errorCount(n int) string {
	if n == 1 {
		return "1 scope or resource type"
	}
	return fmt.Sprintf("%d scopes or resource types", n)
}
