package format

// What projecting a collection has to preserve.
//
// One thing, and it is the thing every later answer depends on: whether the
// collection is complete. A partial collection reported as a plain success is a
// snapshot a reader will query as though it held everything, and a layer missing
// from a snapshot abstains rather than passing — so the incompleteness has to
// travel with the report or the abstention it causes later arrives with no cause.

import (
	"strings"
	"testing"
)

func completeCollection() Collection {
	return Collection{
		OutputPath: "snapshot.json",
		Targets:    2,
		Complete:   true,
		Counts: map[string]int{
			"accounts": 1, "regions": 2, "vpcs": 3, "subnets": 9, "firewalls": 1,
		},
	}
}

func partialCollection() Collection {
	c := completeCollection()
	c.Errors = 1
	c.Complete = false
	c.Counts["firewalls"] = 0
	return c
}

// A complete collection reports what it wrote and what it holds.
func TestFromCollectionReportsWhatItCollected(t *testing.T) {
	got := FromCollection(completeCollection())

	if got.Kind != KindCollection {
		t.Errorf("kind = %q, want %q", got.Kind, KindCollection)
	}
	if !got.Authoritative {
		t.Error("a complete collection was reported as incomplete")
	}
	if got.Notice != "" {
		t.Errorf("a complete collection carries a notice: %q", got.Notice)
	}
	if len(got.Subjects) == 0 || !strings.Contains(got.Subjects[0], "snapshot.json") {
		t.Errorf("subjects = %v, want the path written", got.Subjects)
	}

	// The counts are the answer to whether there is enough here to query, so every
	// resource type asked about has to be on the page.
	collected := rowText(got.Finding.Rows)
	for _, want := range []string{"vpcs", "subnets", "firewalls"} {
		if !strings.Contains(collected, want) {
			t.Errorf("the collected section omits %q:\n%s", want, collected)
		}
	}
}

// A partial collection says so, in the place a reader cannot miss. Requirement 2.5
// carried into requirement 14.6's banner.
func TestFromCollectionStatesAPartialCollection(t *testing.T) {
	got := FromCollection(partialCollection())

	if got.Authoritative {
		t.Error("a partial collection was reported as complete")
	}
	if !strings.Contains(got.Notice, "abstains rather than passing") {
		t.Errorf("the notice does not say what a partial collection costs a later verdict: %q", got.Notice)
	}
	if unresolved := rowText(got.Unresolved.Rows); !strings.Contains(unresolved, "could not be read") {
		t.Errorf("the failures are not reported:\n%s", unresolved)
	}

	body := render(t, got, Options{Mode: ModeMarkdown})
	if !strings.Contains(body, "**Not authoritative.**") {
		t.Errorf("the markdown rendering drops the banner:\n%s", body)
	}
	if !strings.Contains(body, "collection_errors") {
		t.Errorf("the report does not say where the failures are recorded:\n%s", body)
	}
}

// A collection that attempted nothing says so rather than reporting a success.
func TestFromCollectionHandlesAnEmptyRun(t *testing.T) {
	got := FromCollection(Collection{})

	if got.Outcome != outcomeNoCollection {
		t.Errorf("outcome = %q, want %q", got.Outcome, outcomeNoCollection)
	}
	if _, err := renderErr(got); err != nil {
		t.Errorf("rendering an empty collection failed: %v", err)
	}
}
