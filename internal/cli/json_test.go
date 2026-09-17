package cli

// The --json schema, asserted through whole invocations.
//
// Requirement 16.5 asks for output stable enough to assert against, and the only
// way to hold that is to assert against it: these run the CLI the way a pipeline
// does, decode what it printed, and check the parts a consumer builds on — the
// kind discriminator, the three sections in their fixed slots, the row-level
// verdict vocabulary, the authoritative flag, and that every citation names
// something a reader can go and look up.
//
// Prose is not asserted here. An outcome line and an abstention reason are meant
// to be rewritten for clarity, and a test that pinned their wording would make a
// wording change look like a schema break. What is pinned is structure, presence,
// and the closed sets.
//
// Five commands render a format.Report through the Formatter: diagnose, compare,
// diff, test, and verify. query and firewall emit their own operation result under
// --json instead, deliberately, so they are out of this file's scope.
//
// Every invocation is offline: fixtures on disk, and verify runs with --skip-aws
// so no client is constructed.
//
// Redaction (requirement 14.7) is asserted where it is enforced, in
// internal/format's secret tests, over generated reports carrying planted
// credentials. Repeating it here against fixtures with no secrets in them would
// assert nothing.

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

// The decode target. Deliberately a separate declaration from format.Report
// rather than a reuse of it: a consumer reads keys, and a test that decoded into
// the very struct that produced the output would still pass after a tag was
// renamed on both sides.
type jsonRow struct {
	Layer   string `json:"layer"`
	Verdict string `json:"verdict"`
	Subject string `json:"subject"`
	Detail  string `json:"detail"`
}

type jsonSection struct {
	Title string    `json:"title"`
	Rows  []jsonRow `json:"rows"`
	Note  string    `json:"note"`
}

type jsonReport struct {
	Kind        string   `json:"kind"`
	Flow        string   `json:"flow"`
	Outcome     string   `json:"outcome"`
	Source      string   `json:"source"`
	Destination string   `json:"destination"`
	Subjects    []string `json:"subjects"`
	// The three fixed sections. Pointers so an absent section is
	// distinguishable from an empty one — requirement 14.2 wants all three
	// present, and "no abstentions" and "abstentions not reported" are opposite
	// findings that read the same if the key can go missing.
	Finding    *jsonSection  `json:"finding"`
	Cleared    *jsonSection  `json:"cleared"`
	Unresolved *jsonSection  `json:"unresolved"`
	Extra      []jsonSection `json:"extra"`
	// A pointer for the same reason: the flag has to be there whichever way it
	// points, and a plain bool cannot tell a false from a missing key.
	Authoritative *bool    `json:"authoritative"`
	Notice        string   `json:"notice"`
	Notes         []string `json:"notes"`
}

// Fixtures and endpoints. RFC 1918 addresses and placeholder accounts only,
// per requirement 17.
const (
	flowsFile = "testdata/declared-flows.yaml"
	// The double-inspection regression case: a flow a firewall drops, with the
	// rule that dropped it cited.
	blockedSrc = "10.30.32.10"
	blockedDst = "10.30.192.10"
	// A second source in the same snapshot, for the comparison's reference path.
	referenceSrc = "10.29.17.10"
)

// The row-level verdict vocabulary, closed on purpose.
//
// A consumer switches on these, so a new label is a schema change and should
// arrive as a failure here rather than as a surprise downstream. The set spans
// every renderer: layer decisions, comparison outcomes, snapshot changes,
// declared flow results, and the two verdicts and the caveat marker a
// cross-check carries.
var stableVerdicts = map[string]bool{
	// Layer decisions.
	"ALLOW": true, "DENY": true, "ABSTAIN": true,
	// Path comparison.
	"MATCH": true, "DIFFERS": true, "INCOMPLETE": true,
	// Snapshot diff.
	"ADDED": true, "REMOVED": true, "MODIFIED": true, "SAME": true,
	// Declared flows.
	"PASS": true, "FAIL": true, "INCONCLUSIVE": true,
	// Cross-check: the engine's own verdicts, the analyser's, and a caveat.
	"PERMITTED": true, "BLOCKED": true,
	"REACHABLE": true, "NOT REACHABLE": true, "NO RESULT": true,
	"AGREE": true, "DISAGREE": true, "CAVEAT": true,
}

// reportCommands is the set of invocations that render a Report, one per kind.
func reportCommands() []struct {
	name string
	kind string
	args []string
} {
	return []struct {
		name string
		kind string
		args []string
	}{
		{
			name: "diagnose",
			kind: "diagnosis",
			args: []string{
				"diagnose", "--snapshot", blockedSnapshot,
				"--from", blockedSrc, "--to", blockedDst, "--proto", "tcp", "--port", "443",
			},
		},
		{
			name: "compare",
			kind: "comparison",
			args: []string{
				"compare", "--snapshot", blockedSnapshot,
				"--from", blockedSrc, "--to", blockedDst, "--ref-from", referenceSrc,
				"--proto", "tcp", "--port", "443",
			},
		},
		{
			name: "diff",
			kind: "snapshot_diff",
			args: []string{"diff", "--from", permittedSnapshot, "--to", blockedSnapshot},
		},
		{
			name: "test",
			kind: "flow_test",
			args: []string{"test", "--snapshot", permittedSnapshot, "--flows", flowsFile},
		},
		{
			name: "verify",
			kind: "verification",
			args: []string{
				"verify", "--snapshot", blockedSnapshot,
				"--from", blockedSrc, "--to", referenceSrc, "--proto", "tcp", "--port", "8080",
				"--skip-aws",
			},
		},
	}
}

// The schema every report command answers with.
//
// Validates: Requirements 14.2, 16.5
func TestJSONOutputCarriesTheStableReportSchema(t *testing.T) {
	for _, tt := range reportCommands() {
		t.Run(tt.name, func(t *testing.T) {
			got := decodeJSON(t, tt.args...)

			// The discriminator. A consumer reads this first and picks its
			// handler from it, so it is the one field that can never be absent.
			if got.Kind != tt.kind {
				t.Errorf("kind = %q, want %q", got.Kind, tt.kind)
			}
			if got.Outcome == "" {
				t.Error("outcome is empty: the answer in one line is part of every report")
			}

			// All three sections, present whether or not they hold rows.
			for _, s := range []struct {
				name    string
				section *jsonSection
			}{
				{"finding", got.Finding},
				{"cleared", got.Cleared},
				{"unresolved", got.Unresolved},
			} {
				if s.section == nil {
					t.Errorf("section %q is absent: requirement 14.2 wants the blocker, what cleared, and what abstained in every report", s.name)
					continue
				}
				if s.section.Title == "" {
					t.Errorf("section %q has no title", s.name)
				}
				if len(s.section.Rows) == 0 && s.section.Note == "" {
					t.Errorf("section %q is empty and says nothing: an empty section has to state that it is empty", s.name)
				}
				checkRows(t, s.name, s.section.Rows)
			}
			for i, s := range got.Extra {
				checkRows(t, "extra["+s.Title+"]", s.Rows)
				if s.Title == "" {
					t.Errorf("extra[%d] has no title", i)
				}
			}

			// The authoritative flag, and the notice that has to accompany it.
			// Requirement 14.6: a finding resting on an abstention says so.
			if got.Authoritative == nil {
				t.Fatal("authoritative is absent: a consumer cannot tell a corroborated finding from one resting on an abstention")
			}
			if !*got.Authoritative && got.Notice == "" {
				t.Error("authoritative = false with no notice: requirement 14.6 wants the reason stated")
			}
			if *got.Authoritative && got.Notice != "" {
				t.Errorf("authoritative = true with a notice %q: a notice states why a finding is not authoritative", got.Notice)
			}
		})
	}
}

// checkRows asserts the row-level contract: no blank rows, verdicts drawn from
// the closed set, and every citation naming something.
func checkRows(t *testing.T, section string, rows []jsonRow) {
	t.Helper()
	for i, r := range rows {
		if r.Layer == "" && r.Verdict == "" && r.Subject == "" && r.Detail == "" {
			t.Errorf("%s row %d is entirely empty", section, i)
		}
		if r.Verdict != "" && !stableVerdicts[r.Verdict] {
			t.Errorf("%s row %d has verdict %q, which is not in the stable set: a new label is a schema change", section, i, r.Verdict)
		}
		// A row carrying a verdict heads a group and names what decided;
		// a row carrying a subject is a citation and needs its detail.
		if r.Verdict != "" && r.Layer == "" {
			t.Errorf("%s row %d carries verdict %q with no layer to attach it to", section, i, r.Verdict)
		}
		if r.Subject != "" && r.Detail == "" {
			t.Errorf("%s row %d cites %q with no detail: a citation without evidence is a bare identifier", section, i, r.Subject)
		}
	}
}

// The blocking layer, with the rules behind it.
//
// The double-inspection fixture is the case: a flow two firewalls see, dropped by
// a rule the report has to name. Requirement 14.4 wants that evidence and
// cross-cutting 2 wants it behind every finding, so the assertions are that the
// finding section leads with the blocking layer at DENY and that its citations
// carry identifiers.
//
// Validates: Requirements 14.2, 14.4, 16.5
func TestJSONBlockingLayerCarriesCitationsWithIdentifiers(t *testing.T) {
	got := decodeJSON(t,
		"diagnose", "--snapshot", blockedSnapshot,
		"--from", blockedSrc, "--to", blockedDst, "--proto", "tcp", "--port", "443",
	)

	if got.Finding == nil || len(got.Finding.Rows) == 0 {
		t.Fatalf("the finding section holds no rows, but the flow is blocked: %+v", got.Finding)
	}
	head := got.Finding.Rows[0]
	if head.Layer != "firewall" || head.Verdict != "DENY" {
		t.Errorf("finding leads with layer %q verdict %q, want firewall DENY", head.Layer, head.Verdict)
	}

	citations := 0
	for _, r := range got.Finding.Rows[1:] {
		if r.Subject == "" {
			continue
		}
		citations++
		if strings.TrimSpace(r.Subject) == "" {
			t.Errorf("citation %d has a blank identifier", citations)
		}
	}
	if citations == 0 {
		t.Error("the blocking layer cites nothing: requirement 14.4 wants the firewall rule behind the decision")
	}

	// The layers that were evaluated and did not block, each at ALLOW.
	if got.Cleared == nil || len(got.Cleared.Rows) == 0 {
		t.Fatal("no cleared layers reported, but routing and resolution were both evaluated")
	}
	cleared := layerVerdicts(got.Cleared.Rows)
	for _, want := range []string{"resolution", "route"} {
		if cleared[want] != "ALLOW" {
			t.Errorf("cleared layer %q = %q, want ALLOW", want, cleared[want])
		}
	}
}

// Cross-cutting 1, in the schema: an abstention is reported as an abstention.
//
// Both host layers go unread because diagnose opens no Systems Manager client, so
// they have to appear in the unresolved section at ABSTAIN with a reason, must not
// appear among the cleared layers, and the report must not claim to be
// authoritative.
//
// Validates: Requirements 14.2, 14.6, 16.5
func TestJSONAbstentionsAreReportedAsAbstentions(t *testing.T) {
	got := decodeJSON(t,
		"diagnose", "--snapshot", permittedSnapshot,
		"--from", permittedSrc, "--to", permittedDst, "--proto", "tcp", "--port", "443",
	)

	if got.Unresolved == nil {
		t.Fatal("no unresolved section: two host layers went unread")
	}
	abstained := layerVerdicts(got.Unresolved.Rows)
	for _, layer := range []string{"host_firewall", "host_listener"} {
		if abstained[layer] != "ABSTAIN" {
			t.Errorf("unresolved layer %q = %q, want ABSTAIN", layer, abstained[layer])
		}
	}
	// The reason travels with the abstention, not just the label.
	if !hasReason(got.Unresolved.Rows) {
		t.Error("an abstention was reported with no reason: requirement 14.2 wants the reason beside it")
	}

	// The same layers must not be counted as passes anywhere else.
	if got.Cleared != nil {
		cleared := layerVerdicts(got.Cleared.Rows)
		for _, layer := range []string{"host_firewall", "host_listener"} {
			if _, ok := cleared[layer]; ok {
				t.Errorf("layer %q appears among the cleared layers as %q: an abstention folded into a pass is the failure cross-cutting 1 forbids", layer, cleared[layer])
			}
		}
	}

	if got.Authoritative == nil || *got.Authoritative {
		t.Error("authoritative = true on a verdict resting on two abstentions")
	}
	if got.Finding == nil || len(got.Finding.Rows) != 0 {
		t.Errorf("the finding section holds rows, but nothing was shown to block this flow: %+v", got.Finding)
	}
	if got.Finding != nil && got.Finding.Note == "" {
		t.Error("an empty finding section says nothing: it has to state that no layer was shown to block")
	}
}

// One JSON value per invocation, and the same bytes every time.
//
// A consumer pipes stdout into a decoder, so anything else on the stream — a
// second value, a stray line of prose — breaks the parse. And a schema is only
// assertable if it is reproducible: two runs over one snapshot have to encode
// byte for byte identically, which is what rules out map iteration order and
// unsorted findings leaking into the output.
//
// Validates: Requirements 16.5
func TestJSONOutputIsOneValueAndDeterministic(t *testing.T) {
	for _, tt := range reportCommands() {
		t.Run(tt.name, func(t *testing.T) {
			first := runJSON(t, tt.args...)
			second := runJSON(t, tt.args...)
			if !bytes.Equal(first, second) {
				t.Errorf("two runs over the same input printed different bytes:\nfirst:\n%s\nsecond:\n%s", first, second)
			}

			dec := json.NewDecoder(bytes.NewReader(first))
			var v any
			if err := dec.Decode(&v); err != nil {
				t.Fatalf("output is not valid JSON: %v\n%s", err, first)
			}
			if err := dec.Decode(&v); err != io.EOF {
				t.Errorf("stdout carries more than one JSON value (second decode: %v): a consumer decodes the stream whole", err)
			}
		})
	}
}

// runJSON invokes a command with --json and returns stdout.
//
// The exit code is not asserted — exit_test.go owns that contract — but stderr
// is: a report command that printed a diagnostic alongside its JSON has gone
// wrong in a way the decode would not catch.
func runJSON(t *testing.T, args ...string) []byte {
	t.Helper()
	var stdout, stderr bytes.Buffer
	Run(append(append([]string(nil), args...), "--json"), &stdout, &stderr)
	if stderr.Len() != 0 {
		t.Fatalf("aws-netpath %s wrote to stderr: %s", strings.Join(args, " "), stderr.String())
	}
	if stdout.Len() == 0 {
		t.Fatalf("aws-netpath %s printed nothing", strings.Join(args, " "))
	}
	return stdout.Bytes()
}

func decodeJSON(t *testing.T, args ...string) jsonReport {
	t.Helper()
	out := runJSON(t, args...)
	var got jsonReport
	// Unknown fields are refused: a key appearing that this test does not know
	// about is a schema addition, and the point of the file is that additions
	// are noticed.
	dec := json.NewDecoder(bytes.NewReader(out))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&got); err != nil {
		t.Fatalf("decoding aws-netpath %s --json: %v\n%s", strings.Join(args, " "), err, out)
	}
	return got
}

// layerVerdicts maps each layer heading in a section to its verdict.
func layerVerdicts(rows []jsonRow) map[string]string {
	out := make(map[string]string, len(rows))
	for _, r := range rows {
		if r.Layer != "" {
			out[r.Layer] = r.Verdict
		}
	}
	return out
}

// hasReason reports whether any row carries prose without being a citation,
// which is the shape an abstention's reason takes.
func hasReason(rows []jsonRow) bool {
	for _, r := range rows {
		if r.Detail != "" && r.Subject == "" {
			return true
		}
	}
	return false
}
