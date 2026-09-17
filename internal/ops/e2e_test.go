package ops

// The motivating incident, from snapshot to rendered report.
//
// diagnose_test.go already asserts the ops-level verdict for this scenario, so
// this is deliberately not that assertion again. What it adds is the half an
// operator actually reads: the projection onto the Formatter and the rendering
// out of it. A projection that dropped the allowlist citation, folded the three
// sections of requirement 14.2 into one, or omitted the abstentions section
// because nothing abstained would leave every ops-level assertion green and still
// send the reader back to the cloud layers they had already cleared.
//
// The scenario is the one the tool exists for. Every AWS layer permits tcp/22 end
// to end, the firewalld allowlist admits a neighbouring /26 rather than the
// source, and the answer is a single line on a host — which is the investigation
// that would otherwise have been spent in the wrong half of the stack.

import (
	"context"
	"strings"
	"testing"

	"github.com/jajera/aws-netpath/internal/format"
	"github.com/jajera/aws-netpath/internal/model"
)

// The allowlist entry healthyHostProber's firewalld reports. It covers a /26 the
// source is not in, which is what gives requirement 8.4's "citing the allowlist
// entries found" something specific to cite — and what makes the difference
// between a containment test and a string comparison visible in the output.
const testAllowlistEntry = "198.51.100.128/26"

// Every cloud layer passes, the host firewall blocks, and the rendered report
// carries the blocking layer with its citations, the layers that passed, and the
// abstentions with their reasons.
//
// Validates: Requirements 8.4, 14.1, 14.2
func TestMotivatingIncidentRendersTheHostFirewallBlock(t *testing.T) {
	res, err := Diagnose(context.Background(), diagnoseRequest(healthyHostProber()))
	if err != nil {
		t.Fatalf("Diagnose() error = %v", err)
	}

	// Requirement 14.1 asks for exactly one primary blocking Layer, and the claim
	// only means anything once every cloud Layer has been evaluated and cleared: a
	// cloud Layer that blocked would take precedence in flow order, and one that
	// abstained would leave the host firewall as the earliest layer known to block
	// rather than the layer blocking.
	for _, layerRes := range res.Verdict.Results {
		if layerRes.Layer.Host() {
			continue
		}
		if layerRes.Verdict != model.VerdictPass {
			t.Errorf("cloud layer %s = %s (%s), want a pass", layerRes.Layer, layerRes.Verdict, layerRes.Reason)
		}
	}
	// The same statement from the other side: nothing the verdict rests on went
	// unevaluated, so the finding is authoritative rather than provisional.
	if !res.Verdict.Authoritative {
		t.Errorf("verdict is not authoritative on a fully evaluated path: %+v", res.Verdict.Results)
	}

	// Requirement 8.4: the source is absent from the allowlist, so the host
	// firewall is the blocker — and the only one.
	blocker, found := res.PrimaryBlocker()
	if !found || blocker != model.LayerHostFirewall {
		t.Fatalf("primary blocker = %q (found = %t), want %s", blocker, found, model.LayerHostFirewall)
	}
	if len(res.Verdict.AdditionalBlocked) != 0 {
		t.Errorf("additional blockers = %v, want none; requirement 14.1 asks for one primary blocker",
			res.Verdict.AdditionalBlocked)
	}

	report := res.Report()

	// Requirement 14.2: three sections, distinct. Asserted on the projection
	// because "distinct" is a structural claim — a renderer can only keep them
	// apart if they arrive apart.
	for _, s := range []struct {
		name    string
		section *format.Section
	}{
		{"blocking layer", report.Finding},
		{"cleared layers", report.Cleared},
		{"abstentions", report.Unresolved},
	} {
		if s.section == nil {
			t.Fatalf("the report carries no %s section: %+v", s.name, report)
		}
	}
	if !strings.Contains(report.Finding.Title, string(model.LayerHostFirewall)) {
		t.Errorf("blocking section title = %q, want it to name %s", report.Finding.Title, model.LayerHostFirewall)
	}
	// The abstentions section says nothing abstained rather than arriving blank.
	// An empty section and a missing one read identically, and mean the opposite
	// things — which is the confusion the whole abstention machinery exists to
	// prevent.
	if len(report.Unresolved.Rows) == 0 && report.Unresolved.Note == "" {
		t.Error("the abstentions section is empty and silent; an empty section must state that it is empty")
	}
	for _, row := range report.Unresolved.Rows {
		if row.Detail == "" && row.Subject == "" {
			t.Errorf("abstention row %+v carries no reason; requirement 14.2 asks for the reasons", row)
		}
	}

	// Every rendering carries the same three sections. Requirement 14.3 lets the
	// caller choose the format, so a section present in text and absent from JSON
	// would mean the agent and the operator are reading different reports.
	modes := []struct {
		mode     format.Mode
		blocking string
		cleared  string
		abstain  string
	}{
		{
			mode:     format.ModeText,
			blocking: "\nblocking layer — host_firewall:\n",
			cleared:  "\ncleared layers:\n",
			abstain:  "\nabstentions:\n",
		},
		{
			mode:     format.ModeMarkdown,
			blocking: "## blocking layer — host_firewall\n",
			cleared:  "## cleared layers\n",
			abstain:  "## abstentions\n",
		},
		{
			mode:     format.ModeJSON,
			blocking: `"title": "blocking layer — host_firewall"`,
			cleared:  `"title": "cleared layers"`,
			abstain:  `"title": "abstentions"`,
		},
	}
	for _, tc := range modes {
		t.Run(string(tc.mode), func(t *testing.T) {
			got := renderReport(t, report, tc.mode)
			for _, want := range []string{tc.blocking, tc.cleared, tc.abstain} {
				if !strings.Contains(got, want) {
					t.Errorf("the %s rendering omits %q:\n%s", tc.mode, want, got)
				}
			}
			// Requirement 8.4 survives every rendering: the entry that nearly
			// covered the source is the one line an operator has to change.
			if !strings.Contains(got, testAllowlistEntry) {
				t.Errorf("the %s rendering does not cite the allowlist entry %s:\n%s", tc.mode, testAllowlistEntry, got)
			}
		})
	}

	// Cited under the blocking layer specifically, not merely present somewhere in
	// the document. A whole-report search would pass on an allowlist entry that
	// had drifted into the cleared layers, leaving the section an operator reads
	// for the fix without the evidence for it.
	blocking := textSection(t, renderReport(t, report, format.ModeText), "blocking layer — host_firewall")
	if !strings.Contains(blocking, testAllowlistEntry) {
		t.Errorf("the blocking section does not cite the allowlist entry %s:\n%s", testAllowlistEntry, blocking)
	}
	if !strings.Contains(blocking, "[DENY ] "+string(model.LayerHostFirewall)) {
		t.Errorf("the blocking section does not lead with the denying layer:\n%s", blocking)
	}
}

// textSection returns the body of one section of a rendered text report, so an
// assertion can be scoped to the section that is supposed to carry the evidence.
// Sections are separated by a blank line, which is what bounds the body.
func textSection(t *testing.T, rendered, title string) string {
	t.Helper()
	head := "\n" + title + ":\n"
	i := strings.Index(rendered, head)
	if i < 0 {
		t.Fatalf("the rendering has no %q section:\n%s", title, rendered)
	}
	body := rendered[i+len(head):]
	if j := strings.Index(body, "\n\n"); j >= 0 {
		return body[:j]
	}
	return body
}
