package format

// Renderer tests.
//
// The goldens under testdata are the contract for all three renderings: a change
// to the layout is meant to be visible in a diff, because the text output is what
// an operator has learned to read and the JSON is what a test asserts against.
// Run with -update to rewrite them, and read the diff before committing it.

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jajera/aws-netpath/internal/model"
)

var update = flag.Bool("update", false, "rewrite the golden files under testdata")

func render(t *testing.T, r Report, o Options) string {
	t.Helper()
	var b strings.Builder
	if err := Write(&b, r, o); err != nil {
		t.Fatalf("Write(%s): %v", o.Mode, err)
	}
	return b.String()
}

// TestGoldenRenderings pins all three renderings of every fixture.
//
// Requirements 14.2 and 14.3: three distinct sections, in one order, in text by
// default and in markdown or JSON on request.
func TestGoldenRenderings(t *testing.T) {
	cases := []struct {
		golden string
		report Report
		opts   Options
	}{
		{"blocked-text", FromDiagnosis(blockedDiagnosis(t)), Options{Mode: ModeText}},
		{"blocked-markdown", FromDiagnosis(blockedDiagnosis(t)), Options{Mode: ModeMarkdown}},
		{"blocked-json", FromDiagnosis(blockedDiagnosis(t)), Options{Mode: ModeJSON}},
		{"abstained-text", FromDiagnosis(abstainedDiagnosis(t)), Options{Mode: ModeText}},
		{"abstained-markdown", FromDiagnosis(abstainedDiagnosis(t)), Options{Mode: ModeMarkdown}},
		{"abstained-json", FromDiagnosis(abstainedDiagnosis(t)), Options{Mode: ModeJSON}},
		{"comparison-text", FromComparison(comparisonResult(t)), Options{Mode: ModeText}},
		{"comparison-markdown", FromComparison(comparisonResult(t)), Options{Mode: ModeMarkdown}},
		{"comparison-json", FromComparison(comparisonResult(t)), Options{Mode: ModeJSON}},
		{"repeated-text", FromDiagnosis(repeatedRowsDiagnosis(t)), Options{Mode: ModeText}},
		{"repeated-markdown", FromDiagnosis(repeatedRowsDiagnosis(t)), Options{Mode: ModeMarkdown, MaxRows: 4}},
		{"verification-disagreed-text", FromVerification(disagreedVerification()), Options{Mode: ModeText}},
		{"verification-disagreed-markdown", FromVerification(disagreedVerification()), Options{Mode: ModeMarkdown}},
		{"verification-disagreed-json", FromVerification(disagreedVerification()), Options{Mode: ModeJSON}},
		{"verification-cross-region-text", FromVerification(crossRegionVerification()), Options{Mode: ModeText}},
		{"snapshot-diff-text", FromSnapshotDiff(snapshotDiff(t)), Options{Mode: ModeText}},
		{"snapshot-diff-markdown", FromSnapshotDiff(snapshotDiff(t)), Options{Mode: ModeMarkdown}},
		{"snapshot-diff-json", FromSnapshotDiff(snapshotDiff(t)), Options{Mode: ModeJSON}},
	}

	for _, tc := range cases {
		t.Run(tc.golden, func(t *testing.T) {
			got := render(t, tc.report, tc.opts)
			path := filepath.Join("testdata", tc.golden+".golden")
			if *update {
				if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
					t.Fatalf("update %s: %v", path, err)
				}
				return
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			if got != string(want) {
				t.Errorf("rendering differs from %s at %s\n--- got ---\n%s", path, firstDiff(got, string(want)), got)
			}
		})
	}
}

// TestThreeSectionsPresentAndOrdered asserts requirement 14.2 directly: the
// blocking Layer, then the Layers that passed, then the Abstentions — present
// even when a section is empty, because an absent Abstentions section and an
// empty one read identically and mean opposite things.
func TestThreeSectionsPresentAndOrdered(t *testing.T) {
	cases := []struct {
		name    string
		report  Report
		mode    Mode
		ordered []string
	}{
		{"blocked text", FromDiagnosis(blockedDiagnosis(t)), ModeText,
			[]string{"blocking layer — host_firewall:", "cleared layers:", "abstentions:"}},
		{"blocked markdown", FromDiagnosis(blockedDiagnosis(t)), ModeMarkdown,
			[]string{"## blocking layer — host_firewall", "## cleared layers", "## abstentions"}},
		{"abstained text", FromDiagnosis(abstainedDiagnosis(t)), ModeText,
			[]string{"blocking layer:", "cleared layers:", "abstentions:"}},
		{"comparison text", FromComparison(comparisonResult(t)), ModeText,
			[]string{"differences:", "matched layers:", "incomplete comparisons:"}},
		{"comparison markdown", FromComparison(comparisonResult(t)), ModeMarkdown,
			[]string{"## differences", "## matched layers", "## incomplete comparisons"}},
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

// TestJSONCarriesTheThreeSections asserts the same thing about the schema rather
// than the prose, which is what a test asserting against output will key on.
// Requirement 16.5.
func TestJSONCarriesTheThreeSections(t *testing.T) {
	var got Report
	if err := json.Unmarshal([]byte(render(t, FromDiagnosis(abstainedDiagnosis(t)), Options{Mode: ModeJSON})), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if got.Kind != KindDiagnosis {
		t.Errorf("kind = %q, want %q", got.Kind, KindDiagnosis)
	}
	for _, s := range []*Section{got.Finding, got.Cleared, got.Unresolved} {
		if s == nil {
			t.Fatalf("a section is absent from the schema: %+v", got)
		}
		if s.Title == "" {
			t.Errorf("section has no title: %+v", s)
		}
	}
	if got.Unresolved.Rows[0].Layer != string(model.LayerFirewall) {
		t.Errorf("first abstention = %q, want %s", got.Unresolved.Rows[0].Layer, model.LayerFirewall)
	}
	if got.Authoritative {
		t.Error("a verdict resting on two abstentions is reported as authoritative")
	}
}

// TestFirewallDecisionsCiteGroupPriorityAndSID covers requirement 14.4 in every
// mode, including a markdown rendering whose row budget is smaller than the
// number of rows: the rule reference is pinned, so the budget cannot take it.
func TestFirewallDecisionsCiteGroupPriorityAndSID(t *testing.T) {
	const (
		first  = "nfr-allow-east-west sid 3 (priority 6)"
		second = "nfr-inspect-egress sid 11 (priority 20)"
	)

	cases := []struct {
		name string
		opts Options
	}{
		{"text", Options{Mode: ModeText}},
		{"markdown", Options{Mode: ModeMarkdown}},
		{"json", Options{Mode: ModeJSON}},
		{"markdown with a row budget of one", Options{Mode: ModeMarkdown, MaxRows: 1}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := render(t, FromDiagnosis(repeatedRowsDiagnosis(t)), tc.opts)
			for _, want := range []string{first, second} {
				if !strings.Contains(got, want) {
					t.Errorf("firewall rule reference %q is not rendered:\n%s", want, got)
				}
			}
		})
	}
}

// TestMarkdownStatesTruncation covers requirement 14.5. The stating is the part
// that matters: a table that quietly stops has told the reader that what it showed
// was all there was.
func TestMarkdownStatesTruncation(t *testing.T) {
	report := FromDiagnosis(repeatedRowsDiagnosis(t))

	cases := []struct {
		name      string
		opts      Options
		truncated bool
		want      string
	}{
		{"default budget", Options{Mode: ModeMarkdown}, true,
			"1 of 14 rows omitted at the configured limit of 10"},
		{"configured budget", Options{Mode: ModeMarkdown, MaxRows: 4}, true,
			"7 of 14 rows omitted at the configured limit of 4"},
		{"unlimited", Options{Mode: ModeMarkdown, MaxRows: Unlimited}, false, ""},
		{"text is never truncated", Options{Mode: ModeText}, false, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := render(t, report, tc.opts)
			switch {
			case tc.truncated && !strings.Contains(got, tc.want):
				t.Errorf("truncation is not stated, want %q:\n%s", tc.want, got)
			case !tc.truncated && strings.Contains(got, "rows omitted"):
				t.Errorf("rows were truncated when none should have been:\n%s", got)
			}
			if !tc.truncated && !strings.Contains(got, "rtb-0aaa1111bbbb222211") {
				t.Errorf("the last route citation is missing from an untruncated rendering:\n%s", got)
			}
		})
	}
}

// TestNonAuthoritativeBanner covers requirement 14.6. A verdict resting on an
// Abstention says so in every mode, and a verdict that does not rest on one says
// nothing — a banner on every report is a banner nobody reads.
func TestNonAuthoritativeBanner(t *testing.T) {
	cases := []struct {
		name   string
		report Report
		mode   Mode
		want   string
	}{
		{"abstained text", FromDiagnosis(abstainedDiagnosis(t)), ModeText, "!! this verdict is not authoritative"},
		{"abstained markdown", FromDiagnosis(abstainedDiagnosis(t)), ModeMarkdown, "> **Not authoritative.**"},
		{"abstained json", FromDiagnosis(abstainedDiagnosis(t)), ModeJSON, `"authoritative": false`},
		{"blocked text", FromDiagnosis(blockedDiagnosis(t)), ModeText, ""},
		{"blocked markdown", FromDiagnosis(blockedDiagnosis(t)), ModeMarkdown, ""},
		{"blocked json", FromDiagnosis(blockedDiagnosis(t)), ModeJSON, `"authoritative": true`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := render(t, tc.report, Options{Mode: tc.mode})
			if tc.want != "" && !strings.Contains(got, tc.want) {
				t.Fatalf("want %q in:\n%s", tc.want, got)
			}
			if tc.want == "" {
				for _, unwanted := range []string{"not authoritative", "Not authoritative"} {
					if strings.Contains(got, unwanted) {
						t.Fatalf("an authoritative verdict carries %q:\n%s", unwanted, got)
					}
				}
			}
		})
	}
}

// TestBannerNamesTheAbstainingLayer asserts the banner is actionable rather than
// merely present: the operator's next move is to evaluate whichever Layer could
// not be read, so it has to say which one.
func TestBannerNamesTheAbstainingLayer(t *testing.T) {
	got := FromDiagnosis(abstainedDiagnosis(t)).Notice
	for _, want := range []string{"firewall", "host_firewall", "domain list rule group is not modelled"} {
		if !strings.Contains(got, want) {
			t.Errorf("the notice omits %q: %s", want, got)
		}
	}
}

// TestNoBlockerFoundIsStated is requirement 14.1's other half: a run that found
// nothing blocking says so, rather than leaving the verdict line empty.
func TestNoBlockerFoundIsStated(t *testing.T) {
	got := render(t, FromDiagnosis(abstainedDiagnosis(t)), Options{Mode: ModeText})
	for _, want := range []string{"verdict: " + outcomeNoBlocker, "no layer was shown to block this flow"} {
		if !strings.Contains(got, want) {
			t.Errorf("want %q in:\n%s", want, got)
		}
	}
}

// TestJSONIsStableAcrossFindingOrder covers requirement 16.5. Correlation records
// findings in the order the stages produced them, so a test asserting against
// JSON must not be sensitive to that order.
func TestJSONIsStableAcrossFindingOrder(t *testing.T) {
	d := blockedDiagnosis(t)
	first := render(t, FromDiagnosis(d), Options{Mode: ModeJSON})

	reversed := d
	reversed.Verdict.Results = make([]model.LayerResult, 0, len(d.Verdict.Results))
	for i := len(d.Verdict.Results) - 1; i >= 0; i-- {
		reversed.Verdict.Results = append(reversed.Verdict.Results, d.Verdict.Results[i])
	}
	second := render(t, FromDiagnosis(reversed), Options{Mode: ModeJSON})

	if first != second {
		t.Errorf("json output depends on the order findings were recorded in\n--- first ---\n%s\n--- second ---\n%s", first, second)
	}
	if !strings.Contains(first, `"kind": "diagnosis"`) {
		t.Errorf("kind is not the first key:\n%s", first)
	}
}

// TestUnknownModeIsAnError keeps a typo from silently selecting the default: a
// caller asking for "markdwon" wants to know.
func TestUnknownModeIsAnError(t *testing.T) {
	var b strings.Builder
	err := Write(&b, FromDiagnosis(blockedDiagnosis(t)), Options{Mode: "markdwon"})
	if err == nil {
		t.Fatal("an unknown mode rendered without error")
	}
	if !strings.Contains(err.Error(), "markdwon") {
		t.Errorf("the error does not name the mode: %v", err)
	}
}

// TestMarkdownEscapesTableSyntax keeps a pipe in a rule expression from ending
// the column it appears in.
func TestMarkdownEscapesTableSyntax(t *testing.T) {
	d := blockedDiagnosis(t)
	d.Verdict.Results[0].Citations[0].Detail = "zone public | allows 10.0.2.0/24\nand nothing else"

	got := render(t, FromDiagnosis(d), Options{Mode: ModeMarkdown})
	if !strings.Contains(got, `zone public \| allows 10.0.2.0/24 and nothing else`) {
		t.Errorf("a pipe or a newline reached a table cell unescaped:\n%s", got)
	}
}

// firstDiff reports where two renderings part company, so a golden failure points
// at a line rather than at two walls of text.
func firstDiff(got, want string) string {
	g, w := strings.Split(got, "\n"), strings.Split(want, "\n")
	for i := 0; i < len(g) && i < len(w); i++ {
		if g[i] != w[i] {
			return "line " + itoa(i+1) + ":\n  got:  " + g[i] + "\n  want: " + w[i]
		}
	}
	return "line " + itoa(min(len(g), len(w))+1) + ": one rendering is longer than the other"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}
