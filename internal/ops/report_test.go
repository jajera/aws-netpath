package ops

// The seam, exercised end to end.
//
// The renderer's own tests work from fixtures, so they cannot catch a projection
// that drops the flow or names the wrong endpoint. These run the real pipeline and
// render what came out of it, which is the only way to find out that the two
// halves still fit.

import (
	"context"
	"strings"
	"testing"

	"github.com/jajera/aws-netpath/internal/format"
)

func renderReport(t *testing.T, r format.Report, mode format.Mode) string {
	t.Helper()
	var b strings.Builder
	if err := format.Write(&b, r, format.Options{Mode: mode}); err != nil {
		t.Fatalf("format.Write(%s): %v", mode, err)
	}
	return b.String()
}

// Requirements 14.2 and 14.4 through the operation: the motivating incident
// renders as a host firewall block, with the cloud layers it cleared and the
// firewall rule that cleared them.
func TestDiagnoseResultRenders(t *testing.T) {
	res, err := Diagnose(context.Background(), diagnoseRequest(healthyHostProber()))
	if err != nil {
		t.Fatalf("Diagnose() error = %v", err)
	}

	got := renderReport(t, res.Report(), format.ModeText)
	for _, want := range []string{
		"flow: " + res.Flow.String(),
		"source: " + res.Source.Description(),
		"destination: " + res.Destination.Description(),
		"host: " + res.Host.InstanceID,
		"cleared layers:",
		"abstentions:",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the rendering omits %q:\n%s", want, got)
		}
	}

	blocker, blocked := res.PrimaryBlocker()
	switch {
	case blocked && !strings.Contains(got, "verdict: BLOCKED at "+string(blocker)):
		t.Errorf("the rendering does not lead with the blocking layer %s:\n%s", blocker, got)
	case !blocked && !strings.Contains(got, "verdict: NO BLOCKER FOUND"):
		t.Errorf("the rendering does not state that no blocker was found:\n%s", got)
	}
}

// A verdict resting on an abstention says so through the seam as well, since the
// host layers abstain whenever no prober was supplied. Requirement 14.6.
func TestDiagnoseResultWithoutAProberRendersTheBanner(t *testing.T) {
	res, err := Diagnose(context.Background(), diagnoseRequest(nil))
	if err != nil {
		t.Fatalf("Diagnose() error = %v", err)
	}
	if res.Verdict.Authoritative {
		t.Fatal("a run with no host prober produced an authoritative verdict")
	}

	report := res.Report()
	if !strings.Contains(renderReport(t, report, format.ModeText), "!! this verdict is not authoritative") {
		t.Errorf("the text rendering carries no banner:\n%s", renderReport(t, report, format.ModeText))
	}
	if !strings.Contains(renderReport(t, report, format.ModeMarkdown), "> **Not authoritative.**") {
		t.Errorf("the markdown rendering carries no banner:\n%s", renderReport(t, report, format.ModeMarkdown))
	}
	if !strings.Contains(renderReport(t, report, format.ModeJSON), `"authoritative": false`) {
		t.Errorf("the json rendering does not report the verdict as unauthoritative:\n%s", renderReport(t, report, format.ModeJSON))
	}
}

// Requirement 10.1 through the seam: the comparison leads with the differences,
// and the layers both paths met identically are named without their entries.
func TestCompareResultRenders(t *testing.T) {
	res, err := Compare(context.Background(), CompareRequest{
		Snapshot: siblingSnapshot(),
		From:     testSrcAddr.String(),
		To:       testDstInstance,
		RefFrom:  testRefAddr.String(),
		Proto:    "tcp",
		Port:     22,
		Symptom:  "no-route-to-host",
		Prober:   siblingHostProber(),
	})
	if err != nil {
		t.Fatalf("Compare() error = %v", err)
	}

	got := renderReport(t, res.Report(), format.ModeMarkdown)
	for _, want := range []string{
		"# comparison —",
		"## differences",
		"## matched layers",
		"## incomplete comparisons",
		"host_firewall",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the rendering omits %q:\n%s", want, got)
		}
	}
}

// A nil result renders rather than panicking: the CLI maps an error to an exit
// code and may still be asked to print something.
func TestNilResultsRender(t *testing.T) {
	var (
		diagnose *DiagnoseResult
		compare  *CompareResult
	)
	if got := diagnose.Report().Kind; got != format.KindDiagnosis {
		t.Errorf("nil diagnose report kind = %q, want %q", got, format.KindDiagnosis)
	}
	if got := compare.Report().Kind; got != format.KindComparison {
		t.Errorf("nil compare report kind = %q, want %q", got, format.KindComparison)
	}
}
