package cli

import (
	"errors"
	"flag"
	"io"
	"strings"
	"testing"

	"github.com/jajera/aws-netpath/internal/format"
	"github.com/jajera/aws-netpath/internal/symptom"
)

// parseOutputFlags registers the renderer selectors on a throwaway flag set and
// parses args through them, which is how a command reaches them.
func parseOutputFlags(t *testing.T, args ...string) outputFlags {
	t.Helper()
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	out := addOutputFlags(fs)
	if err := fs.Parse(args); err != nil {
		t.Fatalf("parse %v: %v", args, err)
	}
	return out
}

func TestRendererSelection(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want format.Mode
	}{
		// Requirement 14.3: text without asking, JSON or markdown on request.
		{"no flag renders text", nil, format.ModeText},
		{"json", []string{"--json"}, format.ModeJSON},
		{"markdown", []string{"--markdown"}, format.ModeMarkdown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts, err := parseOutputFlags(t, tt.args...).options()
			if err != nil {
				t.Fatalf("options: %v", err)
			}
			if opts.Mode != tt.want {
				t.Errorf("%v selected mode %q, want %q", tt.args, opts.Mode, tt.want)
			}
		})
	}
}

func TestBothRenderersIsAUsageError(t *testing.T) {
	_, err := parseOutputFlags(t, "--json", "--markdown").options()
	if !errors.Is(err, errRendererConflict) {
		t.Fatalf("--json --markdown returned %v, want the renderer conflict", err)
	}
	// The message has to name both flags: an operator who passed two renderers
	// needs to know which one to drop.
	for _, want := range []string{"--json", "--markdown"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not mention %s: %v", want, err)
		}
	}
}

// The help text is read from the classifier rather than restated, so this asserts
// they agree rather than asserting a hardcoded list.
func TestSymptomFlagListsEveryRecognisedSymptom(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	addSymptomFlag(fs)

	f := fs.Lookup("symptom")
	if f == nil {
		t.Fatal("--symptom was not registered")
	}
	if f.DefValue != "" {
		// Requirement 9.5: no symptom means flow order, so the flag cannot
		// default to one.
		t.Errorf("--symptom defaults to %q, want no symptom", f.DefValue)
	}
	for _, s := range symptom.Symptoms() {
		if !strings.Contains(f.Usage, s.String()) {
			t.Errorf("the --symptom help text omits %s: %s", s, f.Usage)
		}
	}
}
