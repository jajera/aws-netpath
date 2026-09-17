package format

// The text renderer, and the inherited output style it keeps.
//
// The style is not decoration. `[ALLOW]`, `[DENY ]`, `[ABSTAIN]`, and the
// indented `cited:` lines beneath them are what the inherited reports already
// print, and an operator who has read that output can read this one without
// being taught anything. Requirement 14.3 makes text the default for the same
// reason: the reader who did not ask for a format is a person.
//
// Nothing is truncated here. The row budget belongs to markdown, whose audience
// pays per token; a person reading a terminal asked for the evidence and gets all
// of it.

import (
	"fmt"
	"io"
	"strings"
)

func writeText(w io.Writer, r Report) error {
	var b strings.Builder

	for _, f := range []struct{ label, value string }{
		{"flow", r.Flow},
		{"source", r.Source},
		{"destination", r.Destination},
		{"symptom", r.Symptom},
		{"host", r.Host},
	} {
		if f.value != "" {
			fmt.Fprintf(&b, "%s: %s\n", f.label, f.value)
		}
	}
	for _, s := range r.Subjects {
		if r.SubjectLabel != "" {
			fmt.Fprintf(&b, "%s: %s\n", r.SubjectLabel, s)
			continue
		}
		fmt.Fprintf(&b, "%s\n", s)
	}
	fmt.Fprintf(&b, "verdict: %s\n", r.Outcome)

	// The banner sits with the verdict it qualifies rather than at the foot of the
	// report, because a reader who stops after the verdict line is exactly the
	// reader requirement 14.6 is written for.
	if !r.Authoritative && r.Notice != "" {
		fmt.Fprintf(&b, "!! %s\n", r.Notice)
	}

	for _, s := range r.sections() {
		writeTextSection(&b, s)
	}
	for _, n := range r.Notes {
		fmt.Fprintf(&b, "note: %s\n", n)
	}

	_, err := io.WriteString(w, b.String())
	return err
}

func writeTextSection(b *strings.Builder, s Section) {
	fmt.Fprintf(b, "\n%s:\n", s.Title)
	for _, row := range s.Rows {
		switch {
		case row.Layer != "":
			fmt.Fprintf(b, "  %s %s\n", statusTag(row.Verdict), row.Layer)
			if row.Detail != "" {
				fmt.Fprintf(b, "         %s\n", row.Detail)
			}
		case row.Subject != "":
			fmt.Fprintf(b, "         cited: %s\n", strings.TrimSpace(row.Subject+"  "+row.Detail))
		case row.Detail != "":
			fmt.Fprintf(b, "         %s\n", row.Detail)
		}
	}
	if s.Note != "" {
		fmt.Fprintf(b, "  (%s)\n", s.Note)
	}
}

// statusTag renders a row label in the inherited fixed-width form, so the
// resource names line up down the page.
func statusTag(verdict string) string {
	if verdict == "" {
		return "       "
	}
	return fmt.Sprintf("[%-5s]", verdict)
}
