package format

// The markdown renderer, and why it truncates.
//
// This is the rendering an agent reads, and an agent pays for every row it is
// handed. Requirement 14.5 asks for markdown suited to low-token consumption,
// truncating repeated rows beyond a configured limit and stating the truncation —
// and the stating is the part that makes truncation honest. A table that quietly
// stops at ten rows has told the reader that ten rows is all there was.
//
// Two kinds of row are never dropped. Firewall policy evidence is pinned, because
// requirement 14.4 wants the rule group, priority, and SID behind every firewall
// decision and a budget is not a reason to stop citing policy. And a row carrying
// a Layer heading is pinned with it, since a table whose heading survived and
// whose evidence did not reads as a Layer with nothing behind it.

import (
	"fmt"
	"io"
	"strings"
)

func writeMarkdown(w io.Writer, r Report, o Options) error {
	var b strings.Builder

	fmt.Fprintf(&b, "# %s — %s\n", title(r.Kind), r.Outcome)

	// Blockquoted and immediately under the heading: the one thing a reader must
	// not miss is that the answer above may not be the answer. Requirement 14.6.
	if !r.Authoritative && r.Notice != "" {
		fmt.Fprintf(&b, "\n> **Not authoritative.** %s\n", r.Notice)
	}

	var header []string
	for _, f := range []struct{ label, value string }{
		{"flow", r.Flow},
		{"source", r.Source},
		{"destination", r.Destination},
		{"symptom", r.Symptom},
		{"host", r.Host},
	} {
		if f.value != "" {
			header = append(header, fmt.Sprintf("- %s: %s", f.label, cell(f.value)))
		}
	}
	for _, s := range r.Subjects {
		header = append(header, fmt.Sprintf("- %s", cell(s)))
	}
	if len(header) > 0 {
		fmt.Fprintf(&b, "\n%s\n", strings.Join(header, "\n"))
	}

	limit, limited := o.rowLimit()
	for _, s := range r.sections() {
		writeMarkdownSection(&b, s, limit, limited)
	}

	if len(r.Notes) > 0 {
		b.WriteString("\n## notes\n\n")
		for _, n := range r.Notes {
			fmt.Fprintf(&b, "- %s\n", cell(n))
		}
	}

	_, err := io.WriteString(w, b.String())
	return err
}

func writeMarkdownSection(b *strings.Builder, s Section, limit int, limited bool) {
	fmt.Fprintf(b, "\n## %s\n", s.Title)

	flat := flatten(s.Rows)
	rows, dropped := truncate(flat, limit, limited)
	switch {
	case len(rows) == 0:
	case bare(rows):
		// A section whose rows are Layer names and nothing else — the Layers a
		// comparison found identical, whose entries are deliberately omitted — is a
		// list. A four-column table around it would be three quarters empty cells.
		b.WriteString("\n")
		for _, row := range rows {
			fmt.Fprintf(b, "- %s (%s)\n", cell(row.Layer), cell(row.Verdict))
		}
	default:
		b.WriteString("\n| layer | verdict | evidence | detail |\n| --- | --- | --- | --- |\n")
		for _, row := range rows {
			fmt.Fprintf(b, "| %s | %s | %s | %s |\n",
				cell(row.Layer), cell(row.Verdict), code(row.Subject), cell(row.Detail))
		}
	}
	if dropped > 0 {
		fmt.Fprintf(b, "\n_%d of %d rows omitted at the configured limit of %d; the text and json renderings carry all of them._\n",
			dropped, len(flat), limit)
	}
	if s.Note != "" {
		fmt.Fprintf(b, "\n_%s._\n", cell(s.Note))
	}
}

// flatten folds a Layer heading and the rows beneath it into one row per piece of
// evidence, each carrying its own Layer and verdict.
//
// The text renderer prints the heading once and indents the evidence under it,
// which is the shape a terminal reads well. A table has no indentation, so the
// same structure there costs a row of empty cells for every heading — and empty
// cells are exactly the tokens requirement 14.5 asks this renderer not to spend.
func flatten(rows []Row) []Row {
	out := make([]Row, 0, len(rows))
	var layer, verdict string
	for i, row := range rows {
		if row.Layer != "" {
			layer, verdict = row.Layer, row.Verdict
			// A heading with detail of its own, or with nothing beneath it, is a row.
			// A bare heading is folded into the rows that follow.
			if row.Detail != "" || row.Subject != "" || i+1 == len(rows) || rows[i+1].Layer != "" {
				out = append(out, row)
			}
			continue
		}
		row.Layer, row.Verdict = layer, verdict
		out = append(out, row)
	}
	return out
}

// truncate keeps as many rows as the limit allows and reports how many it
// dropped, so the renderer can state the truncation rather than imply that the
// table was all there was.
//
// Two exemptions. A pinned row — firewall policy evidence — is always kept,
// because requirement 14.4 wants the rule group, priority, and SID behind every
// firewall decision and a display budget is not a reason to stop citing policy.
// And the first row of each Layer is kept, because a Layer that vanishes entirely
// reads as a Layer that was never evaluated.
func truncate(rows []Row, limit int, limited bool) (kept []Row, dropped int) {
	if !limited || len(rows) <= limit {
		return rows, 0
	}
	kept = make([]Row, 0, limit)
	seen := make(map[string]bool, limit)
	budget := limit
	for _, row := range rows {
		first := row.Layer != "" && !seen[row.Layer]
		seen[row.Layer] = true
		switch {
		case row.pinned || first:
			kept = append(kept, row)
		case budget > 0:
			budget--
			kept = append(kept, row)
		default:
			dropped++
		}
	}
	return kept, dropped
}

// bare reports whether every row is a Layer and a verdict with no evidence
// behind it.
func bare(rows []Row) bool {
	for _, row := range rows {
		if row.Layer == "" || row.Subject != "" || row.Detail != "" {
			return false
		}
	}
	return true
}

// title renders a Kind as a heading. The Kind is a JSON value and spelled for a
// machine; a heading is read by a person, so the underscore goes.
func title(k Kind) string {
	if k == "" {
		return "report"
	}
	return strings.ReplaceAll(string(k), "_", " ")
}

// cell escapes a value for a markdown table: a pipe would end the column and a
// newline would end the row, and the evidence this tool cites contains both.
func cell(s string) string {
	s = strings.ReplaceAll(s, "\r\n", " ")
	s = strings.NewReplacer("\n", " ", "\t", " ", "|", `\|`).Replace(s)
	return strings.TrimSpace(s)
}

// code renders an identifier as inline code, so a rule reference or a command
// survives a markdown reader intact.
func code(s string) string {
	if s == "" {
		return ""
	}
	return "`" + strings.ReplaceAll(cell(s), "`", "'") + "`"
}
