package format

// Requirement 14.7, enforced at the point of emission.
//
// The requirement is that no credential material or secret value is ever
// rendered. There are two places to hold that line: at every point that builds a
// finding, or at the one point that prints one. Only the second is checkable, and
// only the second stays true as collectors and probers are added — the evidence
// this tool cites includes host command output and resource names it did not
// choose, so a formatter that trusts its input to be clean is one surprising tag
// away from printing a token.
//
// So every string leaves through here, and the redaction runs before any renderer
// sees the Report, which means the text, markdown, and JSON outputs cannot
// disagree about what was withheld.
//
// The patterns are deliberately keyed on the label rather than on the shape of
// the value. A 40-character opaque string is indistinguishable from a resource
// identifier, and redacting by shape alone would eat the route table IDs and rule
// references that the citations exist to carry. What is recognisable is an access
// key ID's fixed prefix, a private key's header, and the handful of labels a
// credential is conventionally written under; a label match redacts only the
// value, so the surrounding evidence survives and the reader can see that
// something was withheld and where.

import "regexp"

// redactedMarker replaces a withheld value. It is deliberately visible: a silently
// dropped value reads as evidence that was never collected.
const redactedMarker = "[redacted]"

// credentialLabels are the labels a credential is conventionally written under.
// A label is matched only at a word boundary that is not part of an identifier,
// so an ARN segment does not trigger it.
const credentialLabels = `(?:aws[_-]?)?(?:secret[_-]?access[_-]?key|secret[_-]?key|session[_-]?token|security[_-]?token|access[_-]?key[_-]?id|client[_-]?secret|private[_-]?key|passwd|password|api[_-]?key|auth[_-]?token|credentials?|signature|token|secret)`

// credentialValue is the value a label introduces. It stops at whitespace and at
// the punctuation that ordinarily closes a phrase, so a redaction inside a
// parenthesis or a list does not swallow the bracket and leave the surrounding
// text unreadable.
const credentialValue = `[^\s)\]}>"',;]+`

type redaction struct {
	re   *regexp.Regexp
	repl string
}

var redactions = []redaction{
	// An access key ID is self-identifying: a fixed AWS prefix and sixteen
	// uppercase characters. It is the one credential recognisable by shape alone.
	{regexp.MustCompile(`\b(?:AKIA|ASIA|ABIA|ACCA|AIDA|AROA|ANPA|ANVA|APKA|ASCA)[0-9A-Z]{16}\b`), redactedMarker},
	// An authorization value runs to the end of the line, because a signed header
	// carries spaces inside the value and stopping at the first one would leave the
	// signature behind.
	{regexp.MustCompile(`(?i)(^|[-\s"'(\[{,;])(authorization)(\s*[:=]\s*)[^\n]+`), "${1}${2}${3}" + redactedMarker},
	// A labelled value: the label and its separator survive, the value does not.
	{regexp.MustCompile(`(?i)(^|[-\s"'(\[{,;])(` + credentialLabels + `)(\s*[:=]\s*)` + credentialValue), "${1}${2}${3}" + redactedMarker},
	{regexp.MustCompile(`(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}`), "${1} " + redactedMarker},
	// A PEM private key, whether or not the whole block arrived.
	{regexp.MustCompile(`(?s)-----BEGIN[A-Z ]*PRIVATE KEY-----.*?-----END[A-Z ]*PRIVATE KEY-----`), redactedMarker},
	{regexp.MustCompile(`-----BEGIN[A-Z ]*PRIVATE KEY-----`), redactedMarker},
}

// scrub redacts credential-shaped material in one string.
func scrub(s string) string {
	if s == "" {
		return s
	}
	for _, r := range redactions {
		s = r.re.ReplaceAllString(s, r.repl)
	}
	return s
}

// redacted returns a copy of the Report with every rendered string scrubbed. It
// is called once, by Write, before any renderer runs.
func (r Report) redacted() Report {
	out := r
	out.Flow = scrub(r.Flow)
	out.Outcome = scrub(r.Outcome)
	out.Source = scrub(r.Source)
	out.Destination = scrub(r.Destination)
	out.Symptom = scrub(r.Symptom)
	out.Host = scrub(r.Host)
	out.Notice = scrub(r.Notice)
	out.Subjects = scrubAll(r.Subjects)
	out.Notes = scrubAll(r.Notes)
	out.Finding = r.Finding.redacted()
	out.Cleared = r.Cleared.redacted()
	out.Unresolved = r.Unresolved.redacted()
	if len(r.Extra) > 0 {
		out.Extra = make([]Section, 0, len(r.Extra))
		for _, s := range r.Extra {
			out.Extra = append(out.Extra, *s.redacted())
		}
	}
	return out
}

func (s *Section) redacted() *Section {
	if s == nil {
		return nil
	}
	out := *s
	out.Title = scrub(s.Title)
	out.Note = scrub(s.Note)
	if len(s.Rows) > 0 {
		out.Rows = make([]Row, 0, len(s.Rows))
		for _, row := range s.Rows {
			row.Layer = scrub(row.Layer)
			row.Verdict = scrub(row.Verdict)
			row.Subject = scrub(row.Subject)
			row.Detail = scrub(row.Detail)
			out.Rows = append(out.Rows, row)
		}
	}
	return &out
}

func scrubAll(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, s := range in {
		out = append(out, scrub(s))
	}
	return out
}
