package format

// The JSON renderer, and what "stable" means here.
//
// Requirement 16.5 asks for output stable enough to assert against in tests, so
// the schema is the Report struct: key order is field order, every key is spelled
// by a tag, and nothing is emitted from a map whose iteration order would vary
// between runs. The Layer findings are sorted along the Flow when the Report is
// built, so two runs that recorded the same findings in a different order encode
// byte for byte identically.
//
// Nothing is truncated. The row budget exists to keep an agent's reading cheap;
// a test asserting against JSON wants the whole finding, and a schema whose
// contents depend on a display limit is not one worth asserting against.

import (
	"encoding/json"
	"io"
)

func writeJSON(w io.Writer, r Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	// The evidence carries angle brackets and ampersands — port ranges, rule
	// expressions, command lines — and \u0026 in a citation is unreadable to both
	// audiences this output has.
	enc.SetEscapeHTML(false)
	return enc.Encode(r)
}
