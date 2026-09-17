package cli

// The flags more than one command carries.
//
// Renderer selection and the observed symptom are not properties of a single
// command, and a per-command copy of either is a per-command chance to drift:
// --json meaning one thing under diagnose and another under test is the kind of
// difference nobody notices until a pipeline parses a shape it did not expect. So
// registration and resolution live here once, and a command only decides whether
// it carries them.
//
// Neither helper decides anything a command could disagree about. The renderers
// are the ones internal/format already builds, and the symptom vocabulary is
// read from internal/symptom rather than restated, so help text cannot list a
// symptom the classifier does not recognise or omit one it does.

import (
	"errors"
	"flag"
	"strings"

	"github.com/jajera/aws-netpath/internal/format"
	"github.com/jajera/aws-netpath/internal/symptom"
)

// errRendererConflict reports --json and --markdown given together.
//
// Two renderings of one report cannot both be the output, and choosing one by
// precedence would hand a caller a shape it did not ask for. So this is a usage
// error, refused before the operation runs.
var errRendererConflict = errors.New("--json and --markdown select two different renderings: pass one, or neither for text")

// outputFlags are the renderer selectors carried by every command that renders a
// report.
type outputFlags struct {
	asJSON     *bool
	asMarkdown *bool
}

// addOutputFlags registers --json and --markdown on fs.
//
// Text has no flag because it is the default, which is requirement 14.3: an
// operator gets prose without asking, and a machine asks.
func addOutputFlags(fs *flag.FlagSet) outputFlags {
	return outputFlags{
		asJSON:     fs.Bool("json", false, "render the report as JSON instead of text"),
		asMarkdown: fs.Bool("markdown", false, "render the report as markdown instead of text"),
	}
}

// options resolves the flags to a rendering, or reports the conflict between
// them.
func (o outputFlags) options() (format.Options, error) {
	switch {
	case *o.asJSON && *o.asMarkdown:
		return format.Options{}, errRendererConflict
	case *o.asJSON:
		return format.Options{Mode: format.ModeJSON}, nil
	case *o.asMarkdown:
		return format.Options{Mode: format.ModeMarkdown}, nil
	default:
		return format.Options{Mode: format.ModeText}, nil
	}
}

// addSymptomFlag registers --symptom on fs.
//
// An unrecognised value is refused by the classifier when the operation runs,
// before any snapshot is read, and the resulting error names the flag and lists
// the accepted values. The CLI does not pre-validate it: one rejection, in one
// place, is what keeps the MCP surface answering the same way.
func addSymptomFlag(fs *flag.FlagSet) *string {
	return fs.String("symptom", "",
		"observed client-side failure, which is checked first: "+strings.Join(symptomNames(), ", "))
}

// symptomNames lists the recognised symptoms in the classifier's own order, so
// help text and its error messages agree.
func symptomNames() []string {
	in := symptom.Symptoms()
	out := make([]string, 0, len(in))
	for _, s := range in {
		out = append(out, s.String())
	}
	return out
}
