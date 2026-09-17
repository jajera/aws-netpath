// Package format renders a finding for a human, for an agent, or for a test.
//
// It is the last stage of every operation and it decides nothing. A Verdict
// arrives correlated, with one primary blocking Layer or none, and this package
// arranges it — it never re-derives precedence, never aggregates a Layer, and
// never turns an Abstention into a pass by leaving it out.
//
// Three fixed sections, in one order, for every operation. Requirement 14.2 asks
// for the blocking Layer with its Citations, the Layers that passed, and the
// Abstentions with their reasons, and the order matters as much as the content:
// an operator reading top to bottom meets the answer, then what has been ruled
// out, then what could not be established. The comparison renderer fills the
// same three slots with the differences, the Layers that matched, and the
// comparisons that could not be made, because a reader who has learned where to
// look should not have to learn again per command.
//
// Rendering is pure. One projection — Report — is built once and rendered three
// ways, so text, markdown, and JSON cannot disagree about what was found. The
// package reads no file, makes no API call, and touches no AWS SDK type; the
// only side effect available to it is writing to an io.Writer.
//
// Two guarantees are enforced here rather than assumed of the caller.
//
// A firewall Citation is never dropped. Requirement 14.4 wants the rule group,
// priority, and SID behind every firewall decision, and requirement 14.5 wants
// markdown short enough for an agent to read cheaply. Those pull in opposite
// directions, so firewall rows are pinned: truncation takes ordinary rows and
// leaves the policy evidence alone, and states how many rows it took.
//
// Credential-shaped text is redacted on the way out. Requirement 14.7 forbids
// emitting secret material, and the honest way to hold that line is at the point
// of emission — the evidence this tool cites includes host command output, and a
// formatter that trusts its input to be clean is one surprising tag away from
// printing a token.
package format

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/jajera/aws-netpath/internal/model"
)

// Mode selects a renderer. Text is the default, which is requirement 14.3: an
// operator gets prose without asking, and a machine asks.
type Mode string

const (
	ModeText     Mode = "text"
	ModeMarkdown Mode = "markdown"
	ModeJSON     Mode = "json"
)

// DefaultMaxRows is the markdown row limit when none is configured. It is a
// budget, not a truth claim: the full evidence is always in the text and JSON
// renderings, and every truncated table says how much it left out.
const DefaultMaxRows = 10

// Unlimited disables markdown row truncation.
const Unlimited = -1

// Options configures a rendering.
type Options struct {
	// Mode selects the renderer. The zero value renders text.
	Mode Mode
	// MaxRows is the markdown row limit per section. Zero uses DefaultMaxRows,
	// Unlimited (or any negative value) truncates nothing.
	MaxRows int
}

// rowLimit returns the effective markdown row limit, and whether one applies.
func (o Options) rowLimit() (int, bool) {
	switch {
	case o.MaxRows < 0:
		return 0, false
	case o.MaxRows == 0:
		return DefaultMaxRows, true
	default:
		return o.MaxRows, true
	}
}

// Kind names the operation a Report came from, so a consumer reading JSON knows
// which shape it holds without inspecting the fields.
type Kind string

const (
	KindDiagnosis    Kind = "diagnosis"
	KindComparison   Kind = "comparison"
	KindSnapshotDiff Kind = "snapshot_diff"
)

// Row-level verdict labels. They are the report's vocabulary rather than the
// model's: ALLOW and DENY are what the inherited output already prints, and a
// comparison has outcomes no Layer verdict describes.
const (
	labelAllow      = "ALLOW"
	labelDeny       = "DENY"
	labelAbstain    = "ABSTAIN"
	labelMatch      = "MATCH"
	labelDiffers    = "DIFFERS"
	labelIncomplete = "INCOMPLETE"
)

// Outcome strings. Requirement 14.1 has two halves and this is the second one:
// "no blocker found" is a statement, not an empty verdict line.
const (
	outcomeNoBlocker = "NO BLOCKER FOUND"
	outcomeBlocked   = "BLOCKED at %s"
	// outcomePermitted is the answer to a question that asked whether traffic
	// gets through rather than why it does not. A walk and a policy evaluation
	// both answer it, and they answer it with the same word the inherited output
	// already prints.
	outcomePermitted = "PERMITTED"
	outcomeDiffers   = "DIFFERS at %s"
	outcomeIdentical = "IDENTICAL at every layer compared"
	outcomeNoDiff    = "NO COMPARISON"
)

// Row is one line of evidence.
//
// A row with a Subject is a Citation: it names the thing a reader can go and
// check. A row without one carries the prose that introduces the rows beneath
// it — an Abstention's reason, an Observation's summary — which is the shape the
// inherited output already uses, and keeping it means a reader's eye does not
// have to be retrained.
type Row struct {
	// Layer is set on the first row of a group and empty on the rest, so a
	// renderer prints the Layer heading once.
	Layer string `json:"layer,omitempty"`
	// Verdict is a row-level label: ALLOW, DENY, ABSTAIN, or a comparison
	// outcome. Empty for a continuation row.
	Verdict string `json:"verdict,omitempty"`
	// Subject is the Citation identifier: a resource ID, a rule reference, or the
	// command whose output was read.
	Subject string `json:"subject,omitempty"`
	// Detail is the supporting text: the Citation detail, the Abstention reason,
	// or the comparison summary.
	Detail string `json:"detail,omitempty"`
	// pinned rows survive truncation. Firewall policy evidence is pinned so
	// requirement 14.4 holds whatever the row budget is.
	pinned bool
}

// Section is one of the report's parts. Every report carries the same three in
// the same order, present even when empty, because a missing Abstentions section
// and an empty one read identically and mean opposite things.
type Section struct {
	Title string `json:"title"`
	Rows  []Row  `json:"rows,omitempty"`
	// Note states something about the section as a whole: that it is empty, that
	// other Layers also blocked, or that rows were truncated.
	Note string `json:"note,omitempty"`
}

func (s *Section) add(rows ...Row) {
	if s == nil {
		return
	}
	s.Rows = append(s.Rows, rows...)
}

// Report is the render-ready projection of a finding, and the JSON schema.
//
// Field order is the JSON key order and the reading order, and both are part of
// the contract: requirement 16.5 asks for output stable enough to assert
// against, so this struct is the schema rather than a map or an interface value
// whose shape depends on what was found.
type Report struct {
	Kind Kind   `json:"kind"`
	Flow string `json:"flow,omitempty"`
	// Outcome is the answer in one line: the blocking Layer, or that none was
	// found.
	Outcome     string   `json:"outcome"`
	Source      string   `json:"source,omitempty"`
	Destination string   `json:"destination,omitempty"`
	Symptom     string   `json:"symptom,omitempty"`
	Host        string   `json:"host,omitempty"`
	Subjects    []string `json:"subjects,omitempty"`
	// SubjectLabel is the noun the Subjects are, used by the text renderer to
	// introduce them. A comparison's subjects are paths and a diff's are
	// snapshots, and a report that called both "path" would be teaching the reader
	// something untrue. It is a rendering hint rather than a finding, so it stays
	// out of the JSON schema.
	SubjectLabel string `json:"-"`
	// Finding is section one: the blocking Layer with its Citations, or the
	// differences between two paths.
	Finding *Section `json:"finding,omitempty"`
	// Cleared is section two: the Layers that passed, or the Layers that matched.
	Cleared *Section `json:"cleared,omitempty"`
	// Unresolved is section three: the Abstentions with reasons, or the
	// comparisons that could not be made.
	Unresolved *Section `json:"unresolved,omitempty"`
	// Extra carries findings that are not Layer decisions: Observations, a
	// probable cause, a contradiction against the Symptom, the Layers a
	// comparison leaves as the remaining explanation.
	Extra []Section `json:"extra,omitempty"`
	// Authoritative is false when the finding rests on an Abstention.
	Authoritative bool `json:"authoritative"`
	// Notice states why the finding is not authoritative, empty when it is.
	// Requirement 14.6.
	Notice string   `json:"notice,omitempty"`
	Notes  []string `json:"notes,omitempty"`
}

// sections returns the sections in reading order, skipping any the report does
// not carry.
func (r Report) sections() []Section {
	out := make([]Section, 0, 3+len(r.Extra))
	for _, s := range []*Section{r.Finding, r.Cleared, r.Unresolved} {
		if s != nil {
			out = append(out, *s)
		}
	}
	return append(out, r.Extra...)
}

// Write renders r to w in the requested Mode.
func Write(w io.Writer, r Report, o Options) error {
	r = r.redacted()
	switch o.Mode {
	case ModeText, "":
		return writeText(w, r)
	case ModeMarkdown:
		return writeMarkdown(w, r, o)
	case ModeJSON:
		return writeJSON(w, r)
	default:
		return fmt.Errorf("format: unknown mode %q: want %s, %s, or %s", o.Mode, ModeText, ModeMarkdown, ModeJSON)
	}
}

// WriteDiagnosis renders a diagnosis.
func WriteDiagnosis(w io.Writer, d Diagnosis, o Options) error {
	return Write(w, FromDiagnosis(d), o)
}

// citationRows renders Citations as evidence rows, pinning firewall policy so
// truncation cannot take the rule group, priority, and SID with it.
func citationRows(cs []model.Citation) []Row {
	out := make([]Row, 0, len(cs))
	for _, c := range cs {
		out = append(out, Row{
			Subject: c.Identifier,
			Detail:  c.Detail,
			pinned:  c.Kind == citationKindFirewall,
		})
	}
	return out
}

// citationKindFirewall is the Citation kind carrying firewall policy evidence.
// It matches the kind internal/nfw records.
const citationKindFirewall = "nfw_rule"

// layerRows renders one Layer's finding: a heading row carrying the Layer and
// its verdict, then one row per Citation.
func layerRows(res model.LayerResult) []Row {
	head := Row{Layer: string(res.Layer), Verdict: verdictLabel(res.Verdict)}
	if res.Verdict == model.VerdictAbstain {
		// The reason leads, because an Abstention's reason is the finding and its
		// Citations are only where the reason was established.
		rows := append([]Row{head}, Row{Detail: res.Reason})
		return append(rows, citationRows(res.Citations)...)
	}
	return append([]Row{head}, citationRows(res.Citations)...)
}

func verdictLabel(v model.LayerVerdict) string {
	switch v {
	case model.VerdictPass:
		return labelAllow
	case model.VerdictBlocked:
		return labelDeny
	default:
		return labelAbstain
	}
}

// sortResults orders findings along the Flow, so two runs that recorded the same
// Layers in a different order render identically. An unknown Layer sorts last by
// name rather than being dropped.
func sortResults(in []model.LayerResult) []model.LayerResult {
	out := append([]model.LayerResult(nil), in...)
	sort.SliceStable(out, func(i, j int) bool {
		return lessLayer(out[i].Layer, out[j].Layer)
	})
	return out
}

func sortLayers(in []model.Layer) []model.Layer {
	out := append([]model.Layer(nil), in...)
	sort.SliceStable(out, func(i, j int) bool { return lessLayer(out[i], out[j]) })
	return out
}

func lessLayer(a, b model.Layer) bool {
	ai, bi := a.FlowIndex(), b.FlowIndex()
	switch {
	case ai < 0 && bi < 0:
		return a < b
	case ai < 0:
		return false
	case bi < 0:
		return true
	default:
		return ai < bi
	}
}

func layerList(layers []model.Layer) string {
	names := make([]string, 0, len(layers))
	for _, l := range layers {
		names = append(names, string(l))
	}
	return strings.Join(names, ", ")
}

// joinList renders a short list as a phrase, so a notice reads as a sentence
// rather than as a comma-separated field.
func joinList(items []string) string {
	switch len(items) {
	case 0:
		return ""
	case 1:
		return items[0]
	default:
		return strings.Join(items[:len(items)-1], ", ") + " and " + items[len(items)-1]
	}
}

// dedupe drops repeated notes, keeping first-seen order. Two stages appending the
// same note is not new information, and rendering it twice reads as two findings.
func dedupe(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
