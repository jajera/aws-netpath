package mcpserver

// What the rendering has to hold, and why each of these fails silently without a
// test.
//
// A default that quietly became JSON costs an agent several times the tokens for
// the same finding, and nothing in a passing tool call would say so. A JSON
// rendering that quietly became unreachable costs a caller the only shape it can
// assert against. A row budget that stopped truncating would be a budget in name
// only, and one that truncated without saying so would tell a reader that ten rows
// was all there was — which is the one failure requirement 14.5 names.
//
// And a verdict that lost its non-authoritative banner on the way into markdown
// would read as a pass. That is the failure cross-cutting semantic 1 exists to
// prevent, and the rendering is the last place it can happen.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jajera/aws-netpath/internal/format"
	"github.com/jajera/aws-netpath/internal/model"
	"github.com/jajera/aws-netpath/internal/snapshot"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// call makes a tool call and returns its content, failing the test on a transport
// error or a tool error.
func call(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) string {
	t.Helper()

	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("call %s: %v", name, err)
	}
	if res.IsError {
		t.Fatalf("call %s reported a tool error: %s", name, content(t, res))
	}
	return content(t, res)
}

// Every tool takes the rendering parameter, and none of them insists on it.
//
// Asserted across the whole set rather than on one tool because the parameter is
// embedded: a tool whose arguments struct forgot to embed it would answer in
// markdown regardless of what the caller asked for, and the only visible symptom
// would be a JSON request quietly answered as prose.
func TestEveryToolTakesTheRenderingParameter(t *testing.T) {
	got := tools(t, connect(t, New("test")))

	for name := range operations {
		tool, ok := got[name]
		if !ok {
			continue // reported by TestEveryOperationIsPresentedUnderItsCommandName
		}

		properties, _ := schema(t, tool)["properties"].(map[string]any)
		spec, ok := properties["format"].(map[string]any)
		if !ok {
			t.Errorf("tool %s exposes no format parameter, so a caller cannot ask for json", name)
			continue
		}
		// The accepted values live in the description, because a tool schema
		// carries no enumeration an agent reads. A description that named neither
		// would leave the parameter unguessable.
		desc, _ := spec["description"].(string)
		for _, want := range []string{formatMarkdown, formatJSON} {
			if !strings.Contains(desc, want) {
				t.Errorf("tool %s does not tell a caller it accepts format %q: %q", name, want, desc)
			}
		}
	}
}

// A result is markdown when nothing was asked for. Requirement 14.5: the reader
// on this surface pays per token, so the cheap rendering is the one they get
// without asking.
func TestAToolResultIsMarkdownByDefault(t *testing.T) {
	before, after := snapshotPair(t)

	body := call(t, connect(t, New("test")), "diff", map[string]any{"from": before, "to": after})

	if !strings.HasPrefix(body, "# ") {
		t.Errorf("the default rendering does not open with a markdown heading:\n%s", body)
	}
	if !strings.Contains(body, "| layer | verdict | evidence | detail |") {
		t.Errorf("the default rendering carries no markdown table:\n%s", body)
	}
	// A JSON document would satisfy neither assertion above, but it would also
	// parse — and a rendering that parses as JSON is the regression this guards.
	var probe any
	if err := json.Unmarshal([]byte(body), &probe); err == nil {
		t.Errorf("the default rendering is json:\n%s", body)
	}
	if !strings.Contains(body, removedVPC) {
		t.Errorf("the default rendering lost the finding:\n%s", body)
	}
}

// Markdown is the default rather than the only rendering. A caller that wants a
// shape to assert against has to be able to ask for one; requirement 16.5 is what
// that shape is for.
func TestAToolResultIsJSONOnRequest(t *testing.T) {
	before, after := snapshotPair(t)

	body := call(t, connect(t, New("test")), "diff",
		map[string]any{"from": before, "to": after, "format": "json"})

	var report struct {
		Kind    string `json:"kind"`
		Outcome string `json:"outcome"`
	}
	if err := json.Unmarshal([]byte(body), &report); err != nil {
		t.Fatalf("the json rendering is not json: %v\n%s", err, body)
	}
	if report.Kind != string(format.KindSnapshotDiff) {
		t.Errorf("the json rendering reports kind %q, want %q", report.Kind, format.KindSnapshotDiff)
	}
	if report.Outcome == "" {
		t.Error("the json rendering carries no outcome")
	}
}

// An unrecognised rendering is refused by name rather than silently defaulted.
//
// A caller that asked for text — the CLI's default, and the one rendering this
// surface does not offer — has to be told, or it will read prose it did not ask
// for and pay the terminal rendering's price for it.
func TestAnUnrecognisedRenderingIsRefused(t *testing.T) {
	before, after := snapshotPair(t)

	cs := connect(t, New("test"))
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "diff",
		Arguments: map[string]any{"from": before, "to": after, "format": "text"},
	})
	if err != nil {
		t.Fatalf("call diff: %v", err)
	}
	if !res.IsError {
		t.Fatal("call diff with format text succeeded, want a tool error")
	}

	body := content(t, res)
	for _, want := range []string{"parameter format", formatMarkdown, formatJSON} {
		if !strings.Contains(body, want) {
			t.Errorf("the refusal %q does not mention %q", body, want)
		}
	}
}

// A markdown result truncates repeated rows and says how many it left out.
// Requirement 14.5 — and the saying is the half that makes the budget honest.
func TestAMarkdownResultStatesItsTruncation(t *testing.T) {
	ids := make([]string, 0, maxRows+2)
	for i := range maxRows + 2 {
		ids = append(ids, fmt.Sprintf("vpc-1111111111111%04d", i))
	}
	before, after := snapshotPairRemoving(t, ids...)

	body := call(t, connect(t, New("test")), "diff", map[string]any{"from": before, "to": after})

	if !strings.Contains(body, "rows omitted at the configured limit") {
		t.Errorf("a result over the row budget does not state its truncation:\n%s", body)
	}
	if !strings.Contains(body, "the text and json renderings carry all of them") {
		t.Errorf("the truncation does not say where the omitted rows can be read:\n%s", body)
	}

	// The same call in json is not truncated, or the statement above would be
	// pointing at a rendering that had also dropped them.
	structured := call(t, connect(t, New("test")), "diff",
		map[string]any{"from": before, "to": after, "format": "json"})
	for _, id := range ids {
		if !strings.Contains(structured, id) {
			t.Fatalf("the json rendering dropped %s, which the markdown truncation promises it carries", id)
		}
	}
}

// A verdict resting on something that could not be established keeps its banner in
// markdown.
//
// Cross-cutting semantic 1 and requirement 14.6: an abstention is not a pass, and
// a rendering that dropped the notice would turn one into the other. The declared
// flow run is the cheapest way to produce one offline — a flow whose endpoints no
// collected interface holds is inconclusive, which is neither a pass nor a failure.
func TestMarkdownKeepsTheNonAuthoritativeBanner(t *testing.T) {
	dir := t.TempDir()
	snapPath := filepath.Join(dir, "snapshot.json")
	flowsPath := filepath.Join(dir, "flows.yaml")

	empty := model.NewSnapshot()
	empty.Accounts = []string{"111122223333"}
	empty.Regions = []string{"us-east-1"}
	if err := snapshot.Save(snapPath, empty); err != nil {
		t.Fatalf("write the snapshot: %v", err)
	}

	flows := `flows:
  - name: app to an address no interface holds
    from: 10.0.1.10
    to: 10.0.2.20
    proto: tcp
    port: 443
    expect: permitted
`
	if err := os.WriteFile(flowsPath, []byte(flows), 0o600); err != nil {
		t.Fatalf("write the declared flows: %v", err)
	}

	body := call(t, connect(t, New("test")), "test",
		map[string]any{"snapshot": snapPath, "flows": flowsPath})

	if !strings.Contains(body, "**Not authoritative.**") {
		t.Errorf("a run with an inconclusive flow renders no banner:\n%s", body)
	}
	if !strings.Contains(body, "not authoritative:") {
		t.Errorf("the banner states no reason:\n%s", body)
	}
	// The banner has to precede the sections, because a reader who stops after the
	// outcome is exactly the reader it is written for.
	if strings.Index(body, "**Not authoritative.**") > strings.Index(body, "\n## ") {
		t.Errorf("the banner sits below the first section:\n%s", body)
	}
}
