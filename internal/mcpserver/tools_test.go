package mcpserver

// What the tool set has to hold to be usable at all.
//
// Three things are asserted here, and each of them fails silently without a test.
// An operation missing from the set is a capability an agent cannot reach, with
// nothing else to notice it. A parameter without a description is a parameter an
// agent has to guess at, and a required field marked optional is a call that fails
// at the operation instead of at the schema. And a handler that registers cleanly
// but never reaches internal/ops would pass both of those and answer nothing.
//
// Every assertion is made through a client session rather than against the
// registration structs, because the schema an agent reads is the one that crossed
// the wire.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/jajera/aws-netpath/internal/model"
	"github.com/jajera/aws-netpath/internal/snapshot"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// operations is every command in internal/ops, under the name its CLI subcommand
// carries, with the parameters a call cannot omit.
//
// The required set is stated here rather than derived from the input structs: a
// test that read the same tags the schema is inferred from would agree with
// whatever it found.
var operations = map[string][]string{
	// Nothing is required: collect describes its scope one of three ways, and the
	// operation is the one place that decides whether a description is complete.
	"collect":  {},
	"query":    {"snapshot", "from", "to"},
	"firewall": {"snapshot", "from", "to"},
	"diagnose": {"snapshot", "from", "to"},
	"compare":  {"snapshot", "from", "to", "ref_from"},
	"verify":   {"snapshot", "from", "to"},
	"diff":     {"from", "to"},
	"test":     {"snapshot", "flows"},
}

// tools lists what the session reports the server can do, by name.
func tools(t *testing.T, cs *mcp.ClientSession) map[string]*mcp.Tool {
	t.Helper()

	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	out := make(map[string]*mcp.Tool, len(res.Tools))
	for _, tool := range res.Tools {
		out[tool.Name] = tool
	}
	return out
}

// schema reads a tool's input schema as an agent receives it: the server's schema
// marshalled to JSON, which is a map by the time it arrives.
func schema(t *testing.T, tool *mcp.Tool) map[string]any {
	t.Helper()

	if tool.InputSchema == nil {
		t.Fatalf("tool %s carries no input schema", tool.Name)
	}
	raw, err := json.Marshal(tool.InputSchema)
	if err != nil {
		t.Fatalf("tool %s: marshal input schema: %v", tool.Name, err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("tool %s: input schema is not an object: %v", tool.Name, err)
	}
	return out
}

// Every operation is presented, under the name its command carries. An agent and
// an operator have to be able to describe the same capability the same way, and a
// tool the CLI has no counterpart for is a capability only one of them can reach.
func TestEveryOperationIsPresentedUnderItsCommandName(t *testing.T) {
	got := tools(t, connect(t, New("test")))

	for name := range operations {
		if _, ok := got[name]; !ok {
			t.Errorf("the server presents no %s tool", name)
		}
	}
	for name := range got {
		if _, ok := operations[name]; !ok {
			t.Errorf("the server presents %s, which is not an operation", name)
		}
	}
}

// Every tool describes itself and its parameters. An agent calls a tool from its
// schema alone — it has no source to read and no help text to run — so an
// undescribed parameter is one it has to guess at.
func TestEveryToolDescribesItselfAndItsParameters(t *testing.T) {
	got := tools(t, connect(t, New("test")))

	for name := range operations {
		tool, ok := got[name]
		if !ok {
			continue // reported by TestEveryOperationIsPresentedUnderItsCommandName
		}

		if len(tool.Description) == 0 {
			t.Errorf("tool %s carries no description", name)
		}
		// What a tool needs is the one thing a caller cannot work out from a
		// parameter list: a snapshot is a file it may have to collect first, and
		// credentials are something it may not have at all.
		if !strings.Contains(tool.Description, "Needs ") {
			t.Errorf("tool %s does not state what it needs", name)
		}

		in := schema(t, tool)
		if in["type"] != "object" {
			t.Errorf("tool %s has input schema type %v, want object", name, in["type"])
		}

		properties, ok := in["properties"].(map[string]any)
		if !ok || len(properties) == 0 {
			t.Errorf("tool %s exposes no parameters", name)
			continue
		}
		for param, raw := range properties {
			spec, ok := raw.(map[string]any)
			if !ok {
				t.Errorf("tool %s parameter %s has no schema", name, param)
				continue
			}
			if desc, _ := spec["description"].(string); strings.TrimSpace(desc) == "" {
				t.Errorf("tool %s parameter %s carries no description", name, param)
			}
		}
	}
}

// Required parameters are marked required. A parameter the operation insists on
// but the schema calls optional turns a call an agent could have fixed from the
// schema into one it only discovers by making it.
func TestRequiredParametersAreMarkedRequired(t *testing.T) {
	got := tools(t, connect(t, New("test")))

	for name, want := range operations {
		tool, ok := got[name]
		if !ok {
			continue // reported by TestEveryOperationIsPresentedUnderItsCommandName
		}

		var required []string
		for _, raw := range asSlice(schema(t, tool)["required"]) {
			if s, ok := raw.(string); ok {
				required = append(required, s)
			}
		}
		sort.Strings(required)

		expected := append([]string(nil), want...)
		sort.Strings(expected)

		if strings.Join(required, ",") != strings.Join(expected, ",") {
			t.Errorf("tool %s requires %v, want %v", name, required, expected)
		}
	}
}

func asSlice(v any) []any {
	out, _ := v.([]any)
	return out
}

// A tool call reaches the operation and comes back with its report.
//
// diff is the representative call because it is the one operation that needs
// nothing but files: no credentials, no resolvable endpoints, no engine fixture.
// What is under test is the whole path — schema validation, the handler, the
// operation, the Formatter — rather than what a diff concludes, which
// internal/diffsnap already covers.
//
// The JSON rendering is asked for so the assertions can be made against fields
// rather than against prose. That the default rendering is markdown is asserted
// separately, in rendering_test.go.
func TestAToolCallReachesTheOperation(t *testing.T) {
	before, after := snapshotPair(t)

	cs := connect(t, New("test"))
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "diff",
		Arguments: map[string]any{"from": before, "to": after, "format": "json"},
	})
	if err != nil {
		t.Fatalf("call diff: %v", err)
	}
	if res.IsError {
		t.Fatalf("call diff reported a tool error: %s", content(t, res))
	}

	// The content is the report the equivalent command renders, so the removed VPC
	// has to be in it: a handler that returned an empty report would satisfy every
	// assertion above.
	var report struct {
		Kind          string `json:"kind"`
		Outcome       string `json:"outcome"`
		Authoritative bool   `json:"authoritative"`
	}
	body := content(t, res)
	if err := json.Unmarshal([]byte(body), &report); err != nil {
		t.Fatalf("call diff returned content that is not a report: %v\n%s", err, body)
	}
	if report.Kind != "snapshot_diff" {
		t.Errorf("call diff returned a %q report, want snapshot_diff", report.Kind)
	}
	if !report.Authoritative {
		t.Error("call diff reported a comparison of two snapshots of one schema version as incomplete")
	}
	if !strings.Contains(body, "vpc-1111111111111111a") {
		t.Errorf("call diff did not report the removed VPC:\n%s", body)
	}
}

// removedVPC is the identifier every diff fixture removes between its two
// snapshots, so a test can assert the finding reached the caller.
const removedVPC = "vpc-1111111111111111a"

// snapshotPair writes two snapshots differing by one removed VPC and returns
// their paths.
//
// Both are written by internal/snapshot rather than assembled as JSON, so the
// schema version and captured timestamp are the ones a real collection writes and
// the diff has no reason to call itself incomplete.
func snapshotPair(t *testing.T) (before, after string) {
	t.Helper()
	return snapshotPairRemoving(t, removedVPC)
}

// snapshotPairRemoving writes two snapshots differing by the named VPCs.
func snapshotPairRemoving(t *testing.T, ids ...string) (before, after string) {
	t.Helper()

	dir := t.TempDir()
	before = filepath.Join(dir, "before.json")
	after = filepath.Join(dir, "after.json")

	earlier := model.NewSnapshot()
	earlier.Accounts = []string{"111122223333"}
	earlier.Regions = []string{"us-east-1"}
	for i, id := range ids {
		earlier.VPCs[id] = &model.VPC{
			Meta:  model.Meta{ID: id, Account: "111122223333", Region: "us-east-1"},
			CIDRs: []netip.Prefix{netip.MustParsePrefix(fmt.Sprintf("10.%d.0.0/16", i))},
		}
	}

	later := model.NewSnapshot()
	later.Accounts = earlier.Accounts
	later.Regions = earlier.Regions

	if err := snapshot.Save(before, earlier); err != nil {
		t.Fatalf("write the earlier snapshot: %v", err)
	}
	if err := snapshot.Save(after, later); err != nil {
		t.Fatalf("write the later snapshot: %v", err)
	}
	return before, after
}

// A bad request comes back as a tool error naming the parameter at fault, in the
// vocabulary the caller used.
//
// This is the other half of reaching the operation: the validation is the
// operation's, and an agent told that "--from is required" has been handed a flag
// it has no way to pass.
func TestABadRequestNamesTheParameterAtFault(t *testing.T) {
	cs := connect(t, New("test"))

	// snapshot is supplied and from is not, so the failure has to come from the
	// operation's own field validation rather than from the schema.
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "compare",
		Arguments: map[string]any{"snapshot": "snapshot.json", "from": "", "to": "10.0.1.20", "ref_from": "10.0.1.11"},
	})
	if err != nil {
		t.Fatalf("call compare: %v", err)
	}
	if !res.IsError {
		t.Fatal("call compare with no source succeeded, want a tool error")
	}

	body := content(t, res)
	if !strings.Contains(body, "parameter from is required") {
		t.Errorf("call compare reported %q, want the parameter named as this server spells it", body)
	}
	if strings.Contains(body, "--") {
		t.Errorf("call compare reported %q, which names a command line flag rather than a parameter", body)
	}
}

// content returns a tool result's text, joined when a result carried more than one
// block.
func content(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()

	if len(res.Content) == 0 {
		t.Fatal("the tool returned no content")
	}
	var parts []string
	for _, c := range res.Content {
		text, ok := c.(*mcp.TextContent)
		if !ok {
			t.Fatalf("the tool returned %T, want text content", c)
		}
		parts = append(parts, text.Text)
	}
	return strings.Join(parts, "\n")
}
