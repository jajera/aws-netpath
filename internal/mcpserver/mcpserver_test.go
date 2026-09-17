package mcpserver

// The server is exercised the way a client uses it: connected over a transport,
// initialised, and asked what it can do. Reading the struct back would assert the
// SDK's field layout rather than the surface an agent actually sees.

import (
	"context"
	"sort"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// connect initialises a client session against s over an in-memory transport pair
// and closes both when the test ends.
func connect(t *testing.T, s *mcp.Server) *mcp.ClientSession {
	t.Helper()

	ctx := context.Background()
	serverTransport, clientTransport := mcp.NewInMemoryTransports()

	// The server has to be connected first: the client initialises the session as
	// it connects, and there has to be something there to answer.
	serverSession, err := s.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatalf("connect server: %v", err)
	}
	t.Cleanup(func() { _ = serverSession.Close() })

	client := mcp.NewClient(&mcp.Implementation{Name: "mcpserver-test", Version: "test"}, nil)
	clientSession, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("connect client: %v", err)
	}
	t.Cleanup(func() { _ = clientSession.Close() })

	return clientSession
}

// toolNames lists what the session reports the server can do.
func toolNames(t *testing.T, cs *mcp.ClientSession) []string {
	t.Helper()

	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	names := make([]string, 0, len(res.Tools))
	for _, tool := range res.Tools {
		names = append(names, tool.Name)
	}
	sort.Strings(names)
	return names
}

// A client keys its configuration on the server's name and compares versions to
// see what it is talking to, so both have to survive the handshake.
func TestServerReportsItsIdentity(t *testing.T) {
	cs := connect(t, New("v1.2.3"))

	init := cs.InitializeResult()
	if init.ServerInfo == nil {
		t.Fatal("the server reported no implementation at initialisation")
	}
	if got := init.ServerInfo.Name; got != Name {
		t.Errorf("server name is %q, want %q", got, Name)
	}
	// The version is the binary's, passed in rather than declared here, so a
	// release build and the identity a client reads cannot disagree.
	if got := init.ServerInfo.Version; got != "v1.2.3" {
		t.Errorf("server version is %q, want the version it was built with", got)
	}
	if init.Instructions != Instructions {
		t.Errorf("the server offered instructions %q, want the package's", init.Instructions)
	}
}

// probeIn is a stand-in tool's arguments, kept minimal because what is under test
// is registration rather than any operation's schema.
type probeIn struct {
	Snapshot string `json:"snapshot" jsonschema:"path to a snapshot"`
}

// probe registers a tool named name, echoing its argument back.
func probe(name string) registrar {
	return func(s *mcp.Server) {
		mcp.AddTool(s, &mcp.Tool{Name: name, Description: "a stand-in tool"},
			func(_ context.Context, _ *mcp.CallToolRequest, in probeIn) (*mcp.CallToolResult, any, error) {
				return &mcp.CallToolResult{
					Content: []mcp.Content{&mcp.TextContent{Text: in.Snapshot}},
				}, nil, nil
			})
	}
}

// Every registrar reaches the server. This is the seam the operations are
// registered through, so a registrar dropped on the floor would be a capability
// missing from the agent surface with nothing else to notice it.
func TestEveryRegistrarReachesTheServer(t *testing.T) {
	cs := connect(t, newServer("test", []registrar{probe("first"), probe("second")}))

	got := toolNames(t, cs)
	want := []string{"first", "second"}

	if len(got) != len(want) {
		t.Fatalf("the server presents %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("the server presents %v, want %v", got, want)
			break
		}
	}
}

// A registered tool is callable, not just listed: registration that produced a
// name without a handler behind it would satisfy a listing test and fail an agent.
func TestARegisteredToolIsCallable(t *testing.T) {
	cs := connect(t, newServer("test", []registrar{probe("echo")}))

	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "echo",
		Arguments: map[string]any{"snapshot": "snapshot.json"},
	})
	if err != nil {
		t.Fatalf("call echo: %v", err)
	}
	if res.IsError {
		t.Fatalf("call echo reported a tool error: %+v", res.Content)
	}
	if len(res.Content) == 0 {
		t.Fatal("call echo returned no content")
	}
	text, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("call echo returned %T, want text content", res.Content[0])
	}
	if text.Text != "snapshot.json" {
		t.Errorf("call echo returned %q, want the argument it was given", text.Text)
	}
}

// The tool set is registered through the seam, not around it. New has to apply
// registrars() and nothing else, or a tool added there would never appear.
func TestNewPresentsExactlyTheRegisteredToolSet(t *testing.T) {
	cs := connect(t, New("test"))

	if got, want := len(toolNames(t, cs)), len(registrars()); got != want {
		t.Errorf("New presents %d tools, want the %d in registrars()", got, want)
	}
}
