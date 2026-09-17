// Package mcpserver presents aws-netpath's operations to an agent over MCP.
//
// This is the agent-facing half of requirement 16.3, and it is deliberately the
// same shape as internal/cli: it presents capabilities, it does not implement
// them. Every tool calls into internal/ops, so a tool call and the equivalent
// command run one implementation and cannot answer differently — which is what
// requirement 16.4 asks for, and the only way an agent's answer stays worth as
// much as an operator's.
//
// The transport is stdio, which makes stdout the protocol channel rather than an
// output stream. Nothing in this package or below it may write to stdout: one
// stray line of progress output is a framing error that ends the session. The
// operations already hold to that — internal/ops writes to neither stream and
// never calls os.Exit — and anything this server has to say for itself goes to
// stderr.
package mcpserver

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Name is the implementation name the server reports at initialisation. Clients
// key their configuration on it, so it names the binary rather than the package.
const Name = "aws-netpath"

// Instructions is the hint the server offers a client at initialisation.
//
// It states the one thing an agent cannot infer from a tool schema: that this is
// a two-step tool, where collect reaches AWS once and everything afterwards reads
// a local Snapshot. Without that, an agent asked a reachability question with no
// Snapshot to hand has no way to know what it is missing. It also states the
// read-only guarantee, because an agent that believes a tool might change
// something will hesitate over a tool that cannot.
const Instructions = `aws-netpath answers AWS network reachability questions against a collected
snapshot, offline. Collect once with the collect tool, then query, diagnose,
compare, and test against the resulting snapshot file — those are free, instant,
and reach no AWS API.

Every operation is read-only: nothing here changes AWS or host configuration.

A layer that cannot be authoritatively evaluated is reported as an abstention
with a reason, never as a pass. Treat a verdict marked non-authoritative as
incomplete rather than as a permit.

Results are markdown, truncated to a row budget and stating what was left out.
Pass format: json for the same report as a stable object when you need to read
a field rather than a finding; it is the more expensive of the two.`

// New builds the server with every tool registered.
//
// version is reported at initialisation and is the CLI's version, not a separate
// one: the tools are the operations that binary carries, so a client comparing
// what it is talking to against what it expected should read one number.
func New(version string) *mcp.Server {
	return newServer(version, registrars())
}

// newServer is New with the tool set passed in, so a test can drive registration
// without depending on which operations happen to be registered yet.
func newServer(version string, regs []registrar) *mcp.Server {
	// No Title: the SDK falls back to Name for display, and Name is already the
	// word an operator uses. A title repeating it would be one more place for the
	// two to disagree.
	s := mcp.NewServer(&mcp.Implementation{
		Name:    Name,
		Version: version,
	}, &mcp.ServerOptions{
		Instructions: Instructions,
	})

	for _, add := range regs {
		add(s)
	}

	return s
}

// Serve runs the server over stdio until the client disconnects or ctx is
// cancelled.
//
// The transport is the process's own stdin and stdout, which is what an MCP
// client launching this binary connects to. Serve therefore takes no writers:
// there is nowhere else for the protocol to go, and a caller that redirected it
// would be redirecting the session rather than the output.
func Serve(ctx context.Context, version string) error {
	return New(version).Run(ctx, &mcp.StdioTransport{})
}
