package mcpserver

// The session, and the channel it runs over.
//
// Everything else in this package is asserted over an in-memory transport pair,
// which is the right level for a schema or a rendering and the wrong level for
// two facts about the running server.
//
// The first is that it ends. A client shuts the server down by closing the pipe or
// by signalling it, and a Serve that did not return would leave a process behind
// after the client that started it had gone. The signal path is what internal/cli
// maps to exit 0, so a cancellation that came back as an error would turn an
// ordinary shutdown into a failed command.
//
// The second is that stdout carries the protocol and nothing else. Under stdio
// transport a single stray line — a progress message, a debug print, a library
// writing to the default logger — is a framing error that ends the session, and it
// would end it in the client's log rather than in any test. So stdout is captured
// while every tool is called, and it has to come back empty.
//
// Both tests replace the process's own stdin and stdout, which is the only way to
// reach the transport Serve actually uses. Everything is bounded: a lifecycle test
// that could hang is worse than no lifecycle test.

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// shutdownGrace bounds how long a test waits for Serve to return. It is a
// generous multiple of what a clean shutdown takes, so a slow machine does not
// fail the test and a server that never returns does not hang it.
const shutdownGrace = 10 * time.Second

// errServeDidNotReturn is what a test reads when the grace period ran out.
var errServeDidNotReturn = errors.New("Serve did not return within the grace period")

// A client disconnecting ends the session, and the command succeeds.
//
// This is how a session ordinarily ends: the client that launched the process
// closes the pipe. Serve has to notice and return without an error, or the CLI
// reports a failure for a client that simply finished.
func TestServeReturnsWhenTheClientDisconnects(t *testing.T) {
	s := serveOverStdio(t, context.Background())

	// A call before the disconnect, so what is under test is a session that was
	// doing something rather than one that never started.
	if _, err := s.client.ListTools(context.Background(), nil); err != nil {
		t.Fatalf("list tools over stdio: %v", err)
	}

	s.disconnect()

	if err, ok := s.served(); !ok {
		t.Fatal(errServeDidNotReturn)
	} else if err != nil {
		t.Errorf("Serve returned %v after the client disconnected, want no error", err)
	}
}

// Cancelling the context ends the session, and the command still succeeds.
//
// internal/cli cancels on SIGINT and SIGTERM and maps context.Canceled to exit 0,
// so this is the other half of that mapping: a shutdown asked for is not a
// failure, and Serve must return promptly rather than waiting for the pipe.
func TestServeReturnsWhenTheContextIsCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	s := serveOverStdio(t, ctx)

	if _, err := s.client.ListTools(context.Background(), nil); err != nil {
		t.Fatalf("list tools over stdio: %v", err)
	}

	cancel()

	err, ok := s.served()
	if !ok {
		t.Fatal(errServeDidNotReturn)
	}
	// Either answer is a clean shutdown, and both are what internal/cli treats as
	// exit 0. Anything else is a failure the operator would see reported.
	if err != nil && !errors.Is(err, context.Canceled) {
		t.Errorf("Serve returned %v on cancellation, want nil or %v", err, context.Canceled)
	}
}

// Stdout carries the protocol and nothing else.
//
// Every tool is called, because the write this guards against is the kind that
// gets added inside one handler — and it is the operations below the handlers that
// have the most reason to want to say something. The tool results come back as
// content over the in-memory transport, so anything at all on stdout is a stray
// write, which is the strongest form the assertion takes.
func TestNothingInTheServerPathWritesToStdout(t *testing.T) {
	snap := workloadSnapshot(t)
	flows := declaredFlows(t, "app to database")

	calls := []struct {
		tool string
		args map[string]any
	}{
		{"collect", map[string]any{}},
		{"query", map[string]any{"snapshot": snap, "from": appIP, "to": databaseIP, "port": databasePort}},
		{"firewall", map[string]any{"snapshot": snap, "from": appIP, "to": databaseIP, "port": "443"}},
		{"diagnose", map[string]any{"snapshot": snap, "from": appIP, "to": databaseIP, "port": databasePort}},
		{"compare", map[string]any{
			"snapshot": snap, "from": appIP, "to": databaseIP, "ref_from": peerIP, "port": databasePort,
		}},
		{"verify", map[string]any{
			"snapshot": snap, "from": appIP, "to": databaseIP, "port": databasePort, "skip_aws": true,
		}},
		{"diff", map[string]any{"from": snap, "to": snap}},
		{"test", map[string]any{"snapshot": snap, "flows": flows}},
	}
	if len(calls) != len(operations) {
		t.Fatalf("%d tools are called here, and the server presents %d", len(calls), len(operations))
	}

	cs := connect(t, New("test"))
	stdout := captureStdout(t)

	for _, c := range calls {
		// The outcome is not what is under test — a tool error is a legitimate
		// answer and collect gives one — so failures are left to
		// TestEveryToolReachesItsOperation and only the transport is checked here.
		if _, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
			Name: c.tool, Arguments: c.args,
		}); err != nil {
			t.Errorf("call %s: %v", c.tool, err)
		}
	}

	if written := stdout(); written != "" {
		t.Errorf("the server path wrote %d bytes to stdout, which under stdio transport is a framing error that ends the session:\n%s",
			len(written), written)
	}
}

// A running server over the process's own stdio, and the bytes it wrote there.
type stdioServer struct {
	client *mcp.ClientSession
	// disconnect closes the client, which is what ending the session looks like
	// from the server's side. Calling it more than once is harmless.
	disconnect func()
	// served waits for Serve to return, bounded by shutdownGrace, and reports
	// whether it did. Repeated calls return the same answer.
	served func() (error, bool)
}

// serveOverStdio starts Serve with the process's own stdin and stdout replaced by
// pipes, and returns a client session driving it.
//
// The replacement is what makes the real transport reachable: mcp.StdioTransport
// reads os.Stdin and os.Stdout when it connects, and Serve passes it no writers
// precisely because there is nowhere else for the protocol to go. The globals are
// restored once Serve has returned, so the goroutine that read them and the test
// that wrote them are ordered by the channel between them rather than racing.
func serveOverStdio(t *testing.T, ctx context.Context) *stdioServer {
	t.Helper()

	// stdin: the client writes to inW, the server reads inR.
	inR, inW, err := os.Pipe()
	if err != nil {
		t.Fatalf("open a pipe for the server's stdin: %v", err)
	}
	// stdout: the server writes to outW, the client reads outR.
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatalf("open a pipe for the server's stdout: %v", err)
	}

	origIn, origOut := os.Stdin, os.Stdout
	os.Stdin, os.Stdout = inR, outW
	restore := func() { os.Stdin, os.Stdout = origIn, origOut }

	done := make(chan error, 1)
	go func() { done <- Serve(ctx, "v0.0.0-test") }()

	var (
		mu       sync.Mutex
		serveErr error
		returned bool
	)
	served := func() (error, bool) {
		mu.Lock()
		defer mu.Unlock()
		if returned {
			return serveErr, true
		}
		select {
		case serveErr = <-done:
			returned = true
		case <-time.After(shutdownGrace):
		}
		return serveErr, returned
	}

	// The client gets its own context deliberately: ctx is the server's, and a
	// client that was cancelled alongside it would make the cancellation test an
	// assertion about the client as much as about Serve.
	client := mcp.NewClient(&mcp.Implementation{Name: "mcpserver-test", Version: "test"}, nil)
	cs, err := client.Connect(context.Background(), &mcp.IOTransport{Reader: outR, Writer: inW}, nil)
	if err != nil {
		restore()
		t.Fatalf("connect a client to the server's stdio: %v", err)
	}

	var closeOnce sync.Once
	disconnect := func() {
		closeOnce.Do(func() {
			// Closing the client closes both ends it holds, and the server reading
			// EOF on its stdin is what a disconnect looks like from its side.
			_ = cs.Close()
			_ = inW.Close()
		})
	}

	t.Cleanup(func() {
		disconnect()
		if _, ok := served(); !ok {
			t.Error(errServeDidNotReturn)
		}
		// Only now: the transport read these when it connected, and restoring them
		// before Serve returns would be a write racing that read.
		restore()
		for _, f := range []*os.File{inR, inW, outR, outW} {
			_ = f.Close()
		}
	})

	return &stdioServer{client: cs, disconnect: disconnect, served: served}
}

// captureStdout replaces the process's stdout with a pipe and returns what was
// written to it. The returned function may be called more than once and returns
// the same text; it is also called on cleanup, so a failing test still restores
// stdout.
func captureStdout(t *testing.T) func() string {
	t.Helper()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("open a pipe for stdout: %v", err)
	}

	orig := os.Stdout
	os.Stdout = w

	var (
		seen    syncBuffer
		drained = make(chan struct{})
	)
	go func() {
		defer close(drained)
		_, _ = io.Copy(&seen, r)
	}()

	var (
		once    sync.Once
		written string
	)
	stop := func() string {
		once.Do(func() {
			os.Stdout = orig
			_ = w.Close()
			<-drained
			_ = r.Close()
			written = seen.String()
		})
		return written
	}
	t.Cleanup(func() { stop() })

	return stop
}

// syncBuffer is a buffer written by one goroutine and read by another.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
