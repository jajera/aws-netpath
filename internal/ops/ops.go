// Package ops implements aws-netpath's operations, one layer below the
// interfaces that expose them.
//
// Every capability lives here exactly once. internal/cli parses flags, renders
// results, and maps outcomes to exit codes; the MCP server does the equivalent
// for an agent. Neither holds orchestration logic, so the two interfaces cannot
// drift apart as capabilities are added.
//
// An operation takes a request of named-but-unparsed values, validates them,
// runs the engine, and returns a typed result. Operations never write to stdout
// or stderr, never call os.Exit, and never format output for a human. Field
// validation failures come back as *FieldError so a caller can either print the
// message as-is or report the offending field in its own vocabulary.
package ops

import (
	"fmt"
	"net/netip"

	"github.com/jajera/aws-netpath/internal/flow"
	"github.com/jajera/aws-netpath/internal/model"
	"github.com/jajera/aws-netpath/internal/snapshot"
)

// FieldError reports a request field that was missing or unparseable. Field
// names the offending input so an interface can map it back to whatever it
// calls that input: a CLI flag, an MCP tool parameter, a config key.
type FieldError struct {
	Field string
	Err   error
	msg   string
}

func (e *FieldError) Error() string { return e.msg }

// Unwrap exposes the underlying parse failure, and is nil when the field was
// simply absent.
func (e *FieldError) Unwrap() error { return e.Err }

func missingField(name string) error {
	return &FieldError{Field: name, msg: fmt.Sprintf("--%s is required", name)}
}

func invalidField(name string, err error) error {
	return &FieldError{Field: name, Err: err, msg: fmt.Sprintf("invalid --%s: %v", name, err)}
}

func badField(name string, err error) error {
	return &FieldError{Field: name, Err: err, msg: fmt.Sprintf("--%s: %v", name, err)}
}

// requiredField is one name/value pair checked by requireFields.
type requiredField struct {
	name  string
	value string
}

// requireFields returns the first empty field in the order given. The order is
// fixed rather than map-driven so that an invocation missing several fields
// always reports the same one, which is what makes the output safe to assert
// against.
func requireFields(fields ...requiredField) error {
	for _, f := range fields {
		if f.value == "" {
			return missingField(f.name)
		}
	}
	return nil
}

// parseProtoPort parses a protocol and range-checks the port for protocols that
// carry one. A protocol failure is returned unwrapped because it already names
// the accepted values.
//
// The port failure is a *FieldError, like every other field validation failure
// here: it carries the flag spelling for the CLI to print as-is and the field name
// for an interface that calls the input something else. A caller that could only
// read the message would have to report a flag to an agent that passed a
// parameter.
func parseProtoPort(proto string, port int) (flow.Protocol, error) {
	var zero flow.Protocol
	p, err := flow.ParseProtocol(proto)
	if err != nil {
		return zero, err
	}
	if p.HasPorts() && (port < 1 || port > 65535) {
		return zero, &FieldError{
			Field: "port",
			Err:   fmt.Errorf("a destination port between 1 and 65535 is required for %s", p),
			msg:   fmt.Sprintf("--port is required for %s", p),
		}
	}
	return p, nil
}

// parseEndpoints parses a source and destination address, reporting which of
// the two was at fault.
func parseEndpoints(from, to string) (src, dst netip.Addr, err error) {
	src, err = netip.ParseAddr(from)
	if err != nil {
		return netip.Addr{}, netip.Addr{}, invalidField("from", err)
	}
	dst, err = netip.ParseAddr(to)
	if err != nil {
		return netip.Addr{}, netip.Addr{}, invalidField("to", err)
	}
	return src, dst, nil
}

// loadSnapshot reads a snapshot and rejects a schema version this build cannot
// interpret.
func loadSnapshot(path string) (*model.Snapshot, error) {
	return snapshot.Load(path)
}

// buildSlice assembles a flow from address sets, a protocol, and a port set,
// naming whichever input failed to parse.
func buildSlice(from, to, proto, ports string) (flow.Slice, error) {
	src, err := flow.ParsePrefixSet(from)
	if err != nil {
		return flow.Slice{}, badField("from", err)
	}
	dst, err := flow.ParsePrefixSet(to)
	if err != nil {
		return flow.Slice{}, badField("to", err)
	}
	p, err := flow.ParseProtocol(proto)
	if err != nil {
		return flow.Slice{}, badField("proto", err)
	}
	ps, err := flow.ParsePortSet(ports)
	if err != nil {
		return flow.Slice{}, badField("port", err)
	}
	return flow.NewSlice(src, dst, p, ps), nil
}

// DisplayName prefers a resource's name over its identifier, falling back when
// the resource was never tagged.
func DisplayName(name, id string) string {
	if name != "" {
		return name
	}
	return id
}
