// Package flowtest asserts declared reachability against what the engine finds.
//
// The premise is a build gate rather than an investigation. An operator writes
// down the flows that are supposed to work and the flows that are supposed to be
// refused, commits the file, and a change that breaks one of them fails a
// pipeline instead of paging somebody. Requirement 12.1 asks for exactly that: a
// file declaring expected Flows, each with an expected verdict.
//
// Nothing is evaluated here. The declared flows come in from a file and the
// actual verdicts come in already walked and correlated, so this package is pure
// logic: no Snapshot, no AWS call, no host command, and no second evaluation that
// could disagree with the one the rest of the tool performs.
//
// Three rules shape the judgement, and the third is the one that matters.
//
// A mismatch is a failure and says so with evidence. Requirement 12.2 wants the
// Flow, both verdicts, and the deciding Citation, because "app-to-db ssh failed"
// is a notification and "expected permitted, blocked at security_group, cited
// sg-app egress" is a fix.
//
// A failure is the caller's signal to exit 1. Requirement 12.3 belongs to the
// CLI, so the outcome is exposed as Failed rather than acted on: this package
// calls no os.Exit, prints nothing, and leaves exit-code mapping to the one place
// that owns it.
//
// An Abstention is inconclusive, in its own category, never a pass. Requirement
// 12.4 and cross-cutting 1 — a Layer that could not be evaluated might have been
// the one blocking, so a flow declared permitted and not shown to be blocked has
// not been shown to be permitted either. Where a build gate is concerned that
// distinction is the whole value: a green pipeline that means "we could not check"
// is worse than no gate at all.
package flowtest

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/jajera/aws-netpath/internal/flow"
)

// Reachability is the vocabulary a declared flow asserts in, and the vocabulary
// the engine's verdict is read back into.
//
// Two values, deliberately. A declared flow asserts whether traffic gets through,
// not which Layer decided it: an operator who writes down "this must be refused"
// is asserting the outcome, and a change that moves the refusal from a security
// group to a firewall rule has not broken anything they declared. There is no
// third value because an Abstention is not a reachability answer — it is the
// absence of one, which is why it is carried as an Outcome rather than here.
type Reachability string

const (
	// Permitted is a flow the engine found nothing blocking.
	Permitted Reachability = "permitted"
	// Blocked is a flow some Layer was shown to block.
	Blocked Reachability = "blocked"
)

// Valid reports whether r is one of the two defined values.
func (r Reachability) Valid() bool {
	switch r {
	case Permitted, Blocked:
		return true
	default:
		return false
	}
}

// ParseReachability reads an expected verdict, accepting the spellings an
// operator is likely to reach for. The error names the accepted values rather
// than only rejecting the input, since a declared flow file is written by hand.
func ParseReachability(s string) (Reachability, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "permitted", "permit", "allow", "allowed", "pass", "reachable":
		return Permitted, nil
	case "blocked", "block", "deny", "denied", "drop", "unreachable":
		return Blocked, nil
	case "":
		return "", fmt.Errorf("expect is required: one of %s or %s", Permitted, Blocked)
	default:
		return "", fmt.Errorf("unrecognised expect %q: want %s or %s", s, Permitted, Blocked)
	}
}

// File is a declared flow file.
//
// YAML, matching the shape the Config_Loader already reads, which also means a
// JSON file parses unchanged — YAML is a superset, and a pipeline generating this
// file from a template is more likely to emit JSON.
type File struct {
	Flows []Declared `yaml:"flows" json:"flows"`
}

// Declared is one asserted flow.
//
// The endpoints are strings rather than parsed addresses because they accept
// everything an operator can name an endpoint by — an address, a CIDR, an
// instance ID, a Name tag — and resolving them needs a Snapshot, which this
// package does not have.
type Declared struct {
	// Name labels the flow in the report. Optional: without one the flow
	// describes itself, which is enough for a file of a dozen entries and not
	// enough for a file of a hundred.
	Name string `yaml:"name,omitempty" json:"name,omitempty"`
	// From and To are the endpoints, in any form endpoint resolution accepts.
	From string `yaml:"from" json:"from"`
	To   string `yaml:"to" json:"to"`
	// Proto is the protocol. Required, and not defaulted: a declared flow with
	// an implied protocol asserts something other than what its author read.
	Proto string `yaml:"proto" json:"proto"`
	// Port is the destination port, required for TCP and UDP.
	Port int `yaml:"port,omitempty" json:"port,omitempty"`
	// Expect is the verdict this flow asserts.
	Expect Reachability `yaml:"expect" json:"expect"`
}

// Title names the flow in a report, falling back to the flow itself.
func (d Declared) Title() string {
	if d.Name != "" {
		return d.Name
	}
	return d.Describe()
}

// Describe renders the declared flow, which is what a report shows when the
// engine never got far enough to render the evaluated one.
func (d Declared) Describe() string {
	if d.Port > 0 {
		return fmt.Sprintf("%s -> %s %s/%d", d.From, d.To, d.Proto, d.Port)
	}
	return fmt.Sprintf("%s -> %s %s", d.From, d.To, d.Proto)
}

// Load reads and validates a declared flow file.
func Load(path string) (*File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read declared flows %s: %w", path, err)
	}
	f, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return f, nil
}

// Parse reads a declared flow file from memory.
//
// Unrecognised fields are an error naming the field, matching what the
// Config_Loader does for configuration: a file whose typo was silently ignored
// asserts less than its author believes, and a build gate that quietly stopped
// checking one flow is the failure mode this whole package exists to prevent.
func Parse(data []byte) (*File, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)

	var f File
	if err := dec.Decode(&f); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("flowtest: the declared flow file is empty; at least one flow is required")
		}
		return nil, parseError(err)
	}
	if err := f.Validate(); err != nil {
		return nil, err
	}
	return &f, nil
}

// unknownFieldMessage matches the decoder's report of a field the schema does not
// carry, so the field can be named in this package's own vocabulary rather than
// in terms of the Go type it failed against.
var unknownFieldMessage = regexp.MustCompile(`^(?:line (\d+): )?field (\S+) not found in type \S+$`)

func parseError(err error) error {
	var typeErr *yaml.TypeError
	if !errors.As(err, &typeErr) {
		return fmt.Errorf("flowtest: parse declared flows: %w", err)
	}

	msgs := make([]string, 0, len(typeErr.Errors))
	for _, e := range typeErr.Errors {
		m := unknownFieldMessage.FindStringSubmatch(e)
		switch {
		case m == nil:
			msgs = append(msgs, e)
		case m[1] == "":
			msgs = append(msgs, fmt.Sprintf("unrecognised field %q", m[2]))
		default:
			msgs = append(msgs, fmt.Sprintf("unrecognised field %q at line %s", m[2], m[1]))
		}
	}
	return fmt.Errorf("flowtest: parse declared flows: %s", strings.Join(msgs, "; "))
}

// Validate checks and normalises every declared flow, naming the index and the
// field at fault.
//
// The whole file is rejected on the first problem rather than the bad entry being
// skipped. A declared flow file is an assertion set, and running most of one
// reports a pass count that means nothing.
func (f *File) Validate() error {
	if f == nil || len(f.Flows) == 0 {
		return fmt.Errorf("flowtest: at least one flow is required")
	}
	for i := range f.Flows {
		if err := f.Flows[i].normalise(); err != nil {
			return fmt.Errorf("flowtest: flows[%d]: %w", i, err)
		}
	}
	return nil
}

// normalise trims, validates, and canonicalises one declared flow.
//
// The protocol and port are checked here rather than left to the evaluation,
// because a file with an unusable entry should be refused before any flow is
// walked: a run that reports six passes and then stops on a typo in the seventh
// entry reads as a partial result and is not one.
func (d *Declared) normalise() error {
	d.Name = strings.TrimSpace(d.Name)
	d.From = strings.TrimSpace(d.From)
	d.To = strings.TrimSpace(d.To)
	d.Proto = strings.TrimSpace(d.Proto)

	if d.From == "" {
		return fmt.Errorf("from is required")
	}
	if d.To == "" {
		return fmt.Errorf("to is required")
	}
	if d.Proto == "" {
		return fmt.Errorf("proto is required")
	}

	proto, err := flow.ParseProtocol(d.Proto)
	if err != nil {
		return fmt.Errorf("proto: %w", err)
	}
	d.Proto = proto.String()

	switch {
	case proto.HasPorts() && (d.Port < 1 || d.Port > 65535):
		return fmt.Errorf("port is required for %s and must be between 1 and 65535", proto)
	case !proto.HasPorts() && d.Port != 0:
		return fmt.Errorf("port %d was given for %s, which carries no ports", d.Port, proto)
	}

	expect, err := ParseReachability(string(d.Expect))
	if err != nil {
		return err
	}
	d.Expect = expect
	return nil
}
