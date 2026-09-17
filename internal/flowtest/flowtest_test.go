package flowtest

// Parsing is tested on the refusals as much as on the acceptance.
//
// A declared flow file is an assertion set, and the failure that matters is not a
// file that will not parse — that one announces itself. It is a file that parses
// and asserts less than its author believes: a mistyped key silently dropped, a
// flow with no expected verdict, a TCP flow with no port. Each of those turns a
// green gate into a gate that stopped checking, so each is an error naming the
// field at fault.

import (
	"strings"
	"testing"
)

// A file using every field, including the JSON spelling a pipeline is likelier to
// generate than handwritten YAML.
const validFlows = `flows:
  - name: bastion to app ssh
    from: 192.0.2.10
    to: 198.51.100.20
    proto: tcp
    port: 22
    expect: permitted
  - from: 192.0.2.10
    to: 203.0.113.5
    proto: tcp
    port: 3306
    expect: blocked
`

// TestParseReadsADeclaredFlowFile covers the shape requirement 12.1 asks for: a
// file of expected Flows, each with an expected verdict.
//
// Validates: Requirements 12.1
func TestParseReadsADeclaredFlowFile(t *testing.T) {
	got, err := Parse([]byte(validFlows))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if len(got.Flows) != 2 {
		t.Fatalf("flows = %d, want 2", len(got.Flows))
	}

	first := got.Flows[0]
	if first.Name != "bastion to app ssh" || first.From != "192.0.2.10" || first.To != "198.51.100.20" {
		t.Errorf("flows[0] = %+v, want the declared endpoints", first)
	}
	if first.Proto != "tcp" || first.Port != 22 {
		t.Errorf("flows[0] traffic = %s/%d, want tcp/22", first.Proto, first.Port)
	}
	if first.Expect != Permitted {
		t.Errorf("flows[0].expect = %q, want %q", first.Expect, Permitted)
	}
	if got.Flows[1].Expect != Blocked {
		t.Errorf("flows[1].expect = %q, want %q", got.Flows[1].Expect, Blocked)
	}

	// An unnamed flow describes itself, so a report can locate it.
	if want := "192.0.2.10 -> 203.0.113.5 tcp/3306"; got.Flows[1].Title() != want {
		t.Errorf("flows[1].Title() = %q, want %q", got.Flows[1].Title(), want)
	}
}

// TestParseAcceptsJSON confirms the JSON spelling of the same file, since YAML is
// a superset and a generated flow file is likelier to be JSON.
//
// Validates: Requirements 12.1
func TestParseAcceptsJSON(t *testing.T) {
	const doc = `{"flows":[{"from":"192.0.2.10","to":"198.51.100.20","proto":"tcp","port":22,"expect":"blocked"}]}`

	got, err := Parse([]byte(doc))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if len(got.Flows) != 1 || got.Flows[0].Expect != Blocked {
		t.Fatalf("flows = %+v, want one blocked flow", got.Flows)
	}
}

// TestParseRejections covers every way a declared flow file can be unusable. Each
// error has to name the field at fault, because the file is written by hand.
//
// Validates: Requirements 12.1
func TestParseRejections(t *testing.T) {
	cases := []struct {
		name string
		doc  string
		want []string
	}{
		{
			// The one that matters most: a mistyped key that would otherwise be
			// dropped, leaving the flow asserted on defaults its author never wrote.
			name: "unrecognised field is named",
			doc: `flows:
  - from: 192.0.2.10
    to: 198.51.100.20
    proto: tcp
    port: 22
    expected: permitted
`,
			want: []string{"unrecognised field", "expected"},
		},
		{
			name: "unrecognised top-level field is named",
			doc: `snapshot: snapshot.json
flows:
  - from: 192.0.2.10
    to: 198.51.100.20
    proto: tcp
    port: 22
    expect: permitted
`,
			want: []string{"unrecognised field", "snapshot"},
		},
		{
			name: "malformed yaml is refused",
			doc:  "flows:\n  - from: 192.0.2.10\n   to: 198.51.100.20\n",
			want: []string{"parse declared flows"},
		},
		{
			name: "a field of the wrong type is refused",
			doc: `flows:
  - from: 192.0.2.10
    to: 198.51.100.20
    proto: tcp
    port: twenty-two
    expect: permitted
`,
			// The decoder reports the line rather than the key for a type
			// mismatch, which is enough to locate it in a handwritten file.
			want: []string{"parse declared flows", "line 5"},
		},
		{
			name: "an empty file asserts nothing",
			doc:  "",
			want: []string{"at least one flow is required"},
		},
		{
			name: "a file with no flows asserts nothing",
			doc:  "flows: []\n",
			want: []string{"at least one flow is required"},
		},
		{
			name: "a missing endpoint is named",
			doc: `flows:
  - to: 198.51.100.20
    proto: tcp
    port: 22
    expect: permitted
`,
			want: []string{"flows[0]", "from is required"},
		},
		{
			name: "a missing protocol is named",
			doc: `flows:
  - from: 192.0.2.10
    to: 198.51.100.20
    port: 22
    expect: permitted
`,
			want: []string{"flows[0]", "proto is required"},
		},
		{
			name: "an unsupported protocol is named",
			doc: `flows:
  - from: 192.0.2.10
    to: 198.51.100.20
    proto: sctp
    port: 22
    expect: permitted
`,
			want: []string{"flows[0]", "proto", "sctp"},
		},
		{
			name: "a tcp flow with no port is refused",
			doc: `flows:
  - from: 192.0.2.10
    to: 198.51.100.20
    proto: tcp
    expect: permitted
`,
			want: []string{"flows[0]", "port is required for tcp"},
		},
		{
			name: "a missing expected verdict is refused",
			doc: `flows:
  - from: 192.0.2.10
    to: 198.51.100.20
    proto: tcp
    port: 22
`,
			want: []string{"flows[0]", "expect is required"},
		},
		{
			name: "an unrecognised expected verdict names the accepted values",
			doc: `flows:
  - from: 192.0.2.10
    to: 198.51.100.20
    proto: tcp
    port: 22
    expect: maybe
`,
			want: []string{"flows[0]", "unrecognised expect", "permitted", "blocked"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Parse([]byte(tc.doc))
			if err == nil {
				t.Fatalf("Parse() = %+v, want an error", got)
			}
			for _, want := range tc.want {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not mention %q", err, want)
				}
			}
		})
	}
}

// An ICMP flow carries no port, and the parser normalises the protocol so a report
// spells it the same way whatever the file said.
//
// Validates: Requirements 12.1
func TestParseNormalisesTheProtocol(t *testing.T) {
	const doc = `flows:
  - from: 192.0.2.10
    to: 198.51.100.20
    proto: ICMP
    expect: PERMITTED
`

	got, err := Parse([]byte(doc))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if got.Flows[0].Proto != "icmp" {
		t.Errorf("proto = %q, want %q", got.Flows[0].Proto, "icmp")
	}
	if got.Flows[0].Expect != Permitted {
		t.Errorf("expect = %q, want %q", got.Flows[0].Expect, Permitted)
	}
}
