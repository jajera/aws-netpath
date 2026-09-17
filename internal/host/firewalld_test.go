package host

// Fixture tests for the firewalld parsers.
//
// The rich rule list is the allowlist, so every one of these fixtures is a line
// firewall-cmd prints or a line a hand-written zone file feeds it. Two shapes
// carry most of the weight: the quoted form firewalld emits, and the unquoted
// form an operator types. A parser that reads only one of them narrows the
// allowlist the check believes in without saying so.
//
// Requirement 8.3 is the reason this file leans on containment rather than text.
// The entry 198.51.100.128/26 and the source 198.51.100.150 are not equal as
// strings, and the incident behind this tool was two days spent on that fact.
//
// Addresses are RFC 5737 documentation ranges, RFC 1918 private ranges, and the
// RFC 3849 IPv6 documentation prefix.

import (
	"context"
	"strings"
	"testing"

	"github.com/jajera/aws-netpath/internal/flow"
	"github.com/jajera/aws-netpath/internal/model"
)

// richRuleWant states every field of a parsed rule that changes which traffic it
// governs. Sets are compared by their rendered form so that coverage is asserted
// rather than representation: "none" is the empty set.
type richRuleWant struct {
	priority      int
	family        string
	source        string
	sourceAny     bool
	sourceNegated bool
	element       string
	service       string
	ports         string
	protocol      flow.Protocol
	action        Action
	unresolvable  bool
}

func TestParseRichRule(t *testing.T) {
	tests := []struct {
		name string
		line string
		want richRuleWant
	}{
		{
			// The shape firewall-cmd itself prints.
			name: "quoted port rule",
			line: `rule family="ipv4" source address="198.51.100.128/26" port port="22" protocol="tcp" accept`,
			want: richRuleWant{
				family:   "ipv4",
				source:   "198.51.100.128/26",
				element:  "port",
				ports:    "22",
				protocol: flow.ProtoTCP,
				action:   ActionAccept,
			},
		},
		{
			// The same rule as an operator writes it into a zone file. Both reach
			// firewall-cmd, so both have to read the same.
			name: "unquoted port rule",
			line: `rule family=ipv4 source address=198.51.100.128/26 port port=22 protocol=tcp accept`,
			want: richRuleWant{
				family:   "ipv4",
				source:   "198.51.100.128/26",
				element:  "port",
				ports:    "22",
				protocol: flow.ProtoTCP,
				action:   ActionAccept,
			},
		},
		{
			name: "single-quoted values",
			line: `rule family='ipv4' source address='192.0.2.0/24' port port='443' protocol='tcp' accept`,
			want: richRuleWant{
				family:   "ipv4",
				source:   "192.0.2.0/24",
				element:  "port",
				ports:    "443",
				protocol: flow.ProtoTCP,
				action:   ActionAccept,
			},
		},
		{
			name: "port range",
			line: `rule family="ipv4" source address="10.0.0.0/8" port port="8080-8090" protocol="tcp" accept`,
			want: richRuleWant{
				family:   "ipv4",
				source:   "10.0.0.0/8",
				element:  "port",
				ports:    "8080-8090",
				protocol: flow.ProtoTCP,
				action:   ActionAccept,
			},
		},
		{
			// Priority decides which of two conflicting rules firewalld applies,
			// so a rule that carries one is not the same rule without it.
			name: "explicit priority",
			line: `rule priority="100" family="ipv4" source address="192.168.0.0/16" port port="22" protocol="tcp" accept`,
			want: richRuleWant{
				priority: 100,
				family:   "ipv4",
				source:   "192.168.0.0/16",
				element:  "port",
				ports:    "22",
				protocol: flow.ProtoTCP,
				action:   ActionAccept,
			},
		},
		{
			name: "negative priority",
			line: `rule priority="-10" family="ipv4" source address="192.0.2.0/24" port port="22" protocol="tcp" drop`,
			want: richRuleWant{
				priority: -10,
				family:   "ipv4",
				source:   "192.0.2.0/24",
				element:  "port",
				ports:    "22",
				protocol: flow.ProtoTCP,
				action:   ActionDrop,
			},
		},
		{
			name: "ipv6 family",
			line: `rule family="ipv6" source address="2001:db8::/32" port port="22" protocol="tcp" accept`,
			want: richRuleWant{
				family:   "ipv6",
				source:   "2001:db8::/32",
				element:  "port",
				ports:    "22",
				protocol: flow.ProtoTCP,
				action:   ActionAccept,
			},
		},
		{
			name: "NOT source",
			line: `rule family="ipv4" source NOT address="192.0.2.0/24" port port="22" protocol="tcp" reject`,
			want: richRuleWant{
				family:        "ipv4",
				source:        "192.0.2.0/24",
				sourceNegated: true,
				element:       "port",
				ports:         "22",
				protocol:      flow.ProtoTCP,
				action:        ActionReject,
			},
		},
		{
			name: "inverted source",
			line: `rule family="ipv4" source address="192.0.2.0/24" invert="True" port port="22" protocol="tcp" reject`,
			want: richRuleWant{
				family:        "ipv4",
				source:        "192.0.2.0/24",
				sourceNegated: true,
				element:       "port",
				ports:         "22",
				protocol:      flow.ProtoTCP,
				action:        ActionReject,
			},
		},
		{
			name: "invert false leaves the source as stated",
			line: `rule family="ipv4" source address="192.0.2.0/24" invert="False" port port="22" protocol="tcp" accept`,
			want: richRuleWant{
				family:   "ipv4",
				source:   "192.0.2.0/24",
				element:  "port",
				ports:    "22",
				protocol: flow.ProtoTCP,
				action:   ActionAccept,
			},
		},
		{
			// A service element names ports this package resolves separately, so
			// the rule carries a name rather than a port set.
			name: "service element",
			line: `rule family="ipv4" source address="192.0.2.0/24" service name="ssh" accept`,
			want: richRuleWant{
				family:   "ipv4",
				source:   "192.0.2.0/24",
				element:  "service",
				service:  "ssh",
				ports:    "none",
				protocol: flow.ProtoAny,
				action:   ActionAccept,
			},
		},
		{
			// `protocol value=` constrains the protocol and nothing else, so it
			// governs every port of that protocol.
			name: "protocol element",
			line: `rule family="ipv4" source address="192.0.2.0/24" protocol value="udp" accept`,
			want: richRuleWant{
				family:   "ipv4",
				source:   "192.0.2.0/24",
				element:  "protocol",
				ports:    "none",
				protocol: flow.ProtoUDP,
				action:   ActionAccept,
			},
		},
		{
			// No element at all: the rule governs every port from that source.
			name: "source-wide drop",
			line: `rule family="ipv4" source address="203.0.113.0/24" drop`,
			want: richRuleWant{
				family:   "ipv4",
				source:   "203.0.113.0/24",
				ports:    "none",
				protocol: flow.ProtoAny,
				action:   ActionDrop,
			},
		},
		{
			name: "no source names every source",
			line: `rule family="ipv4" port port="22" protocol="tcp" reject`,
			want: richRuleWant{
				family:    "ipv4",
				source:    "none",
				sourceAny: true,
				element:   "port",
				ports:     "22",
				protocol:  flow.ProtoTCP,
				action:    ActionReject,
			},
		},
		{
			// Logging, auditing and rate limiting cannot admit or deny a port, so
			// their attributes are ignored and the rule stays readable.
			name: "log audit and limit attributes are ignored",
			line: `rule family="ipv4" source address="192.0.2.0/24" port port="22" protocol="tcp" log prefix="ssh" level="info" limit value="3/m" audit limit value="1/m" accept`,
			want: richRuleWant{
				family:   "ipv4",
				source:   "192.0.2.0/24",
				element:  "port",
				ports:    "22",
				protocol: flow.ProtoTCP,
				action:   ActionAccept,
			},
		},
		{
			// A reject type is an attribute of the denial, not of the match.
			name: "reject type is an attribute",
			line: `rule family="ipv4" source address="192.0.2.0/24" port port="22" protocol="tcp" reject type="icmp-admin-prohibited"`,
			want: richRuleWant{
				family:   "ipv4",
				source:   "192.0.2.0/24",
				element:  "port",
				ports:    "22",
				protocol: flow.ProtoTCP,
				action:   ActionReject,
			},
		},
		{
			// `mark` lets the packet continue, so it decides nothing.
			name: "mark decides nothing",
			line: `rule family="ipv4" source address="192.0.2.0/24" port port="22" protocol="tcp" mark set="0x64"`,
			want: richRuleWant{
				family:   "ipv4",
				source:   "192.0.2.0/24",
				element:  "port",
				ports:    "22",
				protocol: flow.ProtoTCP,
				action:   ActionNone,
			},
		},
		{
			// A source-port matches the client's port, which this package does
			// not model. The rule's effect is unknown rather than absent.
			name: "source-port is unresolvable",
			line: `rule family="ipv4" source address="192.0.2.0/24" source-port port="1024-65535" protocol="tcp" accept`,
			want: richRuleWant{
				family:       "ipv4",
				source:       "192.0.2.0/24",
				ports:        "none",
				protocol:     flow.ProtoTCP,
				action:       ActionAccept,
				unresolvable: true,
			},
		},
		{
			name: "forward-port is unresolvable",
			line: `rule family="ipv4" source address="192.0.2.0/24" forward-port port="80" protocol="tcp" to-port="8080"`,
			want: richRuleWant{
				family:       "ipv4",
				source:       "192.0.2.0/24",
				ports:        "none",
				protocol:     flow.ProtoTCP,
				action:       ActionNone,
				unresolvable: true,
			},
		},
		{
			// An ipset names addresses this output does not list, so the rule's
			// reach is unknown. It is not a rule with no source.
			name: "ipset source is unresolvable",
			line: `rule family="ipv4" source ipset="trusted-admins" port port="22" protocol="tcp" accept`,
			want: richRuleWant{
				family:       "ipv4",
				source:       "none",
				sourceAny:    true,
				element:      "port",
				ports:        "22",
				protocol:     flow.ProtoTCP,
				action:       ActionAccept,
				unresolvable: true,
			},
		},
		{
			name: "mac source is unresolvable",
			line: `rule family="ipv4" source mac="00:11:22:33:44:55" port port="22" protocol="tcp" accept`,
			want: richRuleWant{
				family:       "ipv4",
				source:       "none",
				sourceAny:    true,
				element:      "port",
				ports:        "22",
				protocol:     flow.ProtoTCP,
				action:       ActionAccept,
				unresolvable: true,
			},
		},
		{
			// ICMP rules and masquerading cannot open or close a TCP port, so
			// they are set aside rather than reported as unknown: abstaining on a
			// masquerade rule would make every gateway zone unanswerable.
			name: "icmp-block decides no port",
			line: `rule family="ipv4" source address="192.0.2.0/24" icmp-block name="echo-request" drop`,
			want: richRuleWant{
				family:   "ipv4",
				source:   "192.0.2.0/24",
				ports:    "none",
				protocol: flow.ProtoAny,
				action:   ActionDrop,
			},
		},
		{
			name: "masquerade decides no port",
			line: `rule family="ipv4" source address="10.0.0.0/8" masquerade`,
			want: richRuleWant{
				family:   "ipv4",
				source:   "10.0.0.0/8",
				ports:    "none",
				protocol: flow.ProtoAny,
				action:   ActionNone,
			},
		},
		{
			// A token this parser has never seen could be the one that admits the
			// source, so it is recorded rather than skipped.
			name: "unrecognised token is unresolvable",
			line: `rule family="ipv4" source address="192.0.2.0/24" tcp-window-clamp accept`,
			want: richRuleWant{
				family:       "ipv4",
				source:       "192.0.2.0/24",
				ports:        "none",
				protocol:     flow.ProtoAny,
				action:       ActionAccept,
				unresolvable: true,
			},
		},
		{
			// A destination narrows which local address the rule covers, which
			// this check does not ask about: the source is the question.
			name: "destination section does not disturb the source",
			line: `rule family="ipv4" source address="192.0.2.0/24" destination address="10.0.1.23" port port="22" protocol="tcp" accept`,
			want: richRuleWant{
				family:   "ipv4",
				source:   "192.0.2.0/24",
				element:  "port",
				ports:    "22",
				protocol: flow.ProtoTCP,
				action:   ActionAccept,
			},
		},
		{
			// A bare host address is a /32 entry, not a malformed CIDR.
			name: "bare host source",
			line: `rule family="ipv4" source address="192.0.2.10" port port="22" protocol="tcp" accept`,
			want: richRuleWant{
				family:   "ipv4",
				source:   "192.0.2.10/32",
				element:  "port",
				ports:    "22",
				protocol: flow.ProtoTCP,
				action:   ActionAccept,
			},
		},
		{
			name: "comma-separated sources",
			line: `rule family="ipv4" source address="192.0.2.0/24,198.51.100.0/24" port port="22" protocol="tcp" accept`,
			want: richRuleWant{
				family:   "ipv4",
				source:   "192.0.2.0/24,198.51.100.0/24",
				element:  "port",
				ports:    "22",
				protocol: flow.ProtoTCP,
				action:   ActionAccept,
			},
		},
		{
			// firewalld states no family for a rule that applies to both.
			name: "no family stated",
			line: `rule source address="192.0.2.0/24" port port="22" protocol="tcp" accept`,
			want: richRuleWant{
				source:   "192.0.2.0/24",
				element:  "port",
				ports:    "22",
				protocol: flow.ProtoTCP,
				action:   ActionAccept,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseRichRule(tt.line)
			if err != nil {
				t.Fatalf("ParseRichRule(%q) returned an error: %v", tt.line, err)
			}
			if got.Raw != tt.line {
				t.Errorf("Raw = %q, want the line verbatim so the citation quotes it", got.Raw)
			}
			if got.Priority != tt.want.priority {
				t.Errorf("Priority = %d, want %d", got.Priority, tt.want.priority)
			}
			if got.Family != tt.want.family {
				t.Errorf("Family = %q, want %q", got.Family, tt.want.family)
			}
			if source := got.Source.String(); source != tt.want.source {
				t.Errorf("Source = %s, want %s", source, tt.want.source)
			}
			if got.SourceAny != tt.want.sourceAny {
				t.Errorf("SourceAny = %v, want %v", got.SourceAny, tt.want.sourceAny)
			}
			if got.SourceNegated != tt.want.sourceNegated {
				t.Errorf("SourceNegated = %v, want %v", got.SourceNegated, tt.want.sourceNegated)
			}
			if got.Element != tt.want.element {
				t.Errorf("Element = %q, want %q", got.Element, tt.want.element)
			}
			if got.Service != tt.want.service {
				t.Errorf("Service = %q, want %q", got.Service, tt.want.service)
			}
			if ports := got.Ports.String(); ports != tt.want.ports {
				t.Errorf("Ports = %s, want %s", ports, tt.want.ports)
			}
			if got.Protocol != tt.want.protocol {
				t.Errorf("Protocol = %s, want %s", got.Protocol, tt.want.protocol)
			}
			if got.Action != tt.want.action {
				t.Errorf("Action = %q, want %q", got.Action, tt.want.action)
			}
			if unresolvable := got.Unresolvable != ""; unresolvable != tt.want.unresolvable {
				t.Errorf("Unresolvable = %q, want unresolvable = %v", got.Unresolvable, tt.want.unresolvable)
			}
		})
	}
}

// A source or a port the parser cannot read is an error rather than a rule with
// a field missing. The line nobody could parse is exactly the line that might
// have admitted the source, so it must not be quietly reduced to a rule that
// matches nothing.
func TestParseRichRuleRejectsMalformedLines(t *testing.T) {
	tests := []struct {
		name    string
		line    string
		wantErr string
	}{
		{
			name:    "not a rich rule",
			line:    `accept port=22`,
			wantErr: "not a rich rule",
		},
		{
			// firewall-cmd prints diagnostics to stderr, but a captured stream
			// can still put one here.
			name:    "a diagnostic line",
			line:    `FirewallD is not running`,
			wantErr: "not a rich rule",
		},
		{
			name:    "only whitespace",
			line:    "\t  ",
			wantErr: "not a rich rule",
		},
		{
			name:    "unreadable source address",
			line:    `rule family="ipv4" source address="192.0.2.300/24" port port="22" protocol="tcp" accept`,
			wantErr: "unreadable source address",
		},
		{
			name:    "unreadable priority",
			line:    `rule priority="high" family="ipv4" source address="192.0.2.0/24" port port="22" protocol="tcp" accept`,
			wantErr: "unreadable priority",
		},
		{
			name:    "port out of range",
			line:    `rule family="ipv4" source address="192.0.2.0/24" port port="70000" protocol="tcp" accept`,
			wantErr: "unreadable port",
		},
		{
			name:    "port range out of range",
			line:    `rule family="ipv4" source address="192.0.2.0/24" port port="8080-70000" protocol="tcp" accept`,
			wantErr: "unreadable port range",
		},
		{
			name:    "unreadable protocol",
			line:    `rule family="ipv4" source address="192.0.2.0/24" port port="22" protocol="sctp" accept`,
			wantErr: "unreadable protocol",
		},
		{
			name:    "port element without a port",
			line:    `rule family="ipv4" source address="192.0.2.0/24" port protocol="tcp" accept`,
			wantErr: "port element without a port",
		},
		{
			name:    "service element without a name",
			line:    `rule family="ipv4" source address="192.0.2.0/24" service accept`,
			wantErr: "service element without a name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseRichRule(tt.line)
			if err == nil {
				t.Fatalf("ParseRichRule(%q) = %+v, want an error", tt.line, got)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want it to name %q", err, tt.wantErr)
			}
		})
	}
}

// The list is read line by line, blank lines and all, because firewall-cmd
// prints a trailing newline and a zone with no rich rules prints nothing else.
func TestParseRichRules(t *testing.T) {
	out := `rule family="ipv4" source address="198.51.100.128/26" port port="22" protocol="tcp" accept

rule family="ipv4" source address="10.0.0.0/8" service name="https" accept
  rule family="ipv4" source address="203.0.113.0/24" drop
`

	rules, err := ParseRichRules(out)
	if err != nil {
		t.Fatalf("ParseRichRules returned an error: %v", err)
	}
	if len(rules) != 3 {
		t.Fatalf("parsed %d rules, want 3: %+v", len(rules), rules)
	}
	if rules[0].Source.String() != "198.51.100.128/26" || rules[0].Element != "port" {
		t.Errorf("rule 0 = %+v, want the port rule first", rules[0])
	}
	if rules[1].Service != "https" {
		t.Errorf("rule 1 service = %q, want https", rules[1].Service)
	}
	// Leading whitespace is trimmed, and the raw text is trimmed with it so the
	// citation reads as a rule rather than as an indented fragment.
	if rules[2].Raw != `rule family="ipv4" source address="203.0.113.0/24" drop` {
		t.Errorf("rule 2 raw = %q, want the trimmed line", rules[2].Raw)
	}
	if rules[2].Action != ActionDrop {
		t.Errorf("rule 2 action = %q, want drop", rules[2].Action)
	}

	if got, err := ParseRichRules("\n\n  \n"); err != nil || len(got) != 0 {
		t.Errorf("ParseRichRules of a blank list = %+v, %v; want no rules and no error", got, err)
	}
}

// A line that could not be read is reported with its position, because the
// operator has to find it in the zone.
func TestParseRichRulesNamesTheFailingLine(t *testing.T) {
	out := `rule family="ipv4" source address="192.0.2.0/24" port port="22" protocol="tcp" accept
rule family="ipv4" source address="not-an-address" port port="22" protocol="tcp" accept
`

	rules, err := ParseRichRules(out)
	if err == nil {
		t.Fatalf("ParseRichRules = %+v, want an error", rules)
	}
	if !strings.Contains(err.Error(), "line 2") {
		t.Errorf("error = %q, want it to name line 2", err)
	}
	if rules != nil {
		t.Errorf("rules = %+v, want none: a partly read allowlist is not an allowlist", rules)
	}
}

// Requirement 8.3: an entry is matched against the source by network
// containment. Every case here is one a string comparison gets wrong — the entry
// text "198.51.100.128/26" equals none of these addresses — and the two-day
// investigation that motivated this tool is the first row.
func TestRichRuleMatchesTheSourceByContainment(t *testing.T) {
	const line = `rule family="ipv4" source address="198.51.100.128/26" port port="22" protocol="tcp" accept`

	tests := []struct {
		name   string
		source string
		want   bool
	}{
		{name: "inside the entry", source: "198.51.100.150", want: true},
		{name: "the network address of the entry", source: "198.51.100.128", want: true},
		{name: "the last address of the entry", source: "198.51.100.191", want: true},
		{name: "below the entry", source: "198.51.100.10", want: false},
		{name: "one past the entry", source: "198.51.100.192", want: false},
		{name: "a different network entirely", source: "192.0.2.150", want: false},
	}

	rule := mustRichRule(t, line)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := rule.matches(FirewallRequest{
				Source:   mustAddr(t, tt.source),
				Protocol: flow.ProtoTCP,
				Port:     22,
			})
			if err != nil {
				t.Fatalf("matches returned an error: %v", err)
			}
			if got != tt.want {
				t.Errorf("entry %s covering %s = %v, want %v", rule.Source, tt.source, got, tt.want)
			}
		})
	}
}

// The rest of the match: family, negation, element, protocol and port all narrow
// which traffic a rule governs, and a rule that does not govern the traffic must
// not decide it.
func TestRichRuleMatchesNarrowsByFamilyElementAndPort(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		source   string
		protocol flow.Protocol
		port     uint16
		want     bool
	}{
		{
			name:     "an ipv6 rule does not decide an ipv4 flow",
			line:     `rule family="ipv6" source address="2001:db8::/32" port port="22" protocol="tcp" accept`,
			source:   "192.0.2.10",
			protocol: flow.ProtoTCP,
			port:     22,
			want:     false,
		},
		{
			name:     "an ipv4 rule does not decide an ipv6 flow",
			line:     `rule family="ipv4" source address="192.0.2.0/24" port port="22" protocol="tcp" accept`,
			source:   "2001:db8::10",
			protocol: flow.ProtoTCP,
			port:     22,
			want:     false,
		},
		{
			name:     "a negated source excludes what it names",
			line:     `rule family="ipv4" source NOT address="192.0.2.0/24" port port="22" protocol="tcp" reject`,
			source:   "192.0.2.10",
			protocol: flow.ProtoTCP,
			port:     22,
			want:     false,
		},
		{
			name:     "a negated source matches everything else",
			line:     `rule family="ipv4" source NOT address="192.0.2.0/24" port port="22" protocol="tcp" reject`,
			source:   "198.51.100.10",
			protocol: flow.ProtoTCP,
			port:     22,
			want:     true,
		},
		{
			name:     "a port range covers a port inside it",
			line:     `rule family="ipv4" source address="10.0.0.0/8" port port="8080-8090" protocol="tcp" accept`,
			source:   "10.0.1.23",
			protocol: flow.ProtoTCP,
			port:     8085,
			want:     true,
		},
		{
			name:     "a port range does not cover a port past it",
			line:     `rule family="ipv4" source address="10.0.0.0/8" port port="8080-8090" protocol="tcp" accept`,
			source:   "10.0.1.23",
			protocol: flow.ProtoTCP,
			port:     8091,
			want:     false,
		},
		{
			name:     "a tcp rule does not decide a udp flow",
			line:     `rule family="ipv4" source address="10.0.0.0/8" port port="53" protocol="tcp" accept`,
			source:   "10.0.1.23",
			protocol: flow.ProtoUDP,
			port:     53,
			want:     false,
		},
		{
			name:     "a service element resolves to its ports",
			line:     `rule family="ipv4" source address="192.0.2.0/24" service name="ssh" accept`,
			source:   "192.0.2.10",
			protocol: flow.ProtoTCP,
			port:     22,
			want:     true,
		},
		{
			name:     "a service element does not cover another port",
			line:     `rule family="ipv4" source address="192.0.2.0/24" service name="ssh" accept`,
			source:   "192.0.2.10",
			protocol: flow.ProtoTCP,
			port:     3306,
			want:     false,
		},
		{
			name:     "a protocol element covers every port of that protocol",
			line:     `rule family="ipv4" source address="192.0.2.0/24" protocol value="tcp" accept`,
			source:   "192.0.2.10",
			protocol: flow.ProtoTCP,
			port:     9999,
			want:     true,
		},
		{
			name:     "a protocol element does not cover another protocol",
			line:     `rule family="ipv4" source address="192.0.2.0/24" protocol value="tcp" accept`,
			source:   "192.0.2.10",
			protocol: flow.ProtoUDP,
			port:     9999,
			want:     false,
		},
		{
			name:     "a source-wide rule governs every port from that source",
			line:     `rule family="ipv4" source address="203.0.113.0/24" drop`,
			source:   "203.0.113.10",
			protocol: flow.ProtoTCP,
			port:     22,
			want:     true,
		},
		{
			// A rule that only logs or marks decides nothing, whatever it matches.
			name:     "a rule with no action decides nothing",
			line:     `rule family="ipv4" source address="192.0.2.0/24" port port="22" protocol="tcp" mark set="0x64"`,
			source:   "192.0.2.10",
			protocol: flow.ProtoTCP,
			port:     22,
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := mustRichRule(t, tt.line)
			got, err := rule.matches(FirewallRequest{
				Source:   mustAddr(t, tt.source),
				Protocol: tt.protocol,
				Port:     tt.port,
			})
			if err != nil {
				t.Fatalf("matches returned an error: %v", err)
			}
			if got != tt.want {
				t.Errorf("matches = %v, want %v", got, tt.want)
			}
		})
	}
}

// A rule this package cannot evaluate is not a rule it can ignore, but it is
// also not a reason to give up on a port the rule demonstrably does not concern.
// A forward-port names its destination port, so it can be narrowed; a
// source-port names the client's, so it cannot.
func TestRichRuleUnresolvableRulesNarrowWhereTheyCan(t *testing.T) {
	tests := []struct {
		name    string
		line    string
		port    uint16
		wantErr bool
	}{
		{
			name:    "a forward-port is set aside for another port",
			line:    `rule family="ipv4" source address="192.0.2.0/24" forward-port port="80" protocol="tcp" to-port="8080"`,
			port:    443,
			wantErr: false,
		},
		{
			name:    "a forward-port cannot be evaluated for the port it redirects",
			line:    `rule family="ipv4" source address="192.0.2.0/24" forward-port port="80" protocol="tcp" to-port="8080"`,
			port:    80,
			wantErr: true,
		},
		{
			name:    "a source-port cannot be narrowed to a destination port",
			line:    `rule family="ipv4" source address="192.0.2.0/24" source-port port="1024-65535" protocol="tcp" accept`,
			port:    443,
			wantErr: true,
		},
		{
			name:    "an ipset source cannot be evaluated",
			line:    `rule family="ipv4" source ipset="trusted-admins" port port="22" protocol="tcp" accept`,
			port:    22,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := mustRichRule(t, tt.line)
			match, err := rule.matches(FirewallRequest{
				Source:   mustAddr(t, "192.0.2.10"),
				Protocol: flow.ProtoTCP,
				Port:     tt.port,
			})
			if tt.wantErr {
				if err == nil {
					t.Fatalf("matches = %v, nil; want an error saying the rule cannot be evaluated", match)
				}
				if !strings.Contains(err.Error(), "cannot be evaluated") {
					t.Errorf("error = %q, want it to say the rule cannot be evaluated", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("matches returned an error: %v", err)
			}
			if match {
				t.Errorf("matches = true, want the rule set aside for a port it does not concern")
			}
		})
	}
}

// A rule the check cannot read might be the rule that admits the source, so the
// Layer is left unverified rather than declared closed.
func TestFirewallCheckAbstainsOnARuleItCannotEvaluate(t *testing.T) {
	r := &stubRunner{results: map[Check]Result{
		CheckFirewalldRichRules: {Stdout: `rule family="ipv4" source ipset="trusted-admins" port port="22" protocol="tcp" accept` + "\n"},
		CheckFirewalldServices:  {Stdout: "dhcpv6-client\n"},
	}}

	got := FirewallCheck(context.Background(), r, testInstance, FirewallRequest{
		Source:   mustAddr(t, "192.0.2.10"),
		Protocol: flow.ProtoTCP,
		Port:     22,
	})

	assertEmittable(t, got)
	if got.Verdict != model.VerdictAbstain {
		t.Fatalf("verdict = %s, want abstain (%+v)", got.Verdict, got)
	}
	if !strings.Contains(got.Reason, "trusted-admins") {
		t.Errorf("reason = %q, want the ipset named so the operator can resolve it", got.Reason)
	}
}

// Requirement 8.4: a source no entry covers is BLOCKED citing the entries that
// were found. The entries are what the operator has to change, so which entries
// are cited depends on what the zone holds — the near miss when there is one,
// the rules that name other ports when there is not, and the absence of rules
// when the zone has none.
func TestFirewallCheckBlockedCitesTheAllowlistEntriesFound(t *testing.T) {
	const services = "dhcpv6-client https\n"

	tests := []struct {
		name      string
		richRules string
		want      []string
	}{
		{
			// The motivating incident: an allowlist built from a stale template
			// whose entries cover the port but not this source.
			name: "entries for the port that do not contain the source",
			richRules: `rule family="ipv4" source address="198.51.100.128/26" port port="22" protocol="tcp" accept
rule family="ipv4" source address="10.0.1.0/24" port port="22" protocol="tcp" accept
`,
			want: []string{
				"no rich rule admits 192.0.2.10 to tcp/22",
				"allowlist entries for tcp/22, none containing 192.0.2.10",
				"198.51.100.128/26",
				"10.0.1.0/24",
			},
		},
		{
			// Nothing in the zone names the port at all, which is a different
			// mistake from an entry with the wrong source and reads differently.
			name:      "no entry names the port",
			richRules: `rule family="ipv4" source address="203.0.113.0/24" port port="3306" protocol="tcp" accept` + "\n",
			want: []string{
				"no allowlist entry names tcp/22",
				"203.0.113.0/24",
			},
		},
		{
			name:      "the zone has no rich rules",
			richRules: "\n",
			want: []string{
				"zone has no rich rules",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &stubRunner{results: map[Check]Result{
				CheckFirewalldRichRules: {Stdout: tt.richRules},
				CheckFirewalldServices:  {Stdout: services},
			}}

			got := FirewallCheck(context.Background(), r, testInstance, FirewallRequest{
				Source:   mustAddr(t, "192.0.2.10"),
				Protocol: flow.ProtoTCP,
				Port:     22,
			})

			assertEmittable(t, got)
			if got.Verdict != model.VerdictBlocked {
				t.Fatalf("verdict = %s, want blocked (%+v)", got.Verdict, got)
			}
			for _, want := range tt.want {
				if !citationsContain(got.Citations, want) {
					t.Errorf("citations = %+v, want one naming %q", got.Citations, want)
				}
			}
			// Requirement 8.2: the named services are read before anything is
			// concluded, because a service allowance is invisible in the rich rules.
			if !citationsContain(got.Citations, "https") {
				t.Errorf("citations = %+v, want the zone's services reported too", got.Citations)
			}
		})
	}
}

// The service list is one whitespace-separated line, but it reaches the parser
// with a trailing newline, sometimes wrapped, and occasionally with a name
// repeated by a zone that allows it twice.
func TestParseServices(t *testing.T) {
	tests := []struct {
		name string
		out  string
		want []string
	}{
		{
			name: "one line",
			out:  "dhcpv6-client ssh\n",
			want: []string{"dhcpv6-client", "ssh"},
		},
		{
			name: "irregular whitespace",
			out:  "  dhcpv6-client\t\tssh   https  \n",
			want: []string{"dhcpv6-client", "ssh", "https"},
		},
		{
			name: "wrapped over several lines",
			out:  "dhcpv6-client\nssh\nhttps\n",
			want: []string{"dhcpv6-client", "ssh", "https"},
		},
		{
			name: "duplicates collapse, first position kept",
			out:  "ssh https ssh cockpit https\n",
			want: []string{"ssh", "https", "cockpit"},
		},
		{
			name: "no services",
			out:  "",
			want: nil,
		},
		{
			name: "blank output",
			out:  "\n \t\n",
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseServices(tt.out)
			if len(got) != len(tt.want) {
				t.Fatalf("ParseServices(%q) = %v, want %v", tt.out, got, tt.want)
			}
			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Errorf("service %d = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

// A name this package resolves is a port set; a name it does not is an absence
// of knowledge, which the caller has to be able to tell apart from an absence of
// ports.
func TestServicePorts(t *testing.T) {
	tests := []struct {
		name       string
		service    string
		wantKnown  bool
		protocol   flow.Protocol
		port       uint16
		wantCovers bool
	}{
		{
			name: "ssh covers tcp 22", service: "ssh", wantKnown: true,
			protocol: flow.ProtoTCP, port: 22, wantCovers: true,
		},
		{
			name: "ssh does not cover udp 22", service: "ssh", wantKnown: true,
			protocol: flow.ProtoUDP, port: 22, wantCovers: false,
		},
		{
			name: "ssh does not cover another tcp port", service: "ssh", wantKnown: true,
			protocol: flow.ProtoTCP, port: 2222, wantCovers: false,
		},
		{
			// The list is read case-insensitively and trimmed, because a name
			// reaches here from a zone file as readily as from firewall-cmd.
			name: "a name is matched case-insensitively", service: "SSH", wantKnown: true,
			protocol: flow.ProtoTCP, port: 22, wantCovers: true,
		},
		{
			name: "a name is trimmed", service: "  https  ", wantKnown: true,
			protocol: flow.ProtoTCP, port: 443, wantCovers: true,
		},
		{
			name: "dns covers tcp 53", service: "dns", wantKnown: true,
			protocol: flow.ProtoTCP, port: 53, wantCovers: true,
		},
		{
			name: "dns covers udp 53", service: "dns", wantKnown: true,
			protocol: flow.ProtoUDP, port: 53, wantCovers: true,
		},
		{
			name: "a service defined as a range covers a port inside it", service: "mosh", wantKnown: true,
			protocol: flow.ProtoUDP, port: 60500, wantCovers: true,
		},
		{
			name: "a service defined as a range does not cover a port past it", service: "mosh", wantKnown: true,
			protocol: flow.ProtoUDP, port: 61001, wantCovers: false,
		},
		{
			// A protocol with no ports cannot be covered by a port definition.
			name: "no service covers icmp", service: "ssh", wantKnown: true,
			protocol: flow.ProtoICMP, port: 22, wantCovers: false,
		},
		{
			name: "an unknown name is not known", service: "acme-broker", wantKnown: false,
			protocol: flow.ProtoTCP, port: 8443, wantCovers: false,
		},
		{
			name: "an empty name is not known", service: "", wantKnown: false,
			protocol: flow.ProtoTCP, port: 22, wantCovers: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			def, known := ServicePorts(tt.service)
			if known != tt.wantKnown {
				t.Fatalf("ServicePorts(%q) known = %v, want %v", tt.service, known, tt.wantKnown)
			}
			if got := def.covers(tt.protocol, tt.port); got != tt.wantCovers {
				t.Errorf("%q covers %s/%d = %v, want %v", tt.service, tt.protocol, tt.port, got, tt.wantCovers)
			}
		})
	}
}

// A name whose ports this package cannot resolve could be the one that opens the
// port, so the zone is left unverified rather than declared closed. The
// alternative is a confident BLOCKED that sends the operator to the wrong layer,
// which is the failure this tool exists to stop.
func TestFirewallCheckAbstainsOnAnAllowedServiceItCannotResolve(t *testing.T) {
	r := &stubRunner{results: map[Check]Result{
		CheckFirewalldRichRules: {Stdout: "\n"},
		CheckFirewalldServices:  {Stdout: "ssh acme-broker\n"},
	}}

	got := FirewallCheck(context.Background(), r, testInstance, FirewallRequest{
		Source:   mustAddr(t, "192.0.2.10"),
		Protocol: flow.ProtoTCP,
		Port:     8443,
	})

	assertEmittable(t, got)
	if got.Verdict != model.VerdictAbstain {
		t.Fatalf("verdict = %s, want abstain (%+v)", got.Verdict, got)
	}
	if !strings.Contains(got.Reason, "acme-broker") {
		t.Errorf("reason = %q, want the unresolved service named", got.Reason)
	}
	// A name this package does know must not drag the zone into an abstention.
	if strings.Contains(got.Reason, "ssh") {
		t.Errorf("reason = %q, want only the unresolved name", got.Reason)
	}
}

// mustRichRule parses a fixture line that the test requires to be readable.
func mustRichRule(t *testing.T, line string) RichRule {
	t.Helper()
	rule, err := ParseRichRule(line)
	if err != nil {
		t.Fatalf("ParseRichRule(%q): %v", line, err)
	}
	return rule
}

// citationsContain reports whether any citation's detail names want.
func citationsContain(citations []model.Citation, want string) bool {
	for _, c := range citations {
		if strings.Contains(c.Detail, want) {
			return true
		}
	}
	return false
}
