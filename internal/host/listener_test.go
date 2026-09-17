package host

// Fixture tests for the listener parser.
//
// The fixtures are the shapes `ss -tlnp` actually prints, because that is the
// only thing this parser has to be right about. iproute2 varies the header, the
// optional netid column, how it spells a wildcard, and whether the process column
// is there at all, and each of those variations has been mistaken for a host with
// nothing listening at some point.
//
// The strictness cases matter as much as the readable ones: a row the parser
// cannot read has to become an error, never a listener quietly dropped from
// consideration. A dropped row would let the check report "nothing listening" on
// the strength of a line it did not understand.

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/jajera/aws-netpath/internal/flow"
	"github.com/jajera/aws-netpath/internal/model"
)

// Modern iproute2: no netid column, wildcards spelled both `*` and `[::]`, and a
// process column that can name more than one process for one socket.
const ssListenersFull = `State   Recv-Q  Send-Q   Local Address:Port    Peer Address:Port   Process
LISTEN  0       128      0.0.0.0:22            0.0.0.0:*           users:(("sshd",pid=1234,fd=3))
LISTEN  0       100      127.0.0.1:25          0.0.0.0:*           users:(("master",pid=1500,fd=13))
LISTEN  0       511      *:80                  *:*                 users:(("nginx",pid=2001,fd=6),("nginx",pid=2002,fd=6))
LISTEN  0       4096     [::]:443              [::]:*              users:(("nginx",pid=2001,fd=7),("nginx",pid=2002,fd=7))
LISTEN  0       244      [::1]:5432            [::]:*              users:(("postgres",pid=3100,fd=5))
`

// Older iproute2 leads with the netid column, and an unprivileged probe gets no
// process column at all.
const ssListenersNetid = `Netid  State   Recv-Q  Send-Q  Local Address:Port  Peer Address:Port
tcp    LISTEN  0       128     10.0.1.23:8080      0.0.0.0:*
tcp6   LISTEN  0       128     [::]:22             [::]:*
`

// No header, which is what a caller filtering the output leaves behind, plus a
// link-local bind carrying an interface scope.
const ssListenersNoHeader = `LISTEN 0      128    192.168.10.5:3306      0.0.0.0:*
LISTEN 0      128    [fe80::1%eth0]:5355    [::]:*    users:(("systemd-resolve",pid=800,fd=13))
`

// Non-listening states appear when the output covers more than listening sockets.
// They are rows to ignore, not rows to fail on.
const ssListenersMixedStates = `State       Recv-Q Send-Q Local Address:Port     Peer Address:Port    Process
ESTAB       0      0      10.0.1.23:22           198.51.100.10:54321  users:(("sshd",pid=4100,fd=4))
LISTEN      0      128    10.0.1.23:22           0.0.0.0:*            users:(("sshd",pid=1234,fd=3))
CLOSE-WAIT  1      0      10.0.1.23:443          192.0.2.55:44112     users:(("app",pid=900,fd=9))
TIME-WAIT   0      0      10.0.1.23:8080         192.0.2.55:33110
`

// A host with nothing listening still prints the header.
const ssListenersHeaderOnly = "State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n"

// wantListener is the readable part of a parsed socket. Local is the address as
// netip renders it, and empty for the wildcard `ss` spells `*`, which has no
// stated family.
type wantListener struct {
	local   string
	port    uint16
	process string
}

// Requirements 8.1 and 8.5 both rest on this: the sockets the check compares the
// destination against are whatever this parser read out of the host's output.
func TestParseListenersReadsTheShapesSSPrints(t *testing.T) {
	tests := []struct {
		name string
		out  string
		want []wantListener
	}{
		{
			name: "header, no netid column, both wildcard spellings",
			out:  ssListenersFull,
			want: []wantListener{
				{local: "0.0.0.0", port: 22, process: "sshd"},
				{local: "127.0.0.1", port: 25, process: "master"},
				{local: "", port: 80, process: "nginx"},
				{local: "::", port: 443, process: "nginx"},
				{local: "::1", port: 5432, process: "postgres"},
			},
		},
		{
			name: "leading netid column and no process column",
			out:  ssListenersNetid,
			want: []wantListener{
				{local: "10.0.1.23", port: 8080},
				{local: "::", port: 22},
			},
		},
		{
			name: "no header, and a link-local bind with an interface scope",
			out:  ssListenersNoHeader,
			want: []wantListener{
				{local: "192.168.10.5", port: 3306},
				{local: "fe80::1", port: 5355, process: "systemd-resolve"},
			},
		},
		{
			name: "non-listening states are ignored, not read as listeners",
			out:  ssListenersMixedStates,
			want: []wantListener{
				{local: "10.0.1.23", port: 22, process: "sshd"},
			},
		},
		{
			name: "header only",
			out:  ssListenersHeaderOnly,
		},
		{
			name: "no output at all",
			out:  "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseListeners(tc.out)
			if err != nil {
				t.Fatalf("ParseListeners returned %v, want the sockets read", err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("read %d listeners, want %d: %+v", len(got), len(tc.want), got)
			}
			for i, want := range tc.want {
				local := ""
				if got[i].Local.IsValid() {
					local = got[i].Local.String()
				}
				if local != want.local {
					t.Errorf("listener %d local = %q, want %q", i, local, want.local)
				}
				if got[i].Port != want.port {
					t.Errorf("listener %d port = %d, want %d", i, got[i].Port, want.port)
				}
				if got[i].Process != want.process {
					t.Errorf("listener %d process = %q, want %q", i, got[i].Process, want.process)
				}
				// Raw is what a citation quotes, so it has to be the host's own
				// line rather than a rendering of it.
				if got[i].Raw == "" || !strings.Contains(tc.out, got[i].Raw) {
					t.Errorf("listener %d raw = %q, want the line as the host printed it", i, got[i].Raw)
				}
			}
		})
	}
}

// A row that cannot be read is an error. Skipping it would take a listener out of
// consideration and let the check answer "nothing listening" from a line it did
// not understand.
func TestParseListenersRejectsUnreadableRows(t *testing.T) {
	tests := []struct {
		name    string
		out     string
		wantErr string
	}{
		{
			name:    "too few columns",
			out:     "LISTEN 0      128    0.0.0.0:22\n",
			wantErr: "unrecognised ss row",
		},
		{
			name:    "state column missing under a netid column",
			out:     "tcp    0      128    0.0.0.0:22   0.0.0.0:*\n",
			wantErr: "unrecognised ss row",
		},
		{
			name:    "queue length is not a number",
			out:     `LISTEN 0      none   0.0.0.0:22   0.0.0.0:*   users:(("sshd",pid=1234,fd=3))` + "\n",
			wantErr: "is not a queue length",
		},
		{
			name:    "local address has no port",
			out:     "LISTEN 0      128    0.0.0.0      0.0.0.0:*\n",
			wantErr: "no port in local address",
		},
		{
			name:    "local address is not an address",
			out:     "LISTEN 0      128    lo0-alias:22    0.0.0.0:*\n",
			wantErr: "unreadable address",
		},
		{
			name:    "port is a service name rather than a number",
			out:     "LISTEN 0      128    192.0.2.10:https    0.0.0.0:*\n",
			wantErr: "unreadable port",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseListeners(tc.out)
			if err == nil {
				t.Fatalf("ParseListeners read %+v, want an error the check can abstain on", got)
			}
			if got != nil {
				t.Errorf("listeners = %+v, want none: a partial read is not an answer", got)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %q, want it to state %q", err, tc.wantErr)
			}
		})
	}
}

// One unreadable row among readable ones fails the whole read, and names the line,
// because the operator has to be able to see which line stopped it.
func TestParseListenersFailsOnOneBadRowAmongGoodOnes(t *testing.T) {
	out := `State   Recv-Q  Send-Q  Local Address:Port  Peer Address:Port  Process
LISTEN  0       128     0.0.0.0:22          0.0.0.0:*          users:(("sshd",pid=1234,fd=3))
LISTEN  0       ?       0.0.0.0:80          0.0.0.0:*          users:(("nginx",pid=2001,fd=6))
LISTEN  0       128     0.0.0.0:443         0.0.0.0:*          users:(("nginx",pid=2001,fd=7))
`

	got, err := ParseListeners(out)
	if err == nil {
		t.Fatalf("ParseListeners read %+v, want an error", got)
	}
	if got != nil {
		t.Errorf("listeners = %+v, want none", got)
	}
	if !strings.Contains(err.Error(), "line 3") {
		t.Errorf("error = %q, want it to name line 3", err)
	}
}

// optAddr parses s, treating the empty string as no address at all: the wildcard
// `ss` reports as `*`, or a destination that was never resolved.
func optAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	if s == "" {
		return netip.Addr{}
	}
	return mustAddr(t, s)
}

// Whether a socket covers the dialled address is the whole point of the check: a
// daemon on 127.0.0.1 is a listener by every definition except the one that
// counts.
func TestListenerCoversResolvesTheBindingScope(t *testing.T) {
	tests := []struct {
		name  string
		local string
		port  uint16
		dst   string
		dport uint16
		want  bool
	}{
		{
			name:  "wildcard v4 covers an ipv4 destination",
			local: "0.0.0.0", port: 80, dst: "192.0.2.10", dport: 80, want: true,
		},
		{
			name:  "wildcard v4 does not cover an ipv6 destination",
			local: "0.0.0.0", port: 80, dst: "fe80::1", dport: 80, want: false,
		},
		{
			name:  "wildcard v6 covers an ipv6 destination",
			local: "::", port: 443, dst: "fe80::1", dport: 443, want: true,
		},
		{
			// Dual stack: :: accepts mapped IPv4 with the default bindv6only of 0.
			name:  "wildcard v6 covers an ipv4 destination too",
			local: "::", port: 443, dst: "192.0.2.10", dport: 443, want: true,
		},
		{
			name:  "wildcard of unstated family covers any destination",
			local: "", port: 80, dst: "10.0.1.23", dport: 80, want: true,
		},
		{
			name:  "specific v4 bind covers its own address",
			local: "192.0.2.10", port: 8080, dst: "192.0.2.10", dport: 8080, want: true,
		},
		{
			name:  "specific v4 bind covers no other address",
			local: "192.0.2.10", port: 8080, dst: "192.0.2.11", dport: 8080, want: false,
		},
		{
			name:  "loopback bind does not cover a routable destination",
			local: "127.0.0.1", port: 25, dst: "192.0.2.10", dport: 25, want: false,
		},
		{
			name:  "specific v6 bind covers its own address",
			local: "fe80::1", port: 5432, dst: "fe80::1", dport: 5432, want: true,
		},
		{
			name:  "specific v6 bind covers no other address",
			local: "fe80::1", port: 5432, dst: "fe80::2", dport: 5432, want: false,
		},
		{
			name:  "a mapped destination matches the v4 bind it names",
			local: "192.0.2.10", port: 8080, dst: "::ffff:192.0.2.10", dport: 8080, want: true,
		},
		{
			name:  "port mismatch on a specific bind never covers",
			local: "192.0.2.10", port: 8080, dst: "192.0.2.10", dport: 80, want: false,
		},
		{
			name:  "port mismatch on a wildcard bind never covers",
			local: "0.0.0.0", port: 80, dst: "192.0.2.10", dport: 8080, want: false,
		},
		{
			name:  "port mismatch on an unstated wildcard never covers",
			local: "", port: 80, dst: "192.0.2.10", dport: 443, want: false,
		},
		{
			name:  "no destination address never covers",
			local: "0.0.0.0", port: 80, dst: "", dport: 80, want: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			l := Listener{Local: optAddr(t, tc.local), Port: tc.port}
			if got := l.Covers(optAddr(t, tc.dst), tc.dport); got != tc.want {
				t.Errorf("Listener{%s}.Covers(%q, %d) = %t, want %t", l, tc.dst, tc.dport, got, tc.want)
			}
		})
	}
}

// Requirement 8.5: nothing listening on the destination port is BLOCKED, citing
// the listener output. What was found instead is part of the citation, because a
// port bound to loopback and a daemon that is not running send the operator to
// different places.
func TestListenerCheckBlocksWhenNothingCoversTheDestination(t *testing.T) {
	tests := []struct {
		name        string
		stdout      string
		dst         string
		port        uint16
		wantDetails []string
	}{
		{
			name:   "no tcp listeners on the host at all",
			stdout: ssListenersHeaderOnly,
			dst:    "192.0.2.10",
			port:   443,
			wantDetails: []string{
				"no process listening on tcp/443",
				"no tcp listeners reported",
			},
		},
		{
			name:   "the port is bound nowhere on a host with other listeners",
			stdout: ssListening,
			dst:    "192.0.2.10",
			port:   8080,
			wantDetails: []string{
				"no process listening on tcp/8080",
				"0.0.0.0:22 sshd",
			},
		},
		{
			name:   "the port is bound to loopback only",
			stdout: ssListening,
			dst:    "192.0.2.10",
			port:   25,
			wantDetails: []string{
				"bound elsewhere",
				"127.0.0.1:25 master",
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := &stubRunner{results: map[Check]Result{CheckListener: {Stdout: tc.stdout}}}

			got := ListenerCheck(context.Background(), r, testInstance, ListenerRequest{
				Destination: mustAddr(t, tc.dst),
				Protocol:    flow.ProtoTCP,
				Port:        tc.port,
			})

			assertEmittable(t, got)
			if got.Verdict != model.VerdictBlocked {
				t.Fatalf("verdict = %s, want blocked (%+v)", got.Verdict, got)
			}
			if len(got.Citations) == 0 {
				t.Fatal("blocked with no citation, and requirement 8.5 is cited or nothing")
			}
			cited := got.Citations[0]
			if cited.Identifier != "ss -tlnp" {
				t.Errorf("citation identifier = %q, want the command that was run", cited.Identifier)
			}
			for _, want := range tc.wantDetails {
				if !strings.Contains(cited.Detail, want) {
					t.Errorf("citation = %q, want it to state %q", cited.Detail, want)
				}
			}
		})
	}
}
