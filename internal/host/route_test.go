package host

// Fixtures for the two supporting checks.
//
// Both parsers read text a host printed for a human, so the fixtures are the
// shapes a host actually prints rather than the shapes the parsers happen to
// accept: the continuation line that carries the MTU, the type keyword before the
// destination, the `uid` suffix, and the family name in `via inet6`. A parser that
// only handles the tidy case is the parser that abstains on the day it matters.
//
// The judgement is fixtured alongside the parsing, because the interesting
// decisions in these two checks are about what silence means. A non-zero exit
// from `ip route get` is usually an answer; a silent `ping` is not.

import (
	"context"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

// Addresses are documentation (192.0.2.0/24) and private (192.168.10.0/24)
// ranges throughout. The one link-local address is fe80::1, which is the whole
// point of the `via inet6` shape: an IPv4 route whose next hop is an IPv6
// link-local address, as unnumbered peerings produce.

func TestParseRouteReadsTheForwardingDecision(t *testing.T) {
	tests := []struct {
		name string
		out  string
		// want* are compared as text; an empty address means the field must be
		// left invalid rather than filled with a zero value.
		wantType  string
		wantDst   string
		wantVia   string
		wantDev   string
		wantSrc   string
		wantMTU   int
		reachable bool
		summary   string
	}{
		{
			// On-link: no next hop, so the summary has to say so rather than
			// leave the reader wondering which gateway was chosen.
			name:      "on-link with a uid suffix and a cache line",
			out:       "192.168.10.7 dev eth0 src 192.168.10.23 uid 1000 \n    cache \n",
			wantDst:   "192.168.10.7",
			wantDev:   "eth0",
			wantSrc:   "192.168.10.23",
			reachable: true,
			summary:   "on-link dev eth0 src 192.168.10.23",
		},
		{
			name:      "via a gateway",
			out:       "192.0.2.10 via 192.168.10.1 dev eth0 src 192.168.10.23 uid 1000 \n    cache \n",
			wantDst:   "192.0.2.10",
			wantVia:   "192.168.10.1",
			wantDev:   "eth0",
			wantSrc:   "192.168.10.23",
			reachable: true,
			summary:   "via 192.168.10.1 dev eth0 src 192.168.10.23",
		},
		{
			// The MTU is printed on the continuation line and nowhere else, and
			// it is the one attribute here that can explain a failure by itself.
			name:      "mtu carried on the cache continuation line",
			out:       "192.0.2.10 via 192.168.10.1 dev eth0 src 192.168.10.23 uid 1000 \n    cache expires 596sec mtu 1400\n",
			wantDst:   "192.0.2.10",
			wantVia:   "192.168.10.1",
			wantDev:   "eth0",
			wantSrc:   "192.168.10.23",
			wantMTU:   1400,
			reachable: true,
			summary:   "via 192.168.10.1 dev eth0 src 192.168.10.23 mtu 1400",
		},
		{
			name:      "local route to the host's own address",
			out:       "local 192.168.10.23 dev lo table local src 192.168.10.23 uid 1000 \n    cache <local> \n",
			wantType:  "local",
			wantDst:   "192.168.10.23",
			wantDev:   "lo",
			wantSrc:   "192.168.10.23",
			reachable: true,
			summary:   "on-link dev lo src 192.168.10.23",
		},
		{
			// An interface is named, but the type keyword overrules it: this
			// route carries nothing, so Reachable must not be read off `dev`.
			name:     "unreachable type keyword",
			out:      "unreachable 192.0.2.99 dev lo src 192.168.10.23 uid 1000 \n    cache \n",
			wantType: "unreachable",
			wantDst:  "192.0.2.99",
			wantDev:  "lo",
			wantSrc:  "192.168.10.23",
			summary:  "dev lo src 192.168.10.23",
		},
		{
			name:     "prohibit type keyword",
			out:      "prohibit 192.0.2.99 dev lo src 192.168.10.23 uid 1000 \n    cache \n",
			wantType: "prohibit",
			wantDst:  "192.0.2.99",
			wantDev:  "lo",
			wantSrc:  "192.168.10.23",
			summary:  "dev lo src 192.168.10.23",
		},
		{
			// Parseable, but it says nothing about forwarding. The summary must
			// admit that instead of rendering an empty line.
			name:     "type keyword with no forwarding detail",
			out:      "unreachable 192.0.2.99\n",
			wantType: "unreachable",
			wantDst:  "192.0.2.99",
			summary:  "no forwarding detail reported",
		},
		{
			// `via inet6 fe80::1` names the family before the address, so a
			// parser reading the token after `via` finds "inet6" and not a
			// next hop.
			name:      "via inet6 next hop",
			out:       "192.0.2.10 via inet6 fe80::1 dev eth0 src 192.168.10.23 uid 1000 \n    cache \n",
			wantDst:   "192.0.2.10",
			wantVia:   "fe80::1",
			wantDev:   "eth0",
			wantSrc:   "192.168.10.23",
			reachable: true,
			summary:   "via fe80::1 dev eth0 src 192.168.10.23",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseRoute(tt.out)
			if err != nil {
				t.Fatalf("ParseRoute(%q) error = %v", tt.out, err)
			}
			if got.Type != tt.wantType {
				t.Errorf("Type = %q, want %q", got.Type, tt.wantType)
			}
			assertAddr(t, "Destination", tt.wantDst, got.Destination)
			assertAddr(t, "Via", tt.wantVia, got.Via)
			assertAddr(t, "Src", tt.wantSrc, got.Src)
			if got.Dev != tt.wantDev {
				t.Errorf("Dev = %q, want %q", got.Dev, tt.wantDev)
			}
			if got.MTU != tt.wantMTU {
				t.Errorf("MTU = %d, want %d", got.MTU, tt.wantMTU)
			}
			if got.Reachable() != tt.reachable {
				t.Errorf("Reachable() = %t, want %t", got.Reachable(), tt.reachable)
			}
			if summary := got.Summary(); summary != tt.summary {
				t.Errorf("Summary() = %q, want %q", summary, tt.summary)
			}
			if got.Raw == "" {
				t.Error("Raw is empty, so the finding would have nothing to cite")
			}
		})
	}
}

// Output that cannot be read is an error rather than an empty Route: an empty
// Route would read as a host with no route, which is a finding this output has
// not earned.
func TestParseRouteRejectsOutputItCannotRead(t *testing.T) {
	tests := []struct {
		name string
		out  string
	}{
		{name: "empty", out: ""},
		{name: "whitespace only", out: " \n\t \n"},
		{name: "rtnetlink error on stdout", out: "RTNETLINK answers: Network is unreachable\n"},
		{name: "argument rejected by ip", out: `Error: any valid prefix is expected rather than "nope".` + "\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseRoute(tt.out)
			if err == nil {
				t.Fatalf("ParseRoute(%q) = %+v, want an error", tt.out, got)
			}
			if got.Reachable() {
				t.Errorf("unreadable output produced a reachable route %+v", got)
			}
		})
	}
}

func TestRouteCheckClassifiesTheHostsAnswer(t *testing.T) {
	dst := mustAddr(t, "192.0.2.99")

	tests := []struct {
		name        string
		result      Result
		interpreted bool
		// wantText is checked against the Summary of an interpreted finding and
		// against the Reason of an abstention.
		wantText []string
		// wantCitation is the detail the finding must carry, when it is
		// interpreted.
		wantCitation string
	}{
		{
			// `ip route get` exits non-zero when the host has no route, and no
			// route is exactly the finding. Abstaining here would throw away the
			// answer.
			name: "no route is a finding, not a failure",
			result: Result{
				ExitCode: 2,
				Stderr:   "RTNETLINK answers: Network is unreachable\n",
			},
			interpreted:  true,
			wantText:     []string{"no route to 192.0.2.99", "Network is unreachable"},
			wantCitation: "Network is unreachable",
		},
		{
			// Non-zero and silent says nothing about the route, so it is a check
			// that did not run rather than a route that does not exist.
			name:     "non-zero exit with no output abstains",
			result:   Result{ExitCode: 2},
			wantText: []string{"not determined", "exited 2", "no output"},
		},
		{
			name: "output that cannot be parsed abstains",
			result: Result{
				Stdout: `Error: any valid prefix is expected rather than "nope".` + "\n",
			},
			wantText: []string{"not determined", "could not read the output of ip route get 192.0.2.99"},
		},
		{
			// A clean exit with nothing printed is the same problem: there is no
			// forwarding decision to report.
			name:     "clean exit with no output abstains",
			result:   Result{},
			wantText: []string{"not determined", "could not read the output of ip route get 192.0.2.99"},
		},
		{
			// A route the host itself calls unreachable is reported as that,
			// rather than as a route the host would use.
			name: "an unreachable route is reported as its type",
			result: Result{
				Stdout: "unreachable 192.0.2.99 dev lo src 192.168.10.23 uid 1000 \n    cache \n",
			},
			interpreted:  true,
			wantText:     []string{"reports 192.0.2.99 as unreachable"},
			wantCitation: "unreachable 192.0.2.99",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &stubRunner{results: map[Check]Result{CheckLocalRoute: tt.result}}

			got := RouteCheck(context.Background(), r, testInstance, dst)

			if got.Check != CheckLocalRoute {
				t.Errorf("Check = %q, want %q", got.Check, CheckLocalRoute)
			}
			if got.Interpreted() != tt.interpreted {
				t.Fatalf("Interpreted() = %t, want %t (%+v)", got.Interpreted(), tt.interpreted, got)
			}
			text := got.Reason
			if tt.interpreted {
				text = got.Summary
			}
			for _, want := range tt.wantText {
				if !strings.Contains(text, want) {
					t.Errorf("finding text = %q, want it to mention %q", text, want)
				}
			}
			if tt.interpreted {
				assertCited(t, got, "ip route get 192.0.2.99", tt.wantCitation)
			} else if len(got.Citations) != 0 {
				t.Errorf("abstention carries citations %+v, want none", got.Citations)
			}
		})
	}
}

// The recorded `ping -M do` outputs. Each is one run of the probe the path MTU
// check sends: two packets, fragmentation forbidden, a 1472-byte payload so the
// frame is a full 1500 bytes.
const (
	pingArrivesWhole = `PING 192.0.2.10 (192.0.2.10) 1472(1500) bytes of data.
1480 bytes from 192.0.2.10: icmp_seq=1 ttl=253 time=1.10 ms
1480 bytes from 192.0.2.10: icmp_seq=2 ttl=253 time=1.05 ms

--- 192.0.2.10 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1001ms
rtt min/avg/max/mdev = 1.052/1.076/1.101/0.024 ms
`

	pingFragNeeded = `PING 192.0.2.10 (192.0.2.10) 1472(1500) bytes of data.
From 192.168.10.1 icmp_seq=1 Frag needed and DF set (mtu = 1400)
From 192.168.10.1 icmp_seq=2 Frag needed and DF set (mtu = 1400)

--- 192.0.2.10 ping statistics ---
2 packets transmitted, 0 received, +2 errors, 100% packet loss, time 1001ms
`

	// The sending host refused the payload itself, so the fault is on this host's
	// egress interface rather than anywhere in the path.
	pingLocalRefusalStderr = `ping: local error: Message too long, mtu=1500
ping: local error: Message too long, mtu=1500
`

	pingLocalRefusalStdout = `PING 192.0.2.10 (192.0.2.10) 1472(1500) bytes of data.

--- 192.0.2.10 ping statistics ---
2 packets transmitted, 0 received, +2 errors, 100% packet loss, time 1002ms
`

	// A refusal that never reached the statistics line. The refusal is still the
	// answer.
	pingLocalRefusalOnly = `PING 192.0.2.10 (192.0.2.10) 1472(1500) bytes of data.
ping: local error: Message too long, mtu=1500
`

	// Total loss with no ICMP message at all, which is where the check has to
	// stop rather than guess.
	pingSilence = `PING 192.0.2.10 (192.0.2.10) 1472(1500) bytes of data.

--- 192.0.2.10 ping statistics ---
2 packets transmitted, 0 received, 100% packet loss, time 1001ms
`
)

func TestParsePingMTUReadsTheProbe(t *testing.T) {
	tests := []struct {
		name            string
		out             string
		wantPayload     int
		wantTransmitted int
		wantReceived    int
		wantMTU         int
		wantLocalError  string
	}{
		{
			name:            "a full-size payload arrives",
			out:             pingArrivesWhole,
			wantPayload:     1472,
			wantTransmitted: 2,
			wantReceived:    2,
		},
		{
			name:            "fragmentation needed names the path mtu",
			out:             pingFragNeeded,
			wantPayload:     1472,
			wantTransmitted: 2,
			wantMTU:         1400,
		},
		{
			// The mtu on a local error line is the sending interface's, not the
			// path's, and both are read off the same line.
			name:            "a local refusal with statistics",
			out:             pingLocalRefusalStdout + "\n" + pingLocalRefusalStderr,
			wantPayload:     1472,
			wantTransmitted: 2,
			wantMTU:         1500,
			wantLocalError:  "Message too long",
		},
		{
			name:           "a local refusal that never reached the statistics",
			out:            pingLocalRefusalOnly,
			wantPayload:    1472,
			wantMTU:        1500,
			wantLocalError: "Message too long",
		},
		{
			name:            "total loss with no icmp message",
			out:             pingSilence,
			wantPayload:     1472,
			wantTransmitted: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParsePingMTU(tt.out)
			if err != nil {
				t.Fatalf("ParsePingMTU error = %v", err)
			}
			if got.PayloadBytes != tt.wantPayload {
				t.Errorf("PayloadBytes = %d, want %d", got.PayloadBytes, tt.wantPayload)
			}
			if got.Transmitted != tt.wantTransmitted {
				t.Errorf("Transmitted = %d, want %d", got.Transmitted, tt.wantTransmitted)
			}
			if got.Received != tt.wantReceived {
				t.Errorf("Received = %d, want %d", got.Received, tt.wantReceived)
			}
			if got.ReportedMTU != tt.wantMTU {
				t.Errorf("ReportedMTU = %d, want %d", got.ReportedMTU, tt.wantMTU)
			}
			if got.LocalError != tt.wantLocalError {
				t.Errorf("LocalError = %q, want %q", got.LocalError, tt.wantLocalError)
			}
		})
	}
}

// A probe that cannot be counted has not shown anything, so it is an error rather
// than a probe that reported total loss.
func TestParsePingMTURejectsOutputWithNoStatistics(t *testing.T) {
	tests := []struct {
		name string
		out  string
	}{
		{name: "empty", out: ""},
		{name: "ping could not open a socket", out: "ping: socket: Operation not permitted\n"},
		{name: "header only", out: "PING 192.0.2.10 (192.0.2.10) 1472(1500) bytes of data.\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParsePingMTU(tt.out)
			if err == nil {
				t.Fatalf("ParsePingMTU(%q) = %+v, want an error", tt.out, got)
			}
		})
	}
}

func TestPathMTUCheckReportsWhatTheProbeShowed(t *testing.T) {
	dst := mustAddr(t, "192.0.2.10")

	tests := []struct {
		name        string
		result      Result
		interpreted bool
		wantText    []string
	}{
		{
			name:        "a full-size payload crosses the path",
			result:      Result{Stdout: pingArrivesWhole},
			interpreted: true,
			wantText:    []string{"1472-byte payload", "192.0.2.10", "unfragmented"},
		},
		{
			// The reported MTU is the finding: it explains a transfer that
			// stalls after a handshake every Layer permitted.
			name:        "a reported path mtu is named in the finding",
			result:      Result{ExitCode: 1, Stdout: pingFragNeeded},
			interpreted: true,
			wantText:    []string{"1472-byte payload", "path mtu is reported as 1400", "stalls"},
		},
		{
			// Both streams are read, because ping prints the refusal on stderr
			// and the counts on stdout.
			name: "a refusal by the sending host points at this host",
			result: Result{
				ExitCode: 1,
				Stdout:   pingLocalRefusalStdout,
				Stderr:   pingLocalRefusalStderr,
			},
			interpreted: true,
			wantText:    []string{"the host itself refused", "Message too long", "mtu 1500"},
		},
		{
			// Silence is equally consistent with ICMP being filtered, and
			// calling it an MTU fault would send the operator to the wrong
			// device.
			name:     "silence with no fragmentation-needed message abstains",
			result:   Result{ExitCode: 1, Stdout: pingSilence},
			wantText: []string{"not determined", "no fragmentation-needed message", "icmp being filtered"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &stubRunner{results: map[Check]Result{CheckPathMTU: tt.result}}

			got := PathMTUCheck(context.Background(), r, testInstance, dst, 0)

			if got.Check != CheckPathMTU {
				t.Errorf("Check = %q, want %q", got.Check, CheckPathMTU)
			}
			if got.Interpreted() != tt.interpreted {
				t.Fatalf("Interpreted() = %t, want %t (%+v)", got.Interpreted(), tt.interpreted, got)
			}
			text := got.Reason
			if tt.interpreted {
				text = got.Summary
			}
			for _, want := range tt.wantText {
				if !strings.Contains(text, want) {
					t.Errorf("finding text = %q, want it to mention %q", text, want)
				}
			}
			if tt.interpreted {
				assertCited(t, got, "ping -M do -s 1472 -c 2 192.0.2.10", "1472 bytes of payload")
			} else if len(got.Citations) != 0 {
				t.Errorf("abstention carries citations %+v, want none", got.Citations)
			}
		})
	}
}

// Neither supporting check is a Layer, and neither may acquire a verdict: a
// verdict is the power to block, and a path that carries small packets is not
// blocked. The absence is structural, so it is asserted structurally — a field
// added later would fail here rather than quietly gain that power.
func TestFindingCarriesNoLayerVerdict(t *testing.T) {
	typ := reflect.TypeOf(Finding{})
	for i := 0; i < typ.NumField(); i++ {
		switch name := typ.Field(i).Name; name {
		case "Layer", "Verdict":
			t.Errorf("Finding has a %s field, which would give a supporting check the power to block", name)
		}
	}
}

// assertCited holds a finding to the standard the model expects of evidence: the
// command that was run, and the output the finding rests on.
func assertCited(t *testing.T, got Finding, wantCommand, wantDetail string) {
	t.Helper()
	if len(got.Citations) == 0 {
		t.Fatalf("finding %+v has no citation", got)
	}
	c := got.Citations[0]
	if c.Kind != "command" {
		t.Errorf("citation kind = %q, want command", c.Kind)
	}
	if c.Identifier != wantCommand {
		t.Errorf("citation identifier = %q, want %q", c.Identifier, wantCommand)
	}
	if wantDetail != "" && !strings.Contains(c.Detail, wantDetail) {
		t.Errorf("citation detail = %q, want it to carry %q", c.Detail, wantDetail)
	}
}

// assertAddr compares an address field against its expected text, treating an
// empty expectation as "must be left invalid".
func assertAddr(t *testing.T, label, want string, got netip.Addr) {
	t.Helper()
	switch {
	case want == "":
		if got.IsValid() {
			t.Errorf("%s = %s, want no address", label, got)
		}
	case !got.IsValid():
		t.Errorf("%s is unset, want %s", label, want)
	case got.String() != want:
		t.Errorf("%s = %s, want %s", label, got, want)
	}
}
