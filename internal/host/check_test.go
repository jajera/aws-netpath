package host

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/jajera/aws-netpath/internal/flow"
	"github.com/jajera/aws-netpath/internal/model"
)

// stubRunner replays recorded command output, keyed by the Check the command
// serves. It stands in for the transport so a check's parsing and judgement can
// be exercised against the text a host actually prints.
type stubRunner struct {
	results map[Check]Result
	errs    map[Check]error
	ran     []Command
}

func (s *stubRunner) Run(_ context.Context, _ string, cmd Command) (Result, error) {
	s.ran = append(s.ran, cmd)
	if err := s.errs[cmd.Check]; err != nil {
		return Result{Command: cmd}, err
	}
	res := s.results[cmd.Check]
	res.Command = cmd
	return res, nil
}

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	addr, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return addr
}

// assertEmittable holds every result these checks produce to the model's own
// standard: a decision needs a Citation and an Abstention needs a reason.
func assertEmittable(t *testing.T, got model.LayerResult) {
	t.Helper()
	if err := got.Validate(); err != nil {
		t.Fatalf("result is not emittable: %v", err)
	}
}

const ssListening = `State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process
LISTEN 0      128          0.0.0.0:22         0.0.0.0:*     users:(("sshd",pid=1234,fd=3))
LISTEN 0      100        127.0.0.1:25         0.0.0.0:*     users:(("master",pid=1500,fd=13))
`

// Requirement 8.1: a listener covering the destination port clears the Layer.
func TestListenerCheckPassesWhenAProcessListens(t *testing.T) {
	r := &stubRunner{results: map[Check]Result{CheckListener: {Stdout: ssListening}}}

	got := ListenerCheck(context.Background(), r, testInstance, ListenerRequest{
		Destination: mustAddr(t, "192.0.2.10"),
		Protocol:    flow.ProtoTCP,
		Port:        22,
	})

	assertEmittable(t, got)
	if got.Verdict != model.VerdictPass {
		t.Fatalf("verdict = %s, want pass (%+v)", got.Verdict, got)
	}
	if len(r.ran) != 1 || r.ran[0].Line() != "ss -tlnp" {
		t.Errorf("commands run = %v, want [ss -tlnp]", r.ran)
	}
}

// Requirement 8.5: no process on the destination port is BLOCKED, citing the
// listener output. Port 25 is bound to loopback here, which is the near miss the
// citation has to name.
func TestListenerCheckBlocksWhenTheListenerIsBoundElsewhere(t *testing.T) {
	r := &stubRunner{results: map[Check]Result{CheckListener: {Stdout: ssListening}}}

	got := ListenerCheck(context.Background(), r, testInstance, ListenerRequest{
		Destination: mustAddr(t, "192.0.2.10"),
		Protocol:    flow.ProtoTCP,
		Port:        25,
	})

	assertEmittable(t, got)
	if got.Verdict != model.VerdictBlocked {
		t.Fatalf("verdict = %s, want blocked (%+v)", got.Verdict, got)
	}
	if !strings.Contains(got.Citations[0].Detail, "127.0.0.1:25") {
		t.Errorf("citation = %q, want the loopback bind cited", got.Citations[0].Detail)
	}
}

// Requirement 8.3, and the incident the tool exists for: an entry of
// 198.51.100.128/26 covers a source inside it. String equality would not see it.
func TestFirewallCheckMatchesTheSourceByContainment(t *testing.T) {
	r := &stubRunner{results: map[Check]Result{
		CheckFirewalldRichRules: {Stdout: `rule family="ipv4" source address="198.51.100.128/26" port port="22" protocol="tcp" accept` + "\n"},
	}}

	got := FirewallCheck(context.Background(), r, testInstance, FirewallRequest{
		Source:   mustAddr(t, "198.51.100.150"),
		Protocol: flow.ProtoTCP,
		Port:     22,
	})

	assertEmittable(t, got)
	if got.Verdict != model.VerdictPass {
		t.Fatalf("verdict = %s, want pass (%+v)", got.Verdict, got)
	}
	// The services command is not needed once a rich rule admits the source.
	if len(r.ran) != 1 {
		t.Errorf("commands run = %v, want the rich rule list only", r.ran)
	}
}

// Requirement 8.4: a source no entry covers is BLOCKED with the entries found
// cited, and requirement 8.2: the zone's named services are consulted before
// concluding that, because a service allowance is invisible in the rich rules.
func TestFirewallCheckBlocksAndCitesTheEntriesFound(t *testing.T) {
	r := &stubRunner{results: map[Check]Result{
		CheckFirewalldRichRules: {Stdout: `rule family="ipv4" source address="198.51.100.128/26" port port="22" protocol="tcp" accept` + "\n"},
		CheckFirewalldServices:  {Stdout: "dhcpv6-client https\n"},
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
	if len(r.ran) != 2 {
		t.Fatalf("commands run = %v, want the rich rules and the services", r.ran)
	}
	var citedEntry bool
	for _, c := range got.Citations {
		if strings.Contains(c.Detail, "198.51.100.128/26") {
			citedEntry = true
		}
	}
	if !citedEntry {
		t.Errorf("citations = %+v, want the allowlist entry that nearly covered the source", got.Citations)
	}
}

// A named service can allow the port on its own, so the rich rules alone must
// never be read as the whole allowlist.
func TestFirewallCheckPassesOnAZoneService(t *testing.T) {
	r := &stubRunner{results: map[Check]Result{
		CheckFirewalldRichRules: {Stdout: "\n"},
		CheckFirewalldServices:  {Stdout: "dhcpv6-client ssh\n"},
	}}

	got := FirewallCheck(context.Background(), r, testInstance, FirewallRequest{
		Source:   mustAddr(t, "192.0.2.10"),
		Protocol: flow.ProtoTCP,
		Port:     22,
	})

	assertEmittable(t, got)
	if got.Verdict != model.VerdictPass {
		t.Fatalf("verdict = %s, want pass (%+v)", got.Verdict, got)
	}
}

// Requirement 8.6 at the level of one check: firewalld not running leaves the
// Layer unverified, never permitted.
func TestFirewallCheckAbstainsWhenFirewalldIsNotRunning(t *testing.T) {
	r := &stubRunner{results: map[Check]Result{
		CheckFirewalldRichRules: {ExitCode: 252, Stderr: "FirewallD is not running\n"},
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
	if !strings.Contains(got.Reason, "FirewallD is not running") {
		t.Errorf("reason = %q, want the host's own explanation", got.Reason)
	}
}

// The supporting checks report what they found and carry a Citation, without a
// Layer or a verdict of their own.
func TestSupportingChecksReportFindings(t *testing.T) {
	r := &stubRunner{results: map[Check]Result{
		CheckLocalRoute: {Stdout: "192.0.2.10 via 10.0.1.1 dev eth0 src 10.0.1.23 uid 1000\n    cache\n"},
		CheckPathMTU: {ExitCode: 1, Stdout: `PING 192.0.2.10 (192.0.2.10) 1472(1500) bytes of data.
From 10.0.1.1 icmp_seq=1 Frag needed and DF set (mtu = 1400)

--- 192.0.2.10 ping statistics ---
2 packets transmitted, 0 received, 100% packet loss, time 1001ms
`},
	}}
	dst := mustAddr(t, "192.0.2.10")

	route := RouteCheck(context.Background(), r, testInstance, dst)
	if !route.Interpreted() {
		t.Fatalf("route finding = %+v, want an interpreted finding", route)
	}
	if !strings.Contains(route.Summary, "dev eth0") || !strings.Contains(route.Summary, "src 10.0.1.23") {
		t.Errorf("route summary = %q, want the egress interface and source address", route.Summary)
	}
	if len(route.Citations) == 0 {
		t.Error("route finding has no citation")
	}

	mtu := PathMTUCheck(context.Background(), r, testInstance, dst, 0)
	if !mtu.Interpreted() {
		t.Fatalf("path mtu finding = %+v, want an interpreted finding", mtu)
	}
	if !strings.Contains(mtu.Summary, "1400") {
		t.Errorf("path mtu summary = %q, want the reported path mtu", mtu.Summary)
	}
	if len(mtu.Citations) == 0 {
		t.Error("path mtu finding has no citation")
	}
}
