package nfw

import (
	"testing"

	"github.com/jajera/aws-netpath/internal/model"
)

func TestCompileSuricataBracketCIDR(t *testing.T) {
	m, err := compile(model.StatefulRule{
		Action: "PASS", Protocol: "TCP", Direction: model.DirForward,
		Source: "[10.30.32.0/19]", Destination: "[10.30.192.0/20]",
		SourcePort: "ANY", DestinationPort: "443",
	})
	if err != nil {
		t.Fatal(err)
	}
	slice, ok := m.match(mustSlice(t, "10.30.32.0/19", "10.30.192.0/20", "tcp", "443"))
	if !ok {
		t.Fatal("expected bracket CIDRs to match")
	}
	if slice.IsEmpty() {
		t.Fatal("expected non-empty intersection")
	}
}

func TestCompileColonPortRange(t *testing.T) {
	m, err := compile(model.StatefulRule{
		Action: "PASS", Protocol: "TCP", Direction: model.DirForward,
		Source: "ANY", Destination: "ANY",
		SourcePort: "ANY", DestinationPort: "49152:65535",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !m.dstPorts.Contains(50000) {
		t.Error("expected ephemeral port in range")
	}
}

func TestCompileMalformedBracket(t *testing.T) {
	// AWS API occasionally returns a leading [ without closing ].
	m, err := compile(model.StatefulRule{
		Action: "PASS", Protocol: "TCP", Direction: model.DirForward,
		Source: "[10.29.3.32/28", Destination: "ANY",
		SourcePort: "ANY", DestinationPort: "443",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, ok := m.match(mustSlice(t, "10.29.3.32", "10.0.0.1", "tcp", "443"))
	if !ok {
		t.Error("expected malformed bracket CIDR to still parse")
	}
}
