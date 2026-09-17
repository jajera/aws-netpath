package flow

import (
	"net/netip"
	"testing"
)

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("ParseAddr(%q): %v", s, err)
	}
	return a
}

func TestParseProtocol(t *testing.T) {
	tests := []struct {
		in   string
		want Protocol
	}{
		{"tcp", ProtoTCP},
		{"TCP", ProtoTCP},
		{"6", ProtoTCP},
		{"udp", ProtoUDP},
		{"icmp", ProtoICMP},
		{"any", ProtoAny},
		{"-1", ProtoAny},
		{"", ProtoAny},
	}
	for _, tc := range tests {
		got, err := ParseProtocol(tc.in)
		if err != nil {
			t.Errorf("ParseProtocol(%q): %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ParseProtocol(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
	if _, err := ParseProtocol("sctp"); err == nil {
		t.Error("ParseProtocol(sctp) should have failed")
	}
}

// ICMP carries no ports, so a slice must ignore any port set handed to it.
func TestNewSliceWidensPortsForICMP(t *testing.T) {
	s := NewSlice(mustPrefixes(t, "any"), mustPrefixes(t, "any"), ProtoICMP, mustPorts(t, "443"))
	if !s.DstPorts.IsAll() {
		t.Errorf("ICMP slice ports = %s, want any", s.DstPorts)
	}
}

func TestSliceIntersect(t *testing.T) {
	base := NewSlice(
		mustPrefixes(t, "10.30.32.0/19"),
		mustPrefixes(t, "10.30.192.0/20"),
		ProtoTCP,
		AllPorts(),
	)

	t.Run("narrows to matching rule", func(t *testing.T) {
		got, ok := base.Intersect(
			mustPrefixes(t, "10.30.0.0/16"),
			mustPrefixes(t, "10.30.192.0/20"),
			ProtoTCP,
			mustPorts(t, "443"),
		)
		if !ok {
			t.Fatal("expected intersection")
		}
		if got.DstPorts.String() != "443" {
			t.Errorf("ports = %s, want 443", got.DstPorts)
		}
		if got.Src.String() != "10.30.32.0/19" {
			t.Errorf("src = %s, want 10.30.32.0/19", got.Src)
		}
	})

	t.Run("rejects mismatched protocol", func(t *testing.T) {
		if _, ok := base.Intersect(mustPrefixes(t, "any"), mustPrefixes(t, "any"), ProtoUDP, AllPorts()); ok {
			t.Error("tcp ∩ udp should not match")
		}
	})

	t.Run("any protocol adopts the concrete one", func(t *testing.T) {
		wide := NewSlice(mustPrefixes(t, "any"), mustPrefixes(t, "any"), ProtoAny, AllPorts())
		got, ok := wide.Intersect(mustPrefixes(t, "any"), mustPrefixes(t, "any"), ProtoTCP, mustPorts(t, "22"))
		if !ok {
			t.Fatal("expected intersection")
		}
		if got.Proto != ProtoTCP {
			t.Errorf("proto = %v, want tcp", got.Proto)
		}
	})

	t.Run("rejects disjoint addresses", func(t *testing.T) {
		if _, ok := base.Intersect(mustPrefixes(t, "192.168.0.0/16"), mustPrefixes(t, "any"), ProtoTCP, AllPorts()); ok {
			t.Error("disjoint sources should not match")
		}
	})
}

func TestSetUnionSkipsEmptySlices(t *testing.T) {
	empty := Slice{}
	real := NewSlice(mustPrefixes(t, "10.0.0.0/8"), mustPrefixes(t, "10.1.0.0/16"), ProtoTCP, mustPorts(t, "443"))

	s := NewSet(empty).Union(NewSet(real))
	if len(s.Slices) != 1 {
		t.Fatalf("got %d slices, want 1", len(s.Slices))
	}
	if s.IsEmpty() {
		t.Error("set with a real slice should not be empty")
	}
}
