package flow

import "testing"

func mustPorts(t *testing.T, s string) PortSet {
	t.Helper()
	ps, err := ParsePortSet(s)
	if err != nil {
		t.Fatalf("ParsePortSet(%q): %v", s, err)
	}
	return ps
}

func TestParsePortSet(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"any", "any"},
		{"", "any"},
		{"443", "443"},
		{"80-443", "80-443"},
		{"22,80,443", "22,80,443"},
		{"80,81", "80-81"},             // adjacent ranges coalesce
		{"100-200,150-250", "100-250"}, // overlapping ranges merge
		{"443,443", "443"},
	}
	for _, tc := range tests {
		got := mustPorts(t, tc.in).String()
		if got != tc.want {
			t.Errorf("ParsePortSet(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestParsePortSetErrors(t *testing.T) {
	for _, in := range []string{"70000", "443-80", "abc", "-"} {
		if _, err := ParsePortSet(in); err == nil {
			t.Errorf("ParsePortSet(%q) should have failed", in)
		}
	}
}

func TestPortSetIntersect(t *testing.T) {
	tests := []struct {
		a, b, want string
	}{
		{"any", "443", "443"},
		{"80-443", "100-200", "100-200"},
		{"22,80,443", "80-443", "80,443"},
		{"22", "443", "none"},
		{"1-100", "100-200", "100"},
	}
	for _, tc := range tests {
		got := mustPorts(t, tc.a).Intersect(mustPorts(t, tc.b)).String()
		if got != tc.want {
			t.Errorf("%s ∩ %s = %s, want %s", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestPortSetSubtract(t *testing.T) {
	tests := []struct {
		a, b, want string
	}{
		{"any", "443", "0-442,444-65535"},
		{"80-443", "100-200", "80-99,201-443"},
		{"22,80,443", "80", "22,443"},
		{"443", "443", "none"},
		{"443", "22", "443"},
		{"any", "any", "none"},
	}
	for _, tc := range tests {
		got := mustPorts(t, tc.a).Subtract(mustPorts(t, tc.b)).String()
		if got != tc.want {
			t.Errorf("%s - %s = %s, want %s", tc.a, tc.b, got, tc.want)
		}
	}
}

// Subtracting a set and then adding it back must reproduce the original.
func TestPortSetSubtractThenUnionRoundTrips(t *testing.T) {
	all := AllPorts()
	web := mustPorts(t, "80,443")
	if got := all.Subtract(web).Union(web); !got.Equal(all) {
		t.Errorf("(any - {80,443}) ∪ {80,443} = %s, want any", got)
	}
}

func TestPortSetCountAndContains(t *testing.T) {
	if n := AllPorts().Count(); n != 65536 {
		t.Errorf("AllPorts().Count() = %d, want 65536", n)
	}
	ps := mustPorts(t, "80-443")
	if ps.Count() != 364 {
		t.Errorf("Count() = %d, want 364", ps.Count())
	}
	if !ps.Contains(443) || ps.Contains(444) {
		t.Error("Contains boundary check failed")
	}
}

func TestParsePortSetColonRange(t *testing.T) {
	got := mustPorts(t, "49152:65535").String()
	if got != "49152-65535" {
		t.Errorf("got %q, want 49152-65535", got)
	}
}

// The high boundary is where a naive Hi+1 merge overflows uint16.
func TestPortSetUpperBoundary(t *testing.T) {
	ps := mustPorts(t, "65535")
	if got := AllPorts().Subtract(ps).String(); got != "0-65534" {
		t.Errorf("any - 65535 = %s, want 0-65534", got)
	}
	if got := mustPorts(t, "0-65534").Union(ps); !got.IsAll() {
		t.Errorf("0-65534 ∪ 65535 = %s, want any", got)
	}
}
