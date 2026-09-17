package flow

import "testing"

func mustPrefixes(t *testing.T, s string) PrefixSet {
	t.Helper()
	ps, err := ParsePrefixSet(s)
	if err != nil {
		t.Fatalf("ParsePrefixSet(%q): %v", s, err)
	}
	return ps
}

func TestParsePrefixSet(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"any", "0.0.0.0/0"},
		{"10.0.0.0/8", "10.0.0.0/8"},
		{"10.0.0.1", "10.0.0.1/32"},
		{"10.0.0.5/8", "10.0.0.0/8"},             // host bits are masked off
		{"10.0.0.0/8,10.1.0.0/16", "10.0.0.0/8"}, // covered prefix dropped
		{"10.30.32.0/19,10.30.192.0/20", "10.30.32.0/19,10.30.192.0/20"},
	}
	for _, tc := range tests {
		got := mustPrefixes(t, tc.in).String()
		if got != tc.want {
			t.Errorf("ParsePrefixSet(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestPrefixSetIntersect(t *testing.T) {
	tests := []struct {
		a, b, want string
	}{
		{"any", "10.0.0.0/8", "10.0.0.0/8"},
		{"10.0.0.0/8", "10.1.0.0/16", "10.1.0.0/16"},
		{"10.0.0.0/8", "192.168.0.0/16", "none"},
		{"10.30.32.0/19", "10.30.32.0/19", "10.30.32.0/19"},
	}
	for _, tc := range tests {
		got := mustPrefixes(t, tc.a).Intersect(mustPrefixes(t, tc.b)).String()
		if got != tc.want {
			t.Errorf("%s ∩ %s = %s, want %s", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestPrefixSetSubtract(t *testing.T) {
	tests := []struct {
		a, b, want string
	}{
		{"10.0.0.0/8", "10.0.0.0/8", "none"},
		{"10.0.0.0/8", "192.168.0.0/16", "10.0.0.0/8"},
		{"10.0.0.0/8", "10.0.0.0/9", "10.128.0.0/9"},
		{"0.0.0.0/0", "0.0.0.0/1", "128.0.0.0/1"},
	}
	for _, tc := range tests {
		got := mustPrefixes(t, tc.a).Subtract(mustPrefixes(t, tc.b)).String()
		if got != tc.want {
			t.Errorf("%s - %s = %s, want %s", tc.a, tc.b, got, tc.want)
		}
	}
}

// Removing a /24 from a /8 must leave a set that excludes exactly that /24.
func TestPrefixSetSubtractPunchesHole(t *testing.T) {
	rest := mustPrefixes(t, "10.0.0.0/8").Subtract(mustPrefixes(t, "10.1.2.0/24"))

	for _, in := range []string{"10.0.0.1", "10.1.1.255", "10.1.3.0", "10.255.255.255"} {
		if !rest.ContainsAddr(mustAddr(t, in)) {
			t.Errorf("%s should remain after subtraction", in)
		}
	}
	for _, out := range []string{"10.1.2.0", "10.1.2.128", "10.1.2.255"} {
		if rest.ContainsAddr(mustAddr(t, out)) {
			t.Errorf("%s should have been removed", out)
		}
	}
	// A /8 minus a /24 leaves one prefix per bit of depth between them.
	if want := 24 - 8; len(rest.Prefixes()) != want {
		t.Errorf("got %d prefixes, want %d", len(rest.Prefixes()), want)
	}
}

func TestPrefixSetSubtractThenUnionRoundTrips(t *testing.T) {
	whole := mustPrefixes(t, "10.0.0.0/8")
	hole := mustPrefixes(t, "10.1.2.0/24")
	if got := whole.Subtract(hole).Union(hole); !got.Equal(whole) {
		t.Errorf("(a - b) ∪ b = %s, want %s", got, whole)
	}
}

// IPv4 and IPv6 prefixes must never interact.
func TestPrefixSetMixedFamilies(t *testing.T) {
	v4 := mustPrefixes(t, "10.0.0.0/8")
	v6 := mustPrefixes(t, "2001:db8::/32")

	if got := v4.Intersect(v6); !got.IsEmpty() {
		t.Errorf("v4 ∩ v6 = %s, want none", got)
	}
	if got := v4.Subtract(v6); !got.Equal(v4) {
		t.Errorf("v4 - v6 = %s, want %s", got, v4)
	}
	if got := len(v4.Union(v6).Prefixes()); got != 2 {
		t.Errorf("v4 ∪ v6 has %d prefixes, want 2", got)
	}
}
