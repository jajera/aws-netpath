package flow

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// PrefixSet is a set of IP prefixes held in normalized form: masked, sorted,
// and with any prefix contained by another removed. The zero value is empty.
//
// A set holds prefixes of both address families; operations never mix them.
type PrefixSet struct {
	prefixes []netip.Prefix
}

// AllIPv4 returns 0.0.0.0/0.
func AllIPv4() PrefixSet {
	return PrefixSet{prefixes: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}}
}

// NoPrefixes returns the empty set.
func NoPrefixes() PrefixSet { return PrefixSet{} }

// NewPrefixSet normalizes the given prefixes into a set.
func NewPrefixSet(prefixes ...netip.Prefix) PrefixSet {
	return PrefixSet{prefixes: normalizePrefixes(prefixes)}
}

// ParsePrefixSet reads a comma-separated list of CIDRs or bare addresses.
// "any" and "0.0.0.0/0" both yield the full IPv4 space.
func ParsePrefixSet(s string) (PrefixSet, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return PrefixSet{}, fmt.Errorf("empty prefix")
	}
	if strings.EqualFold(s, "any") {
		return AllIPv4(), nil
	}
	var out []netip.Prefix
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		p, err := parseOnePrefix(part)
		if err != nil {
			return PrefixSet{}, err
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		return PrefixSet{}, fmt.Errorf("no prefixes parsed from %q", s)
	}
	return NewPrefixSet(out...), nil
}

// parseOnePrefix accepts either "10.0.0.0/8" or a bare "10.0.0.1" host address.
func parseOnePrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("invalid CIDR %q: %w", s, err)
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid address %q: %w", s, err)
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// normalizePrefixes reduces a list of prefixes to the unique minimal set that
// covers the same addresses: masked, sorted, with covered prefixes dropped and
// sibling prefixes merged back into their parent. Canonicalizing this far is
// what lets Equal compare coverage rather than representation, so that
// subtracting a prefix and adding it back yields the original set.
func normalizePrefixes(in []netip.Prefix) []netip.Prefix {
	if len(in) == 0 {
		return nil
	}
	cur := make([]netip.Prefix, 0, len(in))
	for _, p := range in {
		if p.IsValid() {
			cur = append(cur, p.Masked())
		}
	}
	if len(cur) == 0 {
		return nil
	}

	// Merging a pair may create a new sibling pair one level up, so repeat
	// until a pass changes nothing.
	for {
		sortPrefixes(cur)
		cur = dropCovered(cur)

		next, merged := mergeSiblings(cur)
		if !merged {
			return next
		}
		cur = next
	}
}

// sortPrefixes orders by family, then address, then prefix length. Shorter
// prefixes sort first at a given address so a covering prefix is always seen
// before the prefixes it covers.
func sortPrefixes(ps []netip.Prefix) {
	sort.Slice(ps, func(i, j int) bool {
		if a, b := ps[i].Addr().Is4(), ps[j].Addr().Is4(); a != b {
			return a
		}
		if c := ps[i].Addr().Compare(ps[j].Addr()); c != 0 {
			return c < 0
		}
		return ps[i].Bits() < ps[j].Bits()
	})
}

// dropCovered removes prefixes contained within an earlier, shorter prefix.
// It expects the input to be sorted by sortPrefixes.
func dropCovered(ps []netip.Prefix) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(ps))
	for _, p := range ps {
		covered := false
		for _, q := range out {
			if prefixCovers(q, p) {
				covered = true
				break
			}
		}
		if !covered {
			out = append(out, p)
		}
	}
	return out
}

// mergeSiblings replaces each adjacent pair of prefixes that together fill
// their parent with the parent itself. Sorted order puts siblings next to each
// other, so a single linear pass finds every pair.
func mergeSiblings(ps []netip.Prefix) ([]netip.Prefix, bool) {
	out := make([]netip.Prefix, 0, len(ps))
	merged := false
	for i := 0; i < len(ps); {
		if i+1 < len(ps) && areSiblings(ps[i], ps[i+1]) {
			out = append(out, parentOf(ps[i]))
			merged = true
			i += 2
			continue
		}
		out = append(out, ps[i])
		i++
	}
	return out, merged
}

// areSiblings reports whether a and b are the two halves of one parent prefix.
func areSiblings(a, b netip.Prefix) bool {
	if a == b || a.Bits() != b.Bits() || a.Bits() == 0 {
		return false
	}
	if a.Addr().Is4() != b.Addr().Is4() {
		return false
	}
	return parentOf(a) == parentOf(b)
}

// parentOf returns the prefix one bit shorter that contains p.
func parentOf(p netip.Prefix) netip.Prefix {
	return netip.PrefixFrom(p.Addr(), p.Bits()-1).Masked()
}

// prefixCovers reports whether outer fully contains inner.
func prefixCovers(outer, inner netip.Prefix) bool {
	if outer.Addr().Is4() != inner.Addr().Is4() {
		return false
	}
	return outer.Bits() <= inner.Bits() && outer.Contains(inner.Addr())
}

// IsEmpty reports whether the set contains no addresses.
func (s PrefixSet) IsEmpty() bool { return len(s.prefixes) == 0 }

// Prefixes returns a copy of the normalized prefixes.
func (s PrefixSet) Prefixes() []netip.Prefix {
	out := make([]netip.Prefix, len(s.prefixes))
	copy(out, s.prefixes)
	return out
}

// ContainsAddr reports whether a falls inside any prefix in the set.
func (s PrefixSet) ContainsAddr(a netip.Addr) bool {
	for _, p := range s.prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// Union returns the addresses present in either set.
func (s PrefixSet) Union(o PrefixSet) PrefixSet {
	if s.IsEmpty() {
		return o
	}
	if o.IsEmpty() {
		return s
	}
	return PrefixSet{prefixes: normalizePrefixes(append(s.Prefixes(), o.prefixes...))}
}

// Intersect returns the addresses present in both sets. Because prefixes are
// hierarchical, the intersection of two overlapping prefixes is the longer one.
func (s PrefixSet) Intersect(o PrefixSet) PrefixSet {
	if s.IsEmpty() || o.IsEmpty() {
		return PrefixSet{}
	}
	var out []netip.Prefix
	for _, a := range s.prefixes {
		for _, b := range o.prefixes {
			if prefixCovers(a, b) {
				out = append(out, b)
			} else if prefixCovers(b, a) {
				out = append(out, a)
			}
		}
	}
	return PrefixSet{prefixes: normalizePrefixes(out)}
}

// Subtract returns the addresses in s that are not in o.
func (s PrefixSet) Subtract(o PrefixSet) PrefixSet {
	if s.IsEmpty() || o.IsEmpty() {
		return s
	}
	cur := s.Prefixes()
	for _, b := range o.prefixes {
		var next []netip.Prefix
		for _, a := range cur {
			next = append(next, subtractPrefix(a, b)...)
		}
		cur = next
		if len(cur) == 0 {
			break
		}
	}
	return PrefixSet{prefixes: normalizePrefixes(cur)}
}

// subtractPrefix removes b from a by recursively splitting a into halves until
// the removed region aligns on a prefix boundary.
func subtractPrefix(a, b netip.Prefix) []netip.Prefix {
	if a.Addr().Is4() != b.Addr().Is4() {
		return []netip.Prefix{a}
	}
	if !a.Overlaps(b) {
		return []netip.Prefix{a}
	}
	if prefixCovers(b, a) {
		return nil
	}
	// b is strictly inside a, so split a and recurse into the half that holds b.
	left, right, ok := splitPrefix(a)
	if !ok {
		return nil
	}
	var out []netip.Prefix
	for _, half := range []netip.Prefix{left, right} {
		if half.Overlaps(b) {
			out = append(out, subtractPrefix(half, b)...)
			continue
		}
		out = append(out, half)
	}
	return out
}

// splitPrefix divides a prefix into its two child prefixes one bit longer.
// It reports false when the prefix is already a full-length host route.
func splitPrefix(p netip.Prefix) (netip.Prefix, netip.Prefix, bool) {
	bits := p.Bits()
	if bits >= p.Addr().BitLen() {
		return netip.Prefix{}, netip.Prefix{}, false
	}
	left := netip.PrefixFrom(p.Addr(), bits+1).Masked()

	raw := p.Addr().AsSlice()
	raw[bits/8] |= 1 << uint(7-bits%8)
	addr, ok := netip.AddrFromSlice(raw)
	if !ok {
		return netip.Prefix{}, netip.Prefix{}, false
	}
	right := netip.PrefixFrom(addr, bits+1).Masked()
	return left, right, true
}

// Equal reports whether two sets cover the same addresses.
func (s PrefixSet) Equal(o PrefixSet) bool {
	if len(s.prefixes) != len(o.prefixes) {
		return false
	}
	for i := range s.prefixes {
		if s.prefixes[i] != o.prefixes[i] {
			return false
		}
	}
	return true
}

// String renders the set as a comma-separated CIDR list.
func (s PrefixSet) String() string {
	if s.IsEmpty() {
		return "none"
	}
	parts := make([]string, 0, len(s.prefixes))
	for _, p := range s.prefixes {
		parts = append(parts, p.String())
	}
	return strings.Join(parts, ",")
}
