package flow

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// PortRange is an inclusive range of transport ports.
type PortRange struct {
	Lo uint16 `json:"lo"`
	Hi uint16 `json:"hi"`
}

// PortSet is a set of ports held as sorted, disjoint, non-adjacent ranges.
// The zero value is the empty set.
type PortSet struct {
	ranges []PortRange
}

// AllPorts returns the set containing every port.
func AllPorts() PortSet {
	return PortSet{ranges: []PortRange{{Lo: 0, Hi: 65535}}}
}

// NoPorts returns the empty set.
func NoPorts() PortSet { return PortSet{} }

// SinglePort returns the set containing exactly p.
func SinglePort(p uint16) PortSet {
	return PortSet{ranges: []PortRange{{Lo: p, Hi: p}}}
}

// NewPortSet builds a normalized set from arbitrary, possibly overlapping ranges.
// Ranges with Lo > Hi are rejected.
func NewPortSet(ranges ...PortRange) (PortSet, error) {
	for _, r := range ranges {
		if r.Lo > r.Hi {
			return PortSet{}, fmt.Errorf("invalid port range %d-%d", r.Lo, r.Hi)
		}
	}
	return PortSet{ranges: normalizePorts(ranges)}, nil
}

// normalizePorts sorts ranges and coalesces those that overlap or touch.
func normalizePorts(in []PortRange) []PortRange {
	if len(in) == 0 {
		return nil
	}
	cp := make([]PortRange, len(in))
	copy(cp, in)
	sort.Slice(cp, func(i, j int) bool {
		if cp[i].Lo != cp[j].Lo {
			return cp[i].Lo < cp[j].Lo
		}
		return cp[i].Hi < cp[j].Hi
	})

	out := []PortRange{cp[0]}
	for _, r := range cp[1:] {
		last := &out[len(out)-1]
		// Adjacent ranges merge: 80-99 and 100-120 become 80-120. Guard the
		// uint16 wrap when last.Hi is 65535.
		if r.Lo <= last.Hi || (last.Hi < 65535 && r.Lo == last.Hi+1) {
			if r.Hi > last.Hi {
				last.Hi = r.Hi
			}
			continue
		}
		out = append(out, r)
	}
	return out
}

// IsEmpty reports whether the set contains no ports.
func (s PortSet) IsEmpty() bool { return len(s.ranges) == 0 }

// IsAll reports whether the set contains every port.
func (s PortSet) IsAll() bool {
	return len(s.ranges) == 1 && s.ranges[0].Lo == 0 && s.ranges[0].Hi == 65535
}

// Ranges returns a copy of the normalized ranges.
func (s PortSet) Ranges() []PortRange {
	out := make([]PortRange, len(s.ranges))
	copy(out, s.ranges)
	return out
}

// Contains reports whether p is a member of the set.
func (s PortSet) Contains(p uint16) bool {
	for _, r := range s.ranges {
		if p >= r.Lo && p <= r.Hi {
			return true
		}
	}
	return false
}

// Count returns the number of ports in the set.
func (s PortSet) Count() int {
	n := 0
	for _, r := range s.ranges {
		n += int(r.Hi) - int(r.Lo) + 1
	}
	return n
}

// Union returns the ports present in either set.
func (s PortSet) Union(o PortSet) PortSet {
	if s.IsEmpty() {
		return o
	}
	if o.IsEmpty() {
		return s
	}
	return PortSet{ranges: normalizePorts(append(s.Ranges(), o.ranges...))}
}

// Intersect returns the ports present in both sets.
func (s PortSet) Intersect(o PortSet) PortSet {
	if s.IsEmpty() || o.IsEmpty() {
		return PortSet{}
	}
	var out []PortRange
	i, j := 0, 0
	for i < len(s.ranges) && j < len(o.ranges) {
		a, b := s.ranges[i], o.ranges[j]
		lo, hi := a.Lo, a.Hi
		if b.Lo > lo {
			lo = b.Lo
		}
		if b.Hi < hi {
			hi = b.Hi
		}
		if lo <= hi {
			out = append(out, PortRange{Lo: lo, Hi: hi})
		}
		// Advance whichever range ends first.
		if a.Hi < b.Hi {
			i++
		} else {
			j++
		}
	}
	return PortSet{ranges: normalizePorts(out)}
}

// Subtract returns the ports in s that are not in o.
func (s PortSet) Subtract(o PortSet) PortSet {
	if s.IsEmpty() || o.IsEmpty() {
		return s
	}
	var out []PortRange
	for _, a := range s.ranges {
		cur := []PortRange{a}
		for _, b := range o.ranges {
			var next []PortRange
			for _, c := range cur {
				next = append(next, subtractRange(c, b)...)
			}
			cur = next
			if len(cur) == 0 {
				break
			}
		}
		out = append(out, cur...)
	}
	return PortSet{ranges: normalizePorts(out)}
}

// subtractRange removes b from a, yielding zero, one, or two ranges.
func subtractRange(a, b PortRange) []PortRange {
	if b.Hi < a.Lo || b.Lo > a.Hi {
		return []PortRange{a}
	}
	var out []PortRange
	if b.Lo > a.Lo {
		out = append(out, PortRange{Lo: a.Lo, Hi: b.Lo - 1})
	}
	if b.Hi < a.Hi {
		out = append(out, PortRange{Lo: b.Hi + 1, Hi: a.Hi})
	}
	return out
}

// Equal reports whether two sets contain the same ports.
func (s PortSet) Equal(o PortSet) bool {
	if len(s.ranges) != len(o.ranges) {
		return false
	}
	for i := range s.ranges {
		if s.ranges[i] != o.ranges[i] {
			return false
		}
	}
	return true
}

// String renders the set as "any", "443", "80-443", or a comma-separated mix.
func (s PortSet) String() string {
	if s.IsEmpty() {
		return "none"
	}
	if s.IsAll() {
		return "any"
	}
	parts := make([]string, 0, len(s.ranges))
	for _, r := range s.ranges {
		if r.Lo == r.Hi {
			parts = append(parts, strconv.Itoa(int(r.Lo)))
			continue
		}
		parts = append(parts, fmt.Sprintf("%d-%d", r.Lo, r.Hi))
	}
	return strings.Join(parts, ",")
}

// ParsePortSet reads "any", "443", "80-443", "49152:65535", or "22,80,443-445".
// AWS Network Firewall uses a colon for port ranges; aws-netpath accepts both colon
// and hyphen. An empty string is treated as "any".
func ParsePortSet(s string) (PortSet, error) {
	s = strings.TrimSpace(s)
	if s == "" || strings.EqualFold(s, "any") {
		return AllPorts(), nil
	}
	var ranges []PortRange
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		lo, hi, found := strings.Cut(part, "-")
		if !found {
			lo, hi, found = strings.Cut(part, ":")
		}
		loN, err := strconv.ParseUint(strings.TrimSpace(lo), 10, 16)
		if err != nil {
			return PortSet{}, fmt.Errorf("invalid port %q: %w", lo, err)
		}
		hiN := loN
		if found {
			hiN, err = strconv.ParseUint(strings.TrimSpace(hi), 10, 16)
			if err != nil {
				return PortSet{}, fmt.Errorf("invalid port %q: %w", hi, err)
			}
		}
		if loN > hiN {
			return PortSet{}, fmt.Errorf("invalid port range %s", part)
		}
		ranges = append(ranges, PortRange{Lo: uint16(loN), Hi: uint16(hiN)})
	}
	if len(ranges) == 0 {
		return PortSet{}, fmt.Errorf("no ports parsed from %q", s)
	}
	return PortSet{ranges: normalizePorts(ranges)}, nil
}
