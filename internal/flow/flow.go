// Package flow provides the symbolic algebra aws-netpath uses to reason about
// traffic. Rather than testing one 5-tuple at a time, the engine propagates
// sets of flows through the network model, narrowing them at each policy point.
// What survives to the destination is exactly the set of permitted traffic.
package flow

import (
	"fmt"
	"strings"
)

// Protocol identifies an IP protocol by its assigned number.
type Protocol uint8

const (
	ProtoICMP Protocol = 1
	ProtoTCP  Protocol = 6
	ProtoUDP  Protocol = 17
	// ProtoAny matches every protocol. AWS spells this "-1" in several APIs.
	ProtoAny Protocol = 255
)

// HasPorts reports whether the protocol carries transport ports. Port sets are
// meaningless for ICMP, so the engine leaves them wide open there.
func (p Protocol) HasPorts() bool { return p == ProtoTCP || p == ProtoUDP }

func (p Protocol) String() string {
	switch p {
	case ProtoICMP:
		return "icmp"
	case ProtoTCP:
		return "tcp"
	case ProtoUDP:
		return "udp"
	case ProtoAny:
		return "any"
	default:
		return fmt.Sprintf("proto/%d", uint8(p))
	}
}

// ParseProtocol reads "tcp", "udp", "icmp", "any", "-1", or a protocol number.
func ParseProtocol(s string) (Protocol, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "tcp", "6":
		return ProtoTCP, nil
	case "udp", "17":
		return ProtoUDP, nil
	case "icmp", "1":
		return ProtoICMP, nil
	case "any", "all", "-1", "ip", "":
		return ProtoAny, nil
	default:
		return 0, fmt.Errorf("unsupported protocol %q", s)
	}
}

// Slice is a set of flows sharing one protocol: every combination of a source
// address, a destination address, and a destination port drawn from its sets.
type Slice struct {
	Src      PrefixSet `json:"src"`
	Dst      PrefixSet `json:"dst"`
	Proto    Protocol  `json:"proto"`
	DstPorts PortSet   `json:"dst_ports"`
}

// NewSlice builds a slice, widening ports for protocols that have none.
func NewSlice(src, dst PrefixSet, proto Protocol, ports PortSet) Slice {
	if !proto.HasPorts() {
		ports = AllPorts()
	}
	return Slice{Src: src, Dst: dst, Proto: proto, DstPorts: ports}
}

// IsEmpty reports whether the slice describes no traffic at all.
func (s Slice) IsEmpty() bool {
	return s.Src.IsEmpty() || s.Dst.IsEmpty() || s.DstPorts.IsEmpty()
}

// Intersect narrows a slice against a rule expressed as prefix and port sets.
// Protocols must be compatible; ProtoAny matches anything.
func (s Slice) Intersect(src, dst PrefixSet, proto Protocol, ports PortSet) (Slice, bool) {
	p, ok := intersectProto(s.Proto, proto)
	if !ok {
		return Slice{}, false
	}

	out := Slice{
		Src:   s.Src.Intersect(src),
		Dst:   s.Dst.Intersect(dst),
		Proto: p,
	}
	if p.HasPorts() {
		out.DstPorts = s.DstPorts.Intersect(ports)
	} else {
		out.DstPorts = AllPorts()
	}

	if out.IsEmpty() {
		return Slice{}, false
	}
	return out, true
}

// intersectProto resolves two protocol constraints into one.
func intersectProto(a, b Protocol) (Protocol, bool) {
	switch {
	case a == b:
		return a, true
	case a == ProtoAny:
		return b, true
	case b == ProtoAny:
		return a, true
	default:
		return 0, false
	}
}

func (s Slice) String() string {
	if s.Proto.HasPorts() {
		return fmt.Sprintf("%s -> %s %s/%s", s.Src, s.Dst, s.Proto, s.DstPorts)
	}
	return fmt.Sprintf("%s -> %s %s", s.Src, s.Dst, s.Proto)
}

// Set is a disjunction of slices: the union of the traffic each one describes.
// The engine carries a Set along a path, splitting it whenever a policy permits
// part of the traffic and denies the rest.
type Set struct {
	Slices []Slice `json:"slices"`
}

// NewSet builds a set from a single slice, dropping it if empty.
func NewSet(s Slice) Set {
	if s.IsEmpty() {
		return Set{}
	}
	return Set{Slices: []Slice{s}}
}

// IsEmpty reports whether the set describes no traffic.
func (s Set) IsEmpty() bool {
	for _, sl := range s.Slices {
		if !sl.IsEmpty() {
			return false
		}
	}
	return true
}

// Add appends a slice, ignoring empty ones.
func (s Set) Add(sl Slice) Set {
	if sl.IsEmpty() {
		return s
	}
	return Set{Slices: append(s.Slices, sl)}
}

// Union merges two sets. Slices are kept separate rather than coalesced; the
// representation stays larger than strictly necessary but every slice remains
// traceable back to the rule that produced it, which matters for explanations.
func (s Set) Union(o Set) Set {
	out := Set{Slices: make([]Slice, 0, len(s.Slices)+len(o.Slices))}
	for _, sl := range s.Slices {
		out = out.Add(sl)
	}
	for _, sl := range o.Slices {
		out = out.Add(sl)
	}
	return out
}

func (s Set) String() string {
	if s.IsEmpty() {
		return "none"
	}
	parts := make([]string, 0, len(s.Slices))
	for _, sl := range s.Slices {
		parts = append(parts, sl.String())
	}
	return strings.Join(parts, "; ")
}
