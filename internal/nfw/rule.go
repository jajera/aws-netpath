package nfw

import (
	"fmt"
	"strings"

	"github.com/jajera/aws-netpath/internal/flow"
	"github.com/jajera/aws-netpath/internal/model"
)

// matcher is a stateful rule reduced to the sets it matches on.
type matcher struct {
	src      flow.PrefixSet
	dst      flow.PrefixSet
	proto    flow.Protocol
	srcPorts flow.PortSet
	dstPorts flow.PortSet
	// bidirectional is set for rules whose direction is ANY, which match the
	// header with source and destination swapped as well as as-written.
	bidirectional bool
}

// compile turns a rule's textual header into matchable sets.
func compile(r model.StatefulRule) (matcher, error) {
	src, err := parseEndpoint(r.Source)
	if err != nil {
		return matcher{}, fmt.Errorf("source: %w", err)
	}
	dst, err := parseEndpoint(r.Destination)
	if err != nil {
		return matcher{}, fmt.Errorf("destination: %w", err)
	}
	proto, err := parseRuleProtocol(r.Protocol)
	if err != nil {
		return matcher{}, err
	}
	srcPorts, err := flow.ParsePortSet(normalizeSuricataSet(r.SourcePort))
	if err != nil {
		return matcher{}, fmt.Errorf("source port: %w", err)
	}
	dstPorts, err := flow.ParsePortSet(normalizeSuricataSet(r.DestinationPort))
	if err != nil {
		return matcher{}, fmt.Errorf("destination port: %w", err)
	}

	return matcher{
		src:           src,
		dst:           dst,
		proto:         proto,
		srcPorts:      srcPorts,
		dstPorts:      dstPorts,
		bidirectional: r.Direction == model.DirAny,
	}, nil
}

// match intersects a flow slice with the rule.
//
// For a bidirectional rule the reversed orientation is also tried, pairing the
// rule's source with the flow's destination. aws-netpath tracks destination ports
// only, so in the reversed orientation the rule's source port is what
// constrains them.
func (m matcher) match(s flow.Slice) (flow.Slice, bool) {
	if got, ok := s.Intersect(m.src, m.dst, m.proto, m.dstPorts); ok {
		return got, true
	}
	if m.bidirectional {
		if got, ok := s.Intersect(m.dst, m.src, m.proto, m.srcPorts); ok {
			return got, true
		}
	}
	return flow.Slice{}, false
}

// parseEndpoint reads a rule header address. AWS Network Firewall returns
// Suricata-style values such as [10.0.0.0/8] or [10.0.0.0/8,10.1.0.0/16].
// Brackets are stripped before parsing; comma-separated lists become a union.
func parseEndpoint(s string) (flow.PrefixSet, error) {
	s = normalizeSuricataSet(s)
	if s == "" || strings.EqualFold(s, "any") {
		return flow.AllIPv4(), nil
	}
	return flow.ParsePrefixSet(s)
}

// normalizeSuricataSet strips Suricata list brackets from an address or port
// field. AWS sometimes omits the closing bracket in API responses.
func normalizeSuricataSet(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "[")
	s = strings.TrimSuffix(s, "]")
	return strings.TrimSpace(s)
}

// parseRuleProtocol reads a rule header protocol. Firewall rules spell the
// wildcard "IP" rather than "any".
func parseRuleProtocol(s string) (flow.Protocol, error) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "", "IP", "ANY":
		return flow.ProtoAny, nil
	default:
		return flow.ParseProtocol(s)
	}
}
