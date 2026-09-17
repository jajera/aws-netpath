package host

// The two supporting checks: which way the host would send the packet, and
// whether a full-size packet survives the trip.
//
// Neither is a Layer, and neither gets one. A host with an unexpected egress
// interface is not blocked — it is reachable by a route nobody meant to use, and
// whether that matters depends on the topology. A path that carries small packets
// and drops large ones is not blocked either: the connection establishes, every
// Layer permits it, and it stalls the moment a full segment is sent. Giving
// either a verdict would mean giving it the power to block, which it has not
// earned. They produce Findings instead, which the symptom classifier already
// treats as an extra check rather than a Layer.

import (
	"context"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"github.com/jajera/aws-netpath/internal/model"
)

// Checks decided from the host's own forwarding and MTU behaviour.
const (
	CheckLocalRoute Check = "local_route"
	CheckPathMTU    Check = "path_mtu"
)

var (
	localRouteTemplate = Template{
		Check: CheckLocalRoute,
		Argv:  []string{"ip", "route", "get", "{dst}"},
	}
	// pathMTUTemplate sends two packets with fragmentation forbidden, which is
	// what makes the result meaningful: a packet that arrives arrived whole.
	pathMTUTemplate = Template{
		Check: CheckPathMTU,
		Argv:  []string{"ping", "-M", "do", "-s", "{size}", "-c", "2", "{dst}"},
	}
)

// DefaultProbePayload is the ICMP payload that fills a 1500-byte frame: 1500
// less a 20-byte IPv4 header and an 8-byte ICMP header. A path that carries this
// carries a full-size TCP segment too, which is the case a stall is about.
const DefaultProbePayload = 1472

// Route is the forwarding decision the host reported for one destination.
type Route struct {
	Raw string `json:"raw"`
	// Type is the route type keyword when the host printed one: "local",
	// "unreachable", "prohibit", "broadcast". Empty means an ordinary unicast
	// route.
	Type        string     `json:"type,omitempty"`
	Destination netip.Addr `json:"destination,omitempty"`
	// Via is the next hop, invalid when the destination is on-link.
	Via netip.Addr `json:"via,omitempty"`
	Dev string     `json:"dev,omitempty"`
	// Src is the address the host would send from, which is the address the
	// far-end firewall will see and match its allowlist against.
	Src netip.Addr `json:"src,omitempty"`
	// MTU is the route's MTU when the host stated one, zero otherwise.
	MTU int `json:"mtu,omitempty"`
}

// Reachable reports whether the route would carry a packet.
func (r Route) Reachable() bool {
	switch r.Type {
	case "unreachable", "prohibit", "blackhole", "throw":
		return false
	default:
		return r.Dev != ""
	}
}

// Summary renders the forwarding decision in one line.
func (r Route) Summary() string {
	var parts []string
	if r.Via.IsValid() {
		parts = append(parts, "via "+r.Via.String())
	} else if r.Reachable() {
		parts = append(parts, "on-link")
	}
	if r.Dev != "" {
		parts = append(parts, "dev "+r.Dev)
	}
	if r.Src.IsValid() {
		parts = append(parts, "src "+r.Src.String())
	}
	if r.MTU > 0 {
		parts = append(parts, fmt.Sprintf("mtu %d", r.MTU))
	}
	if len(parts) == 0 {
		return "no forwarding detail reported"
	}
	return strings.Join(parts, " ")
}

// RouteCheck reports how the host would reach dst.
//
// It supports requirement 8.1 rather than deciding it: the egress interface and
// the source address the host would use are what make a far-end allowlist finding
// interpretable, because the address matched against that allowlist is the one
// this command reports as `src`.
func RouteCheck(ctx context.Context, r CommandRunner, instanceID string, dst netip.Addr) Finding {
	if !dst.IsValid() {
		return abstainFinding(CheckLocalRoute, fmt.Errorf("no destination address to look up a route for"))
	}

	res, err := run(ctx, r, instanceID, localRouteTemplate, map[string]string{"dst": dst.String()})
	if err != nil {
		return abstainFinding(CheckLocalRoute, err)
	}

	// A non-zero exit here is usually an answer rather than a failure: `ip route
	// get` exits non-zero with "Network is unreachable" when the host has no
	// route, and no route is exactly the finding.
	if res.ExitCode != 0 {
		detail := firstLine(res.Stderr)
		if detail == "" {
			return abstainFinding(CheckLocalRoute, errCommandFailed(res))
		}
		return Finding{
			Check:     CheckLocalRoute,
			Summary:   fmt.Sprintf("the host has no route to %s: %s", dst, detail),
			Citations: []model.Citation{res.Command.Citation(detail)},
		}
	}

	route, err := ParseRoute(res.Stdout)
	if err != nil {
		return abstainFinding(CheckLocalRoute, errUnreadableOutput(res.Command, err))
	}
	summary := fmt.Sprintf("the host reaches %s %s", dst, route.Summary())
	if !route.Reachable() {
		summary = fmt.Sprintf("the host reports %s as %s", dst, route.Type)
	}
	return Finding{
		Check:     CheckLocalRoute,
		Summary:   summary,
		Citations: []model.Citation{res.Command.Citation(strings.TrimSpace(route.Raw))},
	}
}

// routeTypes are the leading keywords `ip route get` may print before the
// destination.
var routeTypes = map[string]bool{
	"local": true, "unicast": true, "broadcast": true, "multicast": true,
	"anycast": true, "unreachable": true, "prohibit": true, "blackhole": true,
	"throw": true,
}

// ParseRoute reads `ip route get` output.
//
// The continuation lines are folded into the same token stream rather than
// discarded, because the route's MTU is printed there — and the MTU is the one
// attribute of this output that can explain a failure on its own.
func ParseRoute(out string) (Route, error) {
	text := strings.TrimSpace(out)
	if text == "" {
		return Route{}, fmt.Errorf("no route output")
	}
	fields := strings.Fields(text)

	route := Route{Raw: text}
	i := 0
	if routeTypes[fields[0]] {
		route.Type = fields[0]
		i++
	}
	if i < len(fields) {
		if addr, err := netip.ParseAddr(fields[i]); err == nil {
			route.Destination = addr
			i++
		}
	}
	if !route.Destination.IsValid() && route.Type == "" {
		return Route{}, fmt.Errorf("unrecognised route output %q", firstLine(text))
	}

	for ; i < len(fields); i++ {
		switch fields[i] {
		case "via":
			// `via inet6 fe80::1` names the family before the address.
			next := i + 1
			if next < len(fields) && (fields[next] == "inet" || fields[next] == "inet6") {
				next++
			}
			if next < len(fields) {
				if addr, err := netip.ParseAddr(fields[next]); err == nil {
					route.Via = addr
				}
				i = next
			}
		case "dev":
			if i+1 < len(fields) {
				route.Dev = fields[i+1]
				i++
			}
		case "src":
			if i+1 < len(fields) {
				if addr, err := netip.ParseAddr(fields[i+1]); err == nil {
					route.Src = addr
				}
				i++
			}
		case "mtu":
			if i+1 < len(fields) {
				if mtu, err := strconv.Atoi(fields[i+1]); err == nil {
					route.MTU = mtu
				}
				i++
			}
		}
	}
	return route, nil
}

// MTUProbe is what one `ping -M do` run reported.
type MTUProbe struct {
	Raw string `json:"raw"`
	// PayloadBytes is the payload size the probe asked for.
	PayloadBytes int `json:"payload_bytes"`
	Transmitted  int `json:"transmitted"`
	Received     int `json:"received"`
	// ReportedMTU is the MTU named in a fragmentation-needed message, zero when
	// none was reported.
	ReportedMTU int `json:"reported_mtu,omitempty"`
	// LocalError is a refusal by the sending host itself, such as the payload
	// exceeding the egress interface MTU. It is a different fault from a drop in
	// the path and points at a different device.
	LocalError string `json:"local_error,omitempty"`
}

// PathMTUCheck reports whether a payload-sized packet crosses the path whole.
//
// A payload of zero uses DefaultProbePayload. Nothing here concludes that the
// path is healthy from a successful small packet, and nothing concludes an MTU
// fault from silence: total loss with no fragmentation-needed message is equally
// consistent with ICMP being filtered, which is common enough that reporting it
// as an MTU problem would send the operator to the wrong device.
func PathMTUCheck(ctx context.Context, r CommandRunner, instanceID string, dst netip.Addr, payload int) Finding {
	if !dst.IsValid() {
		return abstainFinding(CheckPathMTU, fmt.Errorf("no destination address to probe"))
	}
	if payload <= 0 {
		payload = DefaultProbePayload
	}

	res, err := run(ctx, r, instanceID, pathMTUTemplate, map[string]string{
		"size": strconv.Itoa(payload),
		"dst":  dst.String(),
	})
	if err != nil {
		return abstainFinding(CheckPathMTU, err)
	}

	// `ping` exits non-zero on packet loss, which is the interesting outcome
	// here, so the output is read whichever way it exited. Only output that
	// cannot be read at all is a reason to give up on it.
	probe, parseErr := ParsePingMTU(res.Stdout + "\n" + res.Stderr)
	if parseErr != nil {
		if res.ExitCode != 0 {
			return abstainFinding(CheckPathMTU, errCommandFailed(res))
		}
		return abstainFinding(CheckPathMTU, errUnreadableOutput(res.Command, parseErr))
	}
	if probe.PayloadBytes == 0 {
		probe.PayloadBytes = payload
	}

	switch {
	case probe.LocalError != "":
		summary := fmt.Sprintf("the host itself refused to send a %d-byte payload to %s unfragmented: %s",
			probe.PayloadBytes, dst, probe.LocalError)
		if probe.ReportedMTU > 0 {
			summary += fmt.Sprintf(" (mtu %d)", probe.ReportedMTU)
		}
		return Finding{Check: CheckPathMTU, Summary: summary, Citations: []model.Citation{res.Command.Citation(probe.evidence())}}
	case probe.Received > 0:
		return Finding{
			Check: CheckPathMTU,
			Summary: fmt.Sprintf("a %d-byte payload reaches %s unfragmented, so the path carries a full-size segment",
				probe.PayloadBytes, dst),
			Citations: []model.Citation{res.Command.Citation(probe.evidence())},
		}
	case probe.ReportedMTU > 0:
		return Finding{
			Check: CheckPathMTU,
			Summary: fmt.Sprintf("a %d-byte payload to %s is dropped and the path mtu is reported as %d, which explains a transfer that stalls after the handshake",
				probe.PayloadBytes, dst, probe.ReportedMTU),
			Citations: []model.Citation{res.Command.Citation(probe.evidence())},
		}
	default:
		return abstainFinding(CheckPathMTU, fmt.Errorf(
			"no reply to a %d-byte payload to %s and no fragmentation-needed message, which is equally consistent with icmp being filtered",
			probe.PayloadBytes, dst))
	}
}

// evidence renders the probe as the citation detail: the counts and the reported
// MTU, which is what the finding rests on.
func (p MTUProbe) evidence() string {
	out := fmt.Sprintf("%d bytes of payload, %d transmitted, %d received",
		p.PayloadBytes, p.Transmitted, p.Received)
	if p.ReportedMTU > 0 {
		out += fmt.Sprintf(", mtu reported as %d", p.ReportedMTU)
	}
	if p.LocalError != "" {
		out += ", local error: " + p.LocalError
	}
	return out
}

var (
	// pingHeaderPattern reads the payload size out of "PING host (addr) 1472(1500) bytes of data."
	pingHeaderPattern = regexp.MustCompile(`^PING\s+\S+.*?\s(\d+)\(\d+\)\s+bytes of data`)
	// pingStatsPattern reads "2 packets transmitted, 0 received" and the variants
	// that add "packets" or "+1 errors".
	pingStatsPattern = regexp.MustCompile(`(\d+)\s+packets transmitted,\s+(\d+)(?:\s+packets)?\s+received`)
	// pingMTUPattern reads the MTU out of "Frag needed and DF set (mtu = 1400)"
	// or "local error: Message too long, mtu=1500".
	pingMTUPattern = regexp.MustCompile(`mtu\s*=\s*(\d+)`)
	// pingLocalErrorPattern reads a refusal by the sending host.
	pingLocalErrorPattern = regexp.MustCompile(`local error:\s*([^,\n]+)`)
)

// ParsePingMTU reads `ping -M do` output. Output with neither a statistics line
// nor a local error is unreadable rather than negative: a probe that cannot be
// counted has not shown anything.
func ParsePingMTU(out string) (MTUProbe, error) {
	probe := MTUProbe{Raw: strings.TrimSpace(out)}
	if probe.Raw == "" {
		return MTUProbe{}, fmt.Errorf("no ping output")
	}

	for _, line := range strings.Split(out, "\n") {
		text := strings.TrimSpace(line)
		if text == "" {
			continue
		}
		if m := pingHeaderPattern.FindStringSubmatch(text); m != nil {
			probe.PayloadBytes, _ = strconv.Atoi(m[1])
		}
		if m := pingLocalErrorPattern.FindStringSubmatch(text); m != nil && probe.LocalError == "" {
			probe.LocalError = strings.TrimSpace(m[1])
		}
		if m := pingMTUPattern.FindStringSubmatch(text); m != nil && probe.ReportedMTU == 0 {
			probe.ReportedMTU, _ = strconv.Atoi(m[1])
		}
	}

	stats := pingStatsPattern.FindStringSubmatch(out)
	if stats == nil {
		if probe.LocalError != "" {
			// A host that refused to send never reached the statistics line, and
			// the refusal is itself the answer.
			return probe, nil
		}
		return MTUProbe{}, fmt.Errorf("no ping statistics in %q", firstLine(out))
	}
	probe.Transmitted, _ = strconv.Atoi(stats[1])
	probe.Received, _ = strconv.Atoi(stats[2])
	return probe, nil
}
