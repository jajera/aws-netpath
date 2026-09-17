package host

// The listener check: is anything actually accepting connections on the
// destination port.
//
// It is the cheapest question in the whole tool and the one most often skipped,
// because a cloud path that permits traffic looks like a working service until
// somebody checks. `connection-refused` with every Layer permitting is almost
// always this.
//
// The binding address matters as much as the port. A daemon listening on
// 127.0.0.1 is a listener by every definition except the one that counts: it
// will not answer the address the client dialled. So the check asks whether a
// socket covers the destination address, not merely whether the port appears.

import (
	"context"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"github.com/jajera/aws-netpath/internal/flow"
	"github.com/jajera/aws-netpath/internal/model"
)

// processNamePattern matches the quoted process name inside the
// users:(("sshd",pid=…,fd=…)) column `ss -p` prints.
var processNamePattern = regexp.MustCompile(`\(\("([^"]+)"`)

// CheckListener names the listening-socket check.
const CheckListener Check = "listener"

// listenerTemplate lists listening TCP sockets numerically, with the owning
// process. Numeric output is not cosmetic: a named port would have to be
// resolved against the host's services file to be compared with the destination
// port, and that is a second source of truth for no benefit.
var listenerTemplate = Template{Check: CheckListener, Argv: []string{"ss", "-tlnp"}}

// ListenerRequest is what the listener check is asked about: the address and
// port a client dialled.
type ListenerRequest struct {
	// Destination is the address the client connected to, which is what decides
	// whether a socket bound to one interface is relevant.
	Destination netip.Addr
	Protocol    flow.Protocol
	Port        uint16
}

// Listener is one listening socket read from `ss -tlnp`.
type Listener struct {
	// Local is the bound address. It is the unspecified address (0.0.0.0 or ::)
	// for a wildcard bind, and invalid when the socket was reported as "*",
	// which `ss` uses for a wildcard of unstated family.
	Local netip.Addr `json:"local,omitempty"`
	Port  uint16     `json:"port"`
	// Process is the owning process as `ss` reported it, empty when the probe
	// lacked the privilege to see it. It is evidence, never part of the
	// decision.
	Process string `json:"process,omitempty"`
	// Raw is the line as the host printed it, so a citation can quote the
	// listener output rather than a rendering of it.
	Raw string `json:"raw"`
}

// Covers reports whether the socket would accept a connection to dst on port.
func (l Listener) Covers(dst netip.Addr, port uint16) bool {
	return l.Port == port && l.coversAddr(dst)
}

// coversAddr resolves the three binding cases.
//
// The dual-stack case is the one worth stating: a socket on :: accepts mapped
// IPv4 connections on a host with the default net.ipv6.bindv6only of 0, so it is
// treated as covering both families. A socket on 0.0.0.0 covers IPv4 only. Being
// wrong in the other direction would report a listener as absent when it is
// there, which is a worse error than the reverse — the operator would go looking
// for a daemon that is already running.
func (l Listener) coversAddr(dst netip.Addr) bool {
	if !dst.IsValid() {
		return false
	}
	dst = dst.Unmap()
	switch {
	case !l.Local.IsValid():
		return true
	case l.Local.IsUnspecified():
		return l.Local.Is6() || dst.Is4()
	default:
		return l.Local.Unmap() == dst
	}
}

// String renders the socket as address:port with the owning process, which is
// the form a citation quotes.
func (l Listener) String() string {
	addr := "*"
	if l.Local.IsValid() {
		addr = l.Local.String()
		// Bracket IPv6 so the port stays distinguishable from the address, the
		// way `ss` prints it.
		if l.Local.Unmap().Is6() {
			addr = "[" + addr + "]"
		}
	}
	out := fmt.Sprintf("%s:%d", addr, l.Port)
	if l.Process != "" {
		out += " " + l.Process
	}
	return out
}

// ListenerCheck reports Layer HOST_LISTENER for req.
//
// Requirement 8.1 is the question and requirement 8.5 is the answer when nothing
// listens: BLOCKED, citing the listener output. Nothing here reports PASS on a
// command it could not run or output it could not read; those abstain, because a
// listener that could not be looked for is not a listener that is absent.
func ListenerCheck(ctx context.Context, r CommandRunner, instanceID string, req ListenerRequest) model.LayerResult {
	if err := req.validate(); err != nil {
		return Abstain(model.LayerHostListener, err)
	}

	res, err := run(ctx, r, instanceID, listenerTemplate, nil)
	if err != nil {
		return Abstain(model.LayerHostListener, err)
	}
	// `ss` exits non-zero only when it could not enumerate sockets at all, so
	// there is no output to read and no conclusion to draw.
	if res.ExitCode != 0 {
		return Abstain(model.LayerHostListener, errCommandFailed(res))
	}

	listeners, err := ParseListeners(res.Stdout)
	if err != nil {
		return Abstain(model.LayerHostListener, errUnreadableOutput(res.Command, err))
	}

	target := fmt.Sprintf("%s/%d", req.Protocol, req.Port)
	for _, l := range listeners {
		if l.Covers(req.Destination, req.Port) {
			detail := fmt.Sprintf("%s is listening on %s: %s", target, req.Destination, l.Raw)
			return pass(model.LayerHostListener, res.Command.Citation(detail))
		}
	}

	return blocked(model.LayerHostListener, res.Command.Citation(absentListenerDetail(target, req, listeners)))
}

// absentListenerDetail states what was found instead, which is the citable part
// of requirement 8.5. The near miss is called out on its own line of reasoning:
// a socket on the right port bound to the wrong address is a different fault
// from a daemon that is not running, and the operator's next step differs.
func absentListenerDetail(target string, req ListenerRequest, listeners []Listener) string {
	var nearMisses []string
	for _, l := range listeners {
		if l.Port == req.Port {
			nearMisses = append(nearMisses, l.String())
		}
	}
	if len(nearMisses) > 0 {
		return fmt.Sprintf("no process listening on %s at %s; %s is bound elsewhere: %s",
			target, req.Destination, target, truncateList(nearMisses, listenerCitationLimit))
	}

	if len(listeners) == 0 {
		return fmt.Sprintf("no process listening on %s at %s; no tcp listeners reported", target, req.Destination)
	}
	others := make([]string, 0, len(listeners))
	for _, l := range listeners {
		others = append(others, l.String())
	}
	return fmt.Sprintf("no process listening on %s at %s; listening: %s",
		target, req.Destination, truncateList(others, listenerCitationLimit))
}

// listenerCitationLimit caps how many sockets a citation quotes. A busy host can
// have dozens, and a citation nobody reads cites nothing.
const listenerCitationLimit = 8

func (req ListenerRequest) validate() error {
	if !req.Destination.IsValid() {
		return fmt.Errorf("listener check: no destination address to check a listener against")
	}
	if req.Port == 0 {
		return fmt.Errorf("listener check: no destination port")
	}
	// `ss -tlnp` reports TCP only. A UDP destination has no listening state to
	// report at all, so answering for it would mean answering a question this
	// command cannot be asked.
	if req.Protocol != flow.ProtoTCP {
		return fmt.Errorf("listener check: %s reports tcp listeners only, and the destination protocol is %s",
			listenerTemplate.Check, req.Protocol)
	}
	return nil
}

// ParseListeners reads the listening sockets out of `ss -tlnp` output.
//
// Strictness is the point. A row that cannot be read is an error rather than a
// row to skip, because skipping it would remove a listener from consideration and
// the check would report "nothing listening" on the strength of a line it did not
// understand. The caller turns that error into an Abstention.
func ParseListeners(out string) ([]Listener, error) {
	var listeners []Listener
	for i, line := range strings.Split(out, "\n") {
		text := strings.TrimSpace(line)
		if text == "" || isListenerHeader(text) {
			continue
		}
		l, listening, err := parseListenerRow(text)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", i+1, err)
		}
		if !listening {
			continue
		}
		listeners = append(listeners, l)
	}
	return listeners, nil
}

// listenerHeaderFirstFields are the first column of the header `ss` prints.
// Which one appears depends on whether the netid column is shown, which in turn
// depends on the iproute2 version.
var listenerHeaderFirstFields = map[string]bool{"State": true, "Netid": true}

func isListenerHeader(line string) bool {
	fields := strings.Fields(line)
	return len(fields) > 0 && listenerHeaderFirstFields[fields[0]]
}

// listenerNetids are the values of the optional leading netid column.
var listenerNetids = map[string]bool{"tcp": true, "tcp6": true, "v_str": true, "nl": true}

// parseListenerRow reads one row. listening is false for a row that parsed but
// is not a listening socket, which is a row to ignore rather than an error.
func parseListenerRow(line string) (l Listener, listening bool, err error) {
	fields := strings.Fields(line)
	if len(fields) > 0 && listenerNetids[strings.ToLower(fields[0])] {
		fields = fields[1:]
	}
	// State, Recv-Q, Send-Q, Local Address:Port, Peer Address:Port.
	if len(fields) < 5 {
		return Listener{}, false, fmt.Errorf("unrecognised ss row %q", line)
	}
	if !strings.EqualFold(fields[0], "LISTEN") {
		return Listener{}, false, nil
	}
	// The queue columns are the alignment check: if they are not numbers, the
	// columns are not where this parser thinks they are, and the local address
	// it is about to read is some other field.
	for _, queue := range fields[1:3] {
		if _, convErr := strconv.Atoi(queue); convErr != nil {
			return Listener{}, false, fmt.Errorf("unrecognised ss row %q: %q is not a queue length", line, queue)
		}
	}

	addr, port, err := parseListenAddress(fields[3])
	if err != nil {
		return Listener{}, false, fmt.Errorf("%w in ss row %q", err, line)
	}
	return Listener{
		Local:   addr,
		Port:    port,
		Process: parseListenerProcess(fields[5:]),
		Raw:     line,
	}, true, nil
}

// parseListenAddress splits the Local Address:Port column. An invalid returned
// address means a wildcard `ss` reported as "*".
func parseListenAddress(field string) (netip.Addr, uint16, error) {
	cut := strings.LastIndex(field, ":")
	if cut < 0 {
		return netip.Addr{}, 0, fmt.Errorf("no port in local address %q", field)
	}
	host, portText := field[:cut], field[cut+1:]

	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		return netip.Addr{}, 0, fmt.Errorf("unreadable port %q in local address %q", portText, field)
	}

	// An IPv6 address is bracketed, and either family may carry a %scope suffix
	// on a link-local bind.
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	if scope := strings.Index(host, "%"); scope >= 0 {
		host = host[:scope]
	}
	if host == "*" || host == "" {
		return netip.Addr{}, uint16(port), nil
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, 0, fmt.Errorf("unreadable address %q in local address %q", host, field)
	}
	return addr, uint16(port), nil
}

// parseListenerProcess pulls the process names out of the users:(("sshd",…))
// column, falling back to the raw column when its shape is unfamiliar. This is
// evidence for a human, so an unrecognised shape is passed through rather than
// rejected: it cannot change the verdict.
func parseListenerProcess(rest []string) string {
	joined := strings.TrimSpace(strings.Join(rest, " "))
	if joined == "" {
		return ""
	}
	names := processNamePattern.FindAllStringSubmatch(joined, -1)
	if len(names) == 0 {
		return joined
	}
	seen := make(map[string]bool, len(names))
	out := make([]string, 0, len(names))
	for _, match := range names {
		if name := match[1]; !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	return strings.Join(out, ",")
}
