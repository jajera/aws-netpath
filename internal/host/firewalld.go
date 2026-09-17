package host

// The host firewall check: does firewalld admit this source to this port.
//
// This is the check the whole tool was built around. A host provisioned from an
// older template carried a narrower allowlist than the current one, every cloud
// Layer permitted the traffic, and the entry that should have covered the source
// was compared as a string. `198.51.100.128/26` is not the string
// `198.51.100.150`, so the comparison said "absent" and the investigation went
// looking in the wrong place for two days. Requirement 8.3 exists because of
// that: matching is by network containment, and the containment lives in
// flow.PrefixSet rather than in a comparison written here.
//
// Two commands, not one. A rich rule can name a port, but a zone can also allow
// a named service, and the service allowance is invisible in the rich rule list.
// Concluding BLOCKED from the rich rules alone would be wrong on any host
// configured the ordinary way, so both are consulted before anything is
// concluded — and a service name whose ports this package cannot resolve
// abstains rather than being assumed not to cover the port.

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/jajera/aws-netpath/internal/flow"
	"github.com/jajera/aws-netpath/internal/model"
)

// Checks decided from firewalld's own view of the zone.
const (
	CheckFirewalldRichRules Check = "firewalld_rich_rules"
	CheckFirewalldServices  Check = "firewalld_services"
)

var (
	richRulesTemplate = Template{
		Check: CheckFirewalldRichRules,
		Argv:  []string{"firewall-cmd", "--zone={zone}", "--list-rich-rules"},
	}
	servicesTemplate = Template{
		Check: CheckFirewalldServices,
		Argv:  []string{"firewall-cmd", "--zone={zone}", "--list-services"},
	}
)

// DefaultZone is the zone consulted when the caller names none. It is stated in
// the command line every citation carries, so a wrong guess is visible in the
// output rather than buried in a default.
const DefaultZone = "public"

// FirewallRequest is what the host firewall is asked about.
type FirewallRequest struct {
	// Zone is the firewalld zone to read. Empty means DefaultZone.
	Zone string
	// Source is the address the connection comes from. It is a single address
	// rather than a set because a host firewall decides per packet, and the
	// containment question requirement 8.3 asks is "does an entry cover this
	// address".
	Source   netip.Addr
	Protocol flow.Protocol
	Port     uint16
}

func (req FirewallRequest) zone() string {
	if req.Zone == "" {
		return DefaultZone
	}
	return req.Zone
}

func (req FirewallRequest) validate() error {
	if !req.Source.IsValid() {
		return fmt.Errorf("host firewall check: no source address to match against the allowlist")
	}
	if req.Port == 0 {
		return fmt.Errorf("host firewall check: no destination port")
	}
	if !req.Protocol.HasPorts() {
		return fmt.Errorf("host firewall check: protocol %s carries no ports, so no port allowance can be matched", req.Protocol)
	}
	return nil
}

// FirewallCheck reports Layer HOST_FIREWALL for req.
//
// Requirements 8.2 through 8.4: the source is matched against the zone's rich
// rules and named services by containment, and a source no entry covers is
// BLOCKED with the entries that were found cited — because the entries are what
// the operator has to change, and an unexplained "blocked" sends them reading
// the whole zone.
func FirewallCheck(ctx context.Context, r CommandRunner, instanceID string, req FirewallRequest) model.LayerResult {
	if err := req.validate(); err != nil {
		return Abstain(model.LayerHostFirewall, err)
	}
	subs := map[string]string{"zone": req.zone()}

	richRes, err := run(ctx, r, instanceID, richRulesTemplate, subs)
	if err != nil {
		return Abstain(model.LayerHostFirewall, err)
	}
	// firewalld not running, firewall-cmd absent, or the probe unauthorised all
	// land here. None of them means the port is open.
	if richRes.ExitCode != 0 {
		return Abstain(model.LayerHostFirewall, errCommandFailed(richRes))
	}
	rules, err := ParseRichRules(richRes.Stdout)
	if err != nil {
		return Abstain(model.LayerHostFirewall, errUnreadableOutput(richRes.Command, err))
	}

	if decided, result := evaluateRichRules(rules, req, richRes.Command); decided {
		return result
	}

	servicesRes, err := run(ctx, r, instanceID, servicesTemplate, subs)
	if err != nil {
		return Abstain(model.LayerHostFirewall, err)
	}
	if servicesRes.ExitCode != 0 {
		return Abstain(model.LayerHostFirewall, errCommandFailed(servicesRes))
	}
	services := ParseServices(servicesRes.Stdout)

	if allowed, name := servicesAllow(services, req); allowed {
		detail := fmt.Sprintf("zone %s allows service %s, which covers %s/%d for any source in the zone",
			req.zone(), name, req.Protocol, req.Port)
		return pass(model.LayerHostFirewall, servicesRes.Command.Citation(detail))
	}
	// A service whose ports are unknown here could be the one that opens the
	// port, so the zone cannot be declared closed on the strength of a name this
	// package does not recognise.
	if unknown := unknownServices(services); len(unknown) > 0 {
		return Abstain(model.LayerHostFirewall, fmt.Errorf(
			"zone %s allows service %s, whose ports are not known to aws-netpath, so %s/%d cannot be ruled out",
			req.zone(), strings.Join(unknown, ", "), req.Protocol, req.Port))
	}

	return blocked(model.LayerHostFirewall, blockedCitations(req, rules, services, richRes.Command, servicesRes.Command)...)
}

// evaluateRichRules applies the zone's rich rules to req. decided is false when
// no rule governs the traffic, which sends the caller on to the zone's services
// rather than to a conclusion.
func evaluateRichRules(rules []RichRule, req FirewallRequest, cmd Command) (decided bool, result model.LayerResult) {
	for _, rule := range sortRichRules(rules) {
		match, err := rule.matches(req)
		if err != nil {
			// The rule governs traffic this package cannot evaluate. It might be
			// the rule that decides, so nothing later may be trusted to decide
			// instead.
			return true, Abstain(model.LayerHostFirewall, fmt.Errorf("%s: %w", cmd.Line(), err))
		}
		if !match {
			continue
		}
		switch rule.Action {
		case ActionAccept:
			detail := fmt.Sprintf("%s covers %s for %s/%d: %s",
				rule.sourceDescription(), req.Source, req.Protocol, req.Port, rule.Raw)
			return true, pass(model.LayerHostFirewall, cmd.Citation(detail))
		case ActionReject, ActionDrop:
			detail := fmt.Sprintf("%s %s for %s/%d: %s",
				rule.Action, req.Source, req.Protocol, req.Port, rule.Raw)
			return true, blocked(model.LayerHostFirewall, cmd.Citation(detail))
		}
	}
	return false, model.LayerResult{}
}

// sortRichRules orders rules the way firewalld's chains do: by rich rule
// priority ascending, and at equal priority a denying rule before an accepting
// one, because firewalld puts default-priority denies in the zone's deny chain
// which runs before its allow chain. Two rules of the same priority matching the
// same traffic with opposite actions is a misconfiguration either way; resolving
// it towards the deny is the reading that cannot report a closed port as open.
func sortRichRules(rules []RichRule) []RichRule {
	out := make([]RichRule, len(rules))
	copy(out, rules)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Priority != out[j].Priority {
			return out[i].Priority < out[j].Priority
		}
		return actionRank(out[i].Action) < actionRank(out[j].Action)
	})
	return out
}

func actionRank(a Action) int {
	switch a {
	case ActionReject, ActionDrop:
		return 0
	default:
		return 1
	}
}

// blockedCitations is the evidence for requirement 8.4: the allowlist entries
// that were found, so the operator can see the entry that nearly covered the
// source. In the motivating incident this is the citation that would have ended
// the investigation on the first day.
func blockedCitations(req FirewallRequest, rules []RichRule, services []string, richCmd, servicesCmd Command) []model.Citation {
	target := fmt.Sprintf("%s/%d", req.Protocol, req.Port)

	var forPort, others []string
	for _, rule := range rules {
		if rule.Action == ActionAccept && rule.governsPort(req) {
			forPort = append(forPort, rule.Raw)
			continue
		}
		others = append(others, rule.Raw)
	}

	citations := []model.Citation{richCmd.Citation(fmt.Sprintf(
		"no rich rule admits %s to %s", req.Source, target))}
	switch {
	case len(forPort) > 0:
		citations = append(citations, richCmd.Citation(fmt.Sprintf(
			"allowlist entries for %s, none containing %s: %s",
			target, req.Source, truncateList(forPort, richRuleCitationLimit))))
	case len(others) > 0:
		citations = append(citations, richCmd.Citation(fmt.Sprintf(
			"no allowlist entry names %s; rich rules found: %s",
			target, truncateList(others, richRuleCitationLimit))))
	default:
		citations = append(citations, richCmd.Citation("zone has no rich rules"))
	}

	if len(services) == 0 {
		citations = append(citations, servicesCmd.Citation(fmt.Sprintf("zone %s allows no services", req.zone())))
	} else {
		citations = append(citations, servicesCmd.Citation(fmt.Sprintf(
			"zone %s allows services not covering %s: %s",
			req.zone(), target, truncateList(services, richRuleCitationLimit))))
	}
	return citations
}

// richRuleCitationLimit caps how many entries one citation quotes.
const richRuleCitationLimit = 10

// Action is the decision a rich rule carries.
type Action string

const (
	ActionAccept Action = "accept"
	ActionReject Action = "reject"
	ActionDrop   Action = "drop"
	// ActionNone is a rule that logs, audits, or marks without deciding. It is
	// not a permission and not a denial, so it never resolves the question.
	ActionNone Action = ""
)

// RichRule is one line of `firewall-cmd --list-rich-rules`.
//
// Source is a flow.PrefixSet rather than a string, which is where requirement
// 8.3 is actually satisfied: containment is a property of the type, so no
// comparison written later can regress to string equality.
type RichRule struct {
	Raw      string `json:"raw"`
	Priority int    `json:"priority,omitempty"`
	// Family is "ipv4", "ipv6", or empty when the rule states none.
	Family string `json:"family,omitempty"`
	// Source is the addresses the rule matches. SourceAny is true when the rule
	// names no source and so matches every one.
	Source        flow.PrefixSet `json:"-"`
	SourceAny     bool           `json:"source_any,omitempty"`
	SourceNegated bool           `json:"source_negated,omitempty"`
	// Element is the rich rule element that decides what traffic is matched:
	// "port", "service", "protocol", or empty for a source-wide rule.
	Element  string        `json:"element,omitempty"`
	Service  string        `json:"service,omitempty"`
	Ports    flow.PortSet  `json:"-"`
	Protocol flow.Protocol `json:"protocol,omitempty"`
	Action   Action        `json:"action,omitempty"`
	// Unresolvable states why the rule's effect on a probed flow cannot be
	// determined. A rule that cannot be read is not a rule that can be ignored,
	// so the evaluator abstains when one could apply.
	Unresolvable string `json:"unresolvable,omitempty"`
	// unresolvedPorts narrows an unmodelled element to the destination ports it
	// names. A forward-port rule for port 80 has no bearing on a probe of port
	// 443, and abstaining on it would make any host with a redirect
	// unanswerable — so an unresolvable rule that demonstrably concerns other
	// ports is set aside rather than reported as unknown.
	unresolvedPorts flow.PortSet
}

// sourceDescription renders the source side for a citation.
func (r RichRule) sourceDescription() string {
	switch {
	case r.SourceAny:
		return "rule with any source"
	case r.SourceNegated:
		return fmt.Sprintf("rule excluding %s", r.Source)
	default:
		return fmt.Sprintf("allowlist entry %s", r.Source)
	}
}

// matches reports whether the rule governs req. An error means the rule might
// govern it but cannot be evaluated, which is a reason to abstain rather than a
// reason to move on.
func (r RichRule) matches(req FirewallRequest) (bool, error) {
	if r.Action == ActionNone && r.Unresolvable == "" {
		return false, nil
	}
	if !r.familyMatches(req.Source) {
		return false, nil
	}
	if !r.sourceMatches(req.Source) {
		return false, nil
	}
	if r.Unresolvable != "" {
		if !r.unresolvedPorts.IsEmpty() && !r.unresolvedPorts.Contains(req.Port) {
			return false, nil
		}
		return false, fmt.Errorf("rule cannot be evaluated (%s): %s", r.Unresolvable, r.Raw)
	}
	return r.portMatches(req)
}

// familyMatches keeps an ipv6 rule from deciding an ipv4 flow.
func (r RichRule) familyMatches(src netip.Addr) bool {
	switch strings.ToLower(r.Family) {
	case "ipv4":
		return src.Unmap().Is4()
	case "ipv6":
		return src.Unmap().Is6()
	default:
		return true
	}
}

// sourceMatches is the containment test requirement 8.3 asks for.
func (r RichRule) sourceMatches(src netip.Addr) bool {
	if r.SourceAny {
		return true
	}
	contained := r.Source.ContainsAddr(src)
	if r.SourceNegated {
		return !contained
	}
	return contained
}

// portMatches resolves the rule's element against the probed port.
func (r RichRule) portMatches(req FirewallRequest) (bool, error) {
	switch r.Element {
	case "":
		// A rule naming only a source governs every port from it.
		return true, nil
	case "port":
		if r.Protocol != flow.ProtoAny && r.Protocol != req.Protocol {
			return false, nil
		}
		return r.Ports.Contains(req.Port), nil
	case "service":
		ports, known := ServicePorts(r.Service)
		if !known {
			return false, fmt.Errorf("service %q ports are not known to aws-netpath", r.Service)
		}
		return ports.covers(req.Protocol, req.Port), nil
	case "protocol":
		// `protocol value="tcp"` matches a protocol with no port constraint.
		return r.Protocol == flow.ProtoAny || r.Protocol == req.Protocol, nil
	default:
		return false, nil
	}
}

// governsPort reports whether the rule concerns the probed port at all,
// whatever source it names. It selects the entries worth citing when the
// conclusion is BLOCKED: the near miss is the useful evidence.
func (r RichRule) governsPort(req FirewallRequest) bool {
	switch r.Element {
	case "port":
		if r.Protocol != flow.ProtoAny && r.Protocol != req.Protocol {
			return false
		}
		return r.Ports.Contains(req.Port)
	case "service":
		ports, known := ServicePorts(r.Service)
		return known && ports.covers(req.Protocol, req.Port)
	case "":
		return true
	default:
		return false
	}
}

// ParseRichRules reads `firewall-cmd --list-rich-rules` output, one rule per
// line. A line that is not a rich rule at all is an error: the list is the
// allowlist, and a line nobody could read might be the entry that admits the
// source.
func ParseRichRules(out string) ([]RichRule, error) {
	var rules []RichRule
	for i, line := range strings.Split(out, "\n") {
		text := strings.TrimSpace(line)
		if text == "" {
			continue
		}
		rule, err := ParseRichRule(text)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", i+1, err)
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

// ParseRichRule reads one rich rule.
//
// It reads the elements it can evaluate and records the rest as Unresolvable
// rather than dropping them, which keeps "a rule this package does not model"
// distinct from "a rule that does not apply". Dropping them would silently
// narrow the allowlist the check believes in.
func ParseRichRule(line string) (RichRule, error) {
	tokens := splitRichRule(line)
	if len(tokens) == 0 || tokens[0] != "rule" {
		return RichRule{}, fmt.Errorf("not a rich rule: %q", line)
	}

	rule := RichRule{Raw: line, SourceAny: true, Protocol: flow.ProtoAny}
	section := ""
	for _, token := range tokens[1:] {
		key, value, hasValue := strings.Cut(token, "=")
		value = unquote(value)

		if !hasValue {
			switch key {
			case "port", "service", "protocol":
				// The elements that decide which traffic the rule matches.
				section, rule.Element = key, key
			case "source", "destination":
				section = key
			case "source-port", "forward-port":
				// Both can govern the probed traffic — one matches on a field
				// this package does not model, the other diverts the port
				// elsewhere — so the rule's effect is unknown rather than absent.
				section = key
				rule.Unresolvable = fmt.Sprintf("%s element is not modelled", key)
			case "icmp-type", "icmp-block", "masquerade", "tcp-mss-clamp", "log", "audit", "limit":
				// None of these can admit or deny a TCP or UDP port: they match
				// ICMP, rewrite addresses, clamp a segment size, or only record.
				// They are skipped rather than treated as unknown, because
				// abstaining on a masquerade rule in a gateway zone would leave
				// the common case unanswerable.
				section = key
			case "NOT", "not":
				if section == "source" {
					rule.SourceNegated = true
				}
			case "accept", "reject", "drop", "mark":
				rule.Action = parseAction(key)
			default:
				rule.Unresolvable = fmt.Sprintf("unrecognised token %q", key)
			}
			continue
		}

		switch {
		case key == "family":
			rule.Family = value
		case key == "priority":
			priority, err := parsePriority(value)
			if err != nil {
				return RichRule{}, fmt.Errorf("%w in %q", err, line)
			}
			rule.Priority = priority
		case key == "address" && section == "source":
			set, err := flow.ParsePrefixSet(value)
			if err != nil {
				return RichRule{}, fmt.Errorf("unreadable source address %q in %q: %w", value, line, err)
			}
			rule.Source = set
			rule.SourceAny = false
		case key == "invert" && section == "source":
			rule.SourceNegated = strings.EqualFold(value, "true")
		case (key == "ipset" || key == "mac") && section == "source":
			// An ipset or MAC source cannot be resolved to prefixes from this
			// output, so the rule's reach is unknown rather than empty.
			rule.Unresolvable = fmt.Sprintf("source %s=%s cannot be resolved to addresses", key, value)
		case key == "name" && section == "service":
			rule.Service = value
		case key == "port" && section == "port":
			ports, err := parseFirewalldPorts(value)
			if err != nil {
				return RichRule{}, fmt.Errorf("%w in %q", err, line)
			}
			rule.Ports = ports
		case key == "port" && section == "forward-port":
			// A forward-port names the destination port it redirects, so the rule
			// can be narrowed to it even though the redirect itself is not
			// modelled. A source-port is deliberately not narrowed this way: its
			// port is the client's, and says nothing about the port probed.
			ports, err := parseFirewalldPorts(value)
			if err != nil {
				return RichRule{}, fmt.Errorf("%w in %q", err, line)
			}
			rule.unresolvedPorts = ports
		case key == "protocol":
			proto, err := flow.ParseProtocol(value)
			if err != nil {
				return RichRule{}, fmt.Errorf("unreadable protocol %q in %q: %w", value, line, err)
			}
			rule.Protocol = proto
		case key == "value" && section == "protocol":
			proto, err := flow.ParseProtocol(value)
			if err != nil {
				return RichRule{}, fmt.Errorf("unreadable protocol %q in %q: %w", value, line, err)
			}
			rule.Protocol = proto
		default:
			// Attributes of things this package does not decide on — a reject
			// type, a log prefix, a rate limit, an audit level — cannot change
			// which traffic the rule matches, so they are ignored. The raw rule
			// is cited in full either way.
		}
	}

	if rule.Element == "service" && rule.Service == "" {
		return RichRule{}, fmt.Errorf("service element without a name in %q", line)
	}
	if rule.Element == "port" && rule.Ports.IsEmpty() {
		return RichRule{}, fmt.Errorf("port element without a port in %q", line)
	}
	return rule, nil
}

func parseAction(token string) Action {
	switch token {
	case "accept":
		return ActionAccept
	case "reject":
		return ActionReject
	case "drop":
		return ActionDrop
	default:
		// `mark` sets a packet mark and lets the packet continue, so it decides
		// nothing about admission.
		return ActionNone
	}
}

func parsePriority(value string) (int, error) {
	priority, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		return 0, fmt.Errorf("unreadable priority %q", value)
	}
	return priority, nil
}

// parseFirewalldPorts reads a rich rule port value: "22" or "8080-8090".
func parseFirewalldPorts(value string) (flow.PortSet, error) {
	loText, hiText, ranged := strings.Cut(value, "-")
	low, err := parsePort(loText)
	if err != nil {
		return flow.PortSet{}, fmt.Errorf("unreadable port %q", value)
	}
	high := low
	if ranged {
		high, err = parsePort(hiText)
		if err != nil {
			return flow.PortSet{}, fmt.Errorf("unreadable port range %q", value)
		}
	}
	set, err := flow.NewPortSet(flow.PortRange{Lo: low, Hi: high})
	if err != nil {
		return flow.PortSet{}, fmt.Errorf("unreadable port range %q: %w", value, err)
	}
	return set, nil
}

func parsePort(text string) (uint16, error) {
	port, err := strconv.ParseUint(strings.TrimSpace(text), 10, 16)
	if err != nil {
		return 0, err
	}
	return uint16(port), nil
}

// splitRichRule tokenises a rich rule, keeping a quoted value with its key so
// that `source address="10.0.0.0/8"` yields one token. firewalld quotes its own
// output, but hand-written zone files reach the same command unquoted, so both
// are read.
func splitRichRule(line string) []string {
	var tokens []string
	var current strings.Builder
	quote := rune(0)
	for _, r := range line {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
				continue
			}
			current.WriteRune(r)
		case r == '"' || r == '\'':
			quote = r
		case r == ' ' || r == '\t':
			if current.Len() > 0 {
				tokens = append(tokens, current.String())
				current.Reset()
			}
		default:
			current.WriteRune(r)
		}
	}
	if current.Len() > 0 {
		tokens = append(tokens, current.String())
	}
	return tokens
}

func unquote(value string) string {
	if len(value) >= 2 {
		if (value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'') {
			return value[1 : len(value)-1]
		}
	}
	return value
}

// ParseServices reads `firewall-cmd --list-services` output: service names on one
// whitespace-separated line. Unlike the rich rule list there is nothing here that
// can fail to parse — a name is a name — so the uncertainty moves to whether the
// name's ports are known, which unknownServices reports.
func ParseServices(out string) []string {
	fields := strings.Fields(out)
	if len(fields) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(fields))
	services := make([]string, 0, len(fields))
	for _, name := range fields {
		if !seen[name] {
			seen[name] = true
			services = append(services, name)
		}
	}
	return services
}

// servicesAllow reports whether a zone-wide service allowance covers the probed
// port. A service allowance applies to every source in the zone, so a match ends
// the question.
func servicesAllow(services []string, req FirewallRequest) (bool, string) {
	for _, name := range services {
		if ports, known := ServicePorts(name); known && ports.covers(req.Protocol, req.Port) {
			return true, name
		}
	}
	return false, ""
}

// unknownServices returns the allowed service names whose ports this package
// cannot resolve.
func unknownServices(services []string) []string {
	var unknown []string
	for _, name := range services {
		if _, known := ServicePorts(name); !known {
			unknown = append(unknown, name)
		}
	}
	return unknown
}

// ServiceDefinition is the ports a firewalld service name stands for.
type ServiceDefinition struct {
	TCP flow.PortSet
	UDP flow.PortSet
}

func (d ServiceDefinition) covers(proto flow.Protocol, port uint16) bool {
	switch proto {
	case flow.ProtoTCP:
		return d.TCP.Contains(port)
	case flow.ProtoUDP:
		return d.UDP.Contains(port)
	default:
		return false
	}
}

// ServicePorts returns the ports a firewalld service name covers.
//
// The definitions live on the host in /usr/lib/firewalld/services, and reading
// them would need a command the allowlist does not carry — so this table is a
// deliberate second-best. known being false is not an absence of ports; it is an
// absence of knowledge, and the caller abstains on it rather than concluding the
// port is closed.
func ServicePorts(name string) (def ServiceDefinition, known bool) {
	spec, ok := firewalldServices[strings.ToLower(strings.TrimSpace(name))]
	if !ok {
		return ServiceDefinition{}, false
	}
	return ServiceDefinition{TCP: portsOf(spec.tcp), UDP: portsOf(spec.udp)}, true
}

// KnownServices returns the firewalld service names this package can resolve, in
// sorted order, for documenting what an Abstention on an unknown name means.
func KnownServices() []string {
	out := make([]string, 0, len(firewalldServices))
	for name := range firewalldServices {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

type serviceSpec struct {
	tcp []flow.PortRange
	udp []flow.PortRange
}

func portsOf(ranges []flow.PortRange) flow.PortSet {
	if len(ranges) == 0 {
		return flow.NoPorts()
	}
	set, err := flow.NewPortSet(ranges...)
	if err != nil {
		// The table is source, not input: a bad range here is a bug caught by
		// the package's own tests rather than a runtime condition.
		return flow.NoPorts()
	}
	return set
}

func tcp(ports ...uint16) []flow.PortRange { return portRanges(ports) }
func udp(ports ...uint16) []flow.PortRange { return portRanges(ports) }

func portRanges(ports []uint16) []flow.PortRange {
	out := make([]flow.PortRange, 0, len(ports))
	for _, p := range ports {
		out = append(out, flow.PortRange{Lo: p, Hi: p})
	}
	return out
}

// firewalldServices are the service definitions shipped with firewalld that a
// diagnosis is likely to meet. It is not the whole set and does not pretend to
// be: a name absent from it produces an Abstention naming the name, which is a
// smaller and more honest failure than a guess.
var firewalldServices = map[string]serviceSpec{
	"amqp":            {tcp: tcp(5672)},
	"amqps":           {tcp: tcp(5671)},
	"cockpit":         {tcp: tcp(9090)},
	"dhcp":            {udp: udp(67)},
	"dhcpv6":          {udp: udp(547)},
	"dhcpv6-client":   {udp: udp(546)},
	"dns":             {tcp: tcp(53), udp: udp(53)},
	"dns-over-tls":    {tcp: tcp(853)},
	"docker-registry": {tcp: tcp(5000)},
	"elasticsearch":   {tcp: tcp(9200, 9300)},
	"etcd-client":     {tcp: tcp(2379)},
	"etcd-server":     {tcp: tcp(2380)},
	"finger":          {tcp: tcp(79)},
	"ftp":             {tcp: tcp(21)},
	"git":             {tcp: tcp(9418)},
	"grafana":         {tcp: tcp(3000)},
	"http":            {tcp: tcp(80)},
	"http3":           {udp: udp(443)},
	"https":           {tcp: tcp(443)},
	"imap":            {tcp: tcp(143)},
	"imaps":           {tcp: tcp(993)},
	"ipp":             {tcp: tcp(631), udp: udp(631)},
	"ipsec":           {udp: udp(500, 4500)},
	"kerberos":        {tcp: tcp(88), udp: udp(88)},
	"kibana":          {tcp: tcp(5601)},
	"kube-apiserver":  {tcp: tcp(6443)},
	"ldap":            {tcp: tcp(389)},
	"ldaps":           {tcp: tcp(636)},
	"memcache":        {tcp: tcp(11211), udp: udp(11211)},
	"mdns":            {udp: udp(5353)},
	"mongodb":         {tcp: tcp(27017)},
	"mosh":            {udp: []flow.PortRange{{Lo: 60000, Hi: 61000}}},
	"mqtt":            {tcp: tcp(1883)},
	"mqtt-tls":        {tcp: tcp(8883)},
	"mysql":           {tcp: tcp(3306)},
	"nfs":             {tcp: tcp(2049)},
	"nfs3":            {tcp: tcp(2049), udp: udp(2049)},
	"node-exporter":   {tcp: tcp(9100)},
	"ntp":             {udp: udp(123)},
	"openvpn":         {udp: udp(1194)},
	"pop3":            {tcp: tcp(110)},
	"pop3s":           {tcp: tcp(995)},
	"postgresql":      {tcp: tcp(5432)},
	"prometheus":      {tcp: tcp(9090)},
	"proxy-dhcp":      {udp: udp(67, 4011)},
	"rdp":             {tcp: tcp(3389)},
	"redis":           {tcp: tcp(6379)},
	"redis-sentinel":  {tcp: tcp(26379)},
	"rsyncd":          {tcp: tcp(873)},
	"samba":           {tcp: tcp(139, 445), udp: udp(137, 138)},
	"samba-client":    {udp: udp(137, 138)},
	"smtp":            {tcp: tcp(25)},
	"smtp-submission": {tcp: tcp(587)},
	"smtps":           {tcp: tcp(465)},
	"snmp":            {udp: udp(161)},
	"snmptrap":        {udp: udp(162)},
	"squid":           {tcp: tcp(3128)},
	"ssh":             {tcp: tcp(22)},
	"syslog":          {tcp: tcp(514), udp: udp(514)},
	"syslog-tls":      {tcp: tcp(6514)},
	"telnet":          {tcp: tcp(23)},
	"tftp":            {udp: udp(69)},
	"tftp-client":     {udp: udp(69)},
	"vnc-server":      {tcp: []flow.PortRange{{Lo: 5900, Hi: 5903}}},
	"wireguard":       {udp: udp(51820)},
	"zabbix-agent":    {tcp: tcp(10050)},
	"zabbix-server":   {tcp: tcp(10051)},
}
