package mcpserver

// Every tool is callable, and what it says about itself is true.
//
// Registration and description are covered in tools_test.go, and one
// representative call is made there. That leaves the gap this file closes: a
// handler that registers cleanly, describes itself well, and then fails on the way
// into its operation — a mistyped default, a request field filled from the wrong
// parameter, a result the Formatter cannot render — would satisfy every assertion
// there and answer nothing. So each of the eight is called for real, against a
// snapshot on disk, and asked to come back with the report its operation projects.
//
// Two things a caller relies on before it ever reads a result are asserted
// alongside. The annotations, because an agent decides whether it is allowed to
// call a tool from those and not from the prose: a read-only hint on a tool that
// writes a file is worse than no hint. And requirement 14.7, because the tool
// result is the last thing this surface emits, so it is the place where a
// credential that came in through a resource name or a declared flow's own label
// would leave.
//
// Nothing here needs AWS credentials and nothing here makes a network call. The
// snapshot is written to a temporary directory, verify is asked to skip the
// analyser, and collect is called with no scope so it fails while working out what
// to collect rather than while reaching for it.

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/jajera/aws-netpath/internal/format"
	"github.com/jajera/aws-netpath/internal/model"
	"github.com/jajera/aws-netpath/internal/snapshot"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// The fixture's addresses and identifiers. RFC 1918 space and placeholder
// identifiers only, per requirement 17.2.
const (
	fixtureAccount = "111122223333"
	fixtureRegion  = "us-east-1"
	appIP          = "10.0.1.10"
	peerIP         = "10.0.1.11"
	databaseIP     = "10.0.2.20"
	databasePort   = 443

	firewallPolicyARN = "arn:aws:network-firewall:us-east-1:111122223333:firewall-policy/inspection"
	ruleGroupARN      = "arn:aws:network-firewall:us-east-1:111122223333:stateful-rulegroup/east-west"
)

// workloadSnapshot writes a snapshot holding one VPC, two subnets, and three
// interfaces, and returns its path.
//
// It is written by internal/snapshot rather than checked in as JSON so the schema
// version and captured timestamp are the ones a real collection writes. The shape
// is the smallest one every snapshot-reading tool can answer against: both
// endpoints resolve to collected interfaces, the route table carries the local
// route between them, and the security groups permit the flow, so a tool that
// reaches its operation comes back with a verdict rather than with UNKNOWN.
//
// The third interface is the reference endpoint compare needs: a comparison of a
// path against itself establishes nothing.
func workloadSnapshot(t *testing.T) string {
	t.Helper()

	meta := func(id, name string) model.Meta {
		return model.Meta{ID: id, Name: name, Region: fixtureRegion, Account: fixtureAccount}
	}

	snap := model.NewSnapshot()
	snap.Accounts = []string{fixtureAccount}
	snap.Regions = []string{fixtureRegion}

	snap.VPCs["vpc-0123456789abcdef0"] = &model.VPC{
		Meta:  meta("vpc-0123456789abcdef0", "workload"),
		CIDRs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/16")},
	}
	snap.RouteTables["rtb-0123456789abcdef0"] = &model.RouteTable{
		Meta:   meta("rtb-0123456789abcdef0", "workload-main"),
		VPCID:  "vpc-0123456789abcdef0",
		Routes: []model.Route{{Destination: netip.MustParsePrefix("10.0.0.0/16"), TargetKind: model.TargetLocal, TargetID: "local"}},
	}
	snap.Subnets["subnet-0123456789abcdef0"] = &model.Subnet{
		Meta:         meta("subnet-0123456789abcdef0", "app"),
		VPCID:        "vpc-0123456789abcdef0",
		CIDR:         netip.MustParsePrefix("10.0.1.0/24"),
		RouteTableID: "rtb-0123456789abcdef0",
	}
	snap.Subnets["subnet-0123456789abcdef1"] = &model.Subnet{
		Meta:         meta("subnet-0123456789abcdef1", "database"),
		VPCID:        "vpc-0123456789abcdef0",
		CIDR:         netip.MustParsePrefix("10.0.2.0/24"),
		RouteTableID: "rtb-0123456789abcdef0",
	}
	snap.SecurityGroups["sg-0123456789abcdef0"] = &model.SecurityGroup{
		Meta:  meta("sg-0123456789abcdef0", "app"),
		VPCID: "vpc-0123456789abcdef0",
		Egress: []model.SGRule{{
			Protocol: "tcp", FromPort: databasePort, ToPort: databasePort,
			CIDRs:       []netip.Prefix{netip.MustParsePrefix("10.0.0.0/16")},
			Description: "app to database",
		}},
	}
	snap.SecurityGroups["sg-0123456789abcdef1"] = &model.SecurityGroup{
		Meta:  meta("sg-0123456789abcdef1", "database"),
		VPCID: "vpc-0123456789abcdef0",
		Ingress: []model.SGRule{{
			Protocol: "tcp", FromPort: databasePort, ToPort: databasePort,
			CIDRs:       []netip.Prefix{netip.MustParsePrefix("10.0.1.0/24")},
			Description: "app subnet to database",
		}},
	}

	// One inspection firewall, so the firewall tool has a policy to evaluate.
	// Nothing routes to its endpoint, so it does not join the path the other tools
	// walk: a firewall on the path would be a second thing this fixture asserts.
	snap.Firewalls["fw-0123456789abcdef0"] = &model.Firewall{
		Meta:      meta("fw-0123456789abcdef0", "inspection"),
		VPCID:     "vpc-0123456789abcdef0",
		PolicyARN: firewallPolicyARN,
	}
	snap.FirewallPolicies[firewallPolicyARN] = &model.FirewallPolicy{
		Meta:                   meta(firewallPolicyARN, "inspection"),
		StatefulRuleOrder:      model.StrictOrder,
		StatefulDefaultActions: []string{"aws:drop_strict"},
		StatefulGroups:         []model.RuleGroupRef{{ARN: ruleGroupARN, Priority: 1}},
	}
	snap.RuleGroups[ruleGroupARN] = &model.RuleGroup{
		Meta:      meta(ruleGroupARN, "east-west"),
		RuleOrder: model.StrictOrder,
		Rules: []model.StatefulRule{{
			Action: "PASS", Protocol: "TCP",
			Source: "10.0.1.0/24", SourcePort: "any",
			Destination: "10.0.2.0/24", DestinationPort: "443",
			Direction: model.DirForward, SID: "1",
		}},
	}

	iface := func(id, name, subnet, sg, instance, addr string) *model.NetworkIface {
		return &model.NetworkIface{
			Meta:             meta(id, name),
			VPCID:            "vpc-0123456789abcdef0",
			SubnetID:         subnet,
			PrivateIPs:       []netip.Addr{netip.MustParseAddr(addr)},
			SecurityGroupIDs: []string{sg},
			AttachedTo:       instance,
			Status:           "in-use",
		}
	}
	snap.NetworkIfaces["eni-0123456789abcdef0"] = iface(
		"eni-0123456789abcdef0", "app", "subnet-0123456789abcdef0", "sg-0123456789abcdef0", "i-0123456789abcdef0", appIP)
	snap.NetworkIfaces["eni-0123456789abcdef1"] = iface(
		"eni-0123456789abcdef1", "database", "subnet-0123456789abcdef1", "sg-0123456789abcdef1", "i-0123456789abcdef1", databaseIP)
	snap.NetworkIfaces["eni-0123456789abcdef2"] = iface(
		"eni-0123456789abcdef2", "app-peer", "subnet-0123456789abcdef0", "sg-0123456789abcdef0", "i-0123456789abcdef2", peerIP)

	path := filepath.Join(t.TempDir(), "workload.json")
	if err := snapshot.Save(path, snap); err != nil {
		t.Fatalf("write the workload snapshot: %v", err)
	}
	return path
}

// declaredFlows writes a declared flow file asserting one flow and returns its
// path. The name is a parameter because the flow's own label is caller-supplied
// text that reaches the rendered result, which is what the credential scan below
// uses it for.
func declaredFlows(t *testing.T, name string) string {
	t.Helper()

	body := "flows:\n" +
		"  - name: " + name + "\n" +
		"    from: " + appIP + "\n" +
		"    to: " + databaseIP + "\n" +
		"    proto: tcp\n" +
		"    port: 443\n" +
		"    expect: permitted\n"

	path := filepath.Join(t.TempDir(), "flows.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write the declared flows: %v", err)
	}
	return path
}

// Every tool reaches its operation and comes back with that operation's report.
//
// The arguments are the smallest complete call each tool accepts, and the JSON
// rendering is asked for so the assertion can be made against the report's own
// kind rather than against prose. What is under test is the whole path — schema
// validation, the handler's defaults, the operation, the projection, the Formatter
// — not what any of the operations conclude, which their own packages cover.
func TestEveryToolReachesItsOperation(t *testing.T) {
	snap := workloadSnapshot(t)
	flows := declaredFlows(t, "app to database")

	tests := []struct {
		tool string
		args map[string]any
		// kind is the report the operation projects. Empty means the call is
		// expected to come back as a tool error instead.
		kind format.Kind
		why  string
	}{
		{
			// The one tool that cannot answer without credentials. Called with no
			// scope, so it fails while working out what to collect rather than
			// while reaching for it — which is still the handler reaching the
			// operation and restating what it said.
			//
			// Note that the message it restates names flags: a scope that cannot be
			// resolved comes back as *ops.ScopeError rather than *ops.FieldError, so
			// failed() has no field to translate and passes "--config, (--profiles
			// and --regions), or (--profile and --regions) are required" through
			// verbatim. That is the thing
			// TestABadRequestNamesTheParameterAtFault exists to prevent, on the one
			// path that does not carry a field. Not asserted here, because asserting
			// it would be asserting the defect.
			tool: "collect",
			args: map[string]any{},
			why:  "collect with no scope described cannot know what to read, and says so without reaching AWS",
		},
		{
			tool: "query",
			args: map[string]any{"snapshot": snap, "from": appIP, "to": databaseIP, "port": databasePort},
			kind: format.KindQuery,
		},
		{
			tool: "firewall",
			args: map[string]any{"snapshot": snap, "from": appIP, "to": databaseIP, "port": "443"},
			kind: format.KindFirewall,
		},
		{
			tool: "diagnose",
			args: map[string]any{"snapshot": snap, "from": appIP, "to": databaseIP, "port": databasePort},
			kind: format.KindDiagnosis,
		},
		{
			tool: "compare",
			args: map[string]any{
				"snapshot": snap, "from": appIP, "to": databaseIP,
				"ref_from": peerIP, "port": databasePort,
			},
			kind: format.KindComparison,
		},
		{
			// skip_aws is what makes this callable with no credentials: the model
			// is evaluated and the comparison is reported as unestablished.
			tool: "verify",
			args: map[string]any{
				"snapshot": snap, "from": appIP, "to": databaseIP,
				"port": databasePort, "skip_aws": true,
			},
			kind: format.KindVerification,
		},
		{
			tool: "diff",
			args: map[string]any{"from": snap, "to": snap},
			kind: format.KindSnapshotDiff,
		},
		{
			tool: "test",
			args: map[string]any{"snapshot": snap, "flows": flows},
			kind: format.KindFlowTest,
		},
	}

	if len(tests) != len(operations) {
		t.Fatalf("%d tools are called here, and the server presents %d", len(tests), len(operations))
	}

	cs := connect(t, New("test"))
	for _, tt := range tests {
		t.Run(tt.tool, func(t *testing.T) {
			args := map[string]any{"format": formatJSON}
			for k, v := range tt.args {
				args[k] = v
			}

			res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: tt.tool, Arguments: args})
			if err != nil {
				t.Fatalf("call %s: %v", tt.tool, err)
			}

			body := content(t, res)

			if tt.kind == "" {
				if !res.IsError {
					t.Fatalf("call %s succeeded, want a tool error: %s", tt.tool, tt.why)
				}
				if strings.TrimSpace(body) == "" {
					t.Errorf("call %s failed without saying why", tt.tool)
				}
				return
			}

			if res.IsError {
				t.Fatalf("call %s reported a tool error: %s", tt.tool, body)
			}

			var report struct {
				Kind    string `json:"kind"`
				Outcome string `json:"outcome"`
			}
			if err := json.Unmarshal([]byte(body), &report); err != nil {
				t.Fatalf("call %s returned content that is not a report: %v\n%s", tt.tool, err, body)
			}
			if report.Kind != string(tt.kind) {
				t.Errorf("call %s returned a %q report, want %q", tt.tool, report.Kind, tt.kind)
			}
			// An operation that was reached and produced nothing would still
			// render as a well-formed report of the right kind.
			if strings.TrimSpace(report.Outcome) == "" {
				t.Errorf("call %s returned a report with no outcome:\n%s", tt.tool, body)
			}
		})
	}
}

// posture is what a tool's annotations claim about it.
type posture struct {
	readOnly    bool
	destructive bool
	// openWorld is whether the tool reaches anything outside the files it was
	// given.
	openWorld bool
	why       string
}

// The annotations an agent reads before deciding whether it may call a tool.
//
// Stated here rather than read from the registration structs, for the reason the
// required-parameter set is: a test that read the same values it is checking would
// agree with whatever it found. Every tool is either offline, or one of the two
// that reach AWS, and which is which is the whole of the read-only guarantee this
// surface offers.
func postures() map[string]posture {
	return map[string]posture{
		"query":    {readOnly: true, why: "reads a snapshot file and nothing else"},
		"firewall": {readOnly: true, why: "reads a snapshot file and nothing else"},
		"diagnose": {readOnly: true, why: "opens no Systems Manager client, so it reads a snapshot file and nothing else"},
		"compare":  {readOnly: true, why: "reads one snapshot file and evaluates both paths against it"},
		"diff":     {readOnly: true, why: "reads two snapshot files"},
		"test":     {readOnly: true, why: "reads a snapshot file and a declared flow file"},
		"collect": {
			destructive: true, openWorld: true,
			why: "calls the AWS API and replaces whatever is at the output path",
		},
		"verify": {
			openWorld: true,
			why:       "creates an analysis object in the account, and changes no infrastructure",
		},
	}
}

// A tool's annotations match what it does.
//
// This is the guardrail posture as an agent reads it. Prose is not enough: a
// client that refuses to call anything not marked read-only, or that asks its
// operator before calling anything destructive, is reading these fields, so a tool
// that writes a file behind a read-only hint has been given permission it was
// never granted — and the reverse, an offline query marked destructive, is a
// capability an agent will decline to use.
func TestToolAnnotationsMatchWhatTheToolDoes(t *testing.T) {
	got := tools(t, connect(t, New("test")))
	want := postures()

	if len(want) != len(operations) {
		t.Fatalf("%d tools have a stated posture, and the server presents %d", len(want), len(operations))
	}

	for name, w := range want {
		tool, ok := got[name]
		if !ok {
			continue // reported by TestEveryOperationIsPresentedUnderItsCommandName
		}

		a := tool.Annotations
		if a == nil {
			t.Errorf("tool %s carries no annotations, so an agent cannot tell whether it may call it", name)
			continue
		}

		if a.ReadOnlyHint != w.readOnly {
			t.Errorf("tool %s is annotated read-only=%t, want %t: it %s",
				name, a.ReadOnlyHint, w.readOnly, w.why)
		}
		// The destructive hint is only meaningful on a tool that is not read-only,
		// and the protocol's default for it is true — so a tool that changes
		// something has to state which kind of change it makes, or an agent reads
		// the most alarming reading available.
		if !w.readOnly {
			if a.DestructiveHint == nil {
				t.Errorf("tool %s is not read-only and leaves the destructive hint unset, which an agent reads as destructive: it %s",
					name, w.why)
			} else if *a.DestructiveHint != w.destructive {
				t.Errorf("tool %s is annotated destructive=%t, want %t: it %s",
					name, *a.DestructiveHint, w.destructive, w.why)
			}
		}
		// Likewise the open-world hint defaults to true, so an offline tool that
		// leaves it unset is advertised as reaching the network.
		if a.OpenWorldHint == nil {
			t.Errorf("tool %s leaves the open-world hint unset, which an agent reads as reaching the network: it %s",
				name, w.why)
		} else if *a.OpenWorldHint != w.openWorld {
			t.Errorf("tool %s is annotated open-world=%t, want %t: it %s",
				name, *a.OpenWorldHint, w.openWorld, w.why)
		}
	}
}

// Requirement 14.7 at the point a result leaves this surface.
//
// internal/format holds the line and internal/format tests that it does. What is
// unproven without this is that a tool result goes through it: a handler that
// encoded its operation's result directly would render something that looked
// right, carry no row budget, no banner, and no redaction, and fail nothing.
//
// The material is planted in caller-supplied text rather than injected into the
// Formatter, because that is the route a real one takes — a resource tag, a host
// command's output, or as here the label on a declared flow, all of which this
// tool did not choose and cannot vouch for.
func TestToolOutputCarriesNoCredentialMaterial(t *testing.T) {
	// Example values from AWS's own documentation, so nothing here is a secret.
	const (
		accessKeyID = "AKIAIOSFODNN7EXAMPLE"
		sessionRef  = "aws_session_token=IQoJb3JpZ2luX2VjEXAMPLETOKENVALUE"
	)

	snap := workloadSnapshot(t)
	flows := declaredFlows(t, "app to database collected with "+accessKeyID+" and "+sessionRef)

	cs := connect(t, New("test"))
	for _, mode := range []string{formatMarkdown, formatJSON} {
		t.Run(mode, func(t *testing.T) {
			body := call(t, cs, "test", map[string]any{
				"snapshot": snap, "flows": flows, "format": mode,
			})

			for _, planted := range []string{accessKeyID, "IQoJb3JpZ2luX2VjEXAMPLETOKENVALUE"} {
				if strings.Contains(body, planted) {
					t.Errorf("a tool result carries planted credential material %q:\n%s", planted, body)
				}
			}
			if found := credentialMaterial(body); len(found) > 0 {
				t.Errorf("a tool result carries credential material: %s\n%s", strings.Join(found, "; "), body)
			}
			// Something was withheld and the reader can see that it was. A result
			// that had silently dropped the label would read as evidence nobody
			// ever collected.
			if !strings.Contains(body, "[redacted]") {
				t.Errorf("nothing in the result is marked as withheld:\n%s", body)
			}
			// The evidence around the withheld value survives it, or the
			// redaction has cost the caller the finding as well as the secret.
			if !strings.Contains(body, "app to database") {
				t.Errorf("the declared flow's own label was lost with the credential:\n%s", body)
			}
		})
	}
}

// credentialShapes describes credential material independently of the redactor,
// each with a control string the pattern must match.
//
// The patterns are written here rather than borrowed from internal/format for the
// reason that package writes its own: a scan that asks the redactor whether the
// redactor caught everything proves nothing.
func credentialShapes() []struct {
	name    string
	re      *regexp.Regexp
	control string
} {
	return []struct {
		name    string
		re      *regexp.Regexp
		control string
	}{
		{"aws access key id", regexp.MustCompile(`\b(?:AKIA|ASIA|AIDA|AROA)[0-9A-Z]{16}\b`), "AKIAIOSFODNN7EXAMPLE"},
		// No leading word boundary: the label is conventionally prefixed, and in
		// aws_session_token there is no boundary between the prefix and the label.
		{"labelled credential", regexp.MustCompile(`(?i)(?:aws[_-]?)?(?:secret[_-]?access[_-]?key|session[_-]?token|password|api[_-]?key|client[_-]?secret)\s*[:=]\s*\S{6,}`), "aws_session_token=IQoJb3JpZ2luX2VjEXAMPLE"},
		{"bearer token", regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}`), "bearer eyJhbGciOiJIUzI1NiEXAMPLE"},
		{"private key material", regexp.MustCompile(`-----BEGIN[A-Z ]*PRIVATE KEY-----`), "-----BEGIN RSA PRIVATE KEY-----"},
	}
}

// The scan finds what it claims to look for. Without this, its silence above
// means nothing.
func TestTheCredentialScanIsNotVacuous(t *testing.T) {
	for _, shape := range credentialShapes() {
		t.Run(shape.name, func(t *testing.T) {
			if found := credentialMaterial(shape.control); len(found) == 0 {
				t.Errorf("the scan missed a planted %s: %q", shape.name, shape.control)
			}
		})
	}
}

// credentialMaterial reports every credential shape found in s.
//
// The redaction marker collapses to a single character first. A label whose value
// has been withheld still reads as a labelled credential, and flagging it would
// make the scan complain about the guarantee holding — but deleting the marker
// outright would leave the label butted against whatever followed it on the line,
// which reads as a credential just as well.
func credentialMaterial(s string) []string {
	s = strings.ReplaceAll(s, "[redacted]", "-")
	var found []string
	for _, shape := range credentialShapes() {
		for _, m := range shape.re.FindAllString(s, -1) {
			found = append(found, shape.name+": "+m)
		}
	}
	return found
}
