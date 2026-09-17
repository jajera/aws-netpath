package mcpserver

// The tool set.
//
// This file is the whole of what the server presents, for the reason
// internal/cli lists its commands in one slice: the set of capabilities a surface
// offers is a single fact, and a fact stated in one place cannot half-change. New
// applies this list and nothing else, so a tool is registered by appearing here
// and by no other route.
//
// Each operation in internal/ops appears once, under the name of its CLI
// subcommand — collect, query, firewall, diagnose, compare, verify, diff, test —
// so an operator and an agent describe the same capability the same way. Handlers
// belong beside their registration, calling straight into internal/ops: a handler
// that reimplemented any part of an operation would be the drift requirement 16.4
// exists to prevent.
//
// A handler does five things and no more: resolve the rendering, fill in the
// defaults the equivalent command applies, call the operation, restate a failure
// in the tool's own vocabulary, and render the result. It parses nothing,
// validates nothing beyond what the schema already checked, and decides nothing —
// a tool call and the equivalent command reach the same code with the same
// arguments, which is the only way an agent's answer stays worth as much as an
// operator's.
//
// Every result is a Report projected by internal/ops and rendered by
// internal/format, markdown unless the caller asked for JSON. No tool encodes an
// operation's own result shape: the Formatter is where credential-shaped material
// is withheld on the way out (requirement 14.7), where the row budget is applied
// (requirement 14.5), and where a verdict resting on an abstention is banner-
// marked (requirement 14.6), and a tool that went around it would be a result
// with none of the three.
//
// Nothing here writes to stdout. Under stdio transport stdout is the protocol
// channel, so a stray line is a framing error that ends the session; results go
// back as content and diagnostics go to stderr.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jajera/aws-netpath/internal/format"
	"github.com/jajera/aws-netpath/internal/ops"
	"github.com/jajera/aws-netpath/internal/symptom"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// A registrar adds one tool to a server, with its schema and its handler.
//
// Registration is a closure rather than a row in a table of names and handlers
// because mcp.AddTool is generic over a tool's input and output types: each tool's
// schema is derived from its own Go types, so it cannot be described by a shared
// signature and cannot fall out of step with the arguments its handler reads.
type registrar func(*mcp.Server)

// registrars is the ordered set of tools the server presents.
//
// The order is the order the operations are met in: collect first, because
// everything else reads what it wrote, then the questions that can be asked of a
// snapshot.
func registrars() []registrar {
	return []registrar{
		addCollect,
		addQuery,
		addFirewall,
		addDiagnose,
		addCompare,
		addVerify,
		addDiff,
		addTestFlows,
	}
}

// The defaults an omitted parameter takes.
//
// They are the values the equivalent command applies, restated here because a
// tool schema cannot carry a Go default: an agent that omits proto and an operator
// who omits --proto have to be asking the same question, or the two surfaces
// answer differently for a reason neither of them can see.
const (
	defaultProto = "tcp"
	// defaultPorts is the firewall tool's port set. Firewall policy is evaluated
	// over a set rather than one port, and a rule matching part of the set splits
	// the flow rather than deciding it.
	defaultPorts = "any"
	// defaultSnapshotPath is where collect writes when told nowhere else. It sits
	// inside a gitignored directory because a snapshot is an unsanitised model of a
	// real network, and a default that has to be remembered is one that gets
	// forgotten.
	defaultSnapshotPath = "snapshots/snapshot.json"
	// defaultCollectTimeout bounds one account+region target, in seconds.
	defaultCollectTimeout = 120
	// defaultAnalysisTimeout bounds one Reachability Analyzer analysis.
	defaultAnalysisTimeout = 2 * time.Minute
)

// rendering is the parameter every tool carries for choosing how its result is
// rendered.
//
// It is embedded rather than repeated eight times because the choice is one fact
// about this surface, and eight copies of a description are eight chances for a
// tool to offer a value another tool refuses. The schema is inferred from the
// promoted field, so an agent sees an ordinary optional parameter.
type rendering struct {
	Format string `json:"format,omitempty" jsonschema:"how to render the result: markdown for a compact report, or json for the same report as a stable object; omit for markdown, which is much the cheaper of the two to read"`
}

// Rendering modes, in the words a caller passes.
const (
	formatMarkdown = string(format.ModeMarkdown)
	formatJSON     = string(format.ModeJSON)
)

// mode resolves the requested rendering.
//
// Markdown is the default because the reader here is an agent paying per token,
// which is the opposite of the CLI's default and for the same reason: requirement
// 14.3 gives the reader who did not ask the rendering suited to them, and on this
// surface that reader is not a person at a terminal.
//
// Text is deliberately unreachable. It is the terminal rendering — fixed-width
// tags, indented citation lines, no row budget — and offering it here would hand
// an agent the most expensive of the three renderings under the name of the
// cheapest default the CLI has.
func (r rendering) mode() (format.Mode, error) {
	switch strings.ToLower(strings.TrimSpace(r.Format)) {
	case "", formatMarkdown:
		return format.ModeMarkdown, nil
	case formatJSON:
		return format.ModeJSON, nil
	default:
		return "", fmt.Errorf("parameter format is invalid: %q is not a rendering: want %s or %s, or omit it for %s",
			r.Format, formatMarkdown, formatJSON, formatMarkdown)
	}
}

// collect ------------------------------------------------------------------

// collectIn is the collect tool's arguments.
//
// Every field is optional because the scope is described one of three ways and
// the operation is the one place that decides whether a description is complete.
// A schema marking any of them required would refuse one of the three shapes.
type collectIn struct {
	Config     string `json:"config,omitempty" jsonschema:"path to an aws-netpath YAML file naming each account, its credential profile, and its regions; the multi-account shape, and the only one that lets regions differ per account"`
	Profiles   string `json:"profiles,omitempty" jsonschema:"comma-separated credential profiles, each collected across every region in regions; the multi-profile shortcut"`
	Profile    string `json:"profile,omitempty" jsonschema:"a single credential profile to collect through, used with regions"`
	Regions    string `json:"regions,omitempty" jsonschema:"comma-separated regions to collect, required alongside profile or profiles"`
	Account    string `json:"account,omitempty" jsonschema:"expected account identifier, checked against the account the profile authenticates as; single profile only"`
	AssumeRole string `json:"assume_role,omitempty" jsonschema:"ARN of a role to assume after the profile authenticates"`
	Timeout    *int   `json:"timeout,omitempty" jsonschema:"timeout per account and region, in seconds; omit for 120, or pass 0 for no limit"`
	Output     string `json:"output,omitempty" jsonschema:"path to write the snapshot to, whose parent directory is created if absent; omit for snapshots/snapshot.json, a gitignored location"`
	rendering
}

func addCollect(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name: "collect",
		Description: `Read AWS network configuration into a snapshot file, which every other tool then evaluates offline.

Needs AWS credentials. This is the only tool that calls the AWS API, and every call it makes is a Describe: nothing in AWS is changed. It does write a local file, replacing whatever is at the output path.

Describe the scope one of three ways: config, for a YAML file naming each account with its own profile and regions; profiles with regions, for every profile crossed with every region; or profile with regions, for one account. Each account is reached through its own credential profile, so no delegated administrator or organisation-wide role is involved. Accounts and regions are collected in parallel.

An account or resource type that cannot be read is recorded in the snapshot rather than failing the run, so one unreadable account does not cost the rest.

Returns the path written, the number of account and region pairs attempted, how many failed, whether the collection is therefore partial, and a count of each resource type collected.`,
		Annotations: writesSnapshot(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in collectIn) (*mcp.CallToolResult, any, error) {
		mode, err := in.mode()
		if err != nil {
			return nil, nil, err
		}

		res, err := ops.Collect(ctx, ops.CollectRequest{
			ConfigPath: in.Config,
			Profile:    in.Profile,
			Profiles:   in.Profiles,
			Regions:    in.Regions,
			Account:    in.Account,
			AssumeRole: in.AssumeRole,
			Timeout:    seconds(in.Timeout, defaultCollectTimeout),
			OutputPath: orDefault(in.Output, defaultSnapshotPath),
		})
		if err != nil {
			return failed(err)
		}
		return report(res.Report(), mode)
	})
}

// query --------------------------------------------------------------------

// queryIn is the query tool's arguments.
type queryIn struct {
	Snapshot     string `json:"snapshot" jsonschema:"path to a snapshot file written by the collect tool"`
	From         string `json:"from" jsonschema:"source IP address; an address rather than a CIDR, because this walks one flow"`
	To           string `json:"to" jsonschema:"destination IP address"`
	Proto        string `json:"proto,omitempty" jsonschema:"protocol: tcp, udp, icmp, or any; omit for tcp"`
	Port         int    `json:"port,omitempty" jsonschema:"destination port, required for tcp and udp"`
	SkipFirewall bool   `json:"skip_firewall,omitempty" jsonschema:"evaluate routing and NACLs only, which isolates a routing question from a policy one"`
	rendering
}

func addQuery(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name: "query",
		Description: `Answer whether one flow reaches its destination, against a collected snapshot.

Needs a snapshot and nothing else: evaluation is offline, so this makes no AWS call, costs nothing, and returns immediately.

Walks subnet and transit gateway routing, NACLs, security groups on both endpoints, and every network firewall on the path, in flow order. The reverse direction is walked as its own flow and reported alongside, because asymmetry through a stateful component is a stall rather than a block.

Returns the verdict, every hop with the resource that decided it, the firewall decisions with the rules behind them, the return path, and the layers that could not be evaluated. A layer that could not be evaluated abstains with its reason and is never reported as a pass; where one did, the verdict is marked not authoritative. A verdict of UNKNOWN means the address is not in any collected subnet, so no path was walked — re-collect with the account that owns it.

For why a flow fails rather than whether it does, use diagnose: it adds the host layers and names the earliest blocking layer.`,
		Annotations: offline(),
	}, func(_ context.Context, _ *mcp.CallToolRequest, in queryIn) (*mcp.CallToolResult, any, error) {
		mode, err := in.mode()
		if err != nil {
			return nil, nil, err
		}

		res, err := ops.Query(ops.QueryRequest{
			SnapshotPath: in.Snapshot,
			From:         in.From,
			To:           in.To,
			Proto:        orDefault(in.Proto, defaultProto),
			Port:         in.Port,
			SkipFirewall: in.SkipFirewall,
		})
		if err != nil {
			return failed(err)
		}
		return report(ops.QueryReport(res), mode)
	})
}

// firewall -----------------------------------------------------------------

// firewallIn is the firewall tool's arguments.
type firewallIn struct {
	Snapshot string `json:"snapshot" jsonschema:"path to a snapshot file written by the collect tool"`
	From     string `json:"from" jsonschema:"source CIDR or address"`
	To       string `json:"to" jsonschema:"destination CIDR or address"`
	Proto    string `json:"proto,omitempty" jsonschema:"protocol: tcp, udp, icmp, or any; omit for tcp"`
	Port     string `json:"port,omitempty" jsonschema:"destination ports as a set, such as 443 or 80-443 or 22,443; omit for any"`
	Firewall string `json:"firewall,omitempty" jsonschema:"evaluate only firewalls whose name or identifier contains this substring; omit to evaluate every firewall in the snapshot"`
	rendering
}

func addFirewall(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name: "firewall",
		Description: `Evaluate a flow against every network firewall policy in a snapshot, leaving routing aside.

Needs a snapshot and nothing else: evaluation is offline, so this makes no AWS call.

Rule groups are walked in priority order and each decision cites the rule that produced it. Constructs outside the 5-tuple model, such as domain allowlists or raw Suricata rules, are reported as abstentions rather than guessed at. Ports are given as a set because a rule matching part of the set splits the flow rather than deciding it.

Returns one result per firewall: the decisions with their rule group, priority, and rule reference, and the rule groups that could not be evaluated with the reason. Where any abstained the verdict is marked not authoritative, because the unevaluated group might have been the one that decided the flow.

Use this to answer a policy question on its own. For a verdict over the whole path, use query or diagnose.`,
		Annotations: offline(),
	}, func(_ context.Context, _ *mcp.CallToolRequest, in firewallIn) (*mcp.CallToolResult, any, error) {
		mode, err := in.mode()
		if err != nil {
			return nil, nil, err
		}

		res, err := ops.Firewall(ops.FirewallRequest{
			SnapshotPath: in.Snapshot,
			From:         in.From,
			To:           in.To,
			Proto:        orDefault(in.Proto, defaultProto),
			Ports:        orDefault(in.Port, defaultPorts),
			Only:         in.Firewall,
		})
		if err != nil {
			return failed(err)
		}
		return report(res.Report(), mode)
	})
}

// diagnose -----------------------------------------------------------------

// diagnoseIn is the diagnose tool's arguments.
type diagnoseIn struct {
	Snapshot     string `json:"snapshot" jsonschema:"path to a snapshot file written by the collect tool"`
	From         string `json:"from" jsonschema:"source: an IP address, a CIDR, an instance identifier, or a Name tag"`
	To           string `json:"to" jsonschema:"destination: an IP address, a CIDR, an instance identifier, or a Name tag"`
	Proto        string `json:"proto,omitempty" jsonschema:"protocol: tcp, udp, icmp, or any; omit for tcp"`
	Port         int    `json:"port,omitempty" jsonschema:"destination port, required for tcp and udp"`
	Symptom      string `json:"symptom,omitempty" jsonschema:"the failure the client observed, whose implicated layers are checked first; the accepted values are listed in this tool's description, and omitting it evaluates every layer in flow order"`
	SkipFirewall bool   `json:"skip_firewall,omitempty" jsonschema:"evaluate routing and NACLs only, which isolates a routing question from a policy one"`
	rendering
}

func addDiagnose(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name: "diagnose",
		Description: `Explain why a flow fails, across every layer between the two endpoints. This is the tool to reach for when something cannot connect.

Needs a snapshot. Host probing additionally needs Systems Manager access, which this server does not open a client for, so the host layers abstain and the report says the host is unverified.

Runs the full pipeline against the snapshot: classify the symptom, resolve both endpoints, walk routing, NACLs, security groups, and firewall policy, evaluate the return direction, probe the host layers, then correlate. The earliest blocking layer in flow order is reported as primary and any others are listed after it.

Endpoints accept an address, a CIDR, an instance identifier, or a Name tag. An input matching more than one resource halts with every candidate listed rather than answering for the wrong one.

A symptom narrows the search rather than limiting it — every layer is still reported. Accepted values: ` + strings.Join(symptomNames(), ", ") + `.

Returns the outcome, the blocking layer with its citations, the layers that cleared, and the layers that abstained with their reasons. An abstention is never a pass: where the conclusion rests on one, the report is marked not authoritative, and "no blocker found" with a layer unread is materially weaker than "no blocker found".`,
		Annotations: offline(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in diagnoseIn) (*mcp.CallToolResult, any, error) {
		mode, err := in.mode()
		if err != nil {
			return nil, nil, err
		}

		res, err := ops.Diagnose(ctx, ops.DiagnoseRequest{
			SnapshotPath: in.Snapshot,
			From:         in.From,
			To:           in.To,
			Proto:        orDefault(in.Proto, defaultProto),
			Port:         in.Port,
			Symptom:      in.Symptom,
			SkipFirewall: in.SkipFirewall,
		})
		if err != nil {
			return failed(err)
		}
		return report(res.Report(), mode)
	})
}

// compare ------------------------------------------------------------------

// compareIn is the compare tool's arguments.
type compareIn struct {
	Snapshot     string `json:"snapshot" jsonschema:"path to a snapshot file written by the collect tool; both paths are evaluated against this one collection"`
	From         string `json:"from" jsonschema:"failing path source: an IP address, a CIDR, an instance identifier, or a Name tag"`
	To           string `json:"to" jsonschema:"failing path destination"`
	RefFrom      string `json:"ref_from" jsonschema:"reference path source, the one that works"`
	RefTo        string `json:"ref_to,omitempty" jsonschema:"reference path destination; omit for the same destination as the failing path, which is the ordinary shape of two sources reaching one service"`
	Proto        string `json:"proto,omitempty" jsonschema:"protocol: tcp, udp, icmp, or any; omit for tcp"`
	Port         int    `json:"port,omitempty" jsonschema:"destination port, required for tcp and udp"`
	Symptom      string `json:"symptom,omitempty" jsonschema:"the failure observed on the failing path only; the accepted values are listed in this tool's description"`
	SkipFirewall bool   `json:"skip_firewall,omitempty" jsonschema:"evaluate routing and NACLs only, on both paths"`
	rendering
}

func addCompare(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name: "compare",
		Description: `Report what differs between a failing path and a reference path that works.

Needs a snapshot. Both paths are diagnosed through the same pipeline against one collection, so a difference is a configuration difference rather than an artefact of two evaluations or two collections.

Only the differences are reported. Where every cloud layer matches but the behaviour does not, the report names the layers that remain as an explanation — usually the host. Where a layer abstained on one side, that comparison is reported as incomplete rather than as a match.

The symptom describes the failing path alone. The reference path is the one that works, so there is no observed failure on it to classify. Accepted values: ` + strings.Join(symptomNames(), ", ") + `.

Returns the differences with their citations, the layers that matched, the comparisons that could not be made, and whether the two paths were established as identical everywhere.`,
		Annotations: offline(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in compareIn) (*mcp.CallToolResult, any, error) {
		mode, err := in.mode()
		if err != nil {
			return nil, nil, err
		}

		res, err := ops.Compare(ctx, ops.CompareRequest{
			SnapshotPath: in.Snapshot,
			From:         in.From,
			To:           in.To,
			RefFrom:      in.RefFrom,
			RefTo:        in.RefTo,
			Proto:        orDefault(in.Proto, defaultProto),
			Port:         in.Port,
			Symptom:      in.Symptom,
			SkipFirewall: in.SkipFirewall,
		})
		if err != nil {
			return failed(err)
		}
		return report(res.Report(), mode)
	})
}

// verify -------------------------------------------------------------------

// verifyIn is the verify tool's arguments.
type verifyIn struct {
	Snapshot string `json:"snapshot" jsonschema:"path to a snapshot file written by the collect tool"`
	From     string `json:"from" jsonschema:"source IP address"`
	To       string `json:"to" jsonschema:"destination IP address"`
	Proto    string `json:"proto,omitempty" jsonschema:"protocol: tcp or udp; omit for tcp"`
	Port     int    `json:"port,omitempty" jsonschema:"destination port, required for tcp and udp"`
	Profile  string `json:"profile,omitempty" jsonschema:"credential profile to run the analysis through; either this or config is required unless skip_aws is set"`
	Config   string `json:"config,omitempty" jsonschema:"path to an aws-netpath YAML file, used to find the profile that owns the source region"`
	Region   string `json:"region,omitempty" jsonschema:"region to analyse in; omit for the region the source address sits in"`
	Timeout  *int   `json:"timeout,omitempty" jsonschema:"how long to wait for the analysis, in seconds; omit for 120"`
	SkipAWS  bool   `json:"skip_aws,omitempty" jsonschema:"evaluate the model only and make no AWS call, which needs no credentials and reports the comparison as unestablished"`
	rendering
}

func addVerify(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name: "verify",
		Description: `Cross-check this engine's verdict for a flow against AWS Reachability Analyzer.

Needs a snapshot, and AWS credentials unless skip_aws is set. The analysis is billable and creates an analysis object in the account; it changes no infrastructure.

A single analysis is one region and forward-only over a transit gateway route table, so cross-region and ICMP flows skip the AWS call and the comparison is reported as unestablished rather than guessed at. Those caveats are returned with the result.

Both verdicts are returned with their own evidence, and where they disagree neither is preferred: a disagreement is a finding to investigate, not a vote to settle. Returns the engine verdict with the hop that decided it, the analyser verdict with its analysis reference, whether they agree, and the caveats that limit the comparison.`,
		Annotations: createsAnalysis(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in verifyIn) (*mcp.CallToolResult, any, error) {
		mode, err := in.mode()
		if err != nil {
			return nil, nil, err
		}

		res, err := ops.Verify(ctx, ops.VerifyRequest{
			SnapshotPath: in.Snapshot,
			ConfigPath:   in.Config,
			Profile:      in.Profile,
			Region:       in.Region,
			From:         in.From,
			To:           in.To,
			Proto:        orDefault(in.Proto, defaultProto),
			Port:         in.Port,
			Timeout:      analysisTimeout(in.Timeout),
			SkipAWS:      in.SkipAWS,
		})
		if err != nil {
			// An AWS failure is not a bad request, and the two are fixed
			// differently: an expired login is not a wrong argument.
			var awsErr *ops.AWSError
			if errors.As(err, &awsErr) {
				return nil, nil, fmt.Errorf("aws: %w", awsErr)
			}
			return failed(err)
		}
		return report(ops.VerifyReport(res), mode)
	})
}

// diff ---------------------------------------------------------------------

// diffIn is the diff tool's arguments.
type diffIn struct {
	From string `json:"from" jsonschema:"path to the earlier snapshot"`
	To   string `json:"to" jsonschema:"path to the later snapshot"`
	rendering
}

func addDiff(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name: "diff",
		Description: `Report what changed between two snapshots.

Needs two snapshot files and nothing else. No path is walked and no policy is evaluated, which makes this the cheapest route to a cause: the operator usually knows what broke and needs to find out what moved.

Both files are read even when their schema versions differ, because a collection from before a change and one from after it may have been written by different builds. Where they differ the report states that the comparison may be incomplete, since a field one side records and the other does not cannot be told apart from a field that changed.

Returns the resources added, removed, and modified, grouped by type and by account and region.`,
		Annotations: offline(),
	}, func(_ context.Context, _ *mcp.CallToolRequest, in diffIn) (*mcp.CallToolResult, any, error) {
		mode, err := in.mode()
		if err != nil {
			return nil, nil, err
		}

		res, err := ops.DiffSnapshot(ops.DiffSnapshotRequest{
			FromPath: in.From,
			ToPath:   in.To,
		})
		if err != nil {
			return failed(err)
		}
		return report(res.Report(), mode)
	})
}

// test ---------------------------------------------------------------------

// testFlowsIn is the test tool's arguments.
type testFlowsIn struct {
	Snapshot     string `json:"snapshot" jsonschema:"path to a snapshot file written by the collect tool"`
	Flows        string `json:"flows" jsonschema:"path to a declared flow file: YAML or JSON, with a flows list whose entries carry name, from, to, proto, port, and an expect of permitted or blocked"`
	SkipFirewall bool   `json:"skip_firewall,omitempty" jsonschema:"evaluate routing and NACLs only, on every declared flow"`
	rendering
}

func addTestFlows(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name: "test",
		Description: `Assert a file of declared flows against a snapshot, the way a build gate does.

Needs a snapshot and a declared flow file. Evaluation is offline and makes no AWS call, which is what lets this run on every commit. The host layers are not probed: a declared flow asserts what the network configuration permits, and where the host matters diagnose is the tool that looks.

Each declared flow is resolved, walked, and correlated exactly as a query is, so a flow this reports as blocked is a flow query reports as blocked. A flow whose endpoints cannot be resolved is recorded as inconclusive and the rest are still asserted; a malformed flow file is refused whole.

Returns the flows that did not meet their declaration with both verdicts and the deciding citation, the flows that did, and the flows whose reachability could not be established. An inconclusive flow is neither a pass nor a failure, and a run containing one is marked not authoritative.`,
		Annotations: offline(),
	}, func(_ context.Context, _ *mcp.CallToolRequest, in testFlowsIn) (*mcp.CallToolResult, any, error) {
		mode, err := in.mode()
		if err != nil {
			return nil, nil, err
		}

		res, err := ops.TestFlows(ops.TestFlowsRequest{
			SnapshotPath: in.Snapshot,
			FlowsPath:    in.Flows,
			SkipFirewall: in.SkipFirewall,
		})
		if err != nil {
			return failed(err)
		}
		return report(res.Report(), mode)
	})
}

// Rendering ----------------------------------------------------------------

// maxRows is the row budget one section of a rendered result gets.
//
// Requirement 14.5 asks for markdown suited to low-token consumption, truncating
// repeated rows beyond a configured limit and stating the truncation. This is the
// configured limit for the agent surface, stated rather than defaulted: it is the
// one number that decides what a tool call costs to read, and a value arrived at
// by leaving a field zero is a value nobody chose.
//
// The Formatter's own default is the value, because the budget was picked for this
// audience in the first place — a person at a terminal gets the untruncated text
// rendering, so markdown's limit has only ever had one reader. Two exemptions
// survive it: firewall policy evidence, which requirement 14.4 pins, and the first
// row of each layer, because a layer that vanished entirely would read as a layer
// that was never evaluated.
const maxRows = format.DefaultMaxRows

// report renders an operation's Report as a tool result.
//
// It goes through the Formatter rather than encoding the Report directly, because
// the Formatter is where credential-shaped material is withheld on the way out
// (requirement 14.7), where the row budget is applied (requirement 14.5), and
// where the renderings are kept from disagreeing about what was found.
func report(r format.Report, mode format.Mode) (*mcp.CallToolResult, any, error) {
	var buf bytes.Buffer
	if err := format.Write(&buf, r, format.Options{Mode: mode, MaxRows: maxRows}); err != nil {
		return nil, nil, fmt.Errorf("rendering the report: %w", err)
	}
	return text(buf.String()), nil, nil
}

// text wraps a rendering as tool content.
//
// No structured output is set, and no output schema declared. What an agent reads
// is the rendering, and a schema declared over the Report would describe a nesting
// of sections and rows at greater length than most of the findings it carried.
// Requirement 16.5's stability comes from the Report being a struct rather than
// from a schema restating it.
func text(s string) *mcp.CallToolResult {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: s}}}
}

// Failures -----------------------------------------------------------------

// failed restates an operation's failure as a tool error.
//
// A *ops.FieldError names the input at fault, which is the whole reason it carries
// a field: the CLI reports it as a flag and this reports it as a parameter, so a
// caller is told the name it passed rather than one it has never seen. Anything
// else is passed through — an operation's own message is already written for
// whoever asked. Nothing here panics or exits: a bad request is an answer, not the
// end of the session.
func failed(err error) (*mcp.CallToolResult, any, error) {
	var fieldErr *ops.FieldError
	if errors.As(err, &fieldErr) {
		if cause := fieldErr.Unwrap(); cause != nil {
			return nil, nil, fmt.Errorf("parameter %s is invalid: %w", parameter(fieldErr.Field), cause)
		}
		return nil, nil, fmt.Errorf("parameter %s is required", parameter(fieldErr.Field))
	}
	return nil, nil, err
}

// parameter spells an operation's field name the way this server's schemas do:
// ref-from is a flag, ref_from is a parameter.
func parameter(field string) string {
	return strings.ReplaceAll(field, "-", "_")
}

// Defaults and annotations -------------------------------------------------

// orDefault applies a string default.
//
// It matters most for the protocol: an operation reads an empty protocol as "any",
// which is a wider question than the one an agent leaving the field out is asking,
// and a wider question than the equivalent command would have asked.
func orDefault(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

// seconds resolves an optional second count. The parameter is a pointer because
// zero is meaningful — collect reads it as "no limit" — and an omitted value has
// to be distinguishable from one deliberately set to nothing.
func seconds(value *int, fallback int) int {
	if value == nil {
		return fallback
	}
	return *value
}

// analysisTimeout resolves the analyser's wait.
func analysisTimeout(value *int) time.Duration {
	if value == nil {
		return defaultAnalysisTimeout
	}
	return time.Duration(*value) * time.Second
}

// symptomNames lists the recognised symptoms in the classifier's own order, read
// from it rather than restated, so a tool description cannot offer a value the
// classifier will refuse or omit one it accepts.
func symptomNames() []string {
	in := symptom.Symptoms()
	out := make([]string, 0, len(in))
	for _, s := range in {
		out = append(out, s.String())
	}
	return out
}

// offline annotates a tool that reads a snapshot and reaches nothing else: it
// changes nothing anywhere and makes no network call. An agent that suspects a
// tool might change something will hesitate over one that cannot.
func offline() *mcp.ToolAnnotations {
	return &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: ptr(false)}
}

// writesSnapshot annotates collect. Every AWS call it makes is a Describe, and it
// replaces the file at the output path, so it is not read-only and its write is
// not additive.
func writesSnapshot() *mcp.ToolAnnotations {
	return &mcp.ToolAnnotations{DestructiveHint: ptr(true), OpenWorldHint: ptr(true)}
}

// createsAnalysis annotates verify. Reachability Analyzer path and analysis
// creation are the only calls this tool makes that are not Describe, which makes
// verify the one question that is not read-only: it adds analysis objects to the
// account and is billable, and it changes no infrastructure.
func createsAnalysis() *mcp.ToolAnnotations {
	return &mcp.ToolAnnotations{DestructiveHint: ptr(false), OpenWorldHint: ptr(true)}
}

func ptr(b bool) *bool { return &b }
