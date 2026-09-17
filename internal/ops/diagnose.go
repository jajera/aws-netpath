package ops

// The diagnose operation: the eight stages of the documented request flow, in
// order, with nothing between them that could downgrade an Abstention into a
// pass.
//
//  1. Config    — load the Snapshot and validate its schema version.
//  2. Classify  — map the Symptom to candidate Layers and a check order.
//  3. Resolve   — resolve both endpoints; halt on ambiguity.
//  4. Cloud     — walk routes, NACLs, security groups, and firewall policy.
//  5. Return    — walk the reverse Flow and compare next hops.
//  6. Host      — probe the listener and the host firewall allowlist.
//  7. Correlate — apply verdict precedence and reconcile against the Symptom.
//  8. Format    — return the Verdict and the findings behind it.
//
// Stage 1 loads the Snapshot and rejects a schema version this build cannot
// interpret. It loads no account configuration, because it needs none:
// evaluation is offline, and the only stage wanting credentials is the host
// probe, whose client the caller supplies.
//
// Stages 4 and 5 are one call, because they have to be: asymmetry is a
// comparison of the two directions, so neither direction can be walked in
// isolation and then compared afterwards. The Path_Walker performs both and
// reports them separately.
//
// Stage 6 runs whatever stage 4 concluded. That is the whole point of the tool: a
// clean cloud verdict is where host investigation begins, not where the run ends.
// The probe reaches the instance through Systems Manager rather than through the
// path under test, so a blocked path is no reason to skip it either — and a
// complete report of both halves is what makes the two comparable.
//
// Stage 8 returns structure, not text. Rendering is the Formatter's job, so this
// hands back the correlated model.Verdict alongside the walk and the host
// findings it rests on, and exit-code mapping stays with the CLI.

import (
	"context"
	"fmt"
	"strings"

	"github.com/jajera/aws-netpath/internal/correlate"
	"github.com/jajera/aws-netpath/internal/flow"
	"github.com/jajera/aws-netpath/internal/host"
	"github.com/jajera/aws-netpath/internal/model"
	"github.com/jajera/aws-netpath/internal/query"
	"github.com/jajera/aws-netpath/internal/symptom"
)

// resolutionCitationKind is the evidence category for a resolution finding: the
// resource the endpoint resolved to.
const resolutionCitationKind = "resolution"

// HostProber is the host surface the host stage needs: whether an instance can
// be probed at all, and one validated command at a time. *host.Runner implements
// it.
//
// It is an interface, and nil is a supported value, because Systems Manager
// access is not a precondition for a diagnosis. Without a prober the host Layers
// abstain with the reason, which is requirement 8.6 — and "cloud clear, host
// unverified" remains a materially different answer from "all clear".
type HostProber interface {
	Managed(ctx context.Context, instanceID string) (host.ManagedInstance, error)
	Run(ctx context.Context, instanceID string, cmd host.Command) (host.Result, error)
}

// DiagnoseRequest asks why a flow fails.
type DiagnoseRequest struct {
	// SnapshotPath locates the Snapshot. Snapshot takes precedence when both are
	// given.
	SnapshotPath string
	// Snapshot supplies an already-loaded Snapshot, which is how a caller
	// evaluating two paths against one collection avoids reading it twice.
	Snapshot *model.Snapshot

	// From and To are endpoints in any form ResolveEndpoint accepts: an address,
	// a CIDR, an instance ID, or a Name tag.
	From string
	To   string
	// Proto and Port describe the traffic. Port is required for TCP and UDP.
	Proto string
	Port  int
	// Symptom is the failure the operator observed, empty when none was given.
	// With no Symptom the Layers are evaluated in flow order.
	Symptom string
	// SkipFirewall evaluates routing and NACLs only, isolating a policy question
	// from a routing one.
	SkipFirewall bool

	// Prober dispatches the host checks. Nil abstains the host Layers.
	Prober HostProber
	// InstanceID overrides the instance probed, for a destination whose
	// interface the Snapshot does not attribute to one.
	InstanceID string
	// Zone is the firewalld zone read on the host. Empty uses the default zone,
	// which every citation names so a wrong guess is visible.
	Zone string
}

// HostStage is what stage 6 did.
type HostStage struct {
	// InstanceID is the instance probed, empty when none could be.
	InstanceID string `json:"instance_id,omitempty"`
	// Probed is true when at least one command was dispatched.
	Probed bool `json:"probed"`
	// Managed is what Systems Manager reported about the instance, and is the
	// evidence for an abstention when the instance could not be probed.
	Managed *host.ManagedInstance `json:"managed,omitempty"`
	// Results are the HOST_FIREWALL and HOST_LISTENER Layer findings. There is
	// always one of each: an unprobed host abstains rather than going unreported.
	Results []model.LayerResult `json:"results,omitempty"`
	// Findings are the supporting checks, which carry evidence rather than
	// verdicts.
	Findings []host.Finding `json:"findings,omitempty"`
	// Reason states why nothing was probed, empty when something was.
	Reason string `json:"reason,omitempty"`
}

// DiagnoseResult is the outcome of the eight stages.
type DiagnoseResult struct {
	Flow           flow.Slice             `json:"flow"`
	Classification symptom.Classification `json:"classification"`
	Source         Endpoint               `json:"source"`
	Destination    Endpoint               `json:"destination"`
	// Walk is the cloud-layer result, including the return direction and any
	// asymmetry between the two.
	Walk *query.Result `json:"walk,omitempty"`
	Host HostStage     `json:"host"`
	// Verdict is the correlated outcome: one primary blocking Layer, or none
	// found, with every Layer finding and Abstention behind it.
	Verdict model.Verdict `json:"verdict"`
	Notes   []string      `json:"notes,omitempty"`
}

// Blocked reports whether a Layer blocked the flow.
func (r *DiagnoseResult) Blocked() bool { return r.Verdict.PrimaryBlocker != nil }

// Established reports whether the Verdict was reached with every
// conclusion-affecting Layer evaluated.
//
// False means the diagnosis rests on an Abstention, which requirement 14.6 makes
// non-authoritative and cross-cutting 1 forbids reading as a pass. "No blocker
// found" with a Layer unread is materially weaker than "no blocker found" — the
// unread Layer might have been the one blocking — so the two are distinguishable
// here rather than only in the rendered text. Exposed for the CLI's exit-code
// mapping, which is the one place that acts on it.
func (r *DiagnoseResult) Established() bool { return r != nil && r.Verdict.Authoritative }

// PrimaryBlocker returns the primary blocking Layer. The second return value is
// false when no blocker was found, which is requirement 14.1's other half.
func (r *DiagnoseResult) PrimaryBlocker() (model.Layer, bool) {
	if r.Verdict.PrimaryBlocker == nil {
		return "", false
	}
	return *r.Verdict.PrimaryBlocker, true
}

// Diagnose runs the full pipeline for one flow.
//
// Validation order is fixed — required fields, protocol and port, Symptom, then
// the Snapshot and the endpoints in it — so an invocation with several problems
// always reports the same one first.
func Diagnose(ctx context.Context, req DiagnoseRequest) (*DiagnoseResult, error) {
	if err := requireFields(
		requiredField{"from", req.From},
		requiredField{"to", req.To},
	); err != nil {
		return nil, err
	}
	proto, err := parseProtoPort(req.Proto, req.Port)
	if err != nil {
		return nil, err
	}

	// Stage 2, before the Snapshot is touched: classification is pure logic, so
	// an unrecognised Symptom is reported without a file having been read.
	classification, err := stageClassify(req.Symptom)
	if err != nil {
		return nil, err
	}

	// Stage 1.
	snap, err := stageSnapshot(req)
	if err != nil {
		return nil, err
	}

	// Stage 3.
	src, dst, err := stageResolve(snap, req)
	if err != nil {
		return nil, err
	}

	result := &DiagnoseResult{
		Classification: classification,
		Source:         src,
		Destination:    dst,
	}
	result.Notes = append(result.Notes, src.Notes...)
	result.Notes = append(result.Notes, dst.Notes...)

	// Stages 4 and 5.
	walk, err := query.Run(query.Options{
		Snapshot:     snap,
		SrcIP:        src.Addr,
		DstIP:        dst.Addr,
		Proto:        proto,
		Port:         req.Port,
		SkipFirewall: req.SkipFirewall,
	})
	if err != nil {
		return nil, err
	}
	result.Walk = walk
	result.Flow = walk.Flow

	// Stage 6, whatever stages 4 and 5 concluded.
	result.Host = stageHost(ctx, req, src, dst, proto, classification)

	// Stage 7.
	results := append(walk.LayerResults(), result.Host.Results...)
	results = append(results, resolutionResult(src, dst))
	verdict, err := correlate.Correlate(correlate.Input{
		Symptom:      classification.Symptom,
		Results:      results,
		Observations: walk.Observations(),
	})
	if err != nil {
		return nil, err
	}
	result.Verdict = verdict

	// Stage 8: structure for the Formatter, plus the notes the walk collected on
	// the way.
	result.Notes = append(result.Notes, walk.Notes...)
	if result.Host.Reason != "" {
		result.Notes = append(result.Notes, result.Host.Reason)
	}
	return result, nil
}

// stageClassify maps the Symptom, if any, to candidate Layers and a check order.
// With no Symptom the check order is flow order, which is requirement 9.5.
func stageClassify(input string) (symptom.Classification, error) {
	s, err := symptom.Parse(input)
	if err != nil {
		return symptom.Classification{}, badField("symptom", err)
	}
	return symptom.Classify(s)
}

// stageSnapshot loads the Snapshot, rejecting a schema version this build cannot
// interpret. An already-loaded Snapshot is taken as given: it came through the
// same door.
func stageSnapshot(req DiagnoseRequest) (*model.Snapshot, error) {
	if req.Snapshot != nil {
		return req.Snapshot, nil
	}
	if req.SnapshotPath == "" {
		return nil, missingField("snapshot")
	}
	return loadSnapshot(req.SnapshotPath)
}

// stageResolve resolves both endpoints. An ambiguous input halts the run with
// every candidate listed, and an input matching nothing halts with the accounts
// and regions the Snapshot covers.
func stageResolve(snap *model.Snapshot, req DiagnoseRequest) (src, dst Endpoint, err error) {
	if src, err = ResolveEndpoint(snap, "from", req.From); err != nil {
		return Endpoint{}, Endpoint{}, err
	}
	if dst, err = ResolveEndpoint(snap, "to", req.To); err != nil {
		return Endpoint{}, Endpoint{}, err
	}
	return src, dst, nil
}

// resolutionResult reports the RESOLUTION Layer for the two endpoints.
//
// It is a pass whenever both endpoints were identified, including an external
// one: requirement 6.5 makes address space outside every collected VPC an
// ordinary node, so resolving it is a success and the destination-side
// Abstention the walk records is a separate statement about policy. Where the
// walk could not place an address at all it records its own RESOLUTION
// Abstention, and aggregation keeps that over this pass.
func resolutionResult(src, dst Endpoint) model.LayerResult {
	return model.LayerResult{
		Layer:   model.LayerResolution,
		Verdict: model.VerdictPass,
		Citations: []model.Citation{
			endpointCitation("source", src),
			endpointCitation("destination", dst),
		},
	}
}

func endpointCitation(role string, e Endpoint) model.Citation {
	identifier := e.InterfaceID
	for _, candidate := range []string{e.SubnetID, e.VPCID, e.ExternalNetworkID} {
		if identifier != "" {
			break
		}
		identifier = candidate
	}
	if identifier == "" {
		identifier = e.Addr.String()
	}
	return model.Citation{
		Kind:       resolutionCitationKind,
		Identifier: identifier,
		Detail:     fmt.Sprintf("%s %s resolved to %s", role, e.Input, e.Description()),
	}
}

// stageHost probes the destination host.
//
// Every path out of here produces one finding per host Layer. An unprobeable host
// abstains with the reason — no prober, no instance, an instance Systems Manager
// does not manage, a command that could not be delivered — because a host Layer
// missing from the report reads as a Layer nobody needed to check.
func stageHost(ctx context.Context, req DiagnoseRequest, src, dst Endpoint, proto flow.Protocol, classification symptom.Classification) HostStage {
	stage := HostStage{}

	if req.Prober == nil {
		err := fmt.Errorf("%w: the diagnose operation was given no systems manager client, so the host was not probed",
			host.ErrUndeliverable)
		stage.Reason = err.Error()
		stage.Results = host.AbstainAll(err)
		return stage
	}

	instanceID := strings.TrimSpace(req.InstanceID)
	if instanceID == "" {
		instanceID = dst.InstanceID
	}
	if instanceID == "" {
		err := fmt.Errorf("%w: destination %s resolved to %s, which the snapshot attributes to no instance",
			host.ErrUnmanaged, dst.Input, dst.Description())
		stage.Reason = err.Error()
		stage.Results = host.AbstainAll(err)
		return stage
	}
	stage.InstanceID = instanceID

	managed, err := req.Prober.Managed(ctx, instanceID)
	stage.Managed = &managed
	if err != nil {
		stage.Reason = err.Error()
		stage.Results = host.AbstainAll(err)
		return stage
	}
	stage.Probed = true

	port := uint16(req.Port)
	stage.Results = append(stage.Results,
		host.ListenerCheck(ctx, req.Prober, instanceID, host.ListenerRequest{
			Destination: dst.Addr, Protocol: proto, Port: port,
		}),
		host.FirewallCheck(ctx, req.Prober, instanceID, host.FirewallRequest{
			Zone: req.Zone, Source: src.Addr, Protocol: proto, Port: port,
		}),
	)

	// The supporting checks run from the destination back towards the source,
	// which is the direction they say something about: the route reports the
	// address the host would answer from, and that is the address the source's
	// own allowlist will match against.
	stage.Findings = append(stage.Findings, host.RouteCheck(ctx, req.Prober, instanceID, src.Addr))
	if wantsPathMTU(classification) {
		stage.Findings = append(stage.Findings, host.PathMTUCheck(ctx, req.Prober, instanceID, src.Addr, 0))
	}
	return stage
}

// pathMTUCheckName is how the Symptom_Classifier names the path MTU check. It has
// no Layer of its own, so it is matched by name.
const pathMTUCheckName = "path MTU"

// wantsPathMTU reports whether the Symptom implicates path MTU. The probe sends
// traffic, so it runs when something points at it rather than on every
// diagnosis; a large-packet failure explains a stall, and nothing else.
func wantsPathMTU(c symptom.Classification) bool {
	for _, check := range c.ExtraChecks {
		if strings.EqualFold(check, pathMTUCheckName) {
			return true
		}
	}
	return false
}
