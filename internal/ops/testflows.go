package ops

// The test operation: assert a file of declared flows against one Snapshot.
//
// This is the build-gate face of the same engine the other operations use. Each
// declared flow is resolved, walked, and correlated exactly as a query is, so a
// flow the gate calls blocked is a flow `query` calls blocked — there is no second
// evaluation to drift.
//
// The Snapshot is loaded once for the whole file. A gate asserting twenty flows
// against twenty collections would attribute a collection difference to a
// configuration change, which is the opposite of what it exists to catch.
//
// The host stage does not run, and that is deliberate rather than an omission.
// Host probing reaches an instance through Systems Manager, so it needs
// credentials and costs an API call per check; cross-cutting 5 makes offline
// evaluation the property that lets this run on every commit for nothing. A
// declared flow asserts what the network configuration permits, and where the host
// matters `diagnose` is the operation that looks.
//
// One bad flow does not stop the run. An endpoint that resolves to nothing is
// recorded against that flow as inconclusive and the rest are still asserted,
// because a gate that reports "stopped at flow 3" has told the operator nothing
// about flows 4 to 20. A malformed file is different: that is refused whole,
// before anything is walked.

import (
	"github.com/jajera/aws-netpath/internal/correlate"
	"github.com/jajera/aws-netpath/internal/flowtest"
	"github.com/jajera/aws-netpath/internal/model"
	"github.com/jajera/aws-netpath/internal/query"
)

// TestFlowsRequest asserts a file of declared flows.
type TestFlowsRequest struct {
	// SnapshotPath locates the Snapshot. Snapshot takes precedence when both are
	// given.
	SnapshotPath string
	Snapshot     *model.Snapshot

	// FlowsPath locates the declared flow file. Flows takes precedence when both
	// are given.
	FlowsPath string
	Flows     *flowtest.File

	// SkipFirewall evaluates routing and NACLs only, on every declared flow.
	SkipFirewall bool
}

// TestFlowsResult is the run.
type TestFlowsResult struct {
	Result *flowtest.Result `json:"result"`
}

// Failed reports whether any declared flow did not meet its expected verdict.
// Requirement 12.3 maps this to exit 1; the mapping is the CLI's, so nothing here
// exits.
func (r *TestFlowsResult) Failed() bool { return r != nil && r.Result.Failed() }

// Inconclusive reports whether any declared flow's reachability could not be
// established. Kept separate from Failed because an inconclusive flow is not a
// regression and is not a pass either. Requirement 12.4.
func (r *TestFlowsResult) Inconclusive() bool { return r != nil && r.Result.Inconclusive() }

// Established reports whether every declared flow's reachability was
// demonstrated. The inverse of Inconclusive, named for the exit-code mapping so
// every operation answers the same question in the same words.
func (r *TestFlowsResult) Established() bool {
	return r != nil && r.Result != nil && r.Result.Authoritative
}

// TestFlows evaluates every declared flow against one Snapshot and reports which
// met their expected verdict.
//
// Validation order is fixed — the declared flows, then the Snapshot — so an
// invocation with several problems always reports the same one first. The flow
// file comes first because it is the assertion set: a file that cannot be read
// asserts nothing, whatever Snapshot it would have been asserted against.
func TestFlows(req TestFlowsRequest) (*TestFlowsResult, error) {
	declared, err := stageDeclaredFlows(req)
	if err != nil {
		return nil, err
	}

	snap, err := stageSnapshot(DiagnoseRequest{
		SnapshotPath: req.SnapshotPath, Snapshot: req.Snapshot,
	})
	if err != nil {
		return nil, err
	}

	cases := make([]flowtest.Case, 0, len(declared.Flows))
	for _, d := range declared.Flows {
		cases = append(cases, flowtest.Judge(d, evaluateDeclared(snap, d, req.SkipFirewall)))
	}
	return &TestFlowsResult{Result: flowtest.Summarise(cases)}, nil
}

// stageDeclaredFlows loads the declared flows, validating a file supplied in
// memory on the same terms as one read from disk: an MCP client and a CLI both
// arrive here, and only one of them went through the parser.
func stageDeclaredFlows(req TestFlowsRequest) (*flowtest.File, error) {
	if req.Flows != nil {
		if err := req.Flows.Validate(); err != nil {
			return nil, err
		}
		return req.Flows, nil
	}
	if req.FlowsPath == "" {
		return nil, missingField("flows")
	}
	return flowtest.Load(req.FlowsPath)
}

// evaluateDeclared resolves, walks, and correlates one declared flow.
//
// It is the diagnose pipeline without stages 2 and 6: no Symptom, because a
// declared flow reports no observed failure to classify, and no host probe,
// because the gate is offline. The stages it does run are the same functions
// diagnose runs, and the correlated Verdict it produces is the same shape, so the
// judgement is made on findings this tool produces exactly once.
//
// Every failure is returned on the Evaluation rather than raised, so the flow it
// belongs to is reported as inconclusive and the remaining flows are still
// asserted.
func evaluateDeclared(snap *model.Snapshot, d flowtest.Declared, skipFirewall bool) flowtest.Evaluation {
	proto, err := parseProtoPort(d.Proto, d.Port)
	if err != nil {
		return flowtest.Evaluation{Err: err}
	}

	src, dst, err := stageResolve(snap, DiagnoseRequest{From: d.From, To: d.To})
	if err != nil {
		return flowtest.Evaluation{Err: err}
	}

	walk, err := query.Run(query.Options{
		Snapshot:     snap,
		SrcIP:        src.Addr,
		DstIP:        dst.Addr,
		Proto:        proto,
		Port:         d.Port,
		SkipFirewall: skipFirewall,
	})
	if err != nil {
		return flowtest.Evaluation{Err: err}
	}

	results := append(walk.LayerResults(), resolutionResult(src, dst))
	verdict, err := correlate.Correlate(correlate.Input{
		Results:      results,
		Observations: walk.Observations(),
	})
	if err != nil {
		return flowtest.Evaluation{Flow: walk.Flow.String(), Err: err}
	}
	return flowtest.Evaluation{Flow: walk.Flow.String(), Verdict: verdict}
}
