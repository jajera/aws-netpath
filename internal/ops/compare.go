package ops

// The compare operation: diagnose twice, then subtract.
//
// Baseline comparison is the third of the four things this tool adds to the
// inherited engine, and it is the cheapest to get wrong. The temptation is to
// write a second, lighter evaluation for the reference path — it is only a
// baseline, after all — and the result is two implementations that can disagree
// about what a Layer concluded, which turns every comparison into a question
// about the comparator. So the reference path goes through the same pipeline as
// the failing one, stage for stage, and the Comparator only subtracts.
//
// The Snapshot is loaded once and handed to both runs. Evaluation is offline, so
// the two paths are answered from one collection at one moment: comparing a path
// against a baseline drawn from a different snapshot would attribute a
// collection difference to a configuration difference.
//
// The Symptom belongs to the failing path alone. The reference path is the one
// that works, so there is no observed failure on it to classify, and passing the
// Symptom to both would ask the classifier to explain a success.

import (
	"context"
	"fmt"

	"github.com/jajera/aws-netpath/internal/compare"
	"github.com/jajera/aws-netpath/internal/model"
)

// CompareRequest asks what differs between a failing path and one that works.
type CompareRequest struct {
	// SnapshotPath locates the Snapshot. Snapshot takes precedence when both are
	// given.
	SnapshotPath string
	Snapshot     *model.Snapshot

	// From and To are the failing path, in any form ResolveEndpoint accepts.
	From string
	To   string
	// RefFrom and RefTo are the reference path. An empty RefTo means the same
	// destination, which is the ordinary shape: two sources, one service, one of
	// them working.
	RefFrom string
	RefTo   string

	// Proto and Port describe the traffic. Both paths are evaluated for the same
	// traffic — comparing different flows would compare two unrelated questions.
	Proto string
	Port  int
	// Symptom is the failure observed on the failing path. It is not applied to
	// the reference path.
	Symptom string
	// SkipFirewall evaluates routing and NACLs only, on both paths.
	SkipFirewall bool

	// Prober dispatches the host checks for both paths. Nil abstains the host
	// Layers on both, which makes those Layers' comparison incomplete rather
	// than equal.
	Prober HostProber
	// InstanceID and RefInstanceID override the instance probed for each path.
	InstanceID    string
	RefInstanceID string
	// Zone is the firewalld zone read on both hosts.
	Zone string
}

// CompareResult is the diff and the two diagnoses behind it.
type CompareResult struct {
	// Diff is the answer: the differences, the comparisons that could not be
	// made, and the Layers that remain as an explanation when the cloud Layers
	// match.
	Diff *compare.Result `json:"diff"`
	// Subject and Reference are the full diagnoses. They are returned so a
	// difference can be read in context, and are not what the Formatter leads
	// with: requirement 10.1 asks for the differences, not for both paths in
	// full.
	Subject   *DiagnoseResult `json:"subject"`
	Reference *DiagnoseResult `json:"reference"`
}

// Differs reports whether the two paths were found to differ anywhere.
func (r *CompareResult) Differs() bool { return r.Diff != nil && r.Diff.Differs() }

// Established reports whether every Layer could be compared and both paths'
// own verdicts were authoritative.
//
// False is requirement 10.4's outcome: a Layer that abstained on one side has
// not been shown to match and has not been shown to differ, so "the two paths
// are identical" was not established. Exposed for the CLI's exit-code mapping.
func (r *CompareResult) Established() bool {
	return r != nil && r.Diff != nil && r.Diff.Authoritative
}

// Compare diagnoses both paths against one Snapshot and reports what differs.
//
// Validation order is fixed — the failing path's fields, the reference path's,
// then the traffic — so an invocation with several problems always reports the
// same one first. Errors from either diagnosis are wrapped with the path they
// came from, because "matches no collected instance" is not actionable until the
// operator knows which endpoint it referred to.
func Compare(ctx context.Context, req CompareRequest) (*CompareResult, error) {
	if err := requireFields(
		requiredField{"from", req.From},
		requiredField{"to", req.To},
		requiredField{"ref-from", req.RefFrom},
	); err != nil {
		return nil, err
	}
	// Classified here as well as inside the subject diagnosis, for the same reason
	// diagnose classifies before it reads anything: an unrecognised Symptom is a
	// bad request, and reporting it as one of two paths having failed would name
	// the wrong problem.
	if _, err := stageClassify(req.Symptom); err != nil {
		return nil, err
	}

	// Loaded once, shared by both runs: one collection, one moment, two paths.
	snap, err := stageSnapshot(DiagnoseRequest{
		SnapshotPath: req.SnapshotPath, Snapshot: req.Snapshot,
	})
	if err != nil {
		return nil, err
	}

	subject, err := Diagnose(ctx, DiagnoseRequest{
		Snapshot: snap,
		From:     req.From, To: req.To,
		Proto: req.Proto, Port: req.Port,
		Symptom: req.Symptom, SkipFirewall: req.SkipFirewall,
		Prober: req.Prober, InstanceID: req.InstanceID, Zone: req.Zone,
	})
	if err != nil {
		return nil, fmt.Errorf("%s path: %w", compare.SubjectLabel, err)
	}

	refTo := req.RefTo
	if refTo == "" {
		refTo = req.To
	}
	reference, err := Diagnose(ctx, DiagnoseRequest{
		Snapshot: snap,
		From:     req.RefFrom, To: refTo,
		Proto: req.Proto, Port: req.Port,
		SkipFirewall: req.SkipFirewall,
		Prober:       req.Prober, InstanceID: req.RefInstanceID, Zone: req.Zone,
	})
	if err != nil {
		return nil, fmt.Errorf("%s path: %w", compare.ReferenceLabel, err)
	}

	diff, err := compare.Paths(
		compareSide(compare.SubjectLabel, req.From, req.To, subject),
		compareSide(compare.ReferenceLabel, req.RefFrom, refTo, reference),
	)
	if err != nil {
		return nil, err
	}

	return &CompareResult{Diff: diff, Subject: subject, Reference: reference}, nil
}

// compareSide projects a diagnosis onto the side the Comparator consumes. The
// endpoints are the operator's own words rather than the resolved addresses,
// because the operator has to recognise which path a difference belongs to.
func compareSide(label, from, to string, res *DiagnoseResult) compare.Side {
	return compare.Side{
		Label: label, From: from, To: to,
		Symptom: res.Classification.Symptom,
		Verdict: res.Verdict,
	}
}
