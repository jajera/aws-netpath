package ops

import (
	"context"
	"fmt"
	"strings"

	"github.com/jajera/aws-netpath/internal/collect"
	"github.com/jajera/aws-netpath/internal/config"
	"github.com/jajera/aws-netpath/internal/model"
	"github.com/jajera/aws-netpath/internal/snapshot"
)

// CollectRequest ingests live AWS configuration into a snapshot.
//
// Scope is described one of three ways: a config file, a comma-separated set of
// profiles crossed with a set of regions, or a single profile with regions.
// Each account is reached through its own credential profile; no delegated
// administrator or org-wide role is involved.
type CollectRequest struct {
	ConfigPath string
	Profile    string
	Profiles   string
	Regions    string
	Account    string
	AssumeRole string
	// Timeout applies per account+region target, in seconds. Zero means no limit.
	Timeout int
	// OutputPath receives the snapshot. Empty returns the snapshot without
	// writing it.
	OutputPath string
}

// CollectResult summarises a collection run.
type CollectResult struct {
	Snapshot *model.Snapshot `json:"-"`
	// OutputPath is empty when the snapshot was not written to disk.
	OutputPath string `json:"output_path,omitempty"`
	// Targets counts the account+region pairs attempted.
	Targets int `json:"targets"`
	// Errors counts scopes or resource types that could not be read. The
	// snapshot remains usable; the failures are recorded in it.
	Errors int `json:"errors"`
}

// Partial reports whether anything failed to collect. A partial snapshot is
// still worth querying, so this is surfaced rather than turned into an error.
func (r *CollectResult) Partial() bool { return r.Errors > 0 }

// Counts summarises what the collection read, by resource type.
//
// It lives here rather than in an interface's rendering code because both
// interfaces ask the same question of a collection and there is one answer to it:
// a count assembled twice is a count that can disagree with itself. A map rather
// than a struct because it is a summary for a reader rather than a schema to
// assert against, and every consumer sorts the keys.
func (r *CollectResult) Counts() map[string]int {
	if r == nil || r.Snapshot == nil {
		return map[string]int{}
	}
	snap := r.Snapshot
	return map[string]int{
		"accounts":           len(snap.Accounts),
		"regions":            len(snap.Regions),
		"vpcs":               len(snap.VPCs),
		"subnets":            len(snap.Subnets),
		"route_tables":       len(snap.RouteTables),
		"security_groups":    len(snap.SecurityGroups),
		"nacls":              len(snap.NACLs),
		"network_interfaces": len(snap.NetworkIfaces),
		"transit_gateways":   len(snap.TransitGateways),
		"tgw_attachments":    len(snap.TGWAttachments),
		"firewalls":          len(snap.Firewalls),
		"rule_groups":        len(snap.RuleGroups),
	}
}

// ScopeError marks a failure to work out what to collect, as opposed to a
// failure while collecting. The CLI answers these with usage text, since the
// fix is a different invocation.
type ScopeError struct{ Err error }

func (e *ScopeError) Error() string { return e.Err.Error() }
func (e *ScopeError) Unwrap() error { return e.Err }

// Collect ingests every configured account and region in parallel and writes a
// snapshot. Partial failures are recorded in the snapshot rather than aborting
// the run, so one unreadable account does not cost the rest.
func Collect(ctx context.Context, req CollectRequest) (*CollectResult, error) {
	targets, external, err := resolveTargets(req)
	if err != nil {
		return nil, &ScopeError{Err: err}
	}

	result, err := collect.Run(ctx, collect.Options{
		Targets:  targets,
		External: external,
		Timeout:  req.Timeout,
	})
	if err != nil {
		return nil, err
	}

	out := &CollectResult{
		Snapshot: result.Snapshot,
		Targets:  result.Targets,
		Errors:   result.Errors,
	}

	if req.OutputPath != "" {
		if err := snapshot.Save(req.OutputPath, result.Snapshot); err != nil {
			return nil, err
		}
		out.OutputPath = req.OutputPath
	}
	return out, nil
}

// resolveTargets turns a scope description into account+region targets.
func resolveTargets(req CollectRequest) ([]config.Target, []config.ExternalNetwork, error) {
	if req.ConfigPath != "" {
		f, err := config.Load(req.ConfigPath)
		if err != nil {
			return nil, nil, err
		}
		return f.Targets(), f.External, nil
	}

	if req.Profiles != "" {
		if req.Regions == "" {
			return nil, nil, fmt.Errorf("--regions is required with --profiles")
		}
		if req.Profile != "" {
			return nil, nil, fmt.Errorf("use either --profile or --profiles, not both")
		}
		var ts []config.Target
		for _, p := range splitList(req.Profiles) {
			for _, r := range splitList(req.Regions) {
				ts = append(ts, config.Target{
					Profile:    p,
					Region:     r,
					AssumeRole: strings.TrimSpace(req.AssumeRole),
				})
			}
		}
		if len(ts) == 0 {
			return nil, nil, fmt.Errorf("no profiles or regions specified")
		}
		return ts, nil, nil
	}

	if req.Profile == "" || req.Regions == "" {
		return nil, nil, fmt.Errorf("either --config, (--profiles and --regions), or (--profile and --regions) are required")
	}

	var ts []config.Target
	for _, r := range splitList(req.Regions) {
		ts = append(ts, config.Target{
			AccountID:  strings.TrimSpace(req.Account),
			Profile:    strings.TrimSpace(req.Profile),
			Region:     r,
			AssumeRole: strings.TrimSpace(req.AssumeRole),
		})
	}
	if len(ts) == 0 {
		return nil, nil, fmt.Errorf("no regions specified")
	}
	return ts, nil, nil
}

// splitList parses a comma-separated flag value, discarding empty entries so a
// trailing comma is not an error.
func splitList(s string) []string {
	var out []string
	for _, v := range strings.Split(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}
