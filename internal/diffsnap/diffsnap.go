// Package diffsnap reports what changed between two Snapshots.
//
// It answers the question an operator asks the moment something breaks: what is
// different now. A Snapshot is a JSON file that can be kept, so the collection
// from before a change and the collection from after it are both available, and
// the difference between them is a short list where the incident report is a long
// one. Requirement 11.1 asks for the resources added, removed, and modified;
// requirement 11.2 asks for them grouped by type and by account and region,
// because "a route table changed" is a different sentence from "a route table
// changed in the account you were not looking at".
//
// Nothing is evaluated here. This package compares two models and reports
// differences; it does not walk a path, decide reachability, or rank a change by
// how likely it is to be the cause. A diff that guessed which change mattered
// would be wrong exactly when it was needed most, and the operator reading it
// already knows what they changed.
//
// Pure logic, and deterministic. No AWS SDK, no file access — the caller loads
// both Snapshots. Groups are emitted in a fixed type order and then by account
// and region, and changes within a group in a fixed kind order and then by
// identifier, so two runs over the same pair of Snapshots render identically and
// a diff of two diffs shows only what really moved.
//
// Modification is detected field by field through the model's own JSON encoding
// rather than through per-type comparison code. That is a deliberate trade: a
// deep change inside a resource is reported as its top-level field rather than as
// the individual route or rule that moved, and in exchange every resource type
// present in the model is covered, including the ones added after this package
// was written. A diff that silently skips a type it was never taught about is the
// worse failure.
//
// Two conditions make a diff less than a complete account of what changed, and
// both are reported rather than absorbed. Differing schema versions mean a field
// one side records and the other does not cannot be compared — requirement 11.3.
// And a collection error on either side means a resource reported as added or
// removed may be one that could not be read rather than one that changed, which
// is the same stance the rest of the tool takes towards anything it could not
// establish.
package diffsnap

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jajera/aws-netpath/internal/model"
)

// Labels for the two sides. The Snapshot named first is the earlier one by
// convention, and the labels say so: "before" and "after" are what the operator
// is comparing, whatever the file names happen to be.
const (
	FromLabel = "before"
	ToLabel   = "after"
)

// Kind is what happened to one resource between the two Snapshots.
type Kind string

const (
	KindAdded    Kind = "added"
	KindRemoved  Kind = "removed"
	KindModified Kind = "modified"
)

// kindOrder is the order changes are reported within a group: what appeared,
// what disappeared, then what was altered in place.
var kindOrder = []Kind{KindAdded, KindRemoved, KindModified}

func (k Kind) order() int {
	for i, candidate := range kindOrder {
		if candidate == k {
			return i
		}
	}
	return len(kindOrder)
}

// Resource type names. They are the Snapshot's own JSON vocabulary in the
// singular, so a group heading and the field an operator would look at in the
// file are spelled the same way.
const (
	TypeVPC             = "vpc"
	TypeSubnet          = "subnet"
	TypeRouteTable      = "route_table"
	TypeSecurityGroup   = "security_group"
	TypeNACL            = "nacl"
	TypeNetworkIface    = "network_interface"
	TypeTransitGateway  = "transit_gateway"
	TypeTGWRouteTable   = "tgw_route_table"
	TypeTGWAttachment   = "tgw_attachment"
	TypeVPCPeering      = "vpc_peering"
	TypeFirewall        = "firewall"
	TypeFirewallPolicy  = "firewall_policy"
	TypeRuleGroup       = "rule_group"
	TypeExternalNetwork = "external_network"
)

// typeOrder is the order resource types are reported in. It follows the order
// they are declared on the Snapshot — address space, then subnets, then the
// policy attached to them, then the gateways between them — rather than
// alphabetical order, so a reader meets a changed subnet next to the route table
// that serves it.
var typeOrder = []string{
	TypeVPC,
	TypeSubnet,
	TypeRouteTable,
	TypeSecurityGroup,
	TypeNACL,
	TypeNetworkIface,
	TypeTransitGateway,
	TypeTGWRouteTable,
	TypeTGWAttachment,
	TypeVPCPeering,
	TypeFirewall,
	TypeFirewallPolicy,
	TypeRuleGroup,
	TypeExternalNetwork,
}

func typeIndex(t string) int {
	for i, candidate := range typeOrder {
		if candidate == t {
			return i
		}
	}
	return len(typeOrder)
}

// maxSummaryValue caps a field value quoted inline in a summary. The full values
// stay on the FieldChange, so nothing is lost — a route table's entire route set
// on one line is simply not something a reader can use.
const maxSummaryValue = 96

// unscoped labels a resource whose account and region the collector did not
// record, which is what an older Snapshot carries.
const unscoped = "unscoped"

// FieldChange is one field that differs, with both values as the model encodes
// them. An empty Before means the field was absent from the earlier Snapshot,
// and an empty After that it is absent from the later one.
type FieldChange struct {
	Field  string `json:"field"`
	Before string `json:"before,omitempty"`
	After  string `json:"after,omitempty"`
}

// Change is one resource that appeared, disappeared, or was altered.
//
// Account and Region are on the Change as well as on its Group, so a consumer
// reading a change on its own — a JSON client, a test — does not have to carry
// the grouping to know where the resource lives.
type Change struct {
	Kind Kind   `json:"kind"`
	Type string `json:"type"`
	ID   string `json:"id"`
	// Name is the resource's Name tag, empty when it was never tagged. It is
	// carried because it is what the operator recognises: an identifier locates a
	// resource and a name identifies it.
	Name    string `json:"name,omitempty"`
	Account string `json:"account,omitempty"`
	Region  string `json:"region,omitempty"`
	// Fields are the differing fields, present only for a modification and
	// ordered by field name.
	Fields []FieldChange `json:"fields,omitempty"`
	// Summary states the change in one line.
	Summary string `json:"summary"`
}

// Group is one resource type in one account and region. Requirement 11.2.
type Group struct {
	Type    string `json:"type"`
	Account string `json:"account,omitempty"`
	Region  string `json:"region,omitempty"`
	// Changes are the differences in this group, ordered by kind and then by
	// identifier.
	Changes  []Change `json:"changes,omitempty"`
	Added    int      `json:"added"`
	Removed  int      `json:"removed"`
	Modified int      `json:"modified"`
	// Unchanged counts the resources of this type present in both Snapshots with
	// no field difference. It is a count and not a list: naming every resource
	// that did not change would bury the ones that did.
	Unchanged int `json:"unchanged"`
}

// Changed reports whether this group carries any difference.
func (g Group) Changed() bool { return len(g.Changes) > 0 }

// Scope renders the account and region a group covers.
func (g Group) Scope() string {
	switch {
	case g.Account != "" && g.Region != "":
		return g.Account + " / " + g.Region
	case g.Account != "":
		return g.Account
	case g.Region != "":
		return g.Region
	default:
		return unscoped
	}
}

// Label renders the group heading: the resource type and where it lives.
func (g Group) Label() string { return g.Type + " — " + g.Scope() }

// SnapshotSummary identifies one side of the comparison without repeating it.
type SnapshotSummary struct {
	Label            string    `json:"label"`
	SchemaVersion    int       `json:"schema_version"`
	CapturedAt       time.Time `json:"captured_at"`
	Resources        int       `json:"resources"`
	CollectionErrors int       `json:"collection_errors"`
}

// Caveat is something that makes this diff less than a complete account of what
// changed. It is not a difference and never becomes one.
type Caveat struct {
	Subject string `json:"subject"`
	Summary string `json:"summary"`
}

// Result is the diff.
type Result struct {
	From SnapshotSummary `json:"from"`
	To   SnapshotSummary `json:"to"`
	// Groups carries every type and scope either Snapshot holds, including those
	// with nothing but unchanged resources, so "nothing changed in this region"
	// is something the report can state rather than imply.
	Groups   []Group `json:"groups,omitempty"`
	Added    int     `json:"added"`
	Removed  int     `json:"removed"`
	Modified int     `json:"modified"`
	// Unchanged counts resources present in both Snapshots with no difference.
	Unchanged int `json:"unchanged"`
	// Caveats are the reasons this diff may be incomplete, each with what it
	// leaves unestablished. Requirement 11.3 is one of them.
	Caveats []Caveat `json:"caveats,omitempty"`
	// Complete is false when any Caveat applies.
	Complete bool     `json:"complete"`
	Notes    []string `json:"notes,omitempty"`
}

// Changed reports whether anything differs between the two Snapshots.
func (r *Result) Changed() bool {
	return r != nil && r.Added+r.Removed+r.Modified > 0
}

// ChangedGroups returns the groups carrying differences, in report order.
func (r *Result) ChangedGroups() []Group {
	if r == nil {
		return nil
	}
	out := make([]Group, 0, len(r.Groups))
	for _, g := range r.Groups {
		if g.Changed() {
			out = append(out, g)
		}
	}
	return out
}

// UnchangedGroups returns the groups whose resources are all identical, in
// report order.
func (r *Result) UnchangedGroups() []Group {
	if r == nil {
		return nil
	}
	out := make([]Group, 0, len(r.Groups))
	for _, g := range r.Groups {
		if !g.Changed() && g.Unchanged > 0 {
			out = append(out, g)
		}
	}
	return out
}

// Snapshots reports what changed between two Snapshots.
//
// Both are required: diffing a Snapshot against nothing produces a list in which
// every resource was added, which reads like a collection and is not one.
func Snapshots(from, to *model.Snapshot) (*Result, error) {
	if from == nil || to == nil {
		return nil, fmt.Errorf("diffsnap: two snapshots are required, the %s snapshot and the %s snapshot", FromLabel, ToLabel)
	}

	d := &differ{groups: map[groupKey]*Group{}}
	diffType(d, TypeVPC, from.VPCs, to.VPCs, func(v *model.VPC) model.Meta { return v.Meta })
	diffType(d, TypeSubnet, from.Subnets, to.Subnets, func(v *model.Subnet) model.Meta { return v.Meta })
	diffType(d, TypeRouteTable, from.RouteTables, to.RouteTables, func(v *model.RouteTable) model.Meta { return v.Meta })
	diffType(d, TypeSecurityGroup, from.SecurityGroups, to.SecurityGroups, func(v *model.SecurityGroup) model.Meta { return v.Meta })
	diffType(d, TypeNACL, from.NACLs, to.NACLs, func(v *model.NACL) model.Meta { return v.Meta })
	diffType(d, TypeNetworkIface, from.NetworkIfaces, to.NetworkIfaces, func(v *model.NetworkIface) model.Meta { return v.Meta })
	diffType(d, TypeTransitGateway, from.TransitGateways, to.TransitGateways, func(v *model.TransitGateway) model.Meta { return v.Meta })
	diffType(d, TypeTGWRouteTable, from.TGWRouteTables, to.TGWRouteTables, func(v *model.TGWRouteTable) model.Meta { return v.Meta })
	diffType(d, TypeTGWAttachment, from.TGWAttachments, to.TGWAttachments, func(v *model.TGWAttachment) model.Meta { return v.Meta })
	diffType(d, TypeVPCPeering, from.VPCPeerings, to.VPCPeerings, func(v *model.VPCPeering) model.Meta { return v.Meta })
	diffType(d, TypeFirewall, from.Firewalls, to.Firewalls, func(v *model.Firewall) model.Meta { return v.Meta })
	diffType(d, TypeFirewallPolicy, from.FirewallPolicies, to.FirewallPolicies, func(v *model.FirewallPolicy) model.Meta { return v.Meta })
	diffType(d, TypeRuleGroup, from.RuleGroups, to.RuleGroups, func(v *model.RuleGroup) model.Meta { return v.Meta })
	diffType(d, TypeExternalNetwork, from.ExternalNetworks, to.ExternalNetworks, func(v *model.ExternalNetwork) model.Meta { return v.Meta })
	if d.err != nil {
		return nil, d.err
	}

	res := &Result{
		From:   summarise(FromLabel, from),
		To:     summarise(ToLabel, to),
		Groups: d.result(),
	}
	for _, g := range res.Groups {
		res.Added += g.Added
		res.Removed += g.Removed
		res.Modified += g.Modified
		res.Unchanged += g.Unchanged
	}
	res.Caveats = caveats(res.From, res.To)
	res.Complete = len(res.Caveats) == 0
	res.Notes = res.notes()
	return res, nil
}

// groupKey is the grouping requirement 11.2 asks for: resource type, account,
// and region.
type groupKey struct {
	kind    string
	account string
	region  string
}

// differ accumulates changes into groups.
//
// It carries the first encoding failure rather than returning one per type, so
// the type-by-type call sites in Snapshots stay a list of one-line statements
// about what is compared instead of fourteen error checks.
type differ struct {
	groups map[groupKey]*Group
	err    error
}

func (d *differ) group(kind string, meta model.Meta) *Group {
	key := groupKey{kind: kind, account: meta.Account, region: meta.Region}
	g, ok := d.groups[key]
	if !ok {
		g = &Group{Type: kind, Account: meta.Account, Region: meta.Region}
		d.groups[key] = g
	}
	return g
}

func (d *differ) record(kind string, meta model.Meta, c Change) {
	g := d.group(kind, meta)
	switch c.Kind {
	case KindAdded:
		g.Added++
	case KindRemoved:
		g.Removed++
	case KindModified:
		g.Modified++
	}
	g.Changes = append(g.Changes, c)
}

func (d *differ) unchanged(kind string, meta model.Meta) {
	d.group(kind, meta).Unchanged++
}

// result returns the groups in report order, with each group's changes ordered
// within it. Both orderings are fixed rather than derived from map iteration,
// which is what makes two runs render identically.
func (d *differ) result() []Group {
	out := make([]Group, 0, len(d.groups))
	for _, g := range d.groups {
		sortChanges(g.Changes)
		out = append(out, *g)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		switch {
		case a.Type != b.Type:
			if ai, bi := typeIndex(a.Type), typeIndex(b.Type); ai != bi {
				return ai < bi
			}
			return a.Type < b.Type
		case a.Account != b.Account:
			return a.Account < b.Account
		default:
			return a.Region < b.Region
		}
	})
	return out
}

// sortChanges orders a group's changes by kind and then by identifier.
func sortChanges(in []Change) {
	sort.Slice(in, func(i, j int) bool {
		a, b := in[i], in[j]
		if a.Kind != b.Kind {
			return a.Kind.order() < b.Kind.order()
		}
		return a.ID < b.ID
	})
}

// record is one resource reduced to what a comparison needs: its identity and
// its fields as the model encodes them.
type record struct {
	meta   model.Meta
	fields map[string]string
}

// diffType compares one resource type across both Snapshots.
//
// metaOf is passed explicitly rather than discovered, because the embedded Meta
// every resource carries is a field and not a method, and a reflective lookup
// would trade a compile-time guarantee that each type is wired up correctly for a
// runtime one.
func diffType[T any](d *differ, kind string, before, after map[string]T, metaOf func(T) model.Meta) {
	if d.err != nil {
		return
	}
	from, err := index(kind, before, metaOf)
	if err != nil {
		d.err = err
		return
	}
	to, err := index(kind, after, metaOf)
	if err != nil {
		d.err = err
		return
	}

	for id, rec := range to {
		prev, existed := from[id]
		if !existed {
			d.record(kind, rec.meta, change(KindAdded, kind, id, rec.meta, nil))
			continue
		}
		fields := fieldChanges(prev.fields, rec.fields)
		if len(fields) == 0 {
			d.unchanged(kind, rec.meta)
			continue
		}
		d.record(kind, rec.meta, change(KindModified, kind, id, rec.meta, fields))
	}

	for id, rec := range from {
		if _, present := to[id]; present {
			continue
		}
		d.record(kind, rec.meta, change(KindRemoved, kind, id, rec.meta, nil))
	}
}

// index reduces one side's resources to comparable records, skipping a nil entry
// rather than dereferencing it: a Snapshot hand-written or hand-edited can carry
// one, and a panic is a poor way to report a malformed file.
func index[T any](kind string, in map[string]T, metaOf func(T) model.Meta) (map[string]record, error) {
	out := make(map[string]record, len(in))
	for id, v := range in {
		fields, err := encode(v)
		if err != nil {
			return nil, fmt.Errorf("diffsnap: encode %s %s: %w", kind, id, err)
		}
		if fields == nil {
			continue
		}
		out[id] = record{meta: metaOf(v), fields: fields}
	}
	return out, nil
}

// encode renders a resource as its top-level fields, each value as the model's
// own JSON. A nil resource encodes as JSON null and returns a nil map, which is
// how index recognises one without knowing T.
//
// Map-valued fields — a resource's tags — encode with their keys sorted by the
// standard library, so the encoding of a resource is a function of its contents
// and not of the order they were read in.
func encode(v any) (map[string]string, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, err
	}
	if fields == nil {
		return nil, nil
	}
	out := make(map[string]string, len(fields))
	for name, value := range fields {
		out[name] = string(value)
	}
	return out, nil
}

// fieldChanges returns the fields whose encodings differ, ordered by field name.
func fieldChanges(before, after map[string]string) []FieldChange {
	names := make([]string, 0, len(before)+len(after))
	seen := make(map[string]bool, len(before)+len(after))
	for _, m := range []map[string]string{before, after} {
		for name := range m {
			if !seen[name] {
				seen[name] = true
				names = append(names, name)
			}
		}
	}
	sort.Strings(names)

	var out []FieldChange
	for _, name := range names {
		if before[name] == after[name] {
			continue
		}
		out = append(out, FieldChange{Field: name, Before: before[name], After: after[name]})
	}
	return out
}

// change assembles one difference and the sentence describing it.
func change(kind Kind, resourceType, id string, meta model.Meta, fields []FieldChange) Change {
	return Change{
		Kind:    kind,
		Type:    resourceType,
		ID:      id,
		Name:    meta.Name,
		Account: meta.Account,
		Region:  meta.Region,
		Fields:  fields,
		Summary: summary(kind, meta.Name, fields),
	}
}

// summary states one change in a line.
//
// A single changed field is quoted with both values, because that is the whole
// answer and an operator should not have to open the JSON for it. Several changed
// fields are named without values: the point of the line is then which resource
// to look at, and four before-and-after pairs on one line is not something anyone
// reads.
func summary(kind Kind, name string, fields []FieldChange) string {
	switch kind {
	case KindAdded, KindRemoved:
		if name != "" {
			return fmt.Sprintf("%s, name %s", kind, name)
		}
		return string(kind)
	default:
		if len(fields) == 1 {
			f := fields[0]
			return fmt.Sprintf("%s changed: %s → %s", f.Field, value(f.Before), value(f.After))
		}
		names := make([]string, 0, len(fields))
		for _, f := range fields {
			names = append(names, f.Field)
		}
		return fmt.Sprintf("%d fields changed: %s", len(fields), strings.Join(names, ", "))
	}
}

// value renders a field value for a summary line, capped and with an absent
// field named rather than left blank.
func value(v string) string {
	switch {
	case v == "":
		return "absent"
	case len(v) > maxSummaryValue:
		return v[:maxSummaryValue] + "…"
	default:
		return v
	}
}

func summarise(label string, s *model.Snapshot) SnapshotSummary {
	return SnapshotSummary{
		Label:            label,
		SchemaVersion:    s.SchemaVersion,
		CapturedAt:       s.CapturedAt,
		Resources:        countResources(s),
		CollectionErrors: len(s.CollectionErrors),
	}
}

// countResources counts every resource the diff compares, so the two sides can
// be described by size without listing them.
func countResources(s *model.Snapshot) int {
	return len(s.VPCs) + len(s.Subnets) + len(s.RouteTables) + len(s.SecurityGroups) +
		len(s.NACLs) + len(s.NetworkIfaces) + len(s.TransitGateways) + len(s.TGWRouteTables) +
		len(s.TGWAttachments) + len(s.VPCPeerings) + len(s.Firewalls) + len(s.FirewallPolicies) +
		len(s.RuleGroups) + len(s.ExternalNetworks)
}

// caveats reports what this comparison could not establish.
func caveats(from, to SnapshotSummary) []Caveat {
	var out []Caveat

	// Requirement 11.3. The comparison still runs — a version difference is
	// usually a build difference and most fields still line up — but a field one
	// version records and the other does not is not something this package can
	// tell apart from a field that changed.
	if from.SchemaVersion != to.SchemaVersion {
		out = append(out, Caveat{
			Subject: "schema version",
			Summary: fmt.Sprintf(
				"the %s snapshot was written at schema version %d and the %s snapshot at version %d, so this comparison may be incomplete: a field one version records and the other does not cannot be told apart from a field that changed",
				from.Label, from.SchemaVersion, to.Label, to.SchemaVersion),
		})
	}

	// A resource that could not be read is absent from the Snapshot, and absence
	// is what this package calls a removal. Saying so is the same stance the rest
	// of the tool takes: an unverified thing is never reported as an established
	// one.
	if from.CollectionErrors > 0 || to.CollectionErrors > 0 {
		out = append(out, Caveat{
			Subject: "collection errors",
			Summary: fmt.Sprintf(
				"the %s snapshot records %d collection errors and the %s snapshot %d, so a resource reported as added or removed may be one that could not be read rather than one that changed",
				from.Label, from.CollectionErrors, to.Label, to.CollectionErrors),
		})
	}
	return out
}

// notes record what an operator should know about the diff itself.
func (r *Result) notes() []string {
	var out []string
	if !r.Changed() {
		out = append(out, fmt.Sprintf(
			"the %s and %s snapshots record the same %d resources with the same configuration",
			r.From.Label, r.To.Label, r.Unchanged))
	}
	if r.From.CapturedAt.After(r.To.CapturedAt) {
		out = append(out, fmt.Sprintf(
			"the %s snapshot was captured after the %s snapshot, so every difference below reads in the opposite direction to the one intended",
			r.From.Label, r.To.Label))
	}
	return out
}
