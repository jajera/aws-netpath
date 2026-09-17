package compare

// The comparator is tested on what it is for: naming the difference and nothing
// else.
//
// The table covers one genuine difference at each entry kind requirement 10.2
// lists — route entries, NACL entries, security group rules, firewall rule
// matches, host firewall allowlists — and asserts the same three things every
// time: the Layer is reported as differing, both sides' entries are cited, and
// the Layers the two paths share are named without their contents.
//
// Every case supplies findings for every Layer on both sides. A real walk stops
// at a block, so a path blocked at ROUTE would report nothing after it; that
// case is exercised on its own below. Holding the other Layers identical is what
// isolates the Layer under test, which is the point of the table.

import (
	"strings"
	"testing"

	"github.com/jajera/aws-netpath/internal/correlate"
	"github.com/jajera/aws-netpath/internal/model"
	"github.com/jajera/aws-netpath/internal/symptom"
)

// Placeholder identifiers and RFC 5737 / RFC 1918 addresses only.
const (
	failingSource   = "10.30.1.10"
	referenceSource = "10.30.1.11"
)

func cite(kind, identifier, detail string) model.Citation {
	return model.Citation{Kind: kind, Identifier: identifier, Detail: detail}
}

func passes(layer model.Layer, citations ...model.Citation) model.LayerResult {
	return model.LayerResult{Layer: layer, Verdict: model.VerdictPass, Citations: citations}
}

func blocks(layer model.Layer, citations ...model.Citation) model.LayerResult {
	return model.LayerResult{Layer: layer, Verdict: model.VerdictBlocked, Citations: citations}
}

func abstains(layer model.Layer, reason string) model.LayerResult {
	return model.LayerResult{Layer: layer, Verdict: model.VerdictAbstain, Reason: reason}
}

// sharedPath is the set of findings both paths produce identically: one VPC, one
// route table, one NACL, one security group, one firewall policy, one host. A
// case overrides the Layer it is about and leaves the rest alone.
//
// Only the RESOLUTION citation names the source, because only RESOLUTION differs
// between the two paths by construction — which is why it is the one Layer
// compared by verdict alone.
func sharedPath(source string) []model.LayerResult {
	return []model.LayerResult{
		passes(model.LayerResolution,
			cite("resolution", "eni-source", "source "+source+" resolved to eni-source")),
		passes(model.LayerRoute,
			cite("route", "rtb-app", "route: 10.30.0.0/16 local")),
		passes(model.LayerNACL,
			cite("nacl", "acl-app", "nacl: entry 100 allow 10.30.0.0/16 tcp/22")),
		passes(model.LayerSecurityGroup,
			cite("security_group", "sg-db", "sg: ingress rule allows 10.30.0.0/16 tcp/22")),
		passes(model.LayerFirewall,
			cite("nfw_rule", "nfr-east-west sid 1 (priority 10)", "firewall: pass tcp 10.30.0.0/16 -> 10.30.2.0/24 22")),
		passes(model.LayerReturnPath,
			cite("route", "rtb-app", "return: 10.30.0.0/16 local")),
		passes(model.LayerHostFirewall,
			cite("command", "firewall-cmd --zone=public --list-rich-rules",
				"allowlist entry 10.30.0.0/16 covers the source for tcp/22")),
		passes(model.LayerHostListener,
			cite("command", "ss -tlnp", "sshd is listening on 0.0.0.0:22")),
	}
}

// override replaces the findings for the Layers it names.
func override(base []model.LayerResult, replacements ...model.LayerResult) []model.LayerResult {
	out := make([]model.LayerResult, 0, len(base))
	for _, r := range base {
		replaced := false
		for _, rep := range replacements {
			if rep.Layer == r.Layer {
				out = append(out, rep)
				replaced = true
				break
			}
		}
		if !replaced {
			out = append(out, r)
		}
	}
	return out
}

// remove drops the findings for the Layers it names, standing in for a walk that
// stopped before reaching them.
func remove(base []model.LayerResult, layers ...model.Layer) []model.LayerResult {
	out := make([]model.LayerResult, 0, len(base))
	for _, r := range base {
		drop := false
		for _, l := range layers {
			if r.Layer == l {
				drop = true
				break
			}
		}
		if !drop {
			out = append(out, r)
		}
	}
	return out
}

// side correlates findings the way the diagnose pipeline does, so the comparator
// is exercised on the aggregated verdicts it actually receives.
func side(t *testing.T, label, from string, sym symptom.Symptom, results []model.LayerResult) Side {
	t.Helper()
	verdict, err := correlate.Correlate(correlate.Input{Symptom: sym, Results: results})
	if err != nil {
		t.Fatalf("correlate %s path: %v", label, err)
	}
	return Side{Label: label, From: from, To: "10.30.2.20", Symptom: sym, Verdict: verdict}
}

// One genuine difference at each entry kind requirement 10.2 names.
//
// Validates: Requirements 10.1, 10.2
func TestPathsDiffsEachEntryKind(t *testing.T) {
	cases := []struct {
		name  string
		layer model.Layer
		// subject and reference override the shared path.
		subject   []model.LayerResult
		reference []model.LayerResult
		// wantVerdicts are the two Layer verdicts the diff should report.
		wantSubjectVerdict   model.LayerVerdict
		wantReferenceVerdict model.LayerVerdict
		// wantOnly are substrings expected in the entries cited for each side.
		wantSubjectOnly   string
		wantReferenceOnly string
	}{
		{
			// Route entries: the failing source's subnet has no route to the
			// destination, the reference source's does.
			name:  "route entries",
			layer: model.LayerRoute,
			subject: []model.LayerResult{blocks(model.LayerRoute,
				cite("route", "rtb-batch", "route: no route to 10.30.2.20 in rtb-batch"))},
			reference: []model.LayerResult{passes(model.LayerRoute,
				cite("route", "rtb-app", "route: 10.30.2.0/24 via tgw-hub"))},
			wantSubjectVerdict:   model.VerdictBlocked,
			wantReferenceVerdict: model.VerdictPass,
			wantSubjectOnly:      "no route to 10.30.2.20",
			wantReferenceOnly:    "via tgw-hub",
		},
		{
			// NACL entries: both paths are permitted, by different entries in
			// different lists. Nothing is blocked, and the two paths still
			// differ.
			name:  "nacl entries",
			layer: model.LayerNACL,
			subject: []model.LayerResult{passes(model.LayerNACL,
				cite("nacl", "acl-batch", "nacl: entry 200 allow 10.30.3.0/24 tcp/22"))},
			reference: []model.LayerResult{passes(model.LayerNACL,
				cite("nacl", "acl-app", "nacl: entry 100 allow 10.30.1.0/24 tcp/22"))},
			wantSubjectVerdict:   model.VerdictPass,
			wantReferenceVerdict: model.VerdictPass,
			wantSubjectOnly:      "acl-batch",
			wantReferenceOnly:    "acl-app",
		},
		{
			// Security group rules: the destination group admits the reference
			// source's range and not the failing source's.
			name:  "security group rules",
			layer: model.LayerSecurityGroup,
			subject: []model.LayerResult{blocks(model.LayerSecurityGroup,
				cite("security_group", "sg-db", "sg: no ingress rule allows 10.30.3.10 tcp/22"))},
			reference: []model.LayerResult{passes(model.LayerSecurityGroup,
				cite("security_group", "sg-db", "sg: ingress rule allows 10.30.1.0/24 tcp/22"))},
			wantSubjectVerdict:   model.VerdictBlocked,
			wantReferenceVerdict: model.VerdictPass,
			wantSubjectOnly:      "no ingress rule",
			wantReferenceOnly:    "10.30.1.0/24",
		},
		{
			// Firewall rule matches: different rules in the same policy decided
			// the two paths, and the citation names the rule group, priority,
			// and SID on both sides.
			name:  "firewall rule matches",
			layer: model.LayerFirewall,
			subject: []model.LayerResult{blocks(model.LayerFirewall,
				cite("nfw_rule", "nfr-east-west sid 9 (priority 5)", "firewall: drop tcp 10.30.3.0/24 -> 10.30.2.0/24 22"))},
			reference: []model.LayerResult{passes(model.LayerFirewall,
				cite("nfw_rule", "nfr-east-west sid 1 (priority 10)", "firewall: pass tcp 10.30.1.0/24 -> 10.30.2.0/24 22"))},
			wantSubjectVerdict:   model.VerdictBlocked,
			wantReferenceVerdict: model.VerdictPass,
			wantSubjectOnly:      "sid 9",
			wantReferenceOnly:    "sid 1",
		},
		{
			// Host firewall allowlists: the incident this tool was built for.
			// Every other Layer matches and the allowlist on the failing path
			// does not contain the source.
			name:  "host firewall allowlists",
			layer: model.LayerHostFirewall,
			subject: []model.LayerResult{blocks(model.LayerHostFirewall,
				cite("command", "firewall-cmd --zone=public --list-rich-rules",
					"allowlist entries for tcp/22, none containing 10.30.1.10: rule family=\"ipv4\" source address=\"198.51.100.128/26\" port port=\"22\" protocol=\"tcp\" accept"))},
			reference: []model.LayerResult{passes(model.LayerHostFirewall,
				cite("command", "firewall-cmd --zone=public --list-rich-rules",
					"allowlist entry 198.51.100.0/25 covers 10.30.1.11 for tcp/22"))},
			wantSubjectVerdict:   model.VerdictBlocked,
			wantReferenceVerdict: model.VerdictPass,
			wantSubjectOnly:      "198.51.100.128/26",
			wantReferenceOnly:    "198.51.100.0/25",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			subject := side(t, SubjectLabel, failingSource, symptom.None,
				override(sharedPath(failingSource), tc.subject...))
			reference := side(t, ReferenceLabel, referenceSource, symptom.None,
				override(sharedPath(referenceSource), tc.reference...))

			got, err := Paths(subject, reference)
			if err != nil {
				t.Fatalf("Paths() error = %v", err)
			}

			diff, ok := got.Difference(tc.layer)
			if !ok {
				t.Fatalf("%s is not reported as differing; differences = %+v, matched = %v",
					tc.layer, got.Differences, got.Matched)
			}
			if diff.Status != StatusDiffers {
				t.Fatalf("%s status = %q, want %q (%s)", tc.layer, diff.Status, StatusDiffers, diff.Summary)
			}
			if diff.Subject.Verdict != tc.wantSubjectVerdict {
				t.Errorf("%s subject verdict = %q, want %q", tc.layer, diff.Subject.Verdict, tc.wantSubjectVerdict)
			}
			if diff.Reference.Verdict != tc.wantReferenceVerdict {
				t.Errorf("%s reference verdict = %q, want %q", tc.layer, diff.Reference.Verdict, tc.wantReferenceVerdict)
			}

			// Cross-cutting 2 applied to a diff: the entry is cited on both
			// sides, so the operator can see what to change and what to change
			// it to.
			assertCites(t, tc.layer, "subject", diff.Subject.Only, tc.wantSubjectOnly)
			assertCites(t, tc.layer, "reference", diff.Reference.Only, tc.wantReferenceOnly)

			// Requirement 10.1: only the differences. Every other Layer is named
			// as matching and its entries are left out.
			if len(got.Differences) != 1 {
				t.Errorf("differences = %+v, want only %s", got.Differences, tc.layer)
			}
			for _, l := range got.Matched {
				if l == tc.layer {
					t.Errorf("%s is reported as matching and as differing", l)
				}
			}
			if want := len(model.FlowOrder()) - 1; len(got.Matched) != want {
				t.Errorf("matched = %v, want the other %d layers", got.Matched, want)
			}
		})
	}
}

func assertCites(t *testing.T, layer model.Layer, label string, citations []model.Citation, want string) {
	t.Helper()
	if len(citations) == 0 {
		t.Fatalf("%s %s side cites no entry, want one containing %q", layer, label, want)
	}
	for _, c := range citations {
		if strings.Contains(c.Identifier, want) || strings.Contains(c.Detail, want) {
			return
		}
	}
	t.Errorf("%s %s side entries = %+v, want one containing %q", layer, label, citations, want)
}

// Requirement 10.1: shared configuration is named and not reproduced. A
// comparison that echoes both full paths buries the answer.
func TestPathsReportsDifferencesOnly(t *testing.T) {
	subject := side(t, SubjectLabel, failingSource, symptom.None,
		override(sharedPath(failingSource), blocks(model.LayerFirewall,
			cite("nfw_rule", "nfr-east-west sid 9 (priority 5)", "firewall: drop tcp/22"))))
	reference := side(t, ReferenceLabel, referenceSource, symptom.None, sharedPath(referenceSource))

	got, err := Paths(subject, reference)
	if err != nil {
		t.Fatalf("Paths() error = %v", err)
	}

	if len(got.Differences) != 1 || got.Differences[0].Layer != model.LayerFirewall {
		t.Fatalf("differences = %+v, want only the firewall", got.Differences)
	}
	// The route table both paths share is the clearest test of "differences
	// only": it is in every finding on both sides and must not be cited.
	for _, d := range got.Differences {
		for _, c := range append(d.Subject.Only, d.Reference.Only...) {
			if strings.Contains(c.Identifier, "rtb-app") || strings.Contains(c.Identifier, "acl-app") {
				t.Errorf("shared entry %+v is reported as a difference", c)
			}
		}
	}
	if len(got.Incomplete) != 0 {
		t.Errorf("incomplete = %+v, want none", got.Incomplete)
	}
	if !got.Authoritative {
		t.Errorf("comparison is not authoritative: %v", got.Notes)
	}
}

// Requirement 10.3: identical cloud Layers with different behaviour point at the
// host Layers. This is the motivating incident expressed as a comparison — two
// hosts in one subnet, one allowlist entry apart.
func TestPathsDirectsToHostLayersWhenCloudLayersMatch(t *testing.T) {
	subject := side(t, SubjectLabel, failingSource, symptom.None,
		override(sharedPath(failingSource), blocks(model.LayerHostFirewall,
			cite("command", "firewall-cmd --zone=public --list-rich-rules",
				"allowlist entries for tcp/22, none containing 10.30.1.10"))))
	reference := side(t, ReferenceLabel, referenceSource, symptom.None, sharedPath(referenceSource))

	got, err := Paths(subject, reference)
	if err != nil {
		t.Fatalf("Paths() error = %v", err)
	}

	if !got.BehaviourDiffers {
		t.Fatalf("behaviour difference not established; %+v", got)
	}
	if got.Direction == nil {
		t.Fatalf("no direction reported; differences = %+v, matched = %v", got.Differences, got.Matched)
	}
	if len(got.Direction.Layers) == 0 {
		t.Fatalf("direction names no layers: %+v", got.Direction)
	}
	for _, l := range got.Direction.Layers {
		if !l.Host() {
			t.Errorf("direction names %s, which is not a host layer", l)
		}
	}
	// Cross-cutting 2: the direction is a finding, so it carries the evidence —
	// the cloud Layers found identical, and what each host reported.
	if len(got.Direction.Citations) == 0 {
		t.Fatalf("direction carries no citations: %+v", got.Direction)
	}
	var citesShared, citesSubject, citesReference bool
	for _, c := range got.Direction.Citations {
		if c.Kind == citationKindComparison && strings.Contains(c.Detail, string(model.LayerRoute)) {
			citesShared = true
		}
		if strings.HasPrefix(c.Detail, SubjectLabel+" path:") {
			citesSubject = true
		}
		if strings.HasPrefix(c.Detail, ReferenceLabel+" path:") {
			citesReference = true
		}
	}
	if !citesShared {
		t.Errorf("direction citations = %+v, want the cloud layers found identical", got.Direction.Citations)
	}
	if !citesSubject || !citesReference {
		t.Errorf("direction citations = %+v, want both paths' host findings", got.Direction.Citations)
	}
}

// The same deduction when the host Layers could not be probed at all: the cloud
// Layers are identical, the operator observed a failure, and the host Layers are
// still what remains — reported as incomplete rather than as a difference.
//
// Validates: Requirements 10.3, 10.4
func TestPathsDirectsToHostLayersWhenTheyAbstainOnBothPaths(t *testing.T) {
	unprobed := []model.LayerResult{
		abstains(model.LayerHostFirewall, "no systems manager client, so the host was not probed"),
		abstains(model.LayerHostListener, "no systems manager client, so the host was not probed"),
	}
	subject := side(t, SubjectLabel, failingSource, symptom.ConnectionRefused,
		override(sharedPath(failingSource), unprobed...))
	reference := side(t, ReferenceLabel, referenceSource, symptom.None,
		override(sharedPath(referenceSource), unprobed...))

	got, err := Paths(subject, reference)
	if err != nil {
		t.Fatalf("Paths() error = %v", err)
	}

	if !got.BehaviourDiffers || !strings.Contains(got.Behaviour, string(symptom.ConnectionRefused)) {
		t.Fatalf("behaviour = %q, want the observed symptom to establish the difference", got.Behaviour)
	}
	if got.Direction == nil {
		t.Fatalf("no direction reported; matched = %v, incomplete = %+v", got.Matched, got.Incomplete)
	}
	if len(got.Incomplete) != 2 {
		t.Errorf("incomplete = %+v, want both host layers", got.Incomplete)
	}
	if len(got.Differences) != 0 {
		t.Errorf("differences = %+v, want none: an unprobed layer is not a difference", got.Differences)
	}
	if got.Authoritative {
		t.Error("comparison is authoritative while two layers could not be compared")
	}
}

// Requirement 10.4: a Layer abstaining on one path and evaluated on the other is
// incomplete. Never silently equal, never a difference.
func TestPathsReportsIncompleteWhenALayerAbstainsOnOneSide(t *testing.T) {
	subject := side(t, SubjectLabel, failingSource, symptom.None,
		override(sharedPath(failingSource), abstains(model.LayerFirewall,
			"rule group nfr-domains uses a domain allowlist, which aws-netpath does not model")))
	reference := side(t, ReferenceLabel, referenceSource, symptom.None, sharedPath(referenceSource))

	got, err := Paths(subject, reference)
	if err != nil {
		t.Fatalf("Paths() error = %v", err)
	}

	diff, ok := got.Difference(model.LayerFirewall)
	if !ok {
		t.Fatalf("firewall is not reported; matched = %v", got.Matched)
	}
	if diff.Status != StatusIncomplete {
		t.Fatalf("firewall status = %q, want %q (%s)", diff.Status, StatusIncomplete, diff.Summary)
	}
	for _, l := range got.Matched {
		if l == model.LayerFirewall {
			t.Error("firewall is reported as matching as well as incomplete")
		}
	}
	for _, d := range got.Differences {
		if d.Layer == model.LayerFirewall {
			t.Error("firewall is reported as a difference as well as incomplete")
		}
	}
	// The reason travels with it: an incomplete comparison an operator cannot
	// explain is indistinguishable from one nobody attempted.
	if !strings.Contains(diff.Summary, "domain allowlist") {
		t.Errorf("summary = %q, want the abstention reason", diff.Summary)
	}
	if got.Authoritative {
		t.Error("comparison is authoritative while a layer abstained on one side")
	}
	// And the deduction is withheld: a cloud Layer that could not be read on one
	// path has not been shown to match, so the host Layers are not what remains.
	if got.Direction != nil {
		t.Errorf("direction = %+v, want none while a cloud layer is incomplete", got.Direction)
	}
}

// A Layer one walk never reached is incomplete on the same grounds. A path
// blocked at ROUTE reports nothing after it, and the Layers it never met are
// neither equal to nor different from the reference path's.
func TestPathsReportsALayerNeverReachedAsIncomplete(t *testing.T) {
	subject := side(t, SubjectLabel, failingSource, symptom.None,
		remove(override(sharedPath(failingSource), blocks(model.LayerRoute,
			cite("route", "rtb-batch", "route: no route to 10.30.2.20"))),
			model.LayerNACL, model.LayerSecurityGroup, model.LayerFirewall, model.LayerReturnPath))
	reference := side(t, ReferenceLabel, referenceSource, symptom.None, sharedPath(referenceSource))

	got, err := Paths(subject, reference)
	if err != nil {
		t.Fatalf("Paths() error = %v", err)
	}

	for _, layer := range []model.Layer{
		model.LayerNACL, model.LayerSecurityGroup, model.LayerFirewall, model.LayerReturnPath,
	} {
		diff, ok := got.Difference(layer)
		if !ok {
			t.Fatalf("%s is not reported; matched = %v", layer, got.Matched)
		}
		if diff.Status != StatusIncomplete {
			t.Errorf("%s status = %q, want %q", layer, diff.Status, StatusIncomplete)
		}
		if diff.Subject.Reached {
			t.Errorf("%s is reported as reached on the failing path", layer)
		}
		if !strings.Contains(diff.Summary, "not reached") {
			t.Errorf("%s summary = %q, want it to state the layer was not reached", layer, diff.Summary)
		}
	}
	if _, ok := got.Difference(model.LayerRoute); !ok {
		t.Error("the route difference that stopped the walk is not reported")
	}
}

// Nothing to compare is an error rather than a one-sided list of entries, which
// would read like a diagnosis and is not one.
func TestPathsRequiresFindingsOnBothPaths(t *testing.T) {
	reference := side(t, ReferenceLabel, referenceSource, symptom.None, sharedPath(referenceSource))

	if _, err := Paths(Side{From: failingSource}, reference); err == nil {
		t.Error("Paths() accepted a failing path with no findings")
	}
	if _, err := Paths(reference, Side{From: referenceSource}); err == nil {
		t.Error("Paths() accepted a reference path with no findings")
	}
}

// Two paths that evaluate identically and were not shown to behave differently
// produce no difference and no deduction — and say what would be needed to get
// one, rather than inventing a conclusion from the caller's framing.
func TestPathsWithholdsDirectionWithoutABehaviourDifference(t *testing.T) {
	subject := side(t, SubjectLabel, failingSource, symptom.None, sharedPath(failingSource))
	reference := side(t, ReferenceLabel, referenceSource, symptom.None, sharedPath(referenceSource))

	got, err := Paths(subject, reference)
	if err != nil {
		t.Fatalf("Paths() error = %v", err)
	}

	if got.BehaviourDiffers {
		t.Errorf("behaviour = %q, want no difference asserted", got.Behaviour)
	}
	if got.Direction != nil {
		t.Errorf("direction = %+v, want none", got.Direction)
	}
	if len(got.Differences) != 0 || len(got.Incomplete) != 0 {
		t.Errorf("differences = %+v, incomplete = %+v, want neither", got.Differences, got.Incomplete)
	}
	var explains bool
	for _, note := range got.Notes {
		if strings.Contains(note, "symptom") {
			explains = true
		}
	}
	if !explains {
		t.Errorf("notes = %v, want one stating what would establish a behaviour difference", got.Notes)
	}
}
