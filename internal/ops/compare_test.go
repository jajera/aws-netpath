package ops

// Compare is tested end to end, through the same pipeline a diagnosis uses, on
// the two shapes the operation exists for.
//
// A genuine cloud difference: two sources, one destination, and a destination
// security group that admits one of them. The comparison names the security
// group and nothing else, because everything else about the two paths is the
// same.
//
// And the motivating incident as a comparison: two hosts in one subnet, the same
// destination, identical at every cloud layer, separated by one entry in a
// firewalld allowlist. That is the case where the diff is the whole answer.

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/jajera/aws-netpath/internal/compare"
	"github.com/jajera/aws-netpath/internal/host"
	"github.com/jajera/aws-netpath/internal/model"
	"github.com/jajera/aws-netpath/internal/symptom"
)

const testRefInstance = "i-0b2c3d4e5f6071829"

var testRefAddr = netip.MustParseAddr("10.30.1.11")

// siblingSnapshot adds a second source in the same subnet, on the same security
// group and the same route table. Every cloud layer the two sources meet is
// identical, which is the precondition requirement 10.3 reasons from.
func siblingSnapshot() *model.Snapshot {
	snap := diagnoseSnapshot()
	snap.NetworkIfaces["eni-app-2"] = &model.NetworkIface{
		Meta: model.Meta{
			ID: "eni-app-2", Name: "app-2", Region: testRegionA, Account: testAccountA,
			Tags: map[string]string{"Name": "app-2"},
		},
		VPCID: "vpc-app", SubnetID: "subnet-app", Status: "in-use",
		SecurityGroupIDs: []string{"sg-app"},
		PrivateIPs:       []netip.Addr{testRefAddr},
		AttachedTo:       testRefInstance,
	}
	return snap
}

// batchSubnetSnapshot adds a third subnet whose range the destination security
// group does not admit, so the two paths differ at exactly one cloud layer.
func batchSubnetSnapshot() *model.Snapshot {
	snap := diagnoseSnapshot()
	snap.Subnets["subnet-batch"] = &model.Subnet{
		Meta:  model.Meta{ID: "subnet-batch", Name: "batch-a", Region: testRegionA, Account: testAccountA},
		VPCID: "vpc-app", CIDR: netip.MustParsePrefix("10.30.3.0/24"), RouteTableID: "rt-app",
	}
	snap.NetworkIfaces["eni-batch"] = &model.NetworkIface{
		Meta: model.Meta{
			ID: "eni-batch", Name: "batch-1", Region: testRegionA, Account: testAccountA,
			Tags: map[string]string{"Name": "batch-1"},
		},
		VPCID: "vpc-app", SubnetID: "subnet-batch", Status: "in-use",
		SecurityGroupIDs: []string{"sg-app"},
		PrivateIPs:       []netip.Addr{netip.MustParseAddr("10.30.3.10")},
		AttachedTo:       "i-0c3d4e5f60718293a",
	}
	return snap
}

// The allowlist admits the reference source and not the failing one. One rich
// rule, two sources, two verdicts — matched by containment, which is the whole
// point of requirement 8.3 and the difference this comparison surfaces.
const siblingRichRules = `rule family="ipv4" source address="10.30.1.11/32" port port="22" protocol="tcp" accept
`

func siblingHostProber() *stubProber {
	return &stubProber{results: map[host.Check]host.Result{
		host.CheckListener:           {Stdout: stubListening},
		host.CheckFirewalldRichRules: {Stdout: siblingRichRules},
		host.CheckFirewalldServices:  {Stdout: "dhcpv6-client\n"},
		host.CheckLocalRoute:         {Stdout: "10.30.1.10 via 10.30.2.1 dev eth0 src 10.30.2.20 uid 0\n    cache\n"},
	}}
}

// A cloud difference is reported at the layer that holds it, with both sides'
// rules cited and every shared layer named rather than reproduced.
//
// Validates: Requirements 10.1, 10.2
func TestCompareReportsOnlyTheDifferingCloudLayer(t *testing.T) {
	got, err := Compare(context.Background(), CompareRequest{
		Snapshot: batchSubnetSnapshot(),
		From:     "10.30.3.10",
		To:       testDstInstance,
		RefFrom:  testSrcAddr.String(),
		Proto:    "tcp",
		Port:     22,
		Prober:   healthyHostProber(),
	})
	if err != nil {
		t.Fatalf("Compare() error = %v", err)
	}

	// Both paths came through the diagnose pipeline, so the comparison rests on
	// findings one implementation produced.
	if got.Subject == nil || got.Reference == nil {
		t.Fatalf("Compare() returned %+v, want both diagnoses", got)
	}
	if got.Subject.Walk == nil || got.Reference.Walk == nil {
		t.Fatal("Compare() returned a diagnosis with no walk")
	}

	diff, ok := got.Diff.Difference(model.LayerSecurityGroup)
	if !ok {
		t.Fatalf("security_group is not reported as differing; differences = %+v, matched = %v",
			got.Diff.Differences, got.Diff.Matched)
	}
	if diff.Status != compare.StatusDiffers {
		t.Fatalf("security_group status = %q, want %q (%s)", diff.Status, compare.StatusDiffers, diff.Summary)
	}
	if diff.Subject.Verdict != model.VerdictBlocked || diff.Reference.Verdict != model.VerdictPass {
		t.Errorf("security_group verdicts = %s / %s, want blocked / pass", diff.Subject.Verdict, diff.Reference.Verdict)
	}
	if len(diff.Subject.Only) == 0 || len(diff.Reference.Only) == 0 {
		t.Errorf("security_group entries = %+v / %+v, want the differing rules cited on both sides",
			diff.Subject.Only, diff.Reference.Only)
	}

	// Requirement 10.1: the route table both paths use is shared, so it is named
	// as matching and its routes are not reproduced as a difference.
	var matchedRoute bool
	for _, l := range got.Diff.Matched {
		if l == model.LayerRoute {
			matchedRoute = true
		}
	}
	if !matchedRoute {
		t.Errorf("matched = %v, want the shared route layer named", got.Diff.Matched)
	}
	for _, d := range got.Diff.Differences {
		if d.Layer == model.LayerRoute {
			t.Errorf("the shared route layer is reported as a difference: %+v", d)
		}
	}

	// A cloud layer differs, so the host layers are not what remains.
	if got.Diff.Direction != nil {
		t.Errorf("direction = %+v, want none while a cloud layer differs", got.Diff.Direction)
	}
}

// Requirement 10.3 end to end: identical cloud layers, different behaviour, and
// the host firewall named as the difference.
func TestCompareDirectsToTheHostWhenCloudLayersMatch(t *testing.T) {
	got, err := Compare(context.Background(), CompareRequest{
		Snapshot: siblingSnapshot(),
		From:     testSrcAddr.String(),
		To:       testDstInstance,
		RefFrom:  testRefAddr.String(),
		Proto:    "tcp",
		Port:     22,
		Symptom:  "no-route-to-host",
		Prober:   siblingHostProber(),
	})
	if err != nil {
		t.Fatalf("Compare() error = %v", err)
	}

	// The premise: nothing in the cloud configuration separates the two paths.
	for _, d := range got.Diff.Differences {
		if !d.Layer.Host() {
			t.Fatalf("cloud layer %s differs, which the fixture does not intend: %s", d.Layer, d.Summary)
		}
	}
	for _, d := range got.Diff.Incomplete {
		if !d.Layer.Host() {
			t.Fatalf("cloud layer %s is incomplete, which the fixture does not intend: %s", d.Layer, d.Summary)
		}
	}

	diff, ok := got.Diff.Difference(model.LayerHostFirewall)
	if !ok {
		t.Fatalf("host_firewall is not reported as differing; differences = %+v", got.Diff.Differences)
	}
	if diff.Subject.Verdict != model.VerdictBlocked || diff.Reference.Verdict != model.VerdictPass {
		t.Fatalf("host_firewall verdicts = %s / %s, want blocked / pass", diff.Subject.Verdict, diff.Reference.Verdict)
	}
	var citesEntry bool
	for _, c := range diff.Reference.Only {
		if strings.Contains(c.Detail, testRefAddr.String()) {
			citesEntry = true
		}
	}
	if !citesEntry {
		t.Errorf("reference entries = %+v, want the allowlist entry that admits it", diff.Reference.Only)
	}

	if got.Diff.Direction == nil {
		t.Fatalf("no direction reported; matched = %v", got.Diff.Matched)
	}
	var namesHostFirewall bool
	for _, l := range got.Diff.Direction.Layers {
		if l == model.LayerHostFirewall {
			namesHostFirewall = true
		}
	}
	if !namesHostFirewall {
		t.Errorf("direction layers = %v, want the host firewall named", got.Diff.Direction.Layers)
	}
}

// The Symptom belongs to the failing path. The reference path is the one that
// works, so classifying a failure on it would ask the classifier to explain a
// success.
func TestCompareAppliesTheSymptomToTheFailingPathOnly(t *testing.T) {
	got, err := Compare(context.Background(), CompareRequest{
		Snapshot: siblingSnapshot(),
		From:     testSrcAddr.String(),
		To:       testDstInstance,
		RefFrom:  testRefAddr.String(),
		Proto:    "tcp",
		Port:     22,
		Symptom:  "connection-refused",
		Prober:   siblingHostProber(),
	})
	if err != nil {
		t.Fatalf("Compare() error = %v", err)
	}

	if got.Subject.Classification.Symptom != symptom.ConnectionRefused {
		t.Errorf("failing path symptom = %q, want %q", got.Subject.Classification.Symptom, symptom.ConnectionRefused)
	}
	if got.Reference.Classification.Symptom != symptom.None {
		t.Errorf("reference path symptom = %q, want none", got.Reference.Classification.Symptom)
	}
	if got.Diff.Reference.Symptom != symptom.None {
		t.Errorf("diff reference symptom = %q, want none", got.Diff.Reference.Symptom)
	}
}

// An omitted reference destination means the same destination, which is the
// ordinary shape: two sources, one service, one of them working.
func TestCompareDefaultsTheReferenceDestination(t *testing.T) {
	got, err := Compare(context.Background(), CompareRequest{
		Snapshot: siblingSnapshot(),
		From:     testSrcAddr.String(),
		To:       testDstInstance,
		RefFrom:  testRefAddr.String(),
		Proto:    "tcp",
		Port:     22,
		Prober:   siblingHostProber(),
	})
	if err != nil {
		t.Fatalf("Compare() error = %v", err)
	}

	if got.Diff.Reference.To != testDstInstance {
		t.Errorf("reference destination = %q, want %q", got.Diff.Reference.To, testDstInstance)
	}
	if got.Reference.Destination.InstanceID != testDstInstance {
		t.Errorf("reference resolved destination = %q, want %q", got.Reference.Destination.InstanceID, testDstInstance)
	}
}

// The reference endpoints are validated in their own vocabulary, and a failure on
// either path names the path it came from.
func TestCompareNamesTheFieldAndThePathOnFailure(t *testing.T) {
	base := CompareRequest{
		Snapshot: siblingSnapshot(),
		From:     testSrcAddr.String(),
		To:       testDstInstance,
		RefFrom:  testRefAddr.String(),
		Proto:    "tcp",
		Port:     22,
	}

	missing := base
	missing.RefFrom = ""
	_, err := Compare(context.Background(), missing)
	if err == nil || !strings.Contains(err.Error(), "ref-from") {
		t.Errorf("error = %v, want it to name --ref-from", err)
	}

	unknown := base
	unknown.RefFrom = "web-1"
	_, err = Compare(context.Background(), unknown)
	if err == nil || !strings.Contains(err.Error(), compare.ReferenceLabel) {
		t.Errorf("error = %v, want it to name the reference path", err)
	}
}
