package ops

// Diagnose is tested on the two things the stage order exists for.
//
// The host stage runs on a permitted cloud verdict, and the verdict that comes
// back names the host firewall. That is the motivating incident in miniature:
// every AWS layer clean, the allowlist missing the source, and an investigation
// that would otherwise have started in the wrong half of the stack.
//
// And with no Symptom the layers are evaluated in flow order, because nothing is
// known that would justify preferring one over another.

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/jajera/aws-netpath/internal/host"
	"github.com/jajera/aws-netpath/internal/model"
	"github.com/jajera/aws-netpath/internal/query"
	"github.com/jajera/aws-netpath/internal/symptom"
)

// stubProber replays recorded command output keyed by the Check the command
// serves, standing in for Systems Manager so the host stage can be exercised
// with no account and no network.
type stubProber struct {
	managedErr error
	results    map[host.Check]host.Result
	errs       map[host.Check]error
	ran        []host.Command
}

func (s *stubProber) Managed(_ context.Context, instanceID string) (host.ManagedInstance, error) {
	if s.managedErr != nil {
		return host.ManagedInstance{InstanceID: instanceID}, s.managedErr
	}
	return host.ManagedInstance{
		InstanceID: instanceID, PingStatus: "Online", PlatformType: "Linux",
	}, nil
}

func (s *stubProber) Run(_ context.Context, _ string, cmd host.Command) (host.Result, error) {
	s.ran = append(s.ran, cmd)
	if err := s.errs[cmd.Check]; err != nil {
		return host.Result{Command: cmd}, err
	}
	res := s.results[cmd.Check]
	res.Command = cmd
	return res, nil
}

// The destination is listening on tcp/22 for every address, so the listener layer
// passes and the host firewall is the only host layer that can decide anything.
const stubListening = `State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process
LISTEN 0      128          0.0.0.0:22         0.0.0.0:*     users:(("sshd",pid=1234,fd=3))
`

// The allowlist admits a range the source is not in — the entry a string
// comparison would have called absent and a containment test calls a near miss.
const stubRichRules = `rule family="ipv4" source address="198.51.100.128/26" port port="22" protocol="tcp" accept
`

// healthyHostProber probes a host whose firewalld allowlist omits the source.
func healthyHostProber() *stubProber {
	return &stubProber{results: map[host.Check]host.Result{
		host.CheckListener:           {Stdout: stubListening},
		host.CheckFirewalldRichRules: {Stdout: stubRichRules},
		host.CheckFirewalldServices:  {Stdout: "dhcpv6-client\n"},
		host.CheckLocalRoute:         {Stdout: "10.30.1.10 via 10.30.2.1 dev eth0 src 10.30.2.20 uid 0\n    cache\n"},
	}}
}

func diagnoseRequest(prober HostProber) DiagnoseRequest {
	return DiagnoseRequest{
		Snapshot: diagnoseSnapshot(),
		From:     testSrcAddr.String(),
		To:       testDstInstance,
		Proto:    "tcp",
		Port:     22,
		Prober:   prober,
	}
}

// The host stage runs even when the cloud layers report the traffic permitted,
// and the host firewall becomes the primary blocker on a path AWS allows.
//
// Validates: Requirements 8.1, 14.1
func TestDiagnoseRunsTheHostStageOnAPermittedCloudPath(t *testing.T) {
	prober := healthyHostProber()

	got, err := Diagnose(context.Background(), diagnoseRequest(prober))
	if err != nil {
		t.Fatalf("Diagnose() error = %v", err)
	}

	// The cloud walk permitted the traffic, so nothing about the cloud layers
	// could have prompted the host probe.
	if got.Walk.Verdict != query.VerdictPermitted {
		t.Fatalf("cloud verdict = %s, want %s (%+v)", got.Walk.Verdict, query.VerdictPermitted, got.Walk.BlockedAt)
	}
	for _, layer := range []model.Layer{model.LayerRoute, model.LayerSecurityGroup} {
		res, ok := got.Verdict.Result(layer)
		if !ok || res.Verdict != model.VerdictPass {
			t.Errorf("layer %s = %+v, want a pass", layer, res)
		}
	}

	if !got.Host.Probed {
		t.Fatalf("host stage did not run: %+v", got.Host)
	}
	if got.Host.InstanceID != testDstInstance {
		t.Errorf("probed instance = %q, want %q", got.Host.InstanceID, testDstInstance)
	}

	blocker, found := got.PrimaryBlocker()
	if !found {
		t.Fatalf("no primary blocker; want %s (verdict %+v)", model.LayerHostFirewall, got.Verdict)
	}
	if blocker != model.LayerHostFirewall {
		t.Fatalf("primary blocker = %s, want %s", blocker, model.LayerHostFirewall)
	}
	if len(got.Verdict.AdditionalBlocked) != 0 {
		t.Errorf("additional blockers = %v, want none", got.Verdict.AdditionalBlocked)
	}

	// The listener answered, so the two host layers are distinguishable and the
	// verdict rests on the allowlist rather than on a missing service.
	if res, ok := got.Verdict.Result(model.LayerHostListener); !ok || res.Verdict != model.VerdictPass {
		t.Errorf("host listener = %+v, want a pass", res)
	}

	blocked, _ := got.Verdict.Result(model.LayerHostFirewall)
	var citedEntry bool
	for _, c := range blocked.Citations {
		if strings.Contains(c.Detail, "198.51.100.128/26") {
			citedEntry = true
		}
	}
	if !citedEntry {
		t.Errorf("host firewall citations = %+v, want the allowlist entry that nearly covered the source", blocked.Citations)
	}
}

// The host commands run in the order the stage documents, and every one of them
// is a read.
func TestDiagnoseHostStageRunsTheDocumentedChecks(t *testing.T) {
	prober := healthyHostProber()

	if _, err := Diagnose(context.Background(), diagnoseRequest(prober)); err != nil {
		t.Fatalf("Diagnose() error = %v", err)
	}

	var lines []string
	for _, cmd := range prober.ran {
		lines = append(lines, cmd.Line())
	}
	want := []string{
		"ss -tlnp",
		"firewall-cmd --zone=public --list-rich-rules",
		"firewall-cmd --zone=public --list-services",
		"ip route get 10.30.1.10",
	}
	if !reflect.DeepEqual(lines, want) {
		t.Errorf("commands run = %v, want %v", lines, want)
	}
}

// Requirement 8.6: without Systems Manager the host layers abstain with the
// reason, and the permitted verdict stops being authoritative. "Cloud clear,
// host unverified" is not "all clear".
func TestDiagnoseAbstainsHostLayersWithoutAProber(t *testing.T) {
	req := diagnoseRequest(nil)

	got, err := Diagnose(context.Background(), req)
	if err != nil {
		t.Fatalf("Diagnose() error = %v", err)
	}

	if got.Host.Probed {
		t.Errorf("host stage reported a probe with no prober: %+v", got.Host)
	}
	for _, layer := range host.HostLayers() {
		res, ok := got.Verdict.Result(layer)
		if !ok {
			t.Fatalf("layer %s is missing from the verdict; an unprobed layer must still be reported", layer)
		}
		if res.Verdict != model.VerdictAbstain {
			t.Errorf("layer %s = %s, want abstain", layer, res.Verdict)
		}
		if res.Reason == "" {
			t.Errorf("layer %s abstained without a reason", layer)
		}
	}
	if _, found := got.PrimaryBlocker(); found {
		t.Errorf("primary blocker = %+v, want none found", got.Verdict.PrimaryBlocker)
	}
	if got.Verdict.Authoritative {
		t.Error("verdict is authoritative while the host layers abstained")
	}
}

// An instance Systems Manager does not manage abstains for the same reason, with
// the reason the API gave.
func TestDiagnoseAbstainsHostLayersWhenTheInstanceIsUnmanaged(t *testing.T) {
	prober := healthyHostProber()
	prober.managedErr = errors.New("instance is not an ssm-managed linux host: agent ping status is ConnectionLost")

	got, err := Diagnose(context.Background(), diagnoseRequest(prober))
	if err != nil {
		t.Fatalf("Diagnose() error = %v", err)
	}

	if len(prober.ran) != 0 {
		t.Errorf("commands run = %v, want none dispatched to an unmanaged instance", prober.ran)
	}
	for _, layer := range host.HostLayers() {
		res, _ := got.Verdict.Result(layer)
		if res.Verdict != model.VerdictAbstain {
			t.Errorf("layer %s = %s, want abstain", layer, res.Verdict)
		}
		if !strings.Contains(res.Reason, "ConnectionLost") {
			t.Errorf("layer %s reason = %q, want the reported ping status", layer, res.Reason)
		}
	}
}

// Requirement 9.5: with no Symptom the layers are evaluated in flow order and
// nothing is preferred.
func TestDiagnoseWithoutASymptomUsesFlowOrder(t *testing.T) {
	got, err := Diagnose(context.Background(), diagnoseRequest(healthyHostProber()))
	if err != nil {
		t.Fatalf("Diagnose() error = %v", err)
	}

	if got.Classification.Symptom != symptom.None {
		t.Errorf("symptom = %q, want none", got.Classification.Symptom)
	}
	if len(got.Classification.Candidates) != 0 {
		t.Errorf("candidates = %v, want none without a symptom", got.Classification.Candidates)
	}
	if want := model.FlowOrder(); !reflect.DeepEqual(got.Classification.CheckOrder, want) {
		t.Errorf("check order = %v, want flow order %v", got.Classification.CheckOrder, want)
	}

	// The findings themselves are reported in flow order too, which is what makes
	// the earliest blocking layer the primary one.
	var indexes []int
	for _, res := range got.Verdict.Results {
		indexes = append(indexes, res.Layer.FlowIndex())
	}
	for i := 1; i < len(indexes); i++ {
		if indexes[i] < indexes[i-1] {
			t.Fatalf("verdict results are not in flow order: %+v", got.Verdict.Results)
		}
	}
}

// A supplied Symptom reorders the checks towards the host, which is the whole
// value of classifying it: an actively rejected connection is answered in one
// probe rather than five.
func TestDiagnoseWithASymptomOrdersHostLayersFirst(t *testing.T) {
	req := diagnoseRequest(healthyHostProber())
	req.Symptom = "connection-refused"

	got, err := Diagnose(context.Background(), req)
	if err != nil {
		t.Fatalf("Diagnose() error = %v", err)
	}

	if got.Classification.Symptom != symptom.ConnectionRefused {
		t.Fatalf("symptom = %q, want %q", got.Classification.Symptom, symptom.ConnectionRefused)
	}
	if first := got.Classification.CheckOrder[0]; !first.Host() {
		t.Errorf("check order = %v, want a host layer first", got.Classification.CheckOrder)
	}
}

// An unrecognised symptom is reported before the snapshot is read: classification
// is pure logic, so it costs nothing to fail early and the message names the
// accepted values.
func TestDiagnoseRejectsAnUnknownSymptom(t *testing.T) {
	req := diagnoseRequest(nil)
	req.Symptom = "it-is-broken"

	_, err := Diagnose(context.Background(), req)

	var fieldErr *FieldError
	if !errors.As(err, &fieldErr) || fieldErr.Field != "symptom" {
		t.Fatalf("error = %v, want a *FieldError naming symptom", err)
	}
	if !strings.Contains(err.Error(), string(symptom.ConnectionRefused)) {
		t.Errorf("error = %q, want it to list the accepted symptoms", err)
	}
}

// Requirement 6.3 through the operation: an ambiguous endpoint halts the run
// before any layer is evaluated.
func TestDiagnoseHaltsOnAnAmbiguousEndpoint(t *testing.T) {
	prober := healthyHostProber()
	req := diagnoseRequest(prober)
	req.Snapshot = overlappingSnapshot()
	req.To = testDstAddr.String()

	got, err := Diagnose(context.Background(), req)

	var ambiguousErr *AmbiguousEndpointError
	if !errors.As(err, &ambiguousErr) {
		t.Fatalf("error = %v, want *AmbiguousEndpointError", err)
	}
	if got != nil {
		t.Errorf("result = %+v, want nil on a halt", got)
	}
	if len(prober.ran) != 0 {
		t.Errorf("commands run = %v, want none before the endpoints resolved", prober.ran)
	}
}

// Requirement 6.5 end to end: an external destination is walked as an ordinary
// node rather than refused, and the host layers abstain because address space
// outside the snapshot has no instance to probe.
func TestDiagnoseTreatsAnExternalDestinationAsAnOrdinaryNode(t *testing.T) {
	prober := healthyHostProber()
	req := diagnoseRequest(prober)
	req.Snapshot = externalSnapshot()
	req.To = "198.51.100.0/24"

	got, err := Diagnose(context.Background(), req)
	if err != nil {
		t.Fatalf("Diagnose() error = %v", err)
	}

	if got.Destination.Kind != EndpointExternal {
		t.Errorf("destination kind = %q, want %q", got.Destination.Kind, EndpointExternal)
	}
	if got.Destination.ExternalNetworkID != "ext-onprem" {
		t.Errorf("destination external network = %q, want the declared range", got.Destination.ExternalNetworkID)
	}
	if len(prober.ran) != 0 {
		t.Errorf("commands run = %v, want none for a destination with no instance", prober.ran)
	}
	for _, layer := range host.HostLayers() {
		res, ok := got.Verdict.Result(layer)
		if !ok || res.Verdict != model.VerdictAbstain {
			t.Errorf("layer %s = %+v, want an abstention", layer, res)
		}
	}
	if !strings.Contains(got.Host.Reason, "no instance") {
		t.Errorf("host stage reason = %q, want it to state there was no instance to probe", got.Host.Reason)
	}
}
