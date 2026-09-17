package host

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/jajera/aws-netpath/internal/guardrail"
)

const testInstance = "i-0123456789abcdef0"

// invocationStep is one canned GetCommandInvocation read. The stub replays steps
// in order and repeats the last, so a test can describe a command that stays in
// progress forever without describing an unbounded list.
type invocationStep struct {
	out *ssm.GetCommandInvocationOutput
	err error
}

// stubSSM records what reached the transport. Anything the runner refused should
// leave sent empty, which is what makes "validation runs before dispatch"
// observable rather than assumed.
type stubSSM struct {
	sent []*ssm.SendCommandInput
	// sendErr fails the send; noCommandID accepts it but reports no command id,
	// leaving nothing to poll for.
	sendErr     error
	noCommandID bool

	steps           []invocationStep
	invocationCalls int

	described   []*ssm.DescribeInstanceInformationInput
	instances   []ssmtypes.InstanceInformation
	describeErr error
}

func (s *stubSSM) SendCommand(_ context.Context, in *ssm.SendCommandInput, _ ...func(*ssm.Options)) (*ssm.SendCommandOutput, error) {
	s.sent = append(s.sent, in)
	if s.sendErr != nil {
		return nil, s.sendErr
	}
	if s.noCommandID {
		return &ssm.SendCommandOutput{}, nil
	}
	return &ssm.SendCommandOutput{Command: &ssmtypes.Command{
		CommandId: aws.String("11111111-2222-3333-4444-555555555555"),
	}}, nil
}

func (s *stubSSM) GetCommandInvocation(_ context.Context, _ *ssm.GetCommandInvocationInput, _ ...func(*ssm.Options)) (*ssm.GetCommandInvocationOutput, error) {
	i := s.invocationCalls
	s.invocationCalls++
	if len(s.steps) == 0 {
		return &ssm.GetCommandInvocationOutput{Status: ssmtypes.CommandInvocationStatusSuccess}, nil
	}
	if i >= len(s.steps) {
		i = len(s.steps) - 1
	}
	step := s.steps[i]
	return step.out, step.err
}

func (s *stubSSM) DescribeInstanceInformation(_ context.Context, in *ssm.DescribeInstanceInformationInput, _ ...func(*ssm.Options)) (*ssm.DescribeInstanceInformationOutput, error) {
	s.described = append(s.described, in)
	if s.describeErr != nil {
		return nil, s.describeErr
	}
	return &ssm.DescribeInstanceInformationOutput{InstanceInformationList: s.instances}, nil
}

// fakeClock lets the timeout path be exercised without waiting for it.
type fakeClock struct {
	now    time.Time
	sleeps int
}

func (c *fakeClock) Now() time.Time { return c.now }

func (c *fakeClock) Sleep(_ context.Context, d time.Duration) error {
	c.sleeps++
	c.now = c.now.Add(d)
	return nil
}

func newTestRunner(api SSMAPI, opts ...Option) (*Runner, *fakeClock) {
	clock := &fakeClock{now: time.Unix(1700000000, 0)}
	r := NewRunner(api, opts...)
	r.now = clock.Now
	r.sleep = clock.Sleep
	return r, clock
}

func successStep(stdout string) invocationStep {
	return invocationStep{out: &ssm.GetCommandInvocationOutput{
		Status:                ssmtypes.CommandInvocationStatusSuccess,
		StatusDetails:         aws.String("Success"),
		StandardOutputContent: aws.String(stdout),
	}}
}

func listenerCommand(t *testing.T) Command {
	t.Helper()
	cmd, err := Template{Check: "listener", Argv: []string{"ss", "-tlnp"}}.Build(nil)
	if err != nil {
		t.Fatalf("build listener command: %v", err)
	}
	return cmd
}

// Requirements 8.7 and 15.5: the allowlist is consulted before the send, so a
// command absent from it never reaches Systems Manager. Commands are constructed
// directly here rather than through Build, because Build would refuse them —
// this asserts the runner refuses them too, so no future caller can route around
// the template and reach the transport.
func TestRunRefusesUnallowedCommandsWithoutDispatching(t *testing.T) {
	tests := []struct {
		name    string
		cmd     Command
		wantErr error
	}{
		{
			name:    "unlisted executable",
			cmd:     Command{Check: "mutating", Argv: []string{"systemctl", "restart", "firewalld"}},
			wantErr: guardrail.ErrCommandNotAllowed,
		},
		{
			name:    "shell wrapper around an allowed command",
			cmd:     Command{Check: "mutating", Argv: []string{"sh", "-c", "ss -tlnp"}},
			wantErr: guardrail.ErrCommandNotAllowed,
		},
		{
			name:    "empty argv",
			cmd:     Command{Check: "empty"},
			wantErr: guardrail.ErrCommandNotAllowed,
		},
		{
			name:    "chained argument",
			cmd:     Command{Check: "listener", Argv: []string{"ss", "-tlnp;reboot"}},
			wantErr: guardrail.ErrUnsafeArgument,
		},
		{
			name:    "substituted argument",
			cmd:     Command{Check: "route", Argv: []string{"ip", "route", "get", "$(id)"}},
			wantErr: guardrail.ErrUnsafeArgument,
		},
		{
			name:    "argument the transport would split",
			cmd:     Command{Check: "listener", Argv: []string{"ss", "state established"}},
			wantErr: ErrArgumentNotRepresentable,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stub := &stubSSM{}
			r, _ := newTestRunner(stub)
			_, err := r.Run(context.Background(), testInstance, tc.cmd)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Run(%v) error = %v, want %v", tc.cmd.Argv, err, tc.wantErr)
			}
			if len(stub.sent) != 0 {
				t.Fatalf("transport saw %d commands, want none: %+v", len(stub.sent), stub.sent)
			}
		})
	}
}

func TestRunDispatchesAsAFixedDocumentAndReturnsOutput(t *testing.T) {
	const output = "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*"
	stub := &stubSSM{steps: []invocationStep{successStep(output)}}
	r, _ := newTestRunner(stub, WithTimeout(45*time.Second), WithPollInterval(time.Second))

	cmd := listenerCommand(t)
	res, err := r.Run(context.Background(), testInstance, cmd)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Stdout != output {
		t.Errorf("Stdout = %q, want %q", res.Stdout, output)
	}
	if res.Command.Check != cmd.Check {
		t.Errorf("Result command check = %q, want %q", res.Command.Check, cmd.Check)
	}

	if len(stub.sent) != 1 {
		t.Fatalf("transport saw %d commands, want 1", len(stub.sent))
	}
	in := stub.sent[0]
	if aws.ToString(in.DocumentName) != shellDocument {
		t.Errorf("DocumentName = %q, want %q", aws.ToString(in.DocumentName), shellDocument)
	}
	if len(in.InstanceIds) != 1 || in.InstanceIds[0] != testInstance {
		t.Errorf("InstanceIds = %v, want [%s]", in.InstanceIds, testInstance)
	}
	if got := in.Parameters["commands"]; len(got) != 1 || got[0] != "ss -tlnp" {
		t.Errorf("commands = %v, want [ss -tlnp]", got)
	}
	if aws.ToInt32(in.TimeoutSeconds) != 45 {
		t.Errorf("TimeoutSeconds = %d, want 45", aws.ToInt32(in.TimeoutSeconds))
	}
}

// SendCommand refuses a delivery window under 30 seconds, so a shorter command
// timeout must not be passed through as one.
func TestRunHonoursTheDeliveryTimeoutFloor(t *testing.T) {
	stub := &stubSSM{steps: []invocationStep{successStep("")}}
	r, _ := newTestRunner(stub, WithTimeout(5*time.Second))
	if _, err := r.Run(context.Background(), testInstance, listenerCommand(t)); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := aws.ToInt32(stub.sent[0].TimeoutSeconds); got != minDeliveryTimeout {
		t.Errorf("TimeoutSeconds = %d, want the %d second floor", got, minDeliveryTimeout)
	}
}

// A command that ran and exited non-zero produced output, and reading it is the
// check's job. `ip route get` with no route is exactly this case, so a non-zero
// exit is a result rather than a failure to probe.
func TestRunReturnsOutputForANonZeroExit(t *testing.T) {
	stub := &stubSSM{steps: []invocationStep{{out: &ssm.GetCommandInvocationOutput{
		Status:               ssmtypes.CommandInvocationStatusFailed,
		StatusDetails:        aws.String("Failed"),
		ResponseCode:         2,
		StandardErrorContent: aws.String("RTNETLINK answers: Network is unreachable"),
	}}}}
	r, _ := newTestRunner(stub)

	res, err := r.Run(context.Background(), testInstance, listenerCommand(t))
	if err != nil {
		t.Fatalf("Run: %v, want the output handed back for the check to read", err)
	}
	if res.ExitCode != 2 {
		t.Errorf("ExitCode = %d, want 2", res.ExitCode)
	}
	if !strings.Contains(res.Stderr, "Network is unreachable") {
		t.Errorf("Stderr = %q, want the command's own error text", res.Stderr)
	}
}

// The invocation is briefly unknown after SendCommand accepts it. That is Systems
// Manager's bookkeeping catching up, not a delivery failure, so the runner waits.
func TestRunWaitsForAnInvocationNotYetRecorded(t *testing.T) {
	stub := &stubSSM{steps: []invocationStep{
		{err: &ssmtypes.InvocationDoesNotExist{}},
		{out: &ssm.GetCommandInvocationOutput{Status: ssmtypes.CommandInvocationStatusInProgress}},
		successStep("LISTEN 0 128 0.0.0.0:22 0.0.0.0:*"),
	}}
	r, clock := newTestRunner(stub, WithTimeout(30*time.Second), WithPollInterval(2*time.Second))

	res, err := r.Run(context.Background(), testInstance, listenerCommand(t))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Status != string(ssmtypes.CommandInvocationStatusSuccess) {
		t.Errorf("Status = %q, want Success", res.Status)
	}
	if clock.sleeps != 2 {
		t.Errorf("slept %d times, want 2 between the three reads", clock.sleeps)
	}
}

// Requirement 8.6: a command that cannot be delivered abstains with the reason.
// Each of these leaves the host unverified, and none of them may look like a
// check that ran.
func TestRunReportsUndeliverableCommands(t *testing.T) {
	tests := []struct {
		name     string
		stub     *stubSSM
		wantErr  error
		wantText string
	}{
		{
			name:     "instance unknown to ssm",
			stub:     &stubSSM{sendErr: &ssmtypes.InvalidInstanceId{Message: aws.String("instance not in a valid state")}},
			wantErr:  ErrUnmanaged,
			wantText: testInstance,
		},
		{
			name:     "send rejected",
			stub:     &stubSSM{sendErr: errors.New("AccessDeniedException: not authorized to perform ssm:SendCommand")},
			wantErr:  ErrUndeliverable,
			wantText: "ssm:SendCommand",
		},
		{
			name:     "no command id returned",
			stub:     &stubSSM{noCommandID: true},
			wantErr:  ErrUndeliverable,
			wantText: "command id",
		},
		{
			name: "invocation undeliverable",
			stub: &stubSSM{steps: []invocationStep{{out: &ssm.GetCommandInvocationOutput{
				Status:        ssmtypes.CommandInvocationStatusFailed,
				StatusDetails: aws.String("Undeliverable"),
			}}}},
			wantErr:  ErrUndeliverable,
			wantText: "Undeliverable",
		},
		{
			name: "invocation cancelled",
			stub: &stubSSM{steps: []invocationStep{{out: &ssm.GetCommandInvocationOutput{
				Status:        ssmtypes.CommandInvocationStatusCancelled,
				StatusDetails: aws.String("Canceled"),
			}}}},
			wantErr:  ErrUndeliverable,
			wantText: "ss -tlnp",
		},
		{
			name:     "invocation unreadable",
			stub:     &stubSSM{steps: []invocationStep{{err: errors.New("ThrottlingException: rate exceeded")}}},
			wantErr:  ErrUndeliverable,
			wantText: "ThrottlingException",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, _ := newTestRunner(tc.stub, WithTimeout(30*time.Second), WithPollInterval(2*time.Second))
			_, err := r.Run(context.Background(), testInstance, listenerCommand(t))
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Run error = %v, want %v", err, tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantText) {
				t.Errorf("error = %q, want it to name %q", err, tc.wantText)
			}
		})
	}
}

func TestRunReportsATimedOutCommand(t *testing.T) {
	tests := []struct {
		name  string
		steps []invocationStep
	}{
		{
			name:  "never completes",
			steps: []invocationStep{{out: &ssm.GetCommandInvocationOutput{Status: ssmtypes.CommandInvocationStatusInProgress}}},
		},
		{
			name: "ssm reports timed out",
			steps: []invocationStep{{out: &ssm.GetCommandInvocationOutput{
				Status:        ssmtypes.CommandInvocationStatusTimedOut,
				StatusDetails: aws.String("ExecutionTimedOut"),
			}}},
		},
		{
			name: "delivery timed out",
			steps: []invocationStep{{out: &ssm.GetCommandInvocationOutput{
				Status:        ssmtypes.CommandInvocationStatusFailed,
				StatusDetails: aws.String("DeliveryTimedOut"),
			}}},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stub := &stubSSM{steps: tc.steps}
			r, _ := newTestRunner(stub, WithTimeout(10*time.Second), WithPollInterval(2*time.Second))
			_, err := r.Run(context.Background(), testInstance, listenerCommand(t))
			if !errors.Is(err, ErrCommandTimeout) {
				t.Fatalf("Run error = %v, want %v", err, ErrCommandTimeout)
			}
			if !strings.Contains(err.Error(), "ss -tlnp") {
				t.Errorf("error = %q, want it to name the command", err)
			}
		})
	}
}

// Requirement 8.6: an instance Systems Manager does not manage is reported as
// such, and no command is attempted against it.
func TestManagedClassifiesTheInstance(t *testing.T) {
	online := ssmtypes.InstanceInformation{
		InstanceId:   aws.String(testInstance),
		PingStatus:   ssmtypes.PingStatusOnline,
		PlatformType: ssmtypes.PlatformTypeLinux,
		PlatformName: aws.String("Amazon Linux"),
		AgentVersion: aws.String("3.3.0.0"),
	}
	tests := []struct {
		name     string
		stub     *stubSSM
		instance string
		wantErr  error
		wantText string
	}{
		{name: "online linux host", stub: &stubSSM{instances: []ssmtypes.InstanceInformation{online}}, instance: testInstance},
		{
			name: "agent not reporting",
			stub: &stubSSM{instances: []ssmtypes.InstanceInformation{{
				InstanceId:   aws.String(testInstance),
				PingStatus:   ssmtypes.PingStatusConnectionLost,
				PlatformType: ssmtypes.PlatformTypeLinux,
			}}},
			instance: testInstance,
			wantErr:  ErrUnmanaged,
			wantText: "ConnectionLost",
		},
		{
			name: "non-linux host is out of scope",
			stub: &stubSSM{instances: []ssmtypes.InstanceInformation{{
				InstanceId:   aws.String(testInstance),
				PingStatus:   ssmtypes.PingStatusOnline,
				PlatformType: ssmtypes.PlatformTypeWindows,
			}}},
			instance: testInstance,
			wantErr:  ErrUnmanaged,
			wantText: "Windows",
		},
		{
			name:     "not registered",
			stub:     &stubSSM{},
			instance: testInstance,
			wantErr:  ErrUnmanaged,
			wantText: "not registered",
		},
		{
			name:     "another instance returned",
			stub:     &stubSSM{instances: []ssmtypes.InstanceInformation{{InstanceId: aws.String("i-000000000000000ff"), PingStatus: ssmtypes.PingStatusOnline, PlatformType: ssmtypes.PlatformTypeLinux}}},
			instance: testInstance,
			wantErr:  ErrUnmanaged,
			wantText: "not registered",
		},
		{
			name:     "ssm unreachable",
			stub:     &stubSSM{describeErr: errors.New("AccessDeniedException: not authorized to perform ssm:DescribeInstanceInformation")},
			instance: testInstance,
			wantErr:  ErrUndeliverable,
			wantText: "ssm:DescribeInstanceInformation",
		},
		{
			name:     "not an instance id",
			stub:     &stubSSM{},
			instance: "app-01",
			wantErr:  ErrUnmanaged,
			wantText: "app-01",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, _ := newTestRunner(tc.stub)
			mi, err := r.Managed(context.Background(), tc.instance)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Managed(%q) error = %v, want %v", tc.instance, err, tc.wantErr)
			}
			if tc.wantErr == nil {
				if mi.PingStatus != string(ssmtypes.PingStatusOnline) || mi.PlatformType != string(ssmtypes.PlatformTypeLinux) {
					t.Errorf("instance = %+v, want an online linux host", mi)
				}
				return
			}
			if !strings.Contains(err.Error(), tc.wantText) {
				t.Errorf("error = %q, want it to name %q", err, tc.wantText)
			}
		})
	}
}

// An identifier that cannot name a managed instance is refused before any call is
// made: there is nothing to ask AWS about.
func TestUnusableInstanceIDNeverReachesTheAPI(t *testing.T) {
	for _, id := range []string{"", "app-01", "i-", "10.20.1.10", "i-0123456789abcdefg"} {
		stub := &stubSSM{}
		r, _ := newTestRunner(stub)
		if _, err := r.Managed(context.Background(), id); !errors.Is(err, ErrUnmanaged) {
			t.Errorf("Managed(%q) error = %v, want %v", id, err, ErrUnmanaged)
		}
		if _, err := r.Run(context.Background(), id, listenerCommand(t)); !errors.Is(err, ErrUnmanaged) {
			t.Errorf("Run(%q) error = %v, want %v", id, err, ErrUnmanaged)
		}
		if len(stub.described) != 0 || len(stub.sent) != 0 {
			t.Errorf("id %q reached the api: %d describes, %d sends", id, len(stub.described), len(stub.sent))
		}
	}
}
