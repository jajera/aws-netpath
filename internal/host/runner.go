package host

// Dispatch over AWS Systems Manager.
//
// SendCommand is capable of anything the host's shell is capable of, so the
// guardrail allowlist — not the AWS API allowlist — is the real control here. It
// is checked before the send, and there is no path through this file that
// dispatches a Command that was not built and validated first.
//
// The other half of the file is about what happens when nothing can be run. An
// unmanaged instance, an undeliverable command, and a command that never
// finished are each reported as a distinct error so the host Layers can abstain
// with the reason. None of them is allowed to look like a check that ran and
// found nothing wrong.

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/jajera/aws-netpath/internal/guardrail"
)

// Sentinel errors for the three ways a host check can fail to produce an answer.
// Each is a reason to abstain, never a reason to assume a pass.
var (
	// ErrUnmanaged reports an instance Systems Manager cannot run a command on:
	// unregistered, agent not reporting, or not a Linux host.
	ErrUnmanaged = errors.New("instance is not an ssm-managed linux host")
	// ErrUndeliverable reports a command that could not be delivered to the
	// host, or whose fate Systems Manager could not report.
	ErrUndeliverable = errors.New("host command could not be delivered")
	// ErrCommandTimeout reports a command that was delivered but did not
	// complete in time. The check is unverified; the others still run.
	ErrCommandTimeout = errors.New("host command did not complete in time")
	// ErrArgumentNotRepresentable reports an argv element the transport cannot
	// carry without changing where one argument ends and the next begins.
	ErrArgumentNotRepresentable = errors.New("host command argument not representable")
)

const (
	// shellDocument runs a command on a Linux managed instance. It is the only
	// document this package uses: a document is code, and an operator reading
	// the allowlist should not have to audit a second one.
	shellDocument = "AWS-RunShellScript"
	// probeComment appears against the invocation in the operator's Systems
	// Manager command history, so a probe is identifiable after the fact.
	probeComment = "aws-netpath read-only probe"

	defaultCommandTimeout = 30 * time.Second
	defaultPollInterval   = 2 * time.Second
	// minDeliveryTimeout is the floor SendCommand accepts for TimeoutSeconds.
	minDeliveryTimeout = 30
)

// instanceIDPattern is the shape of an EC2 instance or hybrid managed node id.
// An identifier that is not one cannot name a managed instance, so it is
// refused before it reaches an API call.
var instanceIDPattern = regexp.MustCompile(`^(i|mi)-[0-9a-f]{8,32}$`)

// SSMAPI is the slice of the Systems Manager API the runner uses. Depending on
// the three calls rather than on *ssm.Client is what lets the abstention paths
// be tested against a stub, and it keeps the surface small enough to compare by
// eye against the AWS action allowlist.
type SSMAPI interface {
	SendCommand(ctx context.Context, in *ssm.SendCommandInput, optFns ...func(*ssm.Options)) (*ssm.SendCommandOutput, error)
	GetCommandInvocation(ctx context.Context, in *ssm.GetCommandInvocationInput, optFns ...func(*ssm.Options)) (*ssm.GetCommandInvocationOutput, error)
	DescribeInstanceInformation(ctx context.Context, in *ssm.DescribeInstanceInformationInput, optFns ...func(*ssm.Options)) (*ssm.DescribeInstanceInformationOutput, error)
}

// Runner dispatches validated Commands to one instance and reads their output.
type Runner struct {
	api     SSMAPI
	timeout time.Duration
	poll    time.Duration
	// now and sleep are the runner's only contact with the clock, so the timeout
	// path can be exercised in a test without waiting for it.
	now   func() time.Time
	sleep func(context.Context, time.Duration) error
}

// Option configures a Runner.
type Option func(*Runner)

// WithTimeout sets how long a single command may take to complete.
func WithTimeout(d time.Duration) Option {
	return func(r *Runner) {
		if d > 0 {
			r.timeout = d
		}
	}
}

// WithPollInterval sets the gap between invocation status reads.
func WithPollInterval(d time.Duration) Option {
	return func(r *Runner) {
		if d > 0 {
			r.poll = d
		}
	}
}

// NewRunner returns a Runner dispatching through api.
func NewRunner(api SSMAPI, opts ...Option) *Runner {
	r := &Runner{
		api:     api,
		timeout: defaultCommandTimeout,
		poll:    defaultPollInterval,
		now:     time.Now,
		sleep:   sleepCtx,
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// ManagedInstance is what Systems Manager knows about a probed instance. It is
// returned even when the instance turns out to be unprobeable, because the ping
// status and platform are the evidence for that abstention.
type ManagedInstance struct {
	InstanceID   string
	PingStatus   string
	PlatformType string
	PlatformName string
	AgentVersion string
}

// Result is one command that ran on the host.
//
// A non-zero ExitCode is not an error: `ip route get` exits non-zero when there
// is no route, and that is a finding rather than a failure. Whether the output
// means the Layer passed or blocked is the check's judgement, not the runner's.
type Result struct {
	Command      Command
	Status       string
	StatusDetail string
	ExitCode     int32
	Stdout       string
	Stderr       string
}

// Managed reports whether Systems Manager can run a read-only command on
// instanceID. The error is ErrUnmanaged when the instance is unregistered, its
// agent is not reporting, or it is not Linux — non-Linux host probing is out of
// scope, and guessing at a platform this package cannot parse would be worse
// than abstaining.
func (r *Runner) Managed(ctx context.Context, instanceID string) (ManagedInstance, error) {
	if err := validateInstanceID(instanceID); err != nil {
		return ManagedInstance{}, err
	}
	if err := guardrail.ValidateAction("DescribeInstanceInformation"); err != nil {
		return ManagedInstance{}, err
	}

	out, err := r.api.DescribeInstanceInformation(ctx, &ssm.DescribeInstanceInformationInput{
		Filters: []ssmtypes.InstanceInformationStringFilter{{
			Key:    aws.String("InstanceIds"),
			Values: []string{instanceID},
		}},
	})
	if err != nil {
		var badID *ssmtypes.InvalidInstanceId
		if errors.As(err, &badID) {
			return ManagedInstance{}, fmt.Errorf("%w: ssm does not recognise %s: %w", ErrUnmanaged, instanceID, err)
		}
		return ManagedInstance{}, fmt.Errorf("%w: ssm could not be asked whether %s is managed: %w", ErrUndeliverable, instanceID, err)
	}

	for _, info := range out.InstanceInformationList {
		if aws.ToString(info.InstanceId) != instanceID {
			continue
		}
		mi := ManagedInstance{
			InstanceID:   instanceID,
			PingStatus:   string(info.PingStatus),
			PlatformType: string(info.PlatformType),
			PlatformName: aws.ToString(info.PlatformName),
			AgentVersion: aws.ToString(info.AgentVersion),
		}
		if info.PingStatus != ssmtypes.PingStatusOnline {
			return mi, fmt.Errorf("%w: %s agent ping status is %s", ErrUnmanaged, instanceID, mi.PingStatus)
		}
		if info.PlatformType != ssmtypes.PlatformTypeLinux {
			return mi, fmt.Errorf("%w: %s platform is %s", ErrUnmanaged, instanceID, mi.PlatformType)
		}
		return mi, nil
	}
	return ManagedInstance{InstanceID: instanceID}, fmt.Errorf("%w: %s is not registered with ssm", ErrUnmanaged, instanceID)
}

// Run dispatches cmd to instanceID and returns its output.
//
// Order is the requirement: the allowlist is consulted, then the transport's own
// limits, then the instance identifier, and only then is anything sent. A
// Command that fails any of those never reaches Systems Manager.
func (r *Runner) Run(ctx context.Context, instanceID string, cmd Command) (Result, error) {
	if err := cmd.validate(); err != nil {
		return Result{}, err
	}
	if err := validateInstanceID(instanceID); err != nil {
		return Result{}, err
	}
	if err := guardrail.ValidateAction("SendCommand"); err != nil {
		return Result{}, err
	}

	sent, err := r.api.SendCommand(ctx, &ssm.SendCommandInput{
		DocumentName:   aws.String(shellDocument),
		InstanceIds:    []string{instanceID},
		Comment:        aws.String(probeComment),
		Parameters:     map[string][]string{"commands": {cmd.Line()}},
		TimeoutSeconds: aws.Int32(deliveryTimeout(r.timeout)),
	})
	if err != nil {
		var badID *ssmtypes.InvalidInstanceId
		if errors.As(err, &badID) {
			return Result{}, fmt.Errorf("%w: ssm does not recognise %s: %w", ErrUnmanaged, instanceID, err)
		}
		return Result{}, fmt.Errorf("%w: %s on %s: %w", ErrUndeliverable, cmd.Line(), instanceID, err)
	}
	if sent == nil || sent.Command == nil || aws.ToString(sent.Command.CommandId) == "" {
		return Result{}, fmt.Errorf("%w: %s on %s: ssm accepted the command without returning a command id", ErrUndeliverable, cmd.Line(), instanceID)
	}
	commandID := aws.ToString(sent.Command.CommandId)

	if err := guardrail.ValidateAction("GetCommandInvocation"); err != nil {
		return Result{}, err
	}
	return r.await(ctx, instanceID, commandID, cmd)
}

// await polls the invocation until it reaches a terminal state or the deadline
// passes. A command still running when the deadline passes is a timeout, not a
// result: the check abstains and the remaining checks carry on.
func (r *Runner) await(ctx context.Context, instanceID, commandID string, cmd Command) (Result, error) {
	deadline := r.now().Add(r.timeout)
	for {
		inv, err := r.api.GetCommandInvocation(ctx, &ssm.GetCommandInvocationInput{
			CommandId:  aws.String(commandID),
			InstanceId: aws.String(instanceID),
		})
		switch {
		case err == nil:
			res, done, invErr := interpret(cmd, inv)
			if done {
				return res, invErr
			}
		case isMissingInvocation(err):
			// Systems Manager accepted the command but has not yet recorded the
			// invocation. That is a race with its own bookkeeping, not a failure.
		default:
			return Result{}, fmt.Errorf("%w: %s on %s: %w", ErrUndeliverable, cmd.Line(), instanceID, err)
		}

		if !r.now().Before(deadline) {
			return Result{Command: cmd}, fmt.Errorf("%w: %s on %s after %s", ErrCommandTimeout, cmd.Line(), instanceID, r.timeout)
		}
		if err := r.sleep(ctx, r.poll); err != nil {
			return Result{Command: cmd}, fmt.Errorf("%w: %s on %s: %w", ErrCommandTimeout, cmd.Line(), instanceID, err)
		}
	}
}

// interpret classifies one invocation read. done is false while the command is
// still running. A terminal read yields the output for the check to read, or an
// error saying why there is nothing to read.
func interpret(cmd Command, inv *ssm.GetCommandInvocationOutput) (res Result, done bool, err error) {
	switch inv.Status {
	case ssmtypes.CommandInvocationStatusPending,
		ssmtypes.CommandInvocationStatusInProgress,
		ssmtypes.CommandInvocationStatusDelayed,
		ssmtypes.CommandInvocationStatusCancelling:
		return Result{}, false, nil
	}

	res = Result{
		Command:      cmd,
		Status:       string(inv.Status),
		StatusDetail: aws.ToString(inv.StatusDetails),
		ExitCode:     inv.ResponseCode,
		Stdout:       aws.ToString(inv.StandardOutputContent),
		Stderr:       aws.ToString(inv.StandardErrorContent),
	}

	// The status detail is more specific than the status: a Failed invocation
	// that was never delivered, and one that ran and exited non-zero, are the
	// same status but a different kind of answer.
	if err := detailError(cmd, res); err != nil {
		return res, true, err
	}

	switch inv.Status {
	case ssmtypes.CommandInvocationStatusSuccess, ssmtypes.CommandInvocationStatusFailed:
		return res, true, nil
	case ssmtypes.CommandInvocationStatusTimedOut:
		return res, true, fmt.Errorf("%w: %s: ssm reported %s", ErrCommandTimeout, cmd.Line(), res.Status)
	case ssmtypes.CommandInvocationStatusCancelled:
		return res, true, fmt.Errorf("%w: %s: ssm reported %s", ErrUndeliverable, cmd.Line(), res.Status)
	default:
		return res, true, fmt.Errorf("%w: %s: ssm reported unrecognised status %s", ErrUndeliverable, cmd.Line(), res.Status)
	}
}

// undeliveredDetails are the status details meaning the command never ran on the
// host, so there is no output to interpret.
var undeliveredDetails = map[string]bool{
	"Undeliverable":   true,
	"Terminated":      true,
	"InvalidPlatform": true,
	"AccessDenied":    true,
	"Canceled":        true,
	"Cancelled":       true,
}

// timedOutDetails are the status details meaning the command was cut short by a
// deadline rather than by a decision.
var timedOutDetails = map[string]bool{
	"DeliveryTimedOut":  true,
	"ExecutionTimedOut": true,
}

func detailError(cmd Command, res Result) error {
	switch {
	case undeliveredDetails[res.StatusDetail]:
		return fmt.Errorf("%w: %s: ssm reported %s", ErrUndeliverable, cmd.Line(), res.StatusDetail)
	case timedOutDetails[res.StatusDetail]:
		return fmt.Errorf("%w: %s: ssm reported %s", ErrCommandTimeout, cmd.Line(), res.StatusDetail)
	default:
		return nil
	}
}

func isMissingInvocation(err error) bool {
	var missing *ssmtypes.InvocationDoesNotExist
	return errors.As(err, &missing)
}

// validateInstanceID refuses an identifier that cannot name a managed instance.
// It is reported as ErrUnmanaged rather than as a usage error, because from the
// host Layers' point of view the outcome is the same: nothing can be probed, so
// they abstain.
func validateInstanceID(instanceID string) error {
	if !instanceIDPattern.MatchString(instanceID) {
		return fmt.Errorf("%w: %q is not an instance id", ErrUnmanaged, instanceID)
	}
	return nil
}

// deliveryTimeout converts the command timeout into the delivery window
// SendCommand accepts, which has a floor of 30 seconds.
func deliveryTimeout(d time.Duration) int32 {
	seconds := int32(d.Round(time.Second) / time.Second)
	if seconds < minDeliveryTimeout {
		return minDeliveryTimeout
	}
	return seconds
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
