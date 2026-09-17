// Package guardrail enforces the read-only guarantee in code rather than by
// convention. Every AWS API action and every host command aws-netpath issues
// must appear in an allowlist here, and host command arguments are screened for
// shell metacharacters before dispatch.
//
// Matching is exact. A near miss is a rejection, not a warning: an action or
// command that is not literally in the map is refused, and the error names what
// was refused so the operator can see precisely which call was blocked.
package guardrail

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// allowedAWSActions is the complete set of AWS API actions aws-netpath may
// call. Everything is a read except the two Reachability Analyzer creates,
// which create analysis objects rather than infrastructure and only run under
// the verify command.
var allowedAWSActions = map[string]bool{
	"DescribeInstances": true, "DescribeNetworkInterfaces": true,
	"DescribeSubnets": true, "DescribeVpcs": true, "DescribeRouteTables": true,
	"DescribeNetworkAcls": true, "DescribeSecurityGroups": true,
	"DescribeTransitGateways": true, "DescribeTransitGatewayRouteTables": true,
	"SearchTransitGatewayRoutes": true, "DescribeTransitGatewayAttachments": true,
	"DescribeFirewall": true, "DescribeFirewallPolicy": true, "DescribeRuleGroup": true,
	"GetCallerIdentity": true,
	"SendCommand":       true, "GetCommandInvocation": true, "DescribeInstanceInformation": true,
	"CreateNetworkInsightsPath": true, "StartNetworkInsightsAnalysis": true,
	"DescribeNetworkInsightsAnalyses": true,
}

// allowedHostCommands is the complete set of executables aws-netpath may run on
// a probed host. SendCommand is itself capable of mutation, so this map is the
// real control: it is checked before dispatch, not after.
var allowedHostCommands = map[string]bool{
	"ss": true, "firewall-cmd": true, "ip": true, "ping": true,
}

// Sentinel errors so callers can distinguish a policy refusal from a transport
// failure. Each returned error wraps one of these and names the offending
// action, command, or argument.
var (
	// ErrActionNotAllowed reports an AWS API action absent from the allowlist.
	ErrActionNotAllowed = errors.New("aws action not allowed")
	// ErrCommandNotAllowed reports a host command absent from the allowlist.
	ErrCommandNotAllowed = errors.New("host command not allowed")
	// ErrUnsafeArgument reports a host command argument containing a character
	// that could alter the meaning of the invocation.
	ErrUnsafeArgument = errors.New("unsafe host command argument")
)

// unsafeArgumentChars are the characters rejected in host command arguments.
// Commands are always invoked as argument lists rather than shell strings, so
// none of these can be interpreted by a shell on the paths aws-netpath
// controls. They are rejected anyway, because the cost of being wrong about
// that on one future code path is a mutation on a production host.
//
// The set covers three families:
//
//   - chaining and redirection: ; & | < > $ ` ( )
//   - quoting and escaping, which could reintroduce the above: \ ' "
//   - expansion and globbing: * ? [ ] { } ~ !
//
// Control characters, including newline and carriage return, are rejected
// separately by ValidateArgument. Spaces are permitted: within a single argv
// element a space is data, not a separator.
const unsafeArgumentChars = ";&|<>$`()\\'\"*?[]{}~!"

// ValidateAction reports whether an AWS API action may be called. The action is
// the bare API name, such as "DescribeSubnets", with no service prefix.
func ValidateAction(action string) error {
	if !allowedAWSActions[action] {
		return fmt.Errorf("%w: %q", ErrActionNotAllowed, action)
	}
	return nil
}

// ValidateHostCommand reports whether a host command may be dispatched. The
// command is the bare executable name and args are the individual argv
// elements, never a shell string. Both the command and every argument must pass
// for the call to be permitted.
func ValidateHostCommand(command string, args ...string) error {
	if !allowedHostCommands[command] {
		return fmt.Errorf("%w: %q", ErrCommandNotAllowed, command)
	}
	for i, arg := range args {
		if err := ValidateArgument(arg); err != nil {
			return fmt.Errorf("host command %q argument %d: %w", command, i, err)
		}
	}
	return nil
}

// ValidateArgv is ValidateHostCommand for a command already assembled as an
// argv slice, where argv[0] is the executable. An empty argv is a rejection:
// there is nothing to check against the allowlist, so there is nothing to
// permit.
func ValidateArgv(argv []string) error {
	if len(argv) == 0 {
		return fmt.Errorf("%w: empty argument list", ErrCommandNotAllowed)
	}
	return ValidateHostCommand(argv[0], argv[1:]...)
}

// ValidateArgument reports whether a single argv element is safe to pass to a
// host command. It rejects control characters and the shell metacharacters
// listed in unsafeArgumentChars.
func ValidateArgument(arg string) error {
	for _, r := range arg {
		switch {
		case r < 0x20 || r == 0x7f:
			return fmt.Errorf("%w %q: control character %q", ErrUnsafeArgument, arg, r)
		case strings.ContainsRune(unsafeArgumentChars, r):
			return fmt.Errorf("%w %q: shell metacharacter %q", ErrUnsafeArgument, arg, r)
		}
	}
	return nil
}

// AllowedActions returns the permitted AWS API actions in sorted order, for
// documentation and for reporting the read-only guarantee to an operator.
func AllowedActions() []string { return sortedKeys(allowedAWSActions) }

// AllowedHostCommands returns the permitted host commands in sorted order.
func AllowedHostCommands() []string { return sortedKeys(allowedHostCommands) }

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
