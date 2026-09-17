package cli

// Exit-code mapping, in one place because it is one decision.
//
// Cross-cutting 7 gives three codes and requirement 16.6 makes the CLI use them.
// Read literally they are almost trivial; read as a contract with a pipeline they
// are the tool's most load-bearing output, because a pipeline reads the code and
// nothing else. So the whole mapping is here, as two total functions over the
// facts a command has, rather than as a conditional per command that drifts one
// command at a time.
//
//	0  the answer was established and it is "permitted", or the command succeeded
//	1  a finding to act on, or an answer established only in part — usable either way
//	2  the command could not produce an answer at all
//
// The line between 1 and 2 is whether there is output worth reading. A blocked
// flow, a difference between two paths, a change between two collections, a
// collection that recorded errors: all of those ran, all of them produced a
// report, and all of them are exit 1. A missing flag, an unreadable snapshot, an
// endpoint matching two instances: nothing to read, exit 2.
//
// The line between 0 and 1 is the harder one, and it is where cross-cutting 1
// does the work. An Abstention is not a pass, which means exit 0 cannot be the
// code for "nothing was shown to block this" — only for "nothing blocks this, and
// every layer was checked". A verdict resting on a Layer that could not be read
// is the same class of answer as a collection that recorded errors: usable, and
// short of the question asked. That is exit 1's other half, and it is why
// exitFinding takes two facts rather than one.

import (
	"errors"
	"flag"
)

// Exit codes are chosen so aws-netpath drops into a CI pipeline without a wrapper:
// a blocked flow is a test failure, not a tool error.
const (
	ExitOK      = 0 // the traffic is permitted and every layer was evaluated, or the command succeeded
	ExitBlocked = 1 // a finding to act on, or an answer established only in part
	ExitError   = 2 // bad usage, unreadable input, or an API failure
)

// exitParse maps the outcome of flag parsing to an exit code.
//
// Requested help is a command succeeding. Every command parses with
// flag.ContinueOnError so it can report a bad flag in its own voice, and the flag
// package answers -h and --help by printing usage and returning flag.ErrHelp —
// indistinguishable, to a naive check, from the argument error it returns for a
// flag that does not exist. Treating the two alike makes `aws-netpath diagnose -h`
// exit 2, which tells a pipeline the invocation was wrong when the operator got
// exactly what they asked for. So ErrHelp is separated out and mapped to success,
// matching the top-level `aws-netpath --help`.
//
// Everything else is exit 2: an unrecognised flag, or a value the flag package
// could not parse, means the command was never told what to do.
func exitParse(err error) int {
	switch {
	case err == nil:
		return ExitOK
	case errors.Is(err, flag.ErrHelp):
		return ExitOK
	default:
		return ExitError
	}
}

// exitFinding maps a completed run to an exit code.
//
// finding is whether the run turned up the thing the command exists to look for:
// a blocking Layer, a difference between two paths, a change between two
// collections, a declared flow that did not hold, two sources that disagree.
//
// established is whether the run could say so with everything evaluated. False
// means at least one Layer, comparison, or resource could not be read, so the
// answer is usable but is not the answer that was asked for. Cross-cutting 1
// forbids folding that into a pass, and cross-cutting 7 already has a code for
// "incomplete but usable", so it takes exit 1 alongside the findings.
//
// Note that the two are not independent in practice: a verdict that names a
// blocking Layer is generally established regardless of what abstained after it,
// because an unevaluated Layer cannot un-block traffic another Layer was shown to
// drop. Both facts are still passed, because deciding that is the correlator's
// job, not this function's.
func exitFinding(finding, established bool) int {
	if finding || !established {
		return ExitBlocked
	}
	return ExitOK
}
