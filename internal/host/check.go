package host

// The shared seam every host check sits on.
//
// A check is three steps: name a Template, run it, read the output. What differs
// between checks is only the parsing and the judgement, so the parts that must
// not vary — validation before dispatch, an Abstention when nothing could be
// read, a Citation carrying the command and its output — live here once.
//
// Two kinds of check come out of this. A Layer check returns a
// model.LayerResult, because the listener and the host firewall are Layers with
// verdicts of their own. A supporting check returns a Finding, because the local
// route and the path MTU are evidence rather than decisions: they inform a
// diagnosis without ever blocking one.

import (
	"context"
	"fmt"
	"strings"

	"github.com/jajera/aws-netpath/internal/model"
)

// CommandRunner is the dispatch a check needs: one validated Command to one
// instance, and whatever came back. *Runner implements it.
//
// Checks depend on this rather than on *Runner so that the parsing and the
// judgement can be exercised against recorded command output, which is the only
// way to test a parser against the real shapes a host emits.
type CommandRunner interface {
	Run(ctx context.Context, instanceID string, cmd Command) (Result, error)
}

// Finding is what a supporting check learned.
//
// It carries no verdict because the checks that produce it — the local route and
// the path MTU — are not Layers. Inventing a Layer for them would give them a
// verdict they did not earn, and a path MTU failure blocks nothing: it explains
// a stall that every Layer permitted.
type Finding struct {
	Check   Check  `json:"check"`
	Summary string `json:"summary,omitempty"`
	// Reason is set, and Summary empty, when the check could not be
	// interpreted. A supporting check that says nothing reads as a check that
	// found nothing wrong, so it says why instead.
	Reason    string           `json:"reason,omitempty"`
	Citations []model.Citation `json:"citations,omitempty"`
}

// Interpreted reports whether the check produced an answer.
func (f Finding) Interpreted() bool { return f.Reason == "" }

// abstainFinding returns a Finding stating why the check could not be read.
func abstainFinding(check Check, err error) Finding {
	reason := "not determined"
	if err != nil {
		reason = fmt.Sprintf("not determined: %v", err)
	}
	return Finding{Check: check, Reason: reason}
}

// run builds a Command from tmpl and dispatches it. A build failure is reported
// on the same terms as a dispatch failure: either way the check has no output,
// and the caller's next move is to abstain with the reason.
func run(ctx context.Context, r CommandRunner, instanceID string, tmpl Template, subs map[string]string) (Result, error) {
	if r == nil {
		return Result{}, fmt.Errorf("%w: no runner for check %s", ErrUndeliverable, tmpl.Check)
	}
	cmd, err := tmpl.Build(subs)
	if err != nil {
		return Result{}, err
	}
	return r.Run(ctx, instanceID, cmd)
}

// errCommandFailed reports a command that ran and failed rather than one that
// could not be delivered. It is a distinct condition: Systems Manager did its
// job, and it is the host that had nothing to say. `firewall-cmd` on a host
// without firewalld running is the case that matters, and it must abstain — an
// unreadable firewall is not an open one.
func errCommandFailed(res Result) error {
	detail := firstLine(res.Stderr)
	if detail == "" {
		detail = firstLine(res.Stdout)
	}
	if detail == "" {
		detail = "no output"
	}
	return fmt.Errorf("%s exited %d: %s", res.Command.Line(), res.ExitCode, detail)
}

// errUnreadableOutput reports output that was produced but could not be
// interpreted. Guessing at it would be worse than abstaining: the line nobody
// could parse is exactly the line that might have been the answer.
func errUnreadableOutput(cmd Command, err error) error {
	return fmt.Errorf("could not read the output of %s: %w", cmd.Line(), err)
}

// firstLine returns the first non-blank line of s, trimmed, so an abstention
// reason carries the host's own explanation without carrying a screenful of it.
func firstLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if text := strings.TrimSpace(line); text != "" {
			return text
		}
	}
	return ""
}

// truncateList joins at most limit entries and states how many were left out, so
// a citation stays readable without ever implying it showed everything.
func truncateList(entries []string, limit int) string {
	if len(entries) == 0 {
		return ""
	}
	if len(entries) <= limit {
		return strings.Join(entries, "; ")
	}
	shown := strings.Join(entries[:limit], "; ")
	return fmt.Sprintf("%s; (%d more not shown)", shown, len(entries)-limit)
}

// pass returns the PASS result for a Layer decided on the host.
func pass(layer model.Layer, citations ...model.Citation) model.LayerResult {
	return model.LayerResult{Layer: layer, Verdict: model.VerdictPass, Citations: citations}
}

// blocked returns the BLOCKED result for a Layer decided on the host.
func blocked(layer model.Layer, citations ...model.Citation) model.LayerResult {
	return model.LayerResult{Layer: layer, Verdict: model.VerdictBlocked, Citations: citations}
}
