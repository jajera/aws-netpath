// Package host probes the state a cloud API cannot see: whether a process is
// listening on the destination port, and whether the host firewall admits the
// source. Every probe is read-only, and that is enforced rather than intended —
// each command is built from a fixed template, assembled as an argv list, and
// passed through the Guardrail_Enforcer allowlist before anything is dispatched.
//
// This file is the command surface: what a probe may ask for. The dispatch
// surface, and the abstentions that stand in for a probe that could not run,
// live alongside it in runner.go and abstain.go.
//
// The shape is deliberate. A probe never assembles a command string; it names a
// Template and supplies values for the placeholders in it. Everything else in
// the invocation is literal text the caller cannot influence, so the worst a
// caller can do with a hostile value is fail validation.
package host

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"

	"github.com/jajera/aws-netpath/internal/guardrail"
	"github.com/jajera/aws-netpath/internal/model"
)

// Check names the host check a Command serves. The individual checks declare
// their own values; the runner only carries the name through to citations and
// abstention reasons, so a new check needs no change here.
type Check string

// Command is a host command ready to dispatch: argv[0] is the executable and
// every remaining element is one argument. It exists only as the output of
// Template.Build, which is what makes "no unvalidated input in a host command"
// a property of the type rather than a rule to remember.
type Command struct {
	Check Check
	Argv  []string
}

// Template is a fixed command shape. Text of the form {name} is a placeholder to
// be substituted; everything else is literal and no caller can change it.
//
// Templates are values rather than format strings because a format string can be
// supplied at the call site, and the point of this indirection is that the shape
// of a host command is decided in the source, not at the call.
type Template struct {
	Check Check
	Argv  []string
}

// placeholderPattern matches one {name} placeholder. The braces are themselves
// rejected by the argument screen, so a template that reaches dispatch with a
// placeholder still in it is refused even if this substitution missed it.
var placeholderPattern = regexp.MustCompile(`\{([A-Za-z][A-Za-z0-9_]*)\}`)

// Build substitutes subs into t and returns a validated Command.
//
// Validation runs twice and both passes matter. Each substituted value is
// screened on its own, so the error names the placeholder an operator supplied
// rather than a position in an assembled argv; then the finished invocation is
// screened as a whole, so a template whose literal text is unsafe is refused
// too. A placeholder with no value, or a value with no placeholder, is an error:
// both mean the caller and the template disagree about the command being run.
func (t Template) Build(subs map[string]string) (Command, error) {
	if len(t.Argv) == 0 {
		return Command{}, fmt.Errorf("host command template %q: no argv", t.Check)
	}

	for name, value := range subs {
		if err := guardrail.ValidateArgument(value); err != nil {
			return Command{}, fmt.Errorf("host command template %q substitution %s: %w", t.Check, name, err)
		}
		if err := validateRepresentable(value); err != nil {
			return Command{}, fmt.Errorf("host command template %q substitution %s: %w", t.Check, name, err)
		}
	}

	used := make(map[string]bool, len(subs))
	argv := make([]string, len(t.Argv))
	var missing []string
	for i, element := range t.Argv {
		argv[i] = placeholderPattern.ReplaceAllStringFunc(element, func(match string) string {
			name := match[1 : len(match)-1]
			value, ok := subs[name]
			if !ok {
				missing = append(missing, name)
				return match
			}
			used[name] = true
			return value
		})
	}
	if len(missing) > 0 {
		return Command{}, fmt.Errorf("host command template %q: no value for placeholder %s", t.Check, strings.Join(missing, ", "))
	}
	for name := range subs {
		if !used[name] {
			return Command{}, fmt.Errorf("host command template %q: substitution %s matches no placeholder", t.Check, name)
		}
	}

	cmd := Command{Check: t.Check, Argv: argv}
	if err := cmd.validate(); err != nil {
		return Command{}, err
	}
	return cmd, nil
}

// validate is the whole-invocation gate: the allowlist plus the transport's own
// limits. Run before dispatch, never after.
func (c Command) validate() error {
	if err := guardrail.ValidateArgv(c.Argv); err != nil {
		return err
	}
	for i, element := range c.Argv {
		if err := validateRepresentable(element); err != nil {
			return fmt.Errorf("host command %q argument %d: %w", c.Argv[0], i, err)
		}
	}
	return nil
}

// Line renders the command as the single line the transport carries.
//
// Systems Manager delivers a script, not an argv, so the argv has to be joined
// somewhere. Joining is only faithful while no element contains whitespace and
// no element is empty — otherwise the boundaries the caller drew would be redrawn
// by the remote shell's word splitting. validateRepresentable enforces exactly
// that, which is why this is a plain join and not a quoting routine: quoting
// would reintroduce the metacharacters the guardrail exists to keep out.
func (c Command) Line() string { return strings.Join(c.Argv, " ") }

// String renders the command for a human, which is the same text dispatched.
func (c Command) String() string { return c.Line() }

// Citation returns the evidence for a finding this command produced. Host
// findings cite the command that was run, because the command and its output are
// the only evidence a host check has.
func (c Command) Citation(detail string) model.Citation {
	return model.Citation{Kind: "command", Identifier: c.Line(), Detail: detail}
}

// validateRepresentable reports whether one argv element survives the transport
// with its boundaries intact. Whitespace would split one argument into two, and
// an empty element would vanish; either way the command that ran would not be
// the command that was validated.
func validateRepresentable(element string) error {
	if element == "" {
		return fmt.Errorf("%w: empty argument", ErrArgumentNotRepresentable)
	}
	for _, r := range element {
		if unicode.IsSpace(r) {
			return fmt.Errorf("%w: %q contains whitespace", ErrArgumentNotRepresentable, element)
		}
	}
	return nil
}
