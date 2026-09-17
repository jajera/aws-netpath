package guardrail

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateAction(t *testing.T) {
	tests := []struct {
		name    string
		action  string
		wantErr error
	}{
		{name: "allowlisted read", action: "DescribeSubnets"},
		{name: "allowlisted analyser call", action: "StartNetworkInsightsAnalysis"},
		{name: "mutating action rejected", action: "AuthorizeSecurityGroupIngress", wantErr: ErrActionNotAllowed},
		{name: "wrong case rejected", action: "describesubnets", wantErr: ErrActionNotAllowed},
		{name: "empty action rejected", action: "", wantErr: ErrActionNotAllowed},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateAction(tc.action)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("ValidateAction(%q) error = %v, want %v", tc.action, err, tc.wantErr)
			}
		})
	}
}

func TestValidateHostCommand(t *testing.T) {
	tests := []struct {
		name    string
		argv    []string
		wantErr error
	}{
		{name: "listener check", argv: []string{"ss", "-tlnp"}},
		{name: "firewalld rich rules", argv: []string{"firewall-cmd", "--list-rich-rules"}},
		{name: "route lookup", argv: []string{"ip", "route", "get", "192.0.2.10"}},
		{name: "unlisted command rejected", argv: []string{"systemctl", "restart", "sshd"}, wantErr: ErrCommandNotAllowed},
		{name: "empty argv rejected", argv: nil, wantErr: ErrCommandNotAllowed},
		{name: "chained argument rejected", argv: []string{"ss", "-tlnp; rm -rf /"}, wantErr: ErrUnsafeArgument},
		{name: "substituted argument rejected", argv: []string{"ip", "route", "get", "$(id)"}, wantErr: ErrUnsafeArgument},
		{name: "redirected argument rejected", argv: []string{"ping", "-c", "1", "192.0.2.10 > /etc/hosts"}, wantErr: ErrUnsafeArgument},
		{name: "newline argument rejected", argv: []string{"ss", "-tlnp\nreboot"}, wantErr: ErrUnsafeArgument},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateArgv(tc.argv)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("ValidateArgv(%q) error = %v, want %v", tc.argv, err, tc.wantErr)
			}
		})
	}
}

func TestRejectionNamesTheOffender(t *testing.T) {
	err := ValidateAction("TerminateInstances")
	if err == nil || !strings.Contains(err.Error(), "TerminateInstances") {
		t.Fatalf("action rejection must name the action, got %v", err)
	}
	err = ValidateArgv([]string{"reboot"})
	if err == nil || !strings.Contains(err.Error(), "reboot") {
		t.Fatalf("command rejection must name the command, got %v", err)
	}
	err = ValidateArgv([]string{"ss", "-tlnp && reboot"})
	if err == nil || !strings.Contains(err.Error(), "-tlnp && reboot") {
		t.Fatalf("argument rejection must name the argument, got %v", err)
	}
}

// --- Allowlists are exact-match only (requirements 15.1, 15.2) ---------------

// nearMisses returns the variants of name that an operator, a typo, or an IAM
// policy string might plausibly produce. None of them is the allowlisted name,
// so every one must be refused. Mutations that collapse back onto the original
// (upper-casing an already upper-case name) are dropped by the caller.
func nearMisses(name string) map[string]string {
	return map[string]string{
		"upper cased":      strings.ToUpper(name),
		"lower cased":      strings.ToLower(name),
		"leading space":    " " + name,
		"trailing space":   name + " ",
		"trailing tab":     name + "\t",
		"trailing newline": name + "\n",
		"suffixed":         name + "X",
		"truncated":        name[:len(name)-1],
		"service prefix":   "ec2:" + name,
		"wildcard suffix":  name + "*",
		"absolute path":    "/usr/bin/" + name,
	}
}

func TestAllowlistsAreExactMatchOnly(t *testing.T) {
	surfaces := []struct {
		name     string
		allowed  []string
		validate func(string) error
		wantErr  error
	}{
		{
			name:     "aws actions",
			allowed:  AllowedActions(),
			validate: ValidateAction,
			wantErr:  ErrActionNotAllowed,
		},
		{
			name:     "host commands",
			allowed:  AllowedHostCommands(),
			validate: func(cmd string) error { return ValidateHostCommand(cmd) },
			wantErr:  ErrCommandNotAllowed,
		},
	}
	for _, surface := range surfaces {
		t.Run(surface.name, func(t *testing.T) {
			if len(surface.allowed) == 0 {
				t.Fatalf("%s allowlist is empty", surface.name)
			}
			for _, name := range surface.allowed {
				t.Run(name, func(t *testing.T) {
					if err := surface.validate(name); err != nil {
						t.Fatalf("allowlisted %q rejected: %v", name, err)
					}
					for mutation, variant := range nearMisses(name) {
						if variant == name {
							continue // mutation is a no-op for this name
						}
						if err := surface.validate(variant); !errors.Is(err, surface.wantErr) {
							t.Errorf("%s %q error = %v, want %v", mutation, variant, err, surface.wantErr)
						}
					}
				})
			}
		})
	}
}

// --- Metacharacter arguments are always rejected (requirement 15.3) ---------

// TestChainingAndRedirectionCharactersAreRejected pins the set requirement 15.3
// names, written out literally rather than read from unsafeArgumentChars. A test
// that iterates the implementation's own constant cannot notice a character
// being dropped from it, which is precisely the regression that matters here.
func TestChainingAndRedirectionCharactersAreRejected(t *testing.T) {
	required := []struct {
		name string
		char string
	}{
		{name: "semicolon chains", char: ";"},
		{name: "ampersand backgrounds and chains", char: "&"},
		{name: "pipe chains", char: "|"},
		{name: "less than redirects in", char: "<"},
		{name: "greater than redirects out", char: ">"},
		{name: "dollar substitutes", char: "$"},
		{name: "backtick substitutes", char: "`"},
		{name: "open paren subshells", char: "("},
		{name: "close paren subshells", char: ")"},
		{name: "backslash escapes", char: "\\"},
		{name: "single quote quotes", char: "'"},
		{name: "double quote quotes", char: "\""},
		{name: "newline chains", char: "\n"},
		{name: "carriage return chains", char: "\r"},
	}
	for _, tc := range required {
		t.Run(tc.name, func(t *testing.T) {
			arg := "-tlnp" + tc.char + "reboot"
			if err := ValidateArgument(arg); !errors.Is(err, ErrUnsafeArgument) {
				t.Errorf("ValidateArgument(%q) error = %v, want %v", arg, err, ErrUnsafeArgument)
			}
			if err := ValidateArgv([]string{"ss", arg}); !errors.Is(err, ErrUnsafeArgument) {
				t.Errorf("ValidateArgv(ss %q) error = %v, want %v", arg, err, ErrUnsafeArgument)
			}
		})
	}
}

// TestEveryMetacharacterIsRejectedInEveryPosition asserts the rejection is a
// property of the character, not of where it happens to appear. A screen that
// only inspects the first argument, or only a bare argument, is not a screen.
func TestEveryMetacharacterIsRejectedInEveryPosition(t *testing.T) {
	if unsafeArgumentChars == "" {
		t.Fatal("no metacharacters are screened")
	}
	shapes := map[string]func(string) string{
		"bare":     func(c string) string { return c },
		"appended": func(c string) string { return "-tlnp" + c },
		"prefixed": func(c string) string { return c + "-tlnp" },
		"embedded": func(c string) string { return "192.0.2" + c + "10" },
	}
	for _, r := range unsafeArgumentChars {
		char := string(r)
		t.Run("char="+char, func(t *testing.T) {
			for shape, build := range shapes {
				arg := build(char)
				if err := ValidateArgument(arg); !errors.Is(err, ErrUnsafeArgument) {
					t.Errorf("ValidateArgument(%q) [%s] error = %v, want %v", arg, shape, err, ErrUnsafeArgument)
				}
				// Same argument, reached through the command entry points, in
				// both the first and a later argv position.
				for _, argv := range [][]string{
					{"ss", arg},
					{"ip", "route", "get", arg},
					{"ping", "-c", "1", "192.0.2.10", arg},
				} {
					if err := ValidateArgv(argv); !errors.Is(err, ErrUnsafeArgument) {
						t.Errorf("ValidateArgv(%q) error = %v, want %v", argv, err, ErrUnsafeArgument)
					}
				}
			}
		})
	}
}

func TestControlCharacterArgumentsAreRejected(t *testing.T) {
	tests := []struct {
		name string
		arg  string
	}{
		{name: "newline", arg: "-tlnp\nreboot"},
		{name: "carriage return", arg: "-tlnp\rreboot"},
		{name: "tab", arg: "-tlnp\treboot"},
		{name: "nul", arg: "-tlnp\x00"},
		{name: "delete", arg: "-tlnp\x7f"},
		{name: "escape", arg: "\x1b[2J"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateArgument(tc.arg); !errors.Is(err, ErrUnsafeArgument) {
				t.Fatalf("ValidateArgument(%q) error = %v, want %v", tc.arg, err, ErrUnsafeArgument)
			}
		})
	}
}

// The screen must still admit the arguments the host prober actually needs. A
// validator that rejects everything enforces nothing, because the dispatch path
// would be rewritten to avoid it.
func TestPlausibleHostArgumentsAreAccepted(t *testing.T) {
	tests := []struct {
		name string
		argv []string
	}{
		{name: "listener flags", argv: []string{"ss", "-tlnp"}},
		{name: "firewalld services", argv: []string{"firewall-cmd", "--list-services"}},
		{name: "firewalld zone", argv: []string{"firewall-cmd", "--zone=public", "--list-all"}},
		{name: "route to address", argv: []string{"ip", "route", "get", "192.0.2.10"}},
		{name: "cidr argument", argv: []string{"ip", "route", "show", "10.0.0.0/8"}},
		{name: "mtu probe", argv: []string{"ping", "-c", "1", "-M", "do", "-s", "1472", "192.0.2.10"}},
		{name: "space is data not a separator", argv: []string{"ss", "state established"}},
		{name: "no arguments at all", argv: []string{"ss"}},
		{name: "empty argument", argv: []string{"ss", ""}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateArgv(tc.argv); err != nil {
				t.Fatalf("ValidateArgv(%q) = %v, want nil", tc.argv, err)
			}
		})
	}
}

// --- Validation runs before any dispatch path (requirement 15.5) ------------

// transport stands in for the SSM send path: it records what reached it. If a
// rejected invocation appears here, validation ran too late to matter.
type transport struct{ dispatched [][]string }

func (tr *transport) send(argv []string) { tr.dispatched = append(tr.dispatched, argv) }

// runGuarded is the dispatch shape the host prober is required to use: validate
// the whole invocation, and only then hand it to the transport.
func runGuarded(tr *transport, argv []string) error {
	if err := ValidateArgv(argv); err != nil {
		return err
	}
	tr.send(argv)
	return nil
}

func TestValidationGatesDispatch(t *testing.T) {
	tests := []struct {
		name         string
		argv         []string
		wantErr      error
		wantDispatch bool
	}{
		{name: "allowed invocation reaches transport", argv: []string{"ss", "-tlnp"}, wantDispatch: true},
		{name: "unlisted command never dispatched", argv: []string{"systemctl", "stop", "firewalld"}, wantErr: ErrCommandNotAllowed},
		{name: "chained argument never dispatched", argv: []string{"ss", "-tlnp; reboot"}, wantErr: ErrUnsafeArgument},
		{name: "unsafe trailing argument never dispatched", argv: []string{"ping", "-c", "1", "192.0.2.10 && reboot"}, wantErr: ErrUnsafeArgument},
		{name: "empty argv never dispatched", argv: nil, wantErr: ErrCommandNotAllowed},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tr := &transport{}
			err := runGuarded(tr, tc.argv)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("runGuarded(%q) error = %v, want %v", tc.argv, err, tc.wantErr)
			}
			if got := len(tr.dispatched) > 0; got != tc.wantDispatch {
				t.Fatalf("dispatched = %v, want %v (transport saw %q)", got, tc.wantDispatch, tr.dispatched)
			}
		})
	}
}

// Validation is fail-closed and the command gate is the first gate. An unlisted
// command is refused for being unlisted, without its arguments being consulted:
// nothing about the arguments can make an unlisted command acceptable.
func TestValidationIsFailClosedAndCommandGateIsFirst(t *testing.T) {
	tests := []struct {
		name    string
		argv    []string
		wantErr error
	}{
		{name: "empty argv", argv: []string{}, wantErr: ErrCommandNotAllowed},
		{name: "nil argv", argv: nil, wantErr: ErrCommandNotAllowed},
		{name: "empty command name", argv: []string{""}, wantErr: ErrCommandNotAllowed},
		{name: "whitespace command name", argv: []string{" "}, wantErr: ErrCommandNotAllowed},
		{name: "unlisted command with clean args", argv: []string{"reboot", "now"}, wantErr: ErrCommandNotAllowed},
		{name: "unlisted command with unsafe args", argv: []string{"sh", "-c", "rm -rf / ; reboot"}, wantErr: ErrCommandNotAllowed},
		{name: "shell as command", argv: []string{"bash"}, wantErr: ErrCommandNotAllowed},
		{name: "allowed command inside a shell string", argv: []string{"sh", "-c", "ss -tlnp"}, wantErr: ErrCommandNotAllowed},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateArgv(tc.argv)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("ValidateArgv(%q) error = %v, want %v", tc.argv, err, tc.wantErr)
			}
		})
	}
}

// TestDispatchCallsAreGuarded is a structural check on the tree rather than a
// behavioural one. It holds the two halves of "validation runs before dispatch"
// in place as the host prober lands:
//
//   - the enforcer itself must have no way to execute anything, so it can never
//     become the dispatch path it is meant to gate;
//   - any package that does execute a command must import the enforcer.
//
// Import presence is a weaker claim than call ordering, but it fails loudly the
// moment a dispatch path appears with no guardrail dependency at all, which is
// the regression worth catching automatically. Test files are exempt: fixtures
// legitimately shell out.
func TestDispatchCallsAreGuarded(t *testing.T) {
	const guardrailPkg = "github.com/jajera/aws-netpath/internal/guardrail"

	type pkgInfo struct {
		dispatchFiles  []string
		importsGuard   bool
		importsExecSSM []string
	}
	pkgs := map[string]*pkgInfo{}

	root := filepath.Join("..", "..")
	skipDirs := map[string]bool{".git": true, ".kiro": true, "bin": true, "vendor": true, "testdata": true}

	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, perr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if perr != nil {
			return perr
		}
		dir := filepath.Dir(path)
		info := pkgs[dir]
		if info == nil {
			info = &pkgInfo{}
			pkgs[dir] = info
		}
		for _, imp := range file.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			switch {
			case p == guardrailPkg:
				info.importsGuard = true
			case p == "os/exec" || strings.HasSuffix(p, "/service/ssm"):
				info.importsExecSSM = append(info.importsExecSSM, p)
			}
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if isDispatchCall(sel) {
				info.dispatchFiles = append(info.dispatchFiles, path)
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", root, err)
	}
	if len(pkgs) == 0 {
		t.Fatalf("walked %s and found no Go packages", root)
	}

	self := filepath.Join("..", "..", "internal", "guardrail")
	for dir, info := range pkgs {
		if dir == self {
			if len(info.dispatchFiles) > 0 {
				t.Errorf("the enforcer must not execute commands, found dispatch calls in %v", info.dispatchFiles)
			}
			if len(info.importsExecSSM) > 0 {
				t.Errorf("the enforcer must not import an execution path, found %v", info.importsExecSSM)
			}
			continue
		}
		if len(info.dispatchFiles) > 0 && !info.importsGuard {
			t.Errorf("package %s dispatches commands in %v but does not import %s", dir, info.dispatchFiles, guardrailPkg)
		}
	}
}

// isDispatchCall reports whether a selector call executes something on a host:
// a local process, or a command sent to an instance through SSM.
func isDispatchCall(sel *ast.SelectorExpr) bool {
	switch sel.Sel.Name {
	case "SendCommand":
		return true
	case "Command", "CommandContext":
		pkg, ok := sel.X.(*ast.Ident)
		return ok && pkg.Name == "exec"
	}
	return false
}
