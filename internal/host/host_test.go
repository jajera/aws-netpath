package host

import (
	"errors"
	"strings"
	"testing"

	"github.com/jajera/aws-netpath/internal/guardrail"
)

// A template stands in for the checks landing later: a fixed shape with one
// placeholder, both bare and embedded in a longer argument.
var (
	testRouteTemplate = Template{Check: "route", Argv: []string{"ip", "route", "get", "{dst}"}}
	testZoneTemplate  = Template{Check: "firewalld", Argv: []string{"firewall-cmd", "--zone={zone}", "--list-rich-rules"}}
)

func TestTemplateBuildSubstitutesValidatedValues(t *testing.T) {
	tests := []struct {
		name     string
		template Template
		subs     map[string]string
		wantLine string
	}{
		{
			name:     "bare placeholder",
			template: testRouteTemplate,
			subs:     map[string]string{"dst": "192.0.2.10"},
			wantLine: "ip route get 192.0.2.10",
		},
		{
			name:     "embedded placeholder",
			template: testZoneTemplate,
			subs:     map[string]string{"zone": "public"},
			wantLine: "firewall-cmd --zone=public --list-rich-rules",
		},
		{
			name:     "cidr value",
			template: testRouteTemplate,
			subs:     map[string]string{"dst": "10.20.1.0/24"},
			wantLine: "ip route get 10.20.1.0/24",
		},
		{
			name:     "no placeholders at all",
			template: Template{Check: "listener", Argv: []string{"ss", "-tlnp"}},
			wantLine: "ss -tlnp",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cmd, err := tc.template.Build(tc.subs)
			if err != nil {
				t.Fatalf("Build(%v) = %v, want nil", tc.subs, err)
			}
			if cmd.Line() != tc.wantLine {
				t.Errorf("Line() = %q, want %q", cmd.Line(), tc.wantLine)
			}
			if cmd.Check != tc.template.Check {
				t.Errorf("Check = %q, want %q", cmd.Check, tc.template.Check)
			}
		})
	}
}

// Requirement 15.5: nothing unvalidated is interpolated into a host command. The
// substituted value is screened on its own terms, so a hostile endpoint value is
// refused at the point it enters the command.
func TestTemplateBuildRejectsUnsafeSubstitution(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		wantErr error
	}{
		{name: "command substitution", value: "$(id)", wantErr: guardrail.ErrUnsafeArgument},
		{name: "chained command", value: "192.0.2.10; reboot", wantErr: guardrail.ErrUnsafeArgument},
		{name: "redirection", value: "192.0.2.10>/etc/hosts", wantErr: guardrail.ErrUnsafeArgument},
		{name: "backtick", value: "`id`", wantErr: guardrail.ErrUnsafeArgument},
		{name: "newline", value: "192.0.2.10\nreboot", wantErr: guardrail.ErrUnsafeArgument},
		{name: "glob", value: "192.0.2.*", wantErr: guardrail.ErrUnsafeArgument},
		{name: "space splits one argument into two", value: "192.0.2.10 -c 1", wantErr: ErrArgumentNotRepresentable},
		{name: "tab splits one argument into two", value: "192.0.2.10\t", wantErr: guardrail.ErrUnsafeArgument},
		{name: "empty value vanishes", value: "", wantErr: ErrArgumentNotRepresentable},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cmd, err := testRouteTemplate.Build(map[string]string{"dst": tc.value})
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Build(%q) error = %v, want %v", tc.value, err, tc.wantErr)
			}
			if cmd.Line() != "" {
				t.Errorf("Build(%q) returned command %q, want none", tc.value, cmd.Line())
			}
			if !strings.Contains(err.Error(), "dst") {
				t.Errorf("error %q must name the placeholder dst", err)
			}
		})
	}
}

// A template and its caller disagreeing about the command is an error either
// way round: a placeholder left unresolved would be dispatched as literal
// braces, and an unused value means the caller supplied something the command
// never asked for.
func TestTemplateBuildRequiresPlaceholdersAndValuesToAgree(t *testing.T) {
	tests := []struct {
		name     string
		template Template
		subs     map[string]string
		wantText string
	}{
		{
			name:     "missing value",
			template: testRouteTemplate,
			wantText: "no value for placeholder dst",
		},
		{
			name:     "wrong placeholder name",
			template: testRouteTemplate,
			subs:     map[string]string{"destination": "192.0.2.10"},
			wantText: "no value for placeholder dst",
		},
		{
			name:     "unused value",
			template: Template{Check: "listener", Argv: []string{"ss", "-tlnp"}},
			subs:     map[string]string{"dst": "192.0.2.10"},
			wantText: "substitution dst matches no placeholder",
		},
		{
			name:     "empty template",
			template: Template{Check: "empty"},
			wantText: "no argv",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.template.Build(tc.subs)
			if err == nil {
				t.Fatalf("Build(%v) = nil, want an error", tc.subs)
			}
			if !strings.Contains(err.Error(), tc.wantText) {
				t.Errorf("error = %q, want it to contain %q", err, tc.wantText)
			}
		})
	}
}

// Requirement 8.7: only allowlisted commands. The allowlist gates the template
// too, so a template naming a mutating executable cannot produce a Command at
// all, let alone dispatch one.
func TestTemplateBuildRejectsUnlistedExecutable(t *testing.T) {
	tests := []struct {
		name string
		argv []string
	}{
		{name: "service restart", argv: []string{"systemctl", "restart", "firewalld"}},
		{name: "shell wrapper", argv: []string{"sh", "-c", "ss"}},
		{name: "firewall reload disguised as an argument", argv: []string{"bash", "firewall-cmd"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Template{Check: "mutating", Argv: tc.argv}.Build(nil)
			if !errors.Is(err, guardrail.ErrCommandNotAllowed) {
				t.Fatalf("Build(%v) error = %v, want %v", tc.argv, err, guardrail.ErrCommandNotAllowed)
			}
		})
	}
}

// A literal element the transport cannot carry is refused for the same reason a
// substituted one is: the command that ran would not be the command validated.
func TestTemplateBuildRejectsUnrepresentableLiteral(t *testing.T) {
	_, err := Template{Check: "literal", Argv: []string{"ss", "state established"}}.Build(nil)
	if !errors.Is(err, ErrArgumentNotRepresentable) {
		t.Fatalf("error = %v, want %v", err, ErrArgumentNotRepresentable)
	}
}

func TestCommandCitationNamesTheCommand(t *testing.T) {
	cmd, err := testRouteTemplate.Build(map[string]string{"dst": "192.0.2.10"})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	c := cmd.Citation("dev eth0")
	if c.Kind != "command" {
		t.Errorf("Kind = %q, want command", c.Kind)
	}
	if c.Identifier != "ip route get 192.0.2.10" {
		t.Errorf("Identifier = %q, want the dispatched command line", c.Identifier)
	}
	if c.Detail != "dev eth0" {
		t.Errorf("Detail = %q, want the supplied detail", c.Detail)
	}
}
