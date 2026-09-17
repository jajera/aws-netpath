package nfw

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/jajera/aws-netpath/internal/model"
)

// ruleLine matches AWS Network Firewall Suricata 5-tuple rules with optional
// sid/rev options, for example:
//
//	pass tcp $SRC_0 any -> $DEST 53 (sid:1; rev:1;)
var ruleLine = regexp.MustCompile(`(?i)^(\w+)\s+(tcp|udp|icmp|ip)\s+(\S+)\s+(\S+)\s+->\s+(\S+)\s+(\S+)\s+\(sid:(\d+)`)

// ResolvedRules returns 5-tuple rules for evaluation, expanding Suricata IP set
// variables when the group was authored with rules_string.
func ResolvedRules(g *model.RuleGroup) ([]model.StatefulRule, error) {
	if g == nil {
		return nil, nil
	}
	if len(g.Rules) > 0 {
		return g.Rules, nil
	}
	if strings.TrimSpace(g.RulesString) == "" {
		return nil, nil
	}
	return ParseRulesString(g.RulesString, g.RuleVariables)
}

// ParseRulesString turns AWS NFW Suricata rules into stateful 5-tuple rules by
// substituting $VAR references with the rule group's IP set definitions.
func ParseRulesString(rules string, vars map[string][]string) ([]model.StatefulRule, error) {
	var out []model.StatefulRule
	var problems []string

	for _, line := range strings.Split(rules, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		m := ruleLine.FindStringSubmatch(line)
		if m == nil {
			problems = append(problems, fmt.Sprintf("unsupported rule %q", line))
			continue
		}

		src, err := expandEndpoint(m[3], vars)
		if err != nil {
			problems = append(problems, err.Error())
			continue
		}
		dst, err := expandEndpoint(m[5], vars)
		if err != nil {
			problems = append(problems, err.Error())
			continue
		}

		out = append(out, model.StatefulRule{
			Action:          strings.ToUpper(m[1]),
			Protocol:        strings.ToUpper(m[2]),
			Source:          src,
			SourcePort:      strings.ToUpper(m[4]),
			Destination:     dst,
			DestinationPort: m[6],
			Direction:       model.DirForward,
			SID:             m[7],
		})
	}

	if len(out) == 0 && len(problems) > 0 {
		return nil, fmt.Errorf("%s", strings.Join(problems, "; "))
	}
	if len(problems) > 0 {
		return out, fmt.Errorf("partial expansion: %s", strings.Join(problems, "; "))
	}
	return out, nil
}

func expandEndpoint(token string, vars map[string][]string) (string, error) {
	token = strings.TrimSpace(token)
	if !strings.HasPrefix(token, "$") {
		return token, nil
	}
	name := strings.TrimPrefix(token, "$")
	defs, ok := vars[name]
	if !ok || len(defs) == 0 {
		return "", fmt.Errorf("undefined IP set variable %q", token)
	}
	return strings.Join(defs, ","), nil
}
