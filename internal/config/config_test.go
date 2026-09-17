package config

import "testing"

func TestLoadAndTargets(t *testing.T) {
	const yaml = `
accounts:
  - profile: hub
    regions: [us-east-1, us-west-2]
  - id: "111122223333"
    profile: spoke
    regions: [eu-west-1]
    assume_role: arn:aws:iam::111122223333:role/ReadOnly
external:
  - name: on-prem
    cidrs: [10.29.0.0/19]
`
	f, err := LoadFromBytes([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	targets := f.Targets()
	if len(targets) != 3 {
		t.Fatalf("got %d targets, want 3", len(targets))
	}
	if targets[0].Profile != "hub" || targets[0].Region != "us-east-1" {
		t.Errorf("target[0] = %+v", targets[0])
	}
	if targets[2].AssumeRole == "" {
		t.Error("expected assume role on third target")
	}
	if len(f.External) != 1 || f.External[0].Name != "on-prem" {
		t.Errorf("external = %+v", f.External)
	}
}

func TestValidateRequiresProfile(t *testing.T) {
	_, err := LoadFromBytes([]byte("accounts:\n  - regions: [x]\n"))
	if err == nil {
		t.Fatal("expected validation error")
	}
}
