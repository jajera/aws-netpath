// Package config loads aws-netpath's multi-account collection settings.
//
// Each account entry uses its own AWS profile (and optionally an assume-role
// chain). There is no org-wide delegated admin requirement.
package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// File is the top-level aws-netpath.yaml structure.
type File struct {
	Accounts []Account `yaml:"accounts"`
	// External declares address space outside the cloud provider, such as
	// on-premises prefixes reached over Direct Connect or VPN.
	External []ExternalNetwork `yaml:"external,omitempty"`
}

// Account is one AWS account to collect from.
type Account struct {
	// ID is the 12-digit account number. When empty, collect discovers it via
	// STS GetCallerIdentity after authenticating with Profile.
	ID string `yaml:"id,omitempty"`
	// Profile names an AWS shared config profile (SSO or static credentials).
	Profile string `yaml:"profile"`
	// Regions lists the regions to collect in this account.
	Regions []string `yaml:"regions"`
	// AssumeRole, when set, is assumed after Profile authenticates. Useful for
	// CI pipelines that start from a tooling account.
	AssumeRole string `yaml:"assume_role,omitempty"`
	// ExternalRoleSessionName overrides the default STS session name.
	RoleSessionName string `yaml:"role_session_name,omitempty"`
}

// ExternalNetwork is off-cloud address space to include in the model.
type ExternalNetwork struct {
	Name        string   `yaml:"name"`
	CIDRs       []string `yaml:"cidrs"`
	ReachedVia  string   `yaml:"reached_via,omitempty"`
	Description string   `yaml:"description,omitempty"`
}

// Target is one account+region pair ready for collection.
type Target struct {
	AccountID       string
	Profile         string
	Region          string
	AssumeRole      string
	RoleSessionName string
}

// Load reads and validates a config file.
func Load(path string) (*File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	return LoadFromBytes(data)
}

// LoadFromBytes parses config YAML from memory (tests and embeds).
func LoadFromBytes(data []byte) (*File, error) {
	var f File
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if err := f.Validate(); err != nil {
		return nil, err
	}
	return &f, nil
}

// Validate checks required fields.
func (f *File) Validate() error {
	if len(f.Accounts) == 0 {
		return fmt.Errorf("config: at least one account is required")
	}
	for i, a := range f.Accounts {
		if strings.TrimSpace(a.Profile) == "" {
			return fmt.Errorf("config: accounts[%d].profile is required", i)
		}
		if len(a.Regions) == 0 {
			return fmt.Errorf("config: accounts[%d].regions is required", i)
		}
		for j, r := range a.Regions {
			if strings.TrimSpace(r) == "" {
				return fmt.Errorf("config: accounts[%d].regions[%d] is empty", i, j)
			}
		}
	}
	return nil
}

// Targets expands every account entry into account+region pairs.
func (f *File) Targets() []Target {
	var out []Target
	for _, a := range f.Accounts {
		for _, region := range a.Regions {
			out = append(out, Target{
				AccountID:       strings.TrimSpace(a.ID),
				Profile:         strings.TrimSpace(a.Profile),
				Region:          strings.TrimSpace(region),
				AssumeRole:      strings.TrimSpace(a.AssumeRole),
				RoleSessionName: strings.TrimSpace(a.RoleSessionName),
			})
		}
	}
	return out
}
