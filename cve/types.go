// Package cve is a self-contained, data-driven fingerprint + CVE engine.
//
// Rules live in YAML files under data/fingerprints and data/vuln (embedded in
// the binary). Adding a CVE is a data change, never a code change — the same
// contract as the AISecurityTest rule packs ARTEX now ships.
package cve

import (
	"strings"

	"gopkg.in/yaml.v3"
)

// Condition is one response-matching predicate. A zero condition matches any
// response with a 2xx/3xx status (no status filter).
type Condition struct {
	Method string            `yaml:"method"`
	Path   string            `yaml:"path"`
	Status StatusSpec        `yaml:"status"`
	Header map[string]string `yaml:"headers"`
	Body   string            `yaml:"body"`

	BodyContains   string            `yaml:"body_contains"`
	BodyRegex      string            `yaml:"body_regex"`
	HeaderContains map[string]string `yaml:"header_contains"`
	HeaderRegex    map[string]string `yaml:"header_regex"`
}

// StatusSpec accepts either a scalar status ("status: 200") or a list
// ("status: [200, 401]"). The zero value means "no status filter".
type StatusSpec struct {
	Set    bool
	Values []int
}

func (s *StatusSpec) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.SequenceNode {
		var list []int
		if err := node.Decode(&list); err != nil {
			return err
		}
		s.Set, s.Values = true, list
		return nil
	}
	var one int
	if err := node.Decode(&one); err != nil {
		return err
	}
	s.Set, s.Values = true, []int{one}
	return nil
}

// VersionSpec extracts a version string from a response. When Path is set a
// dedicated request is sent; otherwise the response used for identification is
// reused.
type VersionSpec struct {
	Method string `yaml:"method"`
	Path   string `yaml:"path"`
	// RequestHeaders are sent with the version request (yaml key "headers").
	RequestHeaders map[string]string `yaml:"headers"`
	Body           string            `yaml:"body"`
	BodyRegex      string            `yaml:"body_regex"`
	HeaderRegex    map[string]string `yaml:"header_regex"`
	// Header/ValueRegex extract the version from one specific header.
	Header     string `yaml:"header"`
	ValueRegex string `yaml:"value_regex"`
}

// VersionRule is the fingerprint's version block: a single spec or a list of
// alternative specs (first one that yields a version wins).
type VersionRule []VersionSpec

func (v *VersionRule) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.SequenceNode {
		var list []VersionSpec
		if err := node.Decode(&list); err != nil {
			return err
		}
		*v = list
		return nil
	}
	if node.Kind == yaml.ScalarNode && node.Value == "" {
		return nil
	}
	var one VersionSpec
	if err := node.Decode(&one); err != nil {
		return err
	}
	*v = []VersionSpec{one}
	return nil
}

// Fingerprint identifies a component from one or more response predicates.
type Fingerprint struct {
	ID          string `yaml:"id"`
	Name        string `yaml:"name"`
	Category    string `yaml:"category"`
	Vendor      string `yaml:"vendor"`
	Description string `yaml:"description"`
	Match       struct {
		Any []Condition `yaml:"any"`
	} `yaml:"match"`
	Version VersionRule `yaml:"version"`
	Source  string      `yaml:"-"`
}

// CheckRule describes an optional confirmation request for a CVE rule.
type CheckRule struct {
	Mode    string            `yaml:"mode"` // version (default) | request
	Method  string            `yaml:"method"`
	Path    string            `yaml:"path"`
	Headers map[string]string `yaml:"headers"`
	Body    string            `yaml:"body"`
	Match   Condition         `yaml:"match"`
}

// Vuln is one CVE rule bound to a fingerprint component.
type Vuln struct {
	ID          string     `yaml:"id"`
	Title       string     `yaml:"title"`
	Component   string     `yaml:"component"`
	Severity    string     `yaml:"severity"`
	Affected    string     `yaml:"affected"`
	Description string     `yaml:"description"`
	References  []string   `yaml:"references"`
	Remediation string     `yaml:"remediation"`
	OWASPTags   []string   `yaml:"owasp_tags"`
	Check       *CheckRule `yaml:"check"`
	Source      string     `yaml:"-"`
}

// Mode returns the check mode, defaulting to "version".
func (v *Vuln) Mode() string {
	if v.Check == nil || v.Check.Mode == "" {
		return "version"
	}
	return v.Check.Mode
}

// SeverityRank orders severities from most to least severe (INFO last).
func SeverityRank(s string) int {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return 0
	case "HIGH":
		return 1
	case "MEDIUM":
		return 2
	case "LOW":
		return 3
	}
	return 4
}

// NormalizeSeverity maps rule severities onto ARTEX's finding severity scale.
func NormalizeSeverity(s string) string {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return "critical"
	case "HIGH":
		return "high"
	case "MEDIUM":
		return "medium"
	default:
		return "low"
	}
}
