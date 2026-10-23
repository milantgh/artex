package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/skill"
	actool "github.com/Autumn-27/norma/tool"
	"gopkg.in/yaml.v3"
)

// WhenRule describes when a skill should be offered to the planner. All
// conditions are ANDed together; an empty field imposes no constraint, so a
// skill with no `when:` block is always offered.
//
// Matching is purely deterministic (no LLM): it scans the exploration graph's
// fact nodes and tests each condition against their payloads. This is the
// "规则预筛层" — it prunes the skill menu before the planner ever sees it, so
// the model cannot waste turns on procedures whose preconditions aren't met or
// whose output already exists.
type WhenRule struct {
	// FactExists lists payload keys (or fact 'kind' values) that MUST be present
	// in the exploration graph for this skill to be offered. A fact matches if
	// its payload has the key, OR its payload.kind equals the key.
	// Accepts a scalar ("llm_endpoint_entity") or a list.
	// Example: fact_exists: [llm_endpoint_entity] → offer only after an LLM
	// endpoint has been discovered.
	FactExists whenList `yaml:"fact_exists"`
	// FactMissing lists payload keys that must NOT appear in any fact — used for
	// dedup: a skill whose output fact already exists is not re-offered.
	// Accepts a scalar or a list.
	// Example: fact_missing: [llm_probe_result] → skip if a probe result was
	// already recorded.
	FactMissing whenList `yaml:"fact_missing"`
}

// whenList accepts a frontmatter value written either as a scalar ("a") or as
// a YAML list ([a, b] / block form) and normalises to a trimmed, non-empty
// []string. Mirrors norma's stringOrList so the two stay consistent.
type whenList []string

func (l *whenList) UnmarshalYAML(value *yaml.Node) error {
	var str string
	if err := value.Decode(&str); err == nil {
		*l = parseWhenList(str)
		return nil
	}
	var list []string
	if err := value.Decode(&list); err == nil {
		out := make([]string, 0, len(list))
		for _, p := range list {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
		if len(out) > 0 {
			*l = out
		}
		return nil
	}
	return nil // unparseable → leave nil (no constraint)
}

// parseWhenList splits a scalar list value ("a, b" or "[a, b]").
func parseWhenList(v string) []string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "[")
	v = strings.TrimSuffix(v, "]")
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(strings.Trim(p, `"' `)); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// Matches reports whether the rule is satisfied by the given facts.
func (w WhenRule) Matches(facts []*db.Node) bool {
	return w.MatchesWith(facts, nil)
}

// MatchesWith is like Matches but also considers a set of extra keys (e.g.
// asset-graph extra.kind values mirrored into the matcher) as if they were
// fact keys. This lets a skill's `fact_exists` rule fire when a matching asset
// exists even before an explicit exploration fact is recorded.
func (w WhenRule) MatchesWith(facts []*db.Node, extraKeys map[string]bool) bool {
	if len(w.FactExists) == 0 && len(w.FactMissing) == 0 {
		return true
	}
	keys := collectFactKeys(facts)
	for k := range extraKeys {
		keys[k] = true
	}
	for _, k := range w.FactExists {
		if !keys[k] {
			return false
		}
	}
	for _, k := range w.FactMissing {
		if keys[k] {
			return false
		}
	}
	return true
}

// collectFactKeys builds a set of all payload keys + payload.kind values across
// the given facts, so WhenRule evaluation is O(rules) instead of rescanning.
func collectFactKeys(facts []*db.Node) map[string]bool {
	keys := make(map[string]bool)
	for _, f := range facts {
		if f == nil || len(f.Payload) == 0 {
			continue
		}
		var p map[string]any
		if err := json.Unmarshal(f.Payload, &p); err != nil {
			continue
		}
		for k := range p {
			keys[k] = true
		}
		if k, ok := p["kind"].(string); ok && k != "" {
			keys[k] = true
		}
	}
	return keys
}

// SkillWithRule pairs a norma Skill with its parsed when-rule.
type SkillWithRule struct {
	Skill skill.Skill
	When  WhenRule
}

// ParseWhenRule extracts the `when:` block from a SKILL.md's YAML frontmatter.
// norma's own frontmatter parser ignores `when`, so we re-parse the header
// here. Returns a zero-value WhenRule (always matches) when no `when` block
// exists or the frontmatter is malformed — matching norma's graceful-degrade
// philosophy: a bad header never drops the whole skill.
func ParseWhenRule(skillDir string) WhenRule {
	if skillDir == "" {
		return WhenRule{}
	}
	data, err := os.ReadFile(filepath.Join(skillDir, "SKILL.md"))
	if err != nil {
		return WhenRule{}
	}
	head := extractFrontmatter(string(data))
	if head == "" {
		return WhenRule{}
	}
	var fm struct {
		When WhenRule `yaml:"when"`
	}
	if err := yaml.Unmarshal([]byte(head), &fm); err != nil {
		return WhenRule{}
	}
	return fm.When
}

// extractFrontmatter returns the YAML between the leading "---" and the next
// "---", mirroring norma's parse() split so the two stay in sync.
func extractFrontmatter(s string) string {
	if !strings.HasPrefix(s, "---") {
		return ""
	}
	rest := strings.TrimLeft(strings.TrimPrefix(s, "---"), "\r\n")
	i := strings.Index(rest, "\n---")
	if i < 0 {
		return ""
	}
	return rest[:i]
}

// SkillMatcher holds the visible skills and their when-rules, and can produce
// a filtered Skill tool whose listing only shows skills whose rules match the
// current facts.
type SkillMatcher struct {
	skills []SkillWithRule
}

// NewSkillMatcher builds a matcher from a list of skills, parsing each skill's
// SKILL.md `when:` block on construction.
func NewSkillMatcher(skills []skill.Skill) *SkillMatcher {
	out := make([]SkillWithRule, 0, len(skills))
	for _, s := range skills {
		out = append(out, SkillWithRule{Skill: s, When: ParseWhenRule(s.Dir)})
	}
	return &SkillMatcher{skills: out}
}

// Match returns the skills whose when-rules are satisfied by the given facts.
// Skills with no `when:` block are always returned.
func (m *SkillMatcher) Match(facts []*db.Node) []skill.Skill {
	return m.MatchWith(facts, nil)
}

// MatchWith is like Match but also accepts extra keys (e.g. asset-graph
// extra.kind values) that are treated as virtual fact keys during rule
// evaluation.
func (m *SkillMatcher) MatchWith(facts []*db.Node, extraKeys map[string]bool) []skill.Skill {
	if m == nil {
		return nil
	}
	out := make([]skill.Skill, 0, len(m.skills))
	for _, swr := range m.skills {
		if swr.When.MatchesWith(facts, extraKeys) {
			out = append(out, swr.Skill)
		}
	}
	return out
}

// HasRules reports whether any loaded skill carries a non-empty when-rule.
// When false, the caller can skip the fact-fetch + filtering entirely.
func (m *SkillMatcher) HasRules() bool {
	if m == nil {
		return false
	}
	for _, swr := range m.skills {
		if len(swr.When.FactExists) > 0 || len(swr.When.FactMissing) > 0 {
			return true
		}
	}
	return false
}

// BuildFilteredSkillTool builds a Skill meta-tool whose available-skills listing
// only includes the given matched skills. Invocation still goes through the
// original registry so MCP unlocking (OnInvoke) and usage metering work for any
// skill the agent happens to name — the filter only affects the menu, not the
// dispatch.
func BuildFilteredSkillTool(matched []skill.Skill, original *skill.Registry) actool.CoreTool {
	sub := skill.NewRegistry(matched...)
	sub.OnInvoke = original.OnInvoke
	return sub.Tool()
}
