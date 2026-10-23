package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/skill"
)

func factNode(payload map[string]any) *db.Node {
	b, _ := json.Marshal(payload)
	return &db.Node{Kind: db.KindFact, Payload: b}
}

func TestWhenRule_NoRuleAlwaysMatches(t *testing.T) {
	w := WhenRule{}
	if !w.Matches(nil) {
		t.Fatal("empty rule should match nil facts")
	}
	if !w.Matches([]*db.Node{factNode(map[string]any{"summary": "x"})}) {
		t.Fatal("empty rule should match any facts")
	}
}

func TestWhenRule_FactExists(t *testing.T) {
	w := WhenRule{FactExists: []string{"llm_endpoint_entity"}}
	// No facts → no key → no match
	if w.Matches(nil) {
		t.Fatal("should not match when required fact is absent")
	}
	// Fact with kind=llm_endpoint_entity → match
	if !w.Matches([]*db.Node{factNode(map[string]any{"kind": "llm_endpoint_entity"})}) {
		t.Fatal("should match when fact.kind equals the required key")
	}
	// Fact with a payload field named llm_endpoint_entity → match
	if !w.Matches([]*db.Node{factNode(map[string]any{"llm_endpoint_entity": "http://x"})}) {
		t.Fatal("should match when payload has the required key")
	}
	// Fact with unrelated payload → no match
	if w.Matches([]*db.Node{factNode(map[string]any{"summary": "port closed"})}) {
		t.Fatal("should not match when no fact has the required key")
	}
}

func TestWhenRule_FactMissing(t *testing.T) {
	w := WhenRule{FactMissing: []string{"llm_probe_result"}}
	// No facts → missing → match
	if !w.Matches(nil) {
		t.Fatal("should match when the excluded fact is absent")
	}
	// Fact with the excluded key → no match
	if w.Matches([]*db.Node{factNode(map[string]any{"llm_probe_result": "done"})}) {
		t.Fatal("should not match when the excluded fact exists")
	}
}

func TestWhenRule_AndLogic(t *testing.T) {
	w := WhenRule{
		FactExists:  []string{"llm_endpoint_entity"},
		FactMissing: []string{"llm_probe_result"},
	}
	facts := []*db.Node{
		factNode(map[string]any{"kind": "llm_endpoint_entity"}),
	}
	if !w.Matches(facts) {
		t.Fatal("should match when precondition met and output absent")
	}
	// Add the output fact → should no longer match (dedup)
	facts = append(facts, factNode(map[string]any{"llm_probe_result": "done"}))
	if w.Matches(facts) {
		t.Fatal("should not match once the output fact exists (dedup)")
	}
}

func TestParseWhenRule(t *testing.T) {
	dir := t.TempDir()
	md := `---
name: llm-redteam
description: Red-team LLM endpoints
when:
  fact_exists: [llm_endpoint_entity]
  fact_missing: [llm_probe_result]
---
# Instructions
Do red teaming.
`
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte(md), 0o644); err != nil {
		t.Fatal(err)
	}
	w := ParseWhenRule(dir)
	if len(w.FactExists) != 1 || w.FactExists[0] != "llm_endpoint_entity" {
		t.Fatalf("unexpected FactExists: %#v", w.FactExists)
	}
	if len(w.FactMissing) != 1 || w.FactMissing[0] != "llm_probe_result" {
		t.Fatalf("unexpected FactMissing: %#v", w.FactMissing)
	}
}

func TestParseWhenRule_NoWhenBlock(t *testing.T) {
	dir := t.TempDir()
	md := "---\nname: x\ndescription: y\n---\nbody\n"
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte(md), 0o644); err != nil {
		t.Fatal(err)
	}
	w := ParseWhenRule(dir)
	if len(w.FactExists) != 0 || len(w.FactMissing) != 0 {
		t.Fatalf("expected empty rule, got %#v", w)
	}
}

func TestParseWhenRule_ScalarForm(t *testing.T) {
	dir := t.TempDir()
	md := `---
name: x
description: y
when:
  fact_exists: llm_endpoint_entity
---
body
`
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte(md), 0o644); err != nil {
		t.Fatal(err)
	}
	w := ParseWhenRule(dir)
	// yaml.v3 unmarshals a scalar into []string as a single-element slice
	if len(w.FactExists) != 1 || w.FactExists[0] != "llm_endpoint_entity" {
		t.Fatalf("expected single-element FactExists, got %#v", w.FactExists)
	}
}

func TestSkillMatcher_Match(t *testing.T) {
	dir := t.TempDir()
	// skill A: requires llm_endpoint_entity
	mdA := "---\nname: a\ndescription: a\nwhen:\n  fact_exists: [llm_endpoint_entity]\n---\nbody\n"
	os.MkdirAll(filepath.Join(dir, "a"), 0o755)
	os.WriteFile(filepath.Join(dir, "a", "SKILL.md"), []byte(mdA), 0o644)

	// skill B: no when → always offered
	mdB := "---\nname: b\ndescription: b\n---\nbody\n"
	os.MkdirAll(filepath.Join(dir, "b"), 0o755)
	os.WriteFile(filepath.Join(dir, "b", "SKILL.md"), []byte(mdB), 0o644)

	reg, err := skill.LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	matcher := NewSkillMatcher(reg.List())

	// No facts → only B matches (A's precondition unmet)
	matched := matcher.Match(nil)
	names := map[string]bool{}
	for _, s := range matched {
		names[s.Name] = true
	}
	if names["a"] {
		t.Fatal("skill a should be filtered out without llm_endpoint_entity fact")
	}
	if !names["b"] {
		t.Fatal("skill b (no when) should always be offered")
	}

	// With the precondition fact → both match
	facts := []*db.Node{factNode(map[string]any{"kind": "llm_endpoint_entity"})}
	matched = matcher.Match(facts)
	names = map[string]bool{}
	for _, s := range matched {
		names[s.Name] = true
	}
	if !names["a"] || !names["b"] {
		t.Fatalf("both skills should match, got %#v", names)
	}
}

// TestSkillMatcher_MatchWithAssetKinds verifies that asset-graph extra.kind
// values passed as extraKeys act as virtual fact keys, so a skill whose
// fact_exists rule requires llm_endpoint_entity is offered when an
// llm_endpoint asset exists — even with no explicit exploration fact.
func TestSkillMatcher_MatchWithAssetKinds(t *testing.T) {
	dir := t.TempDir()
	mdA := "---\nname: a\ndescription: a\nwhen:\n  fact_exists: [llm_endpoint_entity]\n---\nbody\n"
	os.MkdirAll(filepath.Join(dir, "a"), 0o755)
	os.WriteFile(filepath.Join(dir, "a", "SKILL.md"), []byte(mdA), 0o644)

	reg, err := skill.LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	matcher := NewSkillMatcher(reg.List())

	// No facts, no asset kinds → skill a filtered out
	if got := matcher.Match(nil); len(got) != 0 {
		t.Fatalf("expected no match without facts/asset kinds, got %d", len(got))
	}

	// Asset kind present (mirrored from assets.extra.kind) → skill a offered
	assetKinds := map[string]bool{"llm_endpoint_entity": true}
	matched := matcher.MatchWith(nil, assetKinds)
	names := map[string]bool{}
	for _, s := range matched {
		names[s.Name] = true
	}
	if !names["a"] {
		t.Fatalf("skill a should match via asset kind, got %#v", names)
	}
}

func TestSkillMatcher_HasRules(t *testing.T) {
	var noRule, withRule skill.Skill
	withRule.Name = "x"
	m := NewSkillMatcher([]skill.Skill{noRule, withRule})
	// neither has a Dir → ParseWhenRule returns empty → no rules
	if m.HasRules() {
		t.Fatal("expected no rules when skills have no Dir")
	}
}

func TestBuildFilteredSkillTool_ListingOnlyMatches(t *testing.T) {
	dir := t.TempDir()
	mdA := "---\nname: a\ndescription: skill a\nwhen:\n  fact_exists: [need_this]\n---\nbody a\n"
	os.MkdirAll(filepath.Join(dir, "a"), 0o755)
	os.WriteFile(filepath.Join(dir, "a", "SKILL.md"), []byte(mdA), 0o644)

	mdB := "---\nname: b\ndescription: skill b\n---\nbody b\n"
	os.MkdirAll(filepath.Join(dir, "b"), 0o755)
	os.WriteFile(filepath.Join(dir, "b", "SKILL.md"), []byte(mdB), 0o644)

	reg, _ := skill.LoadDir(dir)
	matcher := NewSkillMatcher(reg.List())

	// No facts → only b matches
	matched := matcher.Match(nil)
	tool := BuildFilteredSkillTool(matched, reg)
	prompt := tool.Prompt()
	if !strings.Contains(prompt, "skill b") {
		t.Fatalf("filtered listing should contain skill b, got: %s", prompt)
	}
	if strings.Contains(prompt, "skill a") {
		t.Fatalf("filtered listing should NOT contain skill a, got: %s", prompt)
	}
}
