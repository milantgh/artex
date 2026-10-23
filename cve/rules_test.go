package cve

import "testing"

func TestEmbeddedRulePackLoads(t *testing.T) {
	rs, err := LoadEmbedded()
	if err != nil {
		t.Fatalf("LoadEmbedded: %v", err)
	}
	stats := rs.Stats()
	t.Logf("fingerprints=%d vuln_files=%d", stats.Fingerprints, stats.VulnFiles)
	if stats.Fingerprints != 160 {
		t.Errorf("fingerprints = %d, want 160", stats.Fingerprints)
	}
	if stats.VulnFiles != 2534 {
		t.Errorf("vuln files = %d, want 2534", stats.VulnFiles)
	}
	if rs.Fingerprint("dify") == nil || rs.Fingerprint("ollama") == nil {
		t.Fatal("expected dify and ollama fingerprints")
	}
}

func TestEveryVulnPointsAtAKnownComponent(t *testing.T) {
	rs, err := LoadEmbedded()
	if err != nil {
		t.Fatalf("LoadEmbedded: %v", err)
	}
	all, err := rs.AllVulns()
	if err != nil {
		t.Fatalf("AllVulns: %v", err)
	}
	t.Logf("decoded %d unique CVE rules", len(all))
	if len(all) < 2500 {
		t.Fatalf("only %d CVE rules decoded, expected >2500", len(all))
	}
	for _, v := range all {
		if !rs.HasComponent(v.Component) {
			t.Errorf("%s references unknown component %q", v.ID, v.Component)
		}
		if SeverityRank(v.Severity) == 4 && v.Severity != "" {
			// INFO is legal; unknown values are not.
			switch v.Severity {
			case "INFO", "info", "Info":
			default:
				t.Errorf("%s has invalid severity %q", v.ID, v.Severity)
			}
		}
	}
}

func TestRegexRulesCompile(t *testing.T) {
	rs, err := LoadEmbedded()
	if err != nil {
		t.Fatalf("LoadEmbedded: %v", err)
	}
	check := func(expr, where string) {
		if expr == "" {
			return
		}
		p := compilePattern(expr)
		if p.std == nil && p.pcre == nil {
			t.Errorf("%s: regex does not compile: %q", where, expr)
		}
	}
	for _, fp := range rs.Fingerprints() {
		for _, c := range fp.Match.Any {
			check(c.BodyRegex, fp.ID+".body_regex")
			for _, r := range c.HeaderRegex {
				check(r, fp.ID+".header_regex")
			}
		}
		for _, v := range fp.Version {
			check(v.BodyRegex, fp.ID+".version.body_regex")
			check(v.ValueRegex, fp.ID+".version.value_regex")
			for _, r := range v.HeaderRegex {
				check(r, fp.ID+".version.header_regex")
			}
		}
	}
	all, err := rs.AllVulns()
	if err != nil {
		t.Fatalf("AllVulns: %v", err)
	}
	for _, v := range all {
		if v.Check == nil {
			continue
		}
		check(v.Check.Match.BodyRegex, v.ID+".check.body_regex")
		for _, r := range v.Check.Match.HeaderRegex {
			check(r, v.ID+".check.header_regex")
		}
	}
}
