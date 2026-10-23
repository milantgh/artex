package cve

import "testing"

func TestVersionInRange(t *testing.T) {
	cases := []struct {
		version, spec string
		want          bool
	}{
		{"0.6.9", "*", true},
		{"", "*", true},
		{"", "", true},
		{"", ">=1.0", false},
		{"0.6.9", "<=0.6.9", true},
		{"0.6.9", ">0.6.9", false},
		{"0.7.0", ">0.6.9", true},
		{"1.2", "1.2.0", true},
		{"1.2.0", "==1.2", true},
		{"1.2.1", "==1.2", false},
		{"0.1.32", ">=0.1.32,<0.1.46", true},
		{"0.1.46", ">=0.1.32,<0.1.46", false},
		{"0.1.20", "<1.2||>=1.5,<2.0", true},
		{"1.4.0", "<1.2||>=1.5,<2.0", false},
		{"1.9.0", "<1.2||>=1.5,<2.0", true},
		{"1.16.0-rc1", "<1.16.0-rc1", false},
		{"1.16.0", "<1.16.0-rc1", true},
		{"v1.2.3-beta", ">1.2.2", true},
		{"abc", ">=1.0", false},
		{"0.13.5", ">0,<=0.13.5", true},
		{"0.13.6", ">0,<=0.13.5", false},
	}
	for _, c := range cases {
		if got := VersionInRange(c.version, c.spec); got != c.want {
			t.Errorf("VersionInRange(%q, %q) = %v, want %v", c.version, c.spec, got, c.want)
		}
	}
}

func TestParseVersion(t *testing.T) {
	got := ParseVersion("v2.10.3")
	if len(got) != 3 || got[0] != 2 || got[1] != 10 || got[2] != 3 {
		t.Fatalf("ParseVersion = %v", got)
	}
	if ParseVersion("none") != nil {
		t.Fatal("expected nil for unparseable version")
	}
}

func TestLookaheadRegexFallback(t *testing.T) {
	p := compilePattern(`(?is)^(?=.*<title>Dify</title>)(?=.*data\-public\-edition)`)
	if p.std != nil {
		t.Fatal("expected stdlib to reject the lookahead pattern")
	}
	if p.pcre == nil {
		t.Fatal("expected regexp2 fallback to compile")
	}
	if !p.matches("<html><head><title>Dify</title></head><body data-public-edition></body></html>") {
		t.Fatal("expected lookahead pattern to match")
	}
	if p.matches("<html><title>Other</title><body data-public-edition></body></html>") {
		t.Fatal("expected no match without the title")
	}
}
