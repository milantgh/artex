package cve

import (
	"regexp"
	"sync"
	"time"

	"github.com/dlclark/regexp2"
)

// Community rule packs contain PCRE-isms that Go's RE2 cannot compile —
// lookaheads such as `(?=.*<title>Dify</title>)` are common. We compile with
// the stdlib first (fast, linear) and fall back to regexp2 (backtracking,
// lookarounds supported) only for the patterns RE2 rejects. A pattern that
// neither engine accepts degrades to "no match", never to a scan failure.
type pattern struct {
	std  *regexp.Regexp
	pcre *regexp2.Regexp
}

var (
	patternMu    sync.Mutex
	patternCache = map[string]*pattern{}
)

const pcreMatchTimeout = 2 * time.Second

func compilePattern(expr string) *pattern {
	patternMu.Lock()
	defer patternMu.Unlock()
	if p, ok := patternCache[expr]; ok {
		return p
	}
	p := &pattern{}
	if re, err := regexp.Compile(expr); err == nil {
		p.std = re
	} else if re2, err2 := regexp2.Compile(expr, regexp2.None); err2 == nil {
		re2.MatchTimeout = pcreMatchTimeout
		p.pcre = re2
	}
	patternCache[expr] = p
	return p
}

// matches reports whether the pattern occurs anywhere in text (re.search).
func (p *pattern) matches(text string) bool {
	if p == nil {
		return false
	}
	if p.std != nil {
		return p.std.MatchString(text)
	}
	if p.pcre != nil {
		m, err := p.pcre.FindStringMatch(text)
		return err == nil && m != nil
	}
	return false
}

// find returns the first capture group (or the whole match when the pattern
// has no group), mirroring the Python engine's `m.group(1) if m.groups()`.
func (p *pattern) find(text string) (string, bool) {
	if p == nil {
		return "", false
	}
	if p.std != nil {
		m := p.std.FindStringSubmatch(text)
		if m == nil {
			return "", false
		}
		if len(m) > 1 {
			return m[1], true
		}
		return m[0], true
	}
	if p.pcre != nil {
		m, err := p.pcre.FindStringMatch(text)
		if err != nil || m == nil {
			return "", false
		}
		if m.GroupCount() > 1 {
			return m.GroupByNumber(1).String(), true
		}
		return m.String(), true
	}
	return "", false
}
