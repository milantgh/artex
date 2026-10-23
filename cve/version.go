package cve

import (
	"regexp"
	"strconv"
	"strings"
)

var (
	versionNumRe = regexp.MustCompile(`\d+`)
	// ^(>=|<=|==|!=|>|<|=)?\s*(.+)$
	versionOpRe = regexp.MustCompile(`^(>=|<=|==|!=|>|<|=)?\s*(.+)$`)
)

// ParseVersion turns "v1.2.3-beta" into [1,2,3]. Unparseable input → nil.
func ParseVersion(text string) []int {
	nums := versionNumRe.FindAllString(text, -1)
	if len(nums) == 0 {
		return nil
	}
	out := make([]int, 0, len(nums))
	for _, n := range nums {
		v, err := strconv.Atoi(n)
		if err != nil {
			return nil
		}
		out = append(out, v)
	}
	return out
}

// compareVersions compares two numeric tuples, zero-padding the shorter one so
// that "1.2" == "1.2.0" (the rule packs rely on this).
func compareVersions(a, b []int) int {
	n := len(a)
	if len(b) > n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		var av, bv int
		if i < len(a) {
			av = a[i]
		}
		if i < len(b) {
			bv = b[i]
		}
		if av != bv {
			if av > bv {
				return 1
			}
			return -1
		}
	}
	return 0
}

// VersionInRange reports whether version satisfies the compact range spec:
//
//	"*"                 every version
//	">=0.1.32,<0.1.46"  AND of comparisons
//	"<1.2||>=1.5,<2.0"  OR of ranges ("||")
//
// An unknown/empty version matches only the catch-all spec, so version-based
// rules never fire blindly.
func VersionInRange(version, spec string) bool {
	spec = strings.TrimSpace(spec)
	if strings.Contains(spec, "||") {
		for _, part := range strings.Split(spec, "||") {
			if strings.TrimSpace(part) == "" {
				continue
			}
			if VersionInRange(version, part) {
				return true
			}
		}
		return false
	}
	switch strings.ToLower(spec) {
	case "", "*", "all", "any":
		return true
	}

	ver := ParseVersion(version)
	if ver == nil {
		return false
	}

	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" || part == "*" {
			continue
		}
		m := versionOpRe.FindStringSubmatch(part)
		if m == nil {
			continue
		}
		op := m[1]
		if op == "" || op == "=" {
			op = "=="
		}
		want := ParseVersion(m[2])
		if want == nil {
			continue
		}
		c := compareVersions(ver, want)
		var ok bool
		switch op {
		case ">=":
			ok = c >= 0
		case "<=":
			ok = c <= 0
		case ">":
			ok = c > 0
		case "<":
			ok = c < 0
		case "==":
			ok = c == 0
		case "!=":
			ok = c != 0
		default:
			continue
		}
		if !ok {
			return false
		}
	}
	return true
}
