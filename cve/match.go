package cve

import (
	"net/http"
	"sort"
	"strings"
)

// Response is one probed HTTP response (or a transport failure with Err set).
type Response struct {
	Status int
	Header http.Header
	Body   []byte
	Err    error
}

// Text returns the response body as a string.
func (r *Response) Text() string {
	if r == nil {
		return ""
	}
	return string(r.Body)
}

func (r *Response) reachable() bool { return r != nil && r.Err == nil && r.Status != 0 }

// headerText returns one header value, or the whole raw header block for "*".
func headerText(h http.Header, name string) string {
	if h == nil {
		return ""
	}
	if name == "*" {
		keys := make([]string, 0, len(h))
		for k := range h {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var b strings.Builder
		for _, k := range keys {
			for _, v := range h[k] {
				// Header names are lowercased: HTTP header names are
				// case-insensitive and several rule packs spell them in
				// lowercase without the (?i) flag.
				b.WriteString(strings.ToLower(k))
				b.WriteString(": ")
				b.WriteString(v)
				b.WriteString("\n")
			}
		}
		return b.String()
	}
	return h.Get(name)
}

// statusOK applies the optional status filter.
func statusOK(spec StatusSpec, status int) bool {
	if !spec.Set {
		return true
	}
	for _, s := range spec.Values {
		if s == status {
			return true
		}
	}
	return false
}

// Matches evaluates one fingerprint/check condition against a response.
func (c Condition) Matches(resp *Response) bool {
	if !statusOK(c.Status, resp.Status) {
		return false
	}
	body := resp.Text()
	if c.BodyContains != "" && !strings.Contains(body, c.BodyContains) {
		return false
	}
	if c.BodyRegex != "" && !compilePattern(c.BodyRegex).matches(body) {
		return false
	}
	for name, needle := range c.HeaderContains {
		if !strings.Contains(headerText(resp.Header, name), needle) {
			return false
		}
	}
	for name, expr := range c.HeaderRegex {
		if !compilePattern(expr).matches(headerText(resp.Header, name)) {
			return false
		}
	}
	return true
}

func conditionMethod(c Condition) string {
	if strings.TrimSpace(c.Method) == "" {
		return http.MethodGet
	}
	return strings.ToUpper(strings.TrimSpace(c.Method))
}

func conditionPath(c Condition) string {
	if strings.TrimSpace(c.Path) == "" {
		return "/"
	}
	return c.Path
}

func joinURL(base, p string) string {
	if p == "" {
		p = "/"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return base + p
}
