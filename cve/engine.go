package cve

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultTimeout   = 10 * time.Second
	defaultWorkers   = 8
	maxResponseBytes = 4 << 20 // 4 MiB
	defaultUserAgent = "artex-cve/1.0"
)

// Options configures an Engine.
type Options struct {
	// Rules overrides the embedded rule pack (tests / custom rule dirs).
	Rules *RuleSet
	// Client overrides the HTTP client. When nil one is built from Proxy.
	Client *http.Client
	// Proxy returns the recording-proxy address for each request ("" = direct).
	Proxy   func() string
	Timeout time.Duration
	Workers int
	// UserAgent defaults to "artex-cve/1.0".
	UserAgent string
}

// Engine fingerprints targets and evaluates CVE rules against them.
type Engine struct {
	client    *http.Client
	timeout   time.Duration
	workers   int
	userAgent string
	rules     *RuleSet
}

// New builds an engine. The rule pack is loaded lazily by the caller when nil.
func New(opts Options) (*Engine, error) {
	rules := opts.Rules
	if rules == nil {
		var err error
		rules, err = LoadEmbedded()
		if err != nil {
			return nil, err
		}
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	workers := opts.Workers
	if workers <= 0 {
		workers = defaultWorkers
	}
	ua := opts.UserAgent
	if ua == "" {
		ua = defaultUserAgent
	}
	client := opts.Client
	if client == nil {
		client = buildClient(opts.Proxy, timeout)
	}
	return &Engine{client: client, timeout: timeout, workers: workers, userAgent: ua, rules: rules}, nil
}

func buildClient(proxy func() string, timeout time.Duration) *http.Client {
	tr := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, // pentest probe: self-signed is normal
		TLSHandshakeTimeout: timeout,
	}
	if proxy != nil {
		tr.Proxy = func(*http.Request) (*url.URL, error) {
			p := strings.TrimSpace(proxy())
			if p == "" {
				return nil, nil
			}
			return url.Parse(p)
		}
	}
	return &http.Client{
		Transport: tr,
		Timeout:   timeout,
		// Probes must not silently follow redirects: the rule paths are absolute
		// and the evidence must describe the response the rule matched.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// Rules exposes the loaded rule pack.
func (e *Engine) Rules() *RuleSet { return e.rules }

// Detected is one identified component.
type Detected struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Category string `json:"category,omitempty"`
	Version  string `json:"version,omitempty"`
	Evidence string `json:"evidence"`
	Source   string `json:"-"`
}

// Finding is one CVE matched against a detected component.
type Finding struct {
	CVE         string   `json:"cve"`
	Title       string   `json:"title"`
	Severity    string   `json:"severity"`
	Component   string   `json:"component"`
	Version     string   `json:"version,omitempty"`
	Detail      string   `json:"detail,omitempty"`
	Evidence    string   `json:"evidence"`
	References  []string `json:"references,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
	OWASPTags   []string `json:"owasp_tags,omitempty"`
	Source      string   `json:"-"`
}

// Result is a full scan result.
type Result struct {
	Target    string     `json:"target"`
	Detected  []Detected `json:"components"`
	Findings  []Finding  `json:"findings"`
	Probes    int        `json:"probes"`
	ElapsedMS int64      `json:"elapsed_ms"`
}

// ScanOptions narrows a scan. The zero value scans everything, passively.
type ScanOptions struct {
	Only        []string // restrict to these CVE ids (case-insensitive)
	Components  []string // restrict to these component ids
	Active      bool     // allow check.mode=request confirmation requests
	MinSeverity string   // critical|high|medium|low|info ("" = all)
	MaxFindings int      // 0 = unlimited
}

// ---- probe plumbing ----

type cacheEntry struct {
	once sync.Once
	resp *Response
}

type scanCtx struct {
	eng    *Engine
	base   string
	mu     sync.Mutex
	cache  map[string]*cacheEntry
	probes int32
}

func newScanCtx(eng *Engine, base string) *scanCtx {
	return &scanCtx{eng: eng, base: strings.TrimRight(base, "/"), cache: map[string]*cacheEntry{}}
}

func probeKey(method, rawURL string, headers map[string]string, body string) string {
	var b strings.Builder
	b.WriteString(method)
	b.WriteString("\n")
	b.WriteString(rawURL)
	if len(headers) > 0 {
		keys := make([]string, 0, len(headers))
		for k := range headers {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			b.WriteString("\n")
			b.WriteString(strings.ToLower(k))
			b.WriteString(":")
			b.WriteString(headers[k])
		}
	}
	if body != "" {
		b.WriteString("\n\n")
		b.WriteString(body)
	}
	return b.String()
}

// fetch performs (or reuses) one probe. Duplicate probes within a scan collapse
// onto a single request via the per-key once. allowNew=false returns nil for
// URLs that were not already cached (used by the light fingerprint mode).
func (sc *scanCtx) fetch(ctx context.Context, method, rawURL string, headers map[string]string, body string, allowNew bool) *Response {
	key := probeKey(method, rawURL, headers, body)
	sc.mu.Lock()
	ent, ok := sc.cache[key]
	if !ok {
		if !allowNew {
			sc.mu.Unlock()
			return nil
		}
		ent = &cacheEntry{}
		sc.cache[key] = ent
	}
	sc.mu.Unlock()
	ent.once.Do(func() {
		atomic.AddInt32(&sc.probes, 1)
		ent.resp = sc.eng.doRequest(ctx, method, rawURL, headers, body)
	})
	return ent.resp
}

// seed registers an already-fetched response under its probe key so the light
// mode can match without re-requesting the page.
func (sc *scanCtx) seed(method, rawURL string, headers map[string]string, body string, resp *Response) {
	key := probeKey(method, rawURL, headers, body)
	ent := &cacheEntry{resp: resp}
	ent.once.Do(func() {})
	sc.mu.Lock()
	sc.cache[key] = ent
	sc.mu.Unlock()
}

func (e *Engine) doRequest(ctx context.Context, method, rawURL string, headers map[string]string, body string) *Response {
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, rdr)
	if err != nil {
		return &Response{Err: err}
	}
	req.Header.Set("User-Agent", e.userAgent)
	hasCT := false
	for k, v := range headers {
		if strings.EqualFold(k, "Content-Type") {
			hasCT = true
		}
		req.Header.Set(k, v)
	}
	if body != "" && !hasCT {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return &Response{Err: err}
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return &Response{Status: resp.StatusCode, Header: resp.Header, Body: data, Err: err}
	}
	return &Response{Status: resp.StatusCode, Header: resp.Header, Body: data}
}

// ---- fingerprint ----

// Fingerprint probes a target and returns every identified component, in rule
// order. Conditions are tried in order and the first match wins (same contract
// as the Python engine).
func (e *Engine) Fingerprint(ctx context.Context, target string) []Detected {
	sc := newScanCtx(e, target)
	fps := e.rules.Fingerprints()
	out := make([]Detected, len(fps))
	active := make([]bool, len(fps))

	sem := make(chan struct{}, e.workers)
	var wg sync.WaitGroup
	for i, fp := range fps {
		if len(fp.Match.Any) == 0 {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, fp *Fingerprint) {
			defer wg.Done()
			defer func() { <-sem }()
			for _, cond := range fp.Match.Any {
				rawURL := joinURL(sc.base, conditionPath(cond))
				resp := sc.fetch(ctx, conditionMethod(cond), rawURL, cond.Header, cond.Body, true)
				if resp == nil || !resp.reachable() || !cond.Matches(resp) {
					continue
				}
				out[i] = Detected{
					ID:       fp.ID,
					Name:     fp.Name,
					Category: fp.Category,
					Version:  e.probeVersion(ctx, sc, fp.Version, resp),
					Evidence: fmt.Sprintf("%s %s -> HTTP %d", conditionMethod(cond), conditionPath(cond), resp.Status),
					Source:   fp.Source,
				}
				active[i] = true
				return
			}
		}(i, fp)
	}
	wg.Wait()

	res := make([]Detected, 0, len(fps))
	for i := range out {
		if active[i] {
			res = append(res, out[i])
		}
	}
	return res
}

// FingerprintFrom identifies components using an already-fetched page response
// for the target root. No new request is sent to conditions other than "/";
// only version probes of matched components may issue requests. This is the
// cheap mode used by the background enrichment layer.
func (e *Engine) FingerprintFrom(ctx context.Context, target string, resp *Response) []Detected {
	sc := newScanCtx(e, target)
	root := sc.base + "/"
	sc.seed(http.MethodGet, root, nil, "", resp)

	fps := e.rules.Fingerprints()
	var out []Detected
	for _, fp := range fps {
		for _, cond := range fp.Match.Any {
			if conditionMethod(cond) != http.MethodGet {
				continue
			}
			rawURL := joinURL(sc.base, conditionPath(cond))
			if rawURL != root {
				continue // light mode: never fan out to other paths
			}
			r := sc.fetch(ctx, http.MethodGet, rawURL, cond.Header, cond.Body, false)
			if r == nil || !r.reachable() || !cond.Matches(r) {
				continue
			}
			out = append(out, Detected{
				ID:       fp.ID,
				Name:     fp.Name,
				Category: fp.Category,
				Version:  e.probeVersion(ctx, sc, fp.Version, r),
				Evidence: fmt.Sprintf("GET / -> HTTP %d", r.Status),
				Source:   fp.Source,
			})
			break
		}
	}
	return out
}

// probeVersion extracts a version string. A spec with a Path issues its own
// request; otherwise the identification response is reused. The first spec
// yielding a non-empty version wins.
func (e *Engine) probeVersion(ctx context.Context, sc *scanCtx, rule VersionRule, seed *Response) string {
	for _, spec := range rule {
		resp := seed
		if spec.Path != "" {
			method := strings.ToUpper(strings.TrimSpace(spec.Method))
			if method == "" {
				method = http.MethodGet
			}
			resp = sc.fetch(ctx, method, joinURL(sc.base, spec.Path), spec.RequestHeaders, spec.Body, true)
		}
		if resp == nil || resp.Err != nil {
			continue
		}
		if spec.BodyRegex != "" {
			if v, ok := compilePattern(spec.BodyRegex).find(resp.Text()); ok && v != "" {
				return v
			}
		}
		for name, expr := range spec.HeaderRegex {
			text := headerText(resp.Header, name)
			if v, ok := compilePattern(expr).find(text); ok && v != "" {
				return v
			}
		}
		if spec.Header != "" && spec.ValueRegex != "" {
			if v, ok := compilePattern(spec.ValueRegex).find(headerText(resp.Header, spec.Header)); ok && v != "" {
				return v
			}
		}
	}
	return ""
}

// ---- CVE matching ----

// CVEFor returns the rules affecting this component at this version (pure
// computation: no network).
func (e *Engine) CVEFor(component, version string) []*Vuln {
	var out []*Vuln
	for _, v := range e.rules.VulnsFor(component) {
		if VersionInRange(version, v.Affected) {
			out = append(out, v)
		}
	}
	return out
}

// Scan fingerprints the target then evaluates every applicable CVE rule.
func (e *Engine) Scan(ctx context.Context, target string, opts ScanOptions) Result {
	start := time.Now()
	sc := newScanCtx(e, target)
	res := Result{Target: strings.TrimRight(target, "/")}

	res.Detected = e.fingerprintScoped(ctx, sc)

	componentSet := map[string]bool{}
	for _, c := range opts.Components {
		componentSet[c] = true
	}
	onlySet := map[string]bool{}
	for _, o := range opts.Only {
		onlySet[strings.ToLower(o)] = true
	}
	minRank := SeverityRank(opts.MinSeverity)
	if strings.TrimSpace(opts.MinSeverity) == "" {
		minRank = 4
	}

	for _, det := range res.Detected {
		if len(componentSet) > 0 && !componentSet[det.ID] {
			continue
		}
		for _, rule := range e.rules.VulnsFor(det.ID) {
			if len(onlySet) > 0 && !onlySet[strings.ToLower(rule.ID)] {
				continue
			}
			if !VersionInRange(det.Version, rule.Affected) {
				continue
			}
			if SeverityRank(rule.Severity) > minRank {
				continue
			}
			evidence := det.Evidence
			if rule.Mode() == "request" {
				if !opts.Active || rule.Check == nil {
					continue
				}
				resp := e.runCheck(ctx, sc, rule.Check)
				if resp == nil || !resp.reachable() || !rule.Check.Match.Matches(resp) {
					continue
				}
				path := rule.Check.Path
				if path == "" {
					path = "/"
				}
				method := strings.ToUpper(strings.TrimSpace(rule.Check.Method))
				if method == "" {
					method = http.MethodGet
				}
				evidence = fmt.Sprintf("%s %s -> HTTP %d", method, path, resp.Status)
			}
			res.Findings = append(res.Findings, Finding{
				CVE:         rule.ID,
				Title:       rule.Title,
				Severity:    strings.ToUpper(rule.Severity),
				Component:   det.ID,
				Version:     det.Version,
				Detail:      rule.Description,
				Evidence:    evidence,
				References:  rule.References,
				Remediation: rule.Remediation,
				OWASPTags:   rule.OWASPTags,
				Source:      rule.Source,
			})
		}
	}

	sort.SliceStable(res.Findings, func(i, j int) bool {
		ri, rj := SeverityRank(res.Findings[i].Severity), SeverityRank(res.Findings[j].Severity)
		if ri != rj {
			return ri < rj
		}
		return res.Findings[i].CVE < res.Findings[j].CVE
	})
	if opts.MaxFindings > 0 && len(res.Findings) > opts.MaxFindings {
		res.Findings = res.Findings[:opts.MaxFindings]
	}
	res.Probes = int(atomic.LoadInt32(&sc.probes))
	res.ElapsedMS = time.Since(start).Milliseconds()
	return res
}

// fingerprintScoped is Fingerprint but shares the scan's probe cache, so
// confirmation requests reuse responses already fetched.
func (e *Engine) fingerprintScoped(ctx context.Context, sc *scanCtx) []Detected {
	fps := e.rules.Fingerprints()
	out := make([]Detected, len(fps))
	found := make([]bool, len(fps))

	sem := make(chan struct{}, e.workers)
	var wg sync.WaitGroup
	for i, fp := range fps {
		if len(fp.Match.Any) == 0 {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, fp *Fingerprint) {
			defer wg.Done()
			defer func() { <-sem }()
			for _, cond := range fp.Match.Any {
				rawURL := joinURL(sc.base, conditionPath(cond))
				resp := sc.fetch(ctx, conditionMethod(cond), rawURL, cond.Header, cond.Body, true)
				if resp == nil || !resp.reachable() || !cond.Matches(resp) {
					continue
				}
				out[i] = Detected{
					ID:       fp.ID,
					Name:     fp.Name,
					Category: fp.Category,
					Version:  e.probeVersion(ctx, sc, fp.Version, resp),
					Evidence: fmt.Sprintf("%s %s -> HTTP %d", conditionMethod(cond), conditionPath(cond), resp.Status),
					Source:   fp.Source,
				}
				found[i] = true
				return
			}
		}(i, fp)
	}
	wg.Wait()

	res := make([]Detected, 0, len(fps))
	for i := range out {
		if found[i] {
			res = append(res, out[i])
		}
	}
	return res
}

func (e *Engine) runCheck(ctx context.Context, sc *scanCtx, check *CheckRule) *Response {
	method := strings.ToUpper(strings.TrimSpace(check.Method))
	if method == "" {
		method = http.MethodGet
	}
	path := check.Path
	if path == "" {
		path = "/"
	}
	return sc.fetch(ctx, method, joinURL(sc.base, path), check.Headers, check.Body, true)
}

// Lookup searches the rule pack locally (no network).
type LookupOptions struct {
	Component string
	Version   string
	Query     string
	Limit     int
}

// Lookup returns matching CVE rules. Query is a case-insensitive substring
// matched against id, title, component and description.
func (e *Engine) Lookup(opts LookupOptions) ([]*Vuln, error) {
	limit := opts.Limit
	if limit <= 0 {
		limit = 50
	}
	var base []*Vuln
	if strings.TrimSpace(opts.Component) != "" {
		base = e.rules.VulnsFor(opts.Component)
	} else {
		all, err := e.rules.AllVulns()
		if err != nil {
			return nil, err
		}
		base = all
	}
	q := strings.ToLower(strings.TrimSpace(opts.Query))
	out := make([]*Vuln, 0, limit)
	for _, v := range base {
		if opts.Version != "" && !VersionInRange(opts.Version, v.Affected) {
			continue
		}
		if q != "" {
			hay := strings.ToLower(v.ID + " " + v.Title + " " + v.Component + " " + v.Description)
			if !strings.Contains(hay, q) {
				continue
			}
		}
		out = append(out, v)
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}
