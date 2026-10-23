// Package enrich is the engine-side (non-AI) asset auto-completion layer described
// in docs/资产模型与自动关联设计.md §5: an async worker pool that resolves domains
// (dnsx) and probes web assets (HTTP, through the recording proxy) and writes the
// results back into the asset graph — creating IP/port nodes, resolves/exposes
// edges, and filling attrs.dns / attrs.http. DNS is ungated; HTTP probing is gated
// by RoE (§5.2).
package enrich

import (
	"context"
	"crypto/tls"
	"html"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/cve"
	"github.com/Autumn-27/artex/db"

	"github.com/miekg/dns"
	"github.com/projectdiscovery/dnsx/libs/dnsx"
)

type jobKind int

const (
	jobDNS  jobKind = iota // resolve a domain
	jobHTTP                // probe a web asset (site)
)

type job struct {
	kind jobKind
	id   int64  // asset id (domain for DNS, site for HTTP)
	arg  string // host (DNS) or url (HTTP)
}

// Engine owns the resolver, the proxy-routed HTTP client, and the worker pool.
type Engine struct {
	as     *db.AssetStore
	resolv *dnsx.DNSX
	client *http.Client

	jobs   chan job
	cool   sync.Map // dedup/cooldown: "kind:id" -> time.Time (last run)
	once   sync.Once
	closed chan struct{}
}

const (
	cooldown    = 5 * time.Minute
	httpTimeout = 12 * time.Second
	queueSize   = 1024
)

// New builds the engine. proxy() returns the recording-proxy address to route HTTP
// probes through (so they land in the traffic store), evaluated per request so the
// runtime traffic-capture toggle takes effect live; "" = direct. Returns a usable
// engine even if the resolver fails to init (DNS becomes a no-op).
func New(as *db.AssetStore, proxy func() string, workers int) *Engine {
	if workers <= 0 {
		workers = 4
	}
	resolv, err := dnsx.New(dnsx.Options{
		BaseResolvers: dnsx.DefaultResolvers,
		MaxRetries:    3,
		QuestionTypes: []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeCNAME},
		Timeout:       4 * time.Second,
	})
	if err != nil {
		log.Printf("[enrich] dnsx 初始化失败，DNS 解析停用：%v", err)
		resolv = nil
	}
	e := &Engine{
		as:     as,
		resolv: resolv,
		client: buildClient(proxy),
		jobs:   make(chan job, queueSize),
		closed: make(chan struct{}),
	}
	for i := 0; i < workers; i++ {
		go e.worker()
	}
	return e
}

// buildClient returns an HTTP client that dials via the recording proxy (resolved
// per-request via proxy(), so the traffic-capture toggle applies live) and skips
// TLS verification (the proxy re-signs with its MITM CA; targets are often
// self-signed — this is a pentest probe).
func buildClient(proxy func() string) *http.Client {
	tr := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives:   true,
		TLSHandshakeTimeout: httpTimeout,
	}
	if proxy != nil {
		tr.Proxy = func(*http.Request) (*url.URL, error) {
			p := proxy()
			if p == "" {
				return nil, nil // direct
			}
			return url.Parse(p)
		}
	}
	return &http.Client{
		Transport: tr,
		Timeout:   httpTimeout,
		// cap redirects; keep them within scope by re-checking at probe time
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// ResolveDomain enqueues a DNS resolution for a domain asset (ungated). host is the
// FQDN. No-op for an empty engine.
func (e *Engine) ResolveDomain(id int64, host string) { e.enqueue(job{jobDNS, id, host}) }

// ProbeSite enqueues an HTTP probe for a web-asset (site). rawURL is the site URL.
func (e *Engine) ProbeSite(id int64, rawURL string) { e.enqueue(job{jobHTTP, id, rawURL}) }

func (e *Engine) enqueue(j job) {
	if e == nil || id0(j.id) || j.arg == "" {
		return
	}
	select {
	case e.jobs <- j:
	default: // queue full → drop (best-effort enrichment)
		log.Printf("[enrich] 队列已满，丢弃任务 kind=%d id=%d", j.kind, j.id)
	}
}

func id0(id int64) bool { return id <= 0 }

// Close stops the workers (idempotent).
func (e *Engine) Close() {
	if e == nil {
		return
	}
	e.once.Do(func() { close(e.closed) })
}

func (e *Engine) worker() {
	for {
		select {
		case <-e.closed:
			return
		case j := <-e.jobs:
			if e.onCooldown(j) {
				continue
			}
			switch j.kind {
			case jobDNS:
				e.doDNS(j.id, j.arg)
			case jobHTTP:
				e.doHTTP(j.id, j.arg)
			}
		}
	}
}

// onCooldown returns true (skip) if this (kind,id) ran within the cooldown window.
func (e *Engine) onCooldown(j job) bool {
	key := string(rune(j.kind)) + ":" + itoa(j.id)
	if v, ok := e.cool.Load(key); ok {
		if t, ok := v.(time.Time); ok && time.Since(t) < cooldown {
			return true
		}
	}
	e.cool.Store(key, time.Now())
	return false
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

// ---- DNS ----

func (e *Engine) doDNS(id int64, host string) {
	if e.resolv == nil {
		return
	}
	data, err := e.resolv.QueryMultiple(host)
	if err != nil || data == nil {
		return
	}
	ips := uniq(append(append([]string{}, data.A...), data.AAAA...))
	// Upsert resolved IPs into the asset store.
	for _, ip := range ips {
		_, _ = e.as.UpsertIP(db.UpsertIPReq{
			IP:           ip,
			BoundDomains: []string{host},
		})
	}
	// Record A records as subdomains if host looks like a subdomain.
	for _, a := range data.A {
		_, _ = e.as.UpsertSubdomain(db.UpsertSubdomainReq{
			Domain:      host,
			RecordType:  "A",
			RecordValue: []string{a},
		})
	}
	for _, aaaa := range data.AAAA {
		_, _ = e.as.UpsertSubdomain(db.UpsertSubdomainReq{
			Domain:      host,
			RecordType:  "AAAA",
			RecordValue: []string{aaaa},
		})
	}
	for _, cname := range data.CNAME {
		_, _ = e.as.UpsertSubdomain(db.UpsertSubdomainReq{
			Domain:      host,
			RecordType:  "CNAME",
			RecordValue: []string{cname},
		})
	}
}

// ---- HTTP probe ----

var reTitle = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

func (e *Engine) doHTTP(id int64, rawURL string) {
	host := hostOf(rawURL)
	if host == "" {
		return
	}
	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", "artex-enrich/1.0")
	resp, err := e.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // cap 1 MiB
	statusCode := resp.StatusCode
	bodyLen := int64(len(body))
	title := extractTitle(body)
	techs, extra, detected := fingerprintTech(rawURL, statusCode, resp.Header, body)
	_, _ = e.as.UpsertHTTPService(db.UpsertHTTPServiceReq{
		URL:           rawURL,
		StatusCode:    &statusCode,
		ContentLength: &bodyLen,
		PageTitle:     title,
		Technologies:  techs,
		Extra:         extra,
	})
	// If the fingerprint matches a known LLM-serving component, also record an
	// llm_endpoint asset. Its extra.kind=llm_endpoint_entity lets the Skill
	// Matcher offer the llm-redteam skill without waiting for an explicit fact.
	if provider, apiType, ok := detectLLMEndpoint(detected); ok {
		var taskID int64
		if src, err := e.as.GetByIDs([]int64{id}); err == nil && len(src) > 0 && len(src[0].TaskIDs) > 0 {
			taskID = src[0].TaskIDs[0]
		}
		_, _ = e.as.UpsertLLMEndpoint(db.UpsertLLMEndpointReq{
			URL:          rawURL,
			Provider:     provider,
			APIType:      apiType,
			Technologies: techs,
			StatusCode:   &statusCode,
			PageTitle:    title,
			TaskID:       taskID,
		})
	}
}

// fingerprintTech runs the local fingerprint + CVE rule pack against the page
// already fetched by the probe. It never requests other paths (light mode), so
// auto-enrichment stays cheap; matched components and their version-attributable
// CVE counts land in the asset graph (technologies + extra) for the agents to act
// on without re-scanning.
func fingerprintTech(rawURL string, status int, header http.Header, body []byte) ([]string, map[string]any, []cve.Detected) {
	eng, err := cve.Shared()
	if err != nil {
		return nil, nil, nil
	}
	detected := eng.FingerprintFrom(context.Background(), rawURL, &cve.Response{
		Status: status, Header: header, Body: body,
	})
	if len(detected) == 0 {
		return nil, nil, nil
	}
	techs := make([]string, 0, len(detected))
	comps := make([]map[string]any, 0, len(detected))
	totalCVEs := 0
	maxSeverity := ""
	for _, d := range detected {
		techs = append(techs, d.Name)
		rules := eng.CVEFor(d.ID, d.Version)
		comp := map[string]any{
			"id": d.ID, "name": d.Name, "cve_count": len(rules), "evidence": d.Evidence,
		}
		if d.Category != "" {
			comp["category"] = d.Category
		}
		if d.Version != "" {
			comp["version"] = d.Version
		}
		if len(rules) > 0 {
			ids := make([]string, 0, len(rules))
			compMax := ""
			for _, r := range rules {
				ids = append(ids, r.ID)
				if compMax == "" || cve.SeverityRank(r.Severity) < cve.SeverityRank(compMax) {
					compMax = r.Severity
				}
			}
			if len(ids) > 20 {
				ids = ids[:20]
			}
			comp["cves"] = ids
			comp["max_severity"] = compMax
			if maxSeverity == "" || cve.SeverityRank(compMax) < cve.SeverityRank(maxSeverity) {
				maxSeverity = compMax
			}
		}
		totalCVEs += len(rules)
		comps = append(comps, comp)
	}
	extra := map[string]any{"cve_components": comps, "cve_count": totalCVEs}
	if maxSeverity != "" {
		extra["cve_max_severity"] = maxSeverity
	}
	return techs, extra, detected
}

// llmComponents maps fingerprint component IDs to the LLM provider / API type
// they expose. Components not listed here are treated as non-LLM even if they
// happen to proxy LLM traffic (the agent can still insert an llm_endpoint
// manually via insert_assets).
var llmComponents = map[string]struct {
	provider string
	apiType  string
}{
	"ollama":                  {"ollama", "ollama"},
	"openai-compatible":       {"openai", "openai_compatible"},
	"vllm":                    {"vllm", "openai_compatible"},
	"llamafactory":            {"llamafactory", "openai_compatible"},
	"lmdeploy":                {"lmdeploy", "openai_compatible"},
	"sglang":                  {"sglang", "openai_compatible"},
	"xinference":              {"xinference", "openai_compatible"},
	"text-generation-webui":   {"text-generation-webui", "openai_compatible"},
	"llama-cpp":               {"llama-cpp", "openai_compatible"},
	"koboldcpp":               {"koboldcpp", "openai_compatible"},
	"localai":                 {"localai", "openai_compatible"},
	"lm-studio":               {"lm-studio", "openai_compatible"},
	"mlc-llm":                 {"mlc-llm", "openai_compatible"},
	"tensorrt-llm":            {"tensorrt-llm", "openai_compatible"},
	"triton-inference-server": {"triton", "openai_compatible"},
	"petals":                  {"petals", "openai_compatible"},
	"new-api":                 {"new-api", "openai_compatible"},
	"one-api":                 {"one-api", "openai_compatible"},
	"cloudflare-ai-gateway":   {"cloudflare", "openai_compatible"},
	"portkey-ai-gateway":      {"portkey", "openai_compatible"},
	"fireworks-ai":            {"fireworks", "openai_compatible"},
	"together-ai":             {"together", "openai_compatible"},
	"groq":                    {"groq", "openai_compatible"},
	"network-ai":              {"network-ai", "openai_compatible"},
	"onyx":                    {"onyx", "openai_compatible"},
	"kubeai":                  {"kubeai", "openai_compatible"},
	"ray":                     {"ray", "openai_compatible"},
	"fastchat":                {"fastchat", "openai_compatible"},
	"open-webui":              {"open-webui", "openai_compatible"},
	"librechat":               {"librechat", "openai_compatible"},
	"nextchat":                {"nextchat", "openai_compatible"},
	"lollms":                  {"lollms", "openai_compatible"},
	"sillytavern":             {"sillytavern", "openai_compatible"},
	"aphrodite-engine":        {"aphrodite", "openai_compatible"},
	"jan":                     {"jan", "openai_compatible"},
	"lightllm":                {"lightllm", "openai_compatible"},
}

// detectLLMEndpoint inspects fingerprint detections and returns the first
// LLM-serving component's provider/api-type. The first match wins because a
// target typically exposes one LLM stack.
func detectLLMEndpoint(detected []cve.Detected) (provider, apiType string, ok bool) {
	for _, d := range detected {
		if info, exists := llmComponents[d.ID]; exists {
			return info.provider, info.apiType, true
		}
	}
	return "", "", false
}

func extractTitle(body []byte) string {
	m := reTitle.FindSubmatch(body)
	if m == nil {
		return ""
	}
	return strings.TrimSpace(html.UnescapeString(string(m[1])))
}

func hostOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

func isBlank(v any) bool {
	switch x := v.(type) {
	case nil:
		return true
	case string:
		return x == ""
	case float64:
		return x == 0
	case int:
		return x == 0
	}
	return false
}

func uniq(in []string) []string {
	seen := map[string]struct{}{}
	out := in[:0]
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
