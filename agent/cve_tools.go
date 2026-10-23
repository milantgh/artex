package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Autumn-27/artex/cve"
	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

// cveScanTimeout bounds one scan: fingerprinting probes several paths and the
// target may be slow, but a single tool call must not hang a work forever.
const cveScanTimeout = 3 * time.Minute

// cveScan gives agents the deterministic fingerprint + CVE engine that ships
// with ARTEX (the AISecurityTest rule pack ported to Go). It is read-only: it
// never writes findings itself, so the agent keeps control over what is
// reported — confirm the evidence and use report_finding for the real ones.
func (t *ToolSet) cveScan() actool.CoreTool {
	return readTool(
		"cve_scan",
		"【内置 CVE 引擎】对 HTTP 目标做组件指纹识别 + CVE 匹配。使用内置规则库(160 个组件指纹 / 2500+ CVE)，"+
			"不依赖联网查询：先按指纹规则探测组件与版本(页面特征、x-version 等响应头、/api/version 等端点)，"+
			"再用版本区间判定受影响 CVE。默认纯被动(仅版本判定)；active=true 才会发送规则里的确认请求。"+
			"返回 components(id/name/version/evidence) 与 findings(CVE/标题/严重度/证据/修复建议)。"+
			"在任务内调用时默认把确定性结果写入探索图 fact(每个命中组件一条，按 target+组件+版本+CVE 集合去重)，"+
			"传 intent_id 可挂到当前意图；record=false 可只查询不写图。"+
			"优先对已知技术栈的 URL 调用；确认证据成立后用 report_finding 上报(vulnclass 填 CVE 编号，evidence 用本工具证据)。"+
			"遇到不认识的产品可先用 cve_lookup 查规则库里有哪些组件。",
		obj(map[string]any{
			"url": str("目标根 URL，必须带 http:// 或 https://，例如 http://192.168.1.10:3000"),
			"mode": map[string]any{"type": "string", "enum": []string{"cve", "fingerprint"},
				"description": "cve=指纹识别+CVE 匹配(默认)；fingerprint=只识别组件与版本"},
			"components": map[string]any{"type": "array", "items": map[string]any{"type": "string"},
				"description": "可选：只评估这些组件 id(如 dify、ollama)，留空=全部"},
			"only": map[string]any{"type": "array", "items": map[string]any{"type": "string"},
				"description": "可选：只保留这些 CVE 编号"},
			"severity_min": map[string]any{"type": "string", "enum": []string{"critical", "high", "medium", "low", "info"},
				"description": "可选：最低严重度过滤"},
			"active": map[string]any{"type": "boolean",
				"description": "允许发送规则里的确认请求(check.mode=request)。默认 false，只做被动版本判定"},
			"max_findings": map[string]any{"type": "integer",
				"description": "返回的 CVE 条数上限，默认 50；按严重度从高到低取"},
			"intent_id": idp("可选：产生本次扫描的意图 id；任务内会把结果 fact 挂到该意图"),
			"record": map[string]any{"type": "boolean",
				"description": "是否把确定性结果写入探索图 fact，任务内默认 true；只查询时传 false"},
		}, "url"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				URL         string          `json:"url"`
				Mode        string          `json:"mode"`
				Components  []string        `json:"components"`
				Only        []string        `json:"only"`
				SeverityMin string          `json:"severity_min"`
				Active      bool            `json:"active"`
				MaxFindings int             `json:"max_findings"`
				IntentID    json.RawMessage `json:"intent_id"`
				Record      *bool           `json:"record"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			a.URL = strings.TrimSpace(a.URL)
			if !strings.HasPrefix(a.URL, "http://") && !strings.HasPrefix(a.URL, "https://") {
				return actool.Errorf("url 必须以 http:// 或 https:// 开头"), nil
			}
			eng, err := cve.Shared()
			if err != nil {
				return actool.Errorf("CVE 规则库加载失败: " + err.Error()), nil
			}
			ctx, cancel := context.WithTimeout(ctx, cveScanTimeout)
			defer cancel()

			record := t.ts != nil && (a.Record == nil || *a.Record)
			intentID := pid(a.IntentID)

			if a.Mode == "fingerprint" {
				detected := eng.Fingerprint(ctx, a.URL)
				res := cve.Result{Target: strings.TrimRight(a.URL, "/"), Detected: detected}
				var recorded []int64
				if record {
					recorded = t.recordCVEFacts(res, intentID, false)
				}
				return jsonResult(map[string]any{
					"target":            res.Target,
					"mode":              "fingerprint",
					"count":             len(detected),
					"components":        detected,
					"recorded_fact_ids": recorded,
				})
			}

			max := a.MaxFindings
			if max <= 0 {
				max = 50
			}
			res := eng.Scan(ctx, a.URL, cve.ScanOptions{
				Only:        a.Only,
				Components:  a.Components,
				Active:      a.Active,
				MinSeverity: a.SeverityMin,
			})
			var recorded []int64
			if record {
				recorded = t.recordCVEFacts(res, intentID, true)
			}
			total := len(res.Findings)
			findings := res.Findings
			if len(findings) > max {
				findings = findings[:max]
			}
			out := make([]cveFindingOut, 0, len(findings))
			for _, f := range findings {
				out = append(out, cveFindingOut{Finding: f, Level: cve.NormalizeSeverity(f.Severity)})
			}
			return jsonResult(map[string]any{
				"target":            res.Target,
				"mode":              "cve",
				"components":        res.Detected,
				"component_count":   len(res.Detected),
				"findings":          out,
				"finding_count":     total,
				"returned":          len(out),
				"truncated":         total > len(out),
				"probes":            res.Probes,
				"elapsed_ms":        res.ElapsedMS,
				"recorded_fact_ids": recorded,
			})
		},
	)
}

// cveFactDetailLimit caps how many CVE lines go into one fact's detail text.
const cveFactDetailLimit = 20

// recordCVEFacts turns a deterministic scan into exploration-graph facts:
// one per component with known CVEs, plus one summary fact when the pack found
// nothing. evaluated=false means fingerprint-only (CVE rules were not run), so
// the summary must not claim "no known CVEs". Facts are chained to intentID
// (intent→yields→fact) when given. The cve_key in the payload makes repeated
// scans idempotent, so a worker that re-checks a target does not inflate the graph.
func (t *ToolSet) recordCVEFacts(res cve.Result, intentID int64, evaluated bool) []int64 {
	if t.ts == nil {
		return nil
	}
	seen := t.existingCVEFactKeys()

	byComp := map[string][]cve.Finding{}
	for _, f := range res.Findings {
		byComp[f.Component] = append(byComp[f.Component], f)
	}

	// Order components by their worst severity (then by hit count) so the graph
	// lists exploitable surface first, matching the tool's own finding order.
	type compHits struct {
		det  cve.Detected
		fs   []cve.Finding
		rank int
	}
	ranked := make([]compHits, 0, len(res.Detected))
	for _, det := range res.Detected {
		fs := byComp[det.ID]
		if len(fs) == 0 {
			continue
		}
		fs = append([]cve.Finding(nil), fs...)
		sort.SliceStable(fs, func(i, j int) bool {
			ri, rj := cve.SeverityRank(fs[i].Severity), cve.SeverityRank(fs[j].Severity)
			if ri != rj {
				return ri < rj
			}
			return fs[i].CVE < fs[j].CVE
		})
		rank := cve.SeverityRank(fs[0].Severity)
		ranked = append(ranked, compHits{det: det, fs: fs, rank: rank})
	}
	sort.SliceStable(ranked, func(i, j int) bool {
		if ranked[i].rank != ranked[j].rank {
			return ranked[i].rank < ranked[j].rank
		}
		return len(ranked[i].fs) > len(ranked[j].fs)
	})

	var ids []int64
	for _, h := range ranked {
		det, fs := h.det, h.fs
		cves := make([]string, 0, len(fs))
		matches := make([]map[string]any, 0, len(fs))
		lines := make([]string, 0, len(fs))
		for i, f := range fs {
			cves = append(cves, f.CVE)
			matches = append(matches, map[string]any{
				"cve": f.CVE, "severity": f.Severity, "title": f.Title,
			})
			if i < cveFactDetailLimit {
				lines = append(lines, fmt.Sprintf("%s [%s] %s", f.CVE, strings.ToUpper(f.Severity), f.Title))
			}
		}
		if len(fs) > cveFactDetailLimit {
			lines = append(lines, fmt.Sprintf("…共 %d 条", len(fs)))
		}
		version := det.Version
		if version == "" {
			version = "未知版本"
		}
		key := cveFactKey(res.Target, det.ID, det.Version, cves)
		if seen[key] {
			continue
		}
		seen[key] = true
		it := factItem{
			Summary: fmt.Sprintf("%s %s 命中 %d 个已知 CVE（最高 %s）",
				det.Name, version, len(fs), strings.ToUpper(fs[0].Severity)),
			Detail:     strings.Join(lines, "\n"),
			Evidence:   fmt.Sprintf("cve_scan %s：%s", res.Target, det.Evidence),
			Confidence: "observed",
			Extra: map[string]any{
				"cve_key":            key,
				"cve_target":         res.Target,
				"cve_component":      det.ID,
				"cve_component_name": det.Name,
				"cve_version":        det.Version,
				"cve_matches":        matches,
				"cve_evidence":       det.Evidence,
			},
		}
		id, err := t.recordOneFact(it, intentID)
		if err == nil && id > 0 {
			ids = append(ids, id)
		}
	}

	// No matches: still record the deterministic fingerprint so the planner sees
	// what was identified (and can rule the target out instead of re-probing).
	if len(res.Findings) == 0 && len(res.Detected) > 0 {
		comps := make([]string, 0, len(res.Detected))
		payloadComps := make([]map[string]any, 0, len(res.Detected))
		keyParts := make([]string, 0, len(res.Detected))
		var evidence string
		for _, det := range res.Detected {
			version := det.Version
			if version == "" {
				version = "未知版本"
			}
			comps = append(comps, fmt.Sprintf("%s %s", det.Name, version))
			payloadComps = append(payloadComps, map[string]any{
				"id": det.ID, "name": det.Name, "version": det.Version,
			})
			keyParts = append(keyParts, det.ID+"@"+det.Version)
			if evidence == "" {
				evidence = det.Evidence
			}
		}
		sort.Strings(keyParts)
		mode := "cve"
		summary := fmt.Sprintf("指纹识别到 %d 个组件（内置 CVE 规则库未命中已知漏洞）", len(res.Detected))
		if !evaluated {
			mode = "fingerprint"
			summary = fmt.Sprintf("指纹识别到 %d 个组件（仅识别，未做 CVE 匹配）", len(res.Detected))
		}
		key := res.Target + "|" + mode + "|components|" + strings.Join(keyParts, ",")
		if !seen[key] {
			it := factItem{
				Summary:    summary,
				Detail:     strings.Join(comps, "；"),
				Evidence:   fmt.Sprintf("cve_scan %s：%s", res.Target, evidence),
				Confidence: "observed",
				Extra: map[string]any{
					"cve_key":        key,
					"cve_target":     res.Target,
					"cve_components": payloadComps,
				},
			}
			if id, err := t.recordOneFact(it, intentID); err == nil && id > 0 {
				ids = append(ids, id)
			}
		}
	}
	return ids
}

// existingCVEFactKeys collects the cve_key values already present in this
// exploration's facts so repeated scans stay idempotent.
func (t *ToolSet) existingCVEFactKeys() map[string]bool {
	out := map[string]bool{}
	nodes, err := t.ts.ListByKind(db.KindFact, 2000)
	if err != nil {
		return out
	}
	for _, n := range nodes {
		var p map[string]any
		if json.Unmarshal(n.Payload, &p) != nil {
			continue
		}
		if k, ok := p["cve_key"].(string); ok && k != "" {
			out[k] = true
		}
	}
	return out
}

// cveFactKey builds the idempotency key: target + component + version + the
// sorted CVE set. Only the CVEs decide identity, not their order.
func cveFactKey(target, component, version string, cves []string) string {
	sorted := append([]string(nil), cves...)
	sort.Strings(sorted)
	return target + "|" + component + "|" + version + "|" + strings.Join(sorted, ",")
}

// cveFindingOut adds ARTEX's finding severity scale next to the rule severity.
type cveFindingOut struct {
	cve.Finding
	Level string `json:"artex_severity"`
}

// cveLookup queries the local rule pack — no network. It lets an agent ask
// "which CVEs affect this product/version" or "does the pack know product X"
// before spending probe budget.
func (t *ToolSet) cveLookup() actool.CoreTool {
	return readTool(
		"cve_lookup",
		"【内置 CVE 规则库检索】离线查询本地 CVE 规则(不联网)。可按组件 id 列出相关 CVE；"+
			"给出 version 时只返回该版本受影响的条目；也可用 query 按 CVE 编号/标题/产品/描述关键字搜索。"+
			"用于规划阶段判断规则库是否覆盖某产品、某版本有哪些已知漏洞，再用 cve_scan 实测目标。",
		obj(map[string]any{
			"component": str("可选：组件 id(如 dify、ollama、langflow)；留空则在全部规则中搜索"),
			"version":   str("可选：目标版本(如 0.6.9)，按 affected 区间过滤"),
			"query":     str("可选：按 CVE 编号/标题/组件/描述做不区分大小写的子串搜索"),
			"limit":     map[string]any{"type": "integer", "description": "返回条数上限，默认 30"},
		}),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Component string `json:"component"`
				Version   string `json:"version"`
				Query     string `json:"query"`
				Limit     int    `json:"limit"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if a.Limit <= 0 {
				a.Limit = 30
			}
			eng, err := cve.Shared()
			if err != nil {
				return actool.Errorf("CVE 规则库加载失败: " + err.Error()), nil
			}
			rules, err := eng.Lookup(cve.LookupOptions{
				Component: strings.TrimSpace(a.Component),
				Version:   strings.TrimSpace(a.Version),
				Query:     a.Query,
				Limit:     a.Limit,
			})
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			type brief struct {
				CVE         string `json:"cve"`
				Title       string `json:"title"`
				Severity    string `json:"severity"`
				Component   string `json:"component"`
				Affected    string `json:"affected"`
				Remediation string `json:"remediation,omitempty"`
			}
			out := make([]brief, 0, len(rules))
			for _, v := range rules {
				out = append(out, brief{
					CVE: v.ID, Title: v.Title, Severity: v.Severity,
					Component: v.Component, Affected: v.Affected, Remediation: v.Remediation,
				})
			}
			stats := eng.Rules().Stats()
			return jsonResult(map[string]any{
				"count":     len(out),
				"results":   out,
				"rule_pack": map[string]any{"fingerprints": stats.Fingerprints, "cve_rules": stats.VulnFiles},
			})
		},
	)
}
