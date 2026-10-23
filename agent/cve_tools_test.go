package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/cve"
)

func difyTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/", "/apps":
			_, _ = w.Write([]byte(`<html><head><title>Dify</title></head><body data-public-edition></body></html>`))
		case "/health", "/console/api/version":
			w.Header().Set("X-Version", "0.6.9")
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestCVEScanTool(t *testing.T) {
	srv := difyTestServer(t)
	ts := NewToolSet(nil, "test-worker")

	in, _ := json.Marshal(map[string]any{"url": srv.URL, "max_findings": 5})
	res, err := ts.cveScan().Call(context.Background(), in, nil)
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if res.IsError {
		t.Fatalf("cve_scan error: %s", res.Flatten())
	}

	var out struct {
		Components []struct {
			ID      string `json:"id"`
			Version string `json:"version"`
		} `json:"components"`
		Findings []struct {
			CVE   string `json:"cve"`
			Level string `json:"artex_severity"`
		} `json:"findings"`
		FindingCount int  `json:"finding_count"`
		Truncated    bool `json:"truncated"`
	}
	if err := json.Unmarshal([]byte(res.Flatten()), &out); err != nil {
		t.Fatalf("decode: %v (%s)", err, res.Flatten())
	}
	var version string
	for _, c := range out.Components {
		if c.ID == "dify" {
			version = c.Version
		}
	}
	if version != "0.6.9" {
		t.Fatalf("dify version = %q, components=%v", version, out.Components)
	}
	if out.FindingCount == 0 || len(out.Findings) == 0 {
		t.Fatalf("expected findings, got %+v", out)
	}
	if len(out.Findings) > 5 || !out.Truncated {
		t.Fatalf("max_findings not applied: %d findings, truncated=%v", len(out.Findings), out.Truncated)
	}
	for _, f := range out.Findings {
		if f.CVE == "" || f.Level == "" {
			t.Fatalf("finding missing cve/severity: %+v", f)
		}
	}
}

func TestCVEScanFingerprintMode(t *testing.T) {
	srv := difyTestServer(t)
	ts := NewToolSet(nil, "test-worker")
	in, _ := json.Marshal(map[string]any{"url": srv.URL, "mode": "fingerprint"})
	res, err := ts.cveScan().Call(context.Background(), in, nil)
	if err != nil || res.IsError {
		t.Fatalf("Call: %v %s", err, res.Flatten())
	}
	if !strings.Contains(res.Flatten(), `"id":"dify"`) {
		t.Fatalf("dify not detected: %s", res.Flatten())
	}
}

func TestCVEScanRejectsBadURL(t *testing.T) {
	ts := NewToolSet(nil, "test-worker")
	in, _ := json.Marshal(map[string]any{"url": "example.com"})
	res, err := ts.cveScan().Call(context.Background(), in, nil)
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if !res.IsError {
		t.Fatal("expected an error result for a URL without a scheme")
	}
}

func TestCVELookupTool(t *testing.T) {
	ts := NewToolSet(nil, "test-worker")
	in, _ := json.Marshal(map[string]any{"component": "ollama", "version": "0.1.32", "limit": 5})
	res, err := ts.cveLookup().Call(context.Background(), in, nil)
	if err != nil || res.IsError {
		t.Fatalf("Call: %v %s", err, res.Flatten())
	}
	var out struct {
		Count   int `json:"count"`
		Results []struct {
			CVE       string `json:"cve"`
			Component string `json:"component"`
			Affected  string `json:"affected"`
		} `json:"results"`
	}
	if err := json.Unmarshal([]byte(res.Flatten()), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Count == 0 || len(out.Results) == 0 {
		t.Fatalf("expected ollama CVEs: %s", res.Flatten())
	}
	for _, r := range out.Results {
		if r.Component != "ollama" || r.CVE == "" || r.Affected == "" {
			t.Fatalf("unexpected lookup row: %+v", r)
		}
	}
}

func TestCVEFactKeyIgnoresOrder(t *testing.T) {
	a := cveFactKey("http://x", "dify", "0.6.9", []string{"CVE-2025-2", "CVE-2025-1"})
	b := cveFactKey("http://x", "dify", "0.6.9", []string{"CVE-2025-1", "CVE-2025-2"})
	if a != b {
		t.Fatalf("key depends on CVE order: %q != %q", a, b)
	}
	if c := cveFactKey("http://x", "dify", "0.7.0", []string{"CVE-2025-1", "CVE-2025-2"}); a == c {
		t.Fatalf("key ignores version: %q", a)
	}
	if c := cveFactKey("http://y", "dify", "0.6.9", []string{"CVE-2025-1", "CVE-2025-2"}); a == c {
		t.Fatalf("key ignores target: %q", a)
	}
}

// TestCVEScanRecordsFact runs the real tool against a mock Dify target inside a
// task and verifies the deterministic result lands in the exploration graph once.
func TestCVEScanRecordsFact(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	task, err := d.CreateTask("cve scan fact", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	ts := NewToolSet(nil, "fixture")
	ts.ts = d.Exploration(task.ExplorationID)
	ts.taskID = task.ID

	srv := difyTestServer(t)
	in, _ := json.Marshal(map[string]any{"url": srv.URL, "max_findings": 5})
	res, err := ts.cveScan().Call(context.Background(), in, nil)
	if err != nil || res.IsError {
		t.Fatalf("Call: %v %s", err, res.Flatten())
	}
	var out struct {
		Recorded []int64 `json:"recorded_fact_ids"`
	}
	if err := json.Unmarshal([]byte(res.Flatten()), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Recorded) != 1 {
		t.Fatalf("recorded_fact_ids = %v, want 1", out.Recorded)
	}
	node, err := ts.ts.GetNode(out.Recorded[0])
	if err != nil || node == nil {
		t.Fatalf("fact node: %v %v", node, err)
	}
	var payload map[string]any
	if err := json.Unmarshal(node.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if payload["cve_component"] != "dify" || payload["cve_version"] != "0.6.9" {
		t.Fatalf("payload = %v", payload)
	}

	// Same scan again → cve_key dedupes, no new fact.
	res2, err := ts.cveScan().Call(context.Background(), in, nil)
	if err != nil || res2.IsError {
		t.Fatalf("second call: %v %s", err, res2.Flatten())
	}
	var out2 struct {
		Recorded []int64 `json:"recorded_fact_ids"`
	}
	if err := json.Unmarshal([]byte(res2.Flatten()), &out2); err != nil {
		t.Fatal(err)
	}
	if len(out2.Recorded) != 0 {
		t.Fatalf("repeat scan recorded duplicates: %v", out2.Recorded)
	}

	// record=false must not write.
	res3, err := ts.cveScan().Call(context.Background(), json.RawMessage(`{"url":"`+srv.URL+`","record":false}`), nil)
	if err != nil || res3.IsError {
		t.Fatalf("third call: %v %s", err, res3.Flatten())
	}
	var out3 struct {
		Recorded []int64 `json:"recorded_fact_ids"`
	}
	if err := json.Unmarshal([]byte(res3.Flatten()), &out3); err != nil {
		t.Fatal(err)
	}
	if len(out3.Recorded) != 0 {
		t.Fatalf("record=false recorded %v", out3.Recorded)
	}
}

// TestRecordCVEFactsIdempotent verifies scan results land as exploration facts
// once, are chained to the intent, and a repeated scan adds no duplicate nodes.
func TestRecordCVEFactsIdempotent(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	task, err := d.CreateTask("cve fact", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	ts := NewToolSet(nil, "fixture")
	ts.ts = d.Exploration(task.ExplorationID)
	ts.taskID = task.ID

	res := cve.Result{
		Target: "http://fixture:3000",
		Detected: []cve.Detected{
			{ID: "dify", Name: "Dify", Version: "0.6.9", Evidence: "GET / -> HTTP 200"},
		},
		Findings: []cve.Finding{
			{CVE: "CVE-2025-0002", Severity: "HIGH", Title: "b", Component: "dify"},
			{CVE: "CVE-2025-0001", Severity: "CRITICAL", Title: "a", Component: "dify"},
		},
	}
	first := ts.recordCVEFacts(res, 0, true)
	if len(first) != 1 {
		t.Fatalf("first scan recorded %v, want 1 fact", first)
	}
	if second := ts.recordCVEFacts(res, 0, true); len(second) != 0 {
		t.Fatalf("repeat scan recorded duplicates: %v", second)
	}
	node, err := ts.ts.GetNode(first[0])
	if err != nil || node == nil || node.Kind != "fact" {
		t.Fatalf("fact node missing: %+v %v", node, err)
	}
	var payload map[string]any
	if err := json.Unmarshal(node.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if payload["cve_component"] != "dify" || payload["cve_version"] != "0.6.9" {
		t.Fatalf("payload = %v", payload)
	}
	if matches, ok := payload["cve_matches"].([]any); !ok || len(matches) != 2 {
		t.Fatalf("cve_matches = %v", payload["cve_matches"])
	}
}
