package cve

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func difyHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/", "/apps":
			w.Header().Set("Content-Type", "text/html")
			body := `<html><head><title>Dify</title></head><body data-public-edition></body></html>`
			_, _ = w.Write([]byte(body))
		case "/health", "/console/api/version":
			w.Header().Set("X-Version", "0.6.9")
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		default:
			http.NotFound(w, r)
		}
	})
}

func ollamaHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			_, _ = w.Write([]byte("Ollama is running"))
		case "/api/tags":
			_, _ = w.Write([]byte(`{"models":[]}`))
		case "/api/version":
			_, _ = w.Write([]byte(`{"version":"0.1.32"}`))
		default:
			http.NotFound(w, r)
		}
	})
}

func newTestEngine(t *testing.T) *Engine {
	t.Helper()
	eng, err := New(Options{Timeout: 3 * time.Second, Workers: 8})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return eng
}

func findDetected(ds []Detected, id string) *Detected {
	for i := range ds {
		if ds[i].ID == id {
			return &ds[i]
		}
	}
	return nil
}

func TestScanDify(t *testing.T) {
	srv := httptest.NewServer(difyHandler())
	defer srv.Close()

	eng := newTestEngine(t)
	res := eng.Scan(context.Background(), srv.URL, ScanOptions{})

	det := findDetected(res.Detected, "dify")
	if det == nil {
		t.Fatalf("dify not detected; components=%v", res.Detected)
	}
	if det.Version != "0.6.9" {
		t.Errorf("dify version = %q, want 0.6.9", det.Version)
	}
	if len(res.Findings) == 0 {
		t.Fatal("expected CVEs for dify 0.6.9")
	}
	for _, f := range res.Findings {
		if f.Component != "dify" {
			t.Errorf("unexpected component %q", f.Component)
		}
		if f.Evidence == "" || f.Title == "" {
			t.Errorf("finding %s missing evidence/title", f.CVE)
		}
	}
	for i := 1; i < len(res.Findings); i++ {
		if SeverityRank(res.Findings[i-1].Severity) > SeverityRank(res.Findings[i].Severity) {
			t.Errorf("findings not sorted by severity: %s before %s",
				res.Findings[i-1].Severity, res.Findings[i].Severity)
		}
	}
	t.Logf("dify %s -> %d findings, %d probes", det.Version, len(res.Findings), res.Probes)
}

func TestScanOllamaAndScopeFilters(t *testing.T) {
	srv := httptest.NewServer(ollamaHandler())
	defer srv.Close()

	eng := newTestEngine(t)
	all := eng.Scan(context.Background(), srv.URL, ScanOptions{})
	det := findDetected(all.Detected, "ollama")
	if det == nil || det.Version != "0.1.32" {
		t.Fatalf("ollama detection = %+v", det)
	}
	if len(all.Findings) == 0 {
		t.Fatal("expected CVEs for ollama 0.1.32")
	}

	scoped := eng.Scan(context.Background(), srv.URL, ScanOptions{Components: []string{"dify"}})
	if len(scoped.Findings) != 0 {
		t.Errorf("component filter leaked %d findings", len(scoped.Findings))
	}

	one := all.Findings[0].CVE
	only := eng.Scan(context.Background(), srv.URL, ScanOptions{Only: []string{strings.ToLower(one)}})
	if len(only.Findings) != 1 || only.Findings[0].CVE != one {
		t.Errorf("only filter returned %v", only.Findings)
	}

	high := eng.Scan(context.Background(), srv.URL, ScanOptions{MinSeverity: "high"})
	for _, f := range high.Findings {
		if SeverityRank(f.Severity) > 1 {
			t.Errorf("min severity filter leaked %s (%s)", f.Severity, f.CVE)
		}
	}
}

func TestFingerprintFromUsesSeedResponse(t *testing.T) {
	eng := newTestEngine(t)
	srv := httptest.NewServer(difyHandler())
	defer srv.Close()

	resp := &Response{
		Status: 200,
		Header: http.Header{"Content-Type": []string{"text/html"}},
		Body:   []byte(`<html><head><title>Dify</title></head><body data-public-edition></body></html>`),
	}
	ds := eng.FingerprintFrom(context.Background(), srv.URL, resp)
	det := findDetected(ds, "dify")
	if det == nil {
		t.Fatalf("light fingerprint missed dify: %v", ds)
	}
	if det.Version != "0.6.9" {
		t.Errorf("version = %q, want 0.6.9", det.Version)
	}
	if n := len(eng.CVEFor("dify", det.Version)); n == 0 {
		t.Error("expected version-matching CVEs for dify 0.6.9")
	}
}

func TestLookup(t *testing.T) {
	eng := newTestEngine(t)
	vs, err := eng.Lookup(LookupOptions{Component: "ollama", Version: "0.1.32"})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if len(vs) == 0 {
		t.Fatal("expected ollama CVEs for 0.1.32")
	}
	for _, v := range vs {
		if !VersionInRange("0.1.32", v.Affected) {
			t.Errorf("%s affected %q does not include 0.1.32", v.ID, v.Affected)
		}
	}
	found, err := eng.Lookup(LookupOptions{Query: "ollama", Limit: 10})
	if err != nil || len(found) == 0 {
		t.Fatalf("query lookup: %v, %d", err, len(found))
	}
}
