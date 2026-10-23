package enrich

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Autumn-27/artex/cve"
	"github.com/Autumn-27/artex/db"
)

// TestFingerprintTechWritesCVEComponents verifies the enrichment bridge turns
// one already-fetched page into asset technologies + structured CVE components.
func TestFingerprintTechWritesCVEComponents(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/", "/apps":
			_, _ = w.Write([]byte(`<html><head><title>Dify</title></head><body data-public-edition></body></html>`))
		case "/console/api/version":
			w.Header().Set("X-Version", "0.6.9")
			_, _ = w.Write([]byte(`{"version":"0.6.9"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body := make([]byte, 4096)
	n, _ := resp.Body.Read(body)

	techs, extra, _ := fingerprintTech(srv.URL, resp.StatusCode, resp.Header, body[:n])
	if len(techs) == 0 {
		t.Fatalf("no technologies detected")
	}
	if extra == nil {
		t.Fatal("no extra payload")
	}
	comps, ok := extra["cve_components"].([]map[string]any)
	if !ok || len(comps) == 0 {
		t.Fatalf("cve_components = %v", extra["cve_components"])
	}
	var dify map[string]any
	for _, c := range comps {
		if c["id"] == "dify" {
			dify = c
		}
	}
	if dify == nil {
		t.Fatalf("dify not in components: %v", comps)
	}
	if dify["version"] != "0.6.9" {
		t.Fatalf("version = %v", dify["version"])
	}
	if dify["evidence"] == "" {
		t.Fatalf("missing evidence: %v", dify)
	}
	if cnt, _ := dify["cve_count"].(int); cnt == 0 {
		t.Fatalf("expected CVEs for dify 0.6.9: %v", dify)
	}
	if total, _ := extra["cve_count"].(int); total == 0 {
		t.Fatalf("cve_count = %v", extra["cve_count"])
	}
}

// TestDetectLLMEndpoint verifies the fingerprint → provider/apiType mapping for
// known LLM-serving components, and that non-LLM detections return ok=false.
func TestDetectLLMEndpoint(t *testing.T) {
	cases := []struct {
		name      string
		detected  []cve.Detected
		provider  string
		apiType   string
		ok        bool
	}{
		{
			name:     "ollama",
			detected: []cve.Detected{{ID: "ollama", Name: "Ollama"}},
			provider: "ollama", apiType: "ollama", ok: true,
		},
		{
			name:     "vllm openai compatible",
			detected: []cve.Detected{{ID: "vllm", Name: "vLLM"}},
			provider: "vllm", apiType: "openai_compatible", ok: true,
		},
		{
			name:     "first llm component wins",
			detected: []cve.Detected{{ID: "nginx"}, {ID: "ollama", Name: "Ollama"}},
			provider: "ollama", apiType: "ollama", ok: true,
		},
		{
			name:     "non-llm component",
			detected: []cve.Detected{{ID: "nginx", Name: "nginx"}},
			ok: false,
		},
		{
			name:     "empty",
			detected: nil,
			ok:       false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, a, ok := detectLLMEndpoint(c.detected)
			if ok != c.ok {
				t.Fatalf("ok: want %v, got %v", c.ok, ok)
			}
			if !ok {
				return
			}
			if p != c.provider {
				t.Errorf("provider: want %q, got %q", c.provider, p)
			}
			if a != c.apiType {
				t.Errorf("apiType: want %q, got %q", c.apiType, a)
			}
		})
	}
}

// TestDoHTTPDetectsLLMEndpoint is an end-to-end test of the enrichment →
// llm_endpoint bridge: a mock Ollama server is probed, and the engine must
// automatically create an llm_endpoint asset whose extra.kind lets the Skill
// Matcher offer the llm-redteam skill.
func TestDoHTTPDetectsLLMEndpoint(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skipf("no database config (%v) — skipping", err)
	}
	d, err := db.Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer d.Close()

	task, err := d.CreateTask("enrich-llm-probe", "probe a mock ollama", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM tasks WHERE id = $1`, task.ID)
	defer d.Exec(`DELETE FROM assets WHERE task_ids @> ARRAY[$1]::bigint[]`, task.ID)

	as := d.Assets()

	// Source asset (root_domain) carrying the task id so doHTTP can look up
	// TaskIDs via GetByIDs and attach them to the generated llm_endpoint.
	srcID, err := as.UpsertRootDomain(db.UpsertRootDomainReq{
		Domain: "ollama-enrich-test.local",
		TaskID: task.ID,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Mock Ollama: the fingerprint matches path "/" with body "Ollama is running".
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.WriteHeader(200)
			_, _ = w.Write([]byte("Ollama is running"))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	eng := New(as, func() string { return "" }, 1)
	defer eng.Close()

	eng.ProbeSite(srcID, srv.URL)

	// The worker runs asynchronously; poll for the llm_endpoint asset.
	deadline := time.Now().Add(15 * time.Second)
	var (
		assetType string
		kind      string
	)
	for time.Now().Before(deadline) {
		err = d.QueryRow(`SELECT type, extra->>'kind' FROM assets WHERE type = 'llm_endpoint' AND url = $1`, srv.URL).
			Scan(&assetType, &kind)
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("llm_endpoint asset not created for mock ollama: %v", err)
	}
	if assetType != "llm_endpoint" {
		t.Errorf("type: want llm_endpoint, got %s", assetType)
	}
	if kind != "llm_endpoint_entity" {
		t.Errorf("extra.kind: want llm_endpoint_entity, got %q", kind)
	}
}
