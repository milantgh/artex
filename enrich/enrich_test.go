package enrich

import (
	"net/http"
	"net/http/httptest"
	"testing"
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

	techs, extra := fingerprintTech(srv.URL, resp.StatusCode, resp.Header, body[:n])
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
