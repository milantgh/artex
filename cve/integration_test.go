package cve

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
)

// TestIntegrationTargets runs the engine against live mock targets. It is
// opt-in: set ARTEX_CVE_TARGETS="dify=http://127.0.0.1:18090,ollama=http://..."
// (the mock_target.py server in the AISecurityTest repo serves these).
func TestIntegrationTargets(t *testing.T) {
	spec := strings.TrimSpace(os.Getenv("ARTEX_CVE_TARGETS"))
	if spec == "" {
		t.Skip("set ARTEX_CVE_TARGETS to run live-target integration checks")
	}
	eng := newTestEngine(t)
	for _, pair := range strings.Split(spec, ",") {
		parts := strings.SplitN(strings.TrimSpace(pair), "=", 2)
		if len(parts) != 2 {
			continue
		}
		component, target := parts[0], parts[1]
		res := eng.Scan(context.Background(), target, ScanOptions{})
		det := findDetected(res.Detected, component)
		if det == nil {
			t.Errorf("%s: component not detected (%v)", target, res.Detected)
			continue
		}
		t.Logf("%-9s %-28s version=%-10s components=%d cves=%d probes=%d elapsed=%dms",
			component, target, det.Version, len(res.Detected), len(res.Findings), res.Probes, res.ElapsedMS)
		if os.Getenv("ARTEX_CVE_IDS") == "1" {
			for _, f := range res.Findings {
				fmt.Printf("CVEID %s\n", f.CVE)
			}
		}
	}
}
