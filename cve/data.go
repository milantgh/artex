package cve

import (
	"embed"
	"os"
	"sync"
	"sync/atomic"
)

// Embedded rule pack. Adding a CVE is a YAML drop-in under data/vuln.
//
//go:embed data/fingerprints/*.yaml data/vuln/*.yaml
var embeddedRuleFS embed.FS

var (
	embeddedOnce sync.Once
	embeddedRS   *RuleSet
	embeddedErr  error
)

// LoadEmbedded decodes the built-in fingerprint pack. The CVE rules stay on
// disk (embedded FS) and are decoded per detected component on demand, so this
// is cheap (~160 small files, no network).
func LoadEmbedded() (*RuleSet, error) {
	embeddedOnce.Do(func() {
		embeddedRS, embeddedErr = LoadFS(embeddedRuleFS, "data")
	})
	return embeddedRS, embeddedErr
}

// LoadDir loads an external rule pack laid out as <dir>/fingerprints + <dir>/vuln.
func LoadDir(dir string) (*RuleSet, error) {
	return LoadFS(os.DirFS(dir), "")
}

var (
	sharedOnce   sync.Once
	sharedEngine *Engine
	sharedErr    error
	// sharedProxyFn is read per request so the ARTEX traffic-capture toggle
	// applies live (probes land in the traffic store when capture is on).
	sharedProxyFn atomic.Value // func() string
)

// SetSharedProxy wires the recording-proxy address provider used by Shared().
func SetSharedProxy(fn func() string) {
	if fn == nil {
		fn = func() string { return "" }
	}
	sharedProxyFn.Store(fn)
}

func currentSharedProxy() string {
	v := sharedProxyFn.Load()
	if v == nil {
		return ""
	}
	fn, ok := v.(func() string)
	if !ok {
		return ""
	}
	return fn()
}

// Shared returns the process-wide engine used by agent tools and the
// enrichment layer. The first call builds it, so startup is unaffected.
func Shared() (*Engine, error) {
	sharedOnce.Do(func() {
		sharedEngine, sharedErr = New(Options{Proxy: currentSharedProxy})
	})
	return sharedEngine, sharedErr
}
