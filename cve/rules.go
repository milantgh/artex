package cve

import (
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// RuleSet is an immutable index over the embedded rule pack plus a lazy cache
// for per-component CVE files (only the components actually detected are
// decoded, so a scan never pays for all ~2.5k CVE files).
type RuleSet struct {
	root string
	fsys fs.FS

	fingerprints []*Fingerprint
	fpByID       map[string]*Fingerprint

	vulnFiles map[string][]string // component -> rule file paths
	unindexed []string            // files without a "__<component>" suffix

	mu        sync.Mutex
	vulnCache map[string][]*Vuln

	allOnce sync.Once
	all     []*Vuln
	allErr  error
}

// RuleStats is a small summary of the loaded pack.
type RuleStats struct {
	Fingerprints int
	VulnFiles    int
}

// LoadFS builds a RuleSet from fsys. root is where fingerprints/ and vuln/
// live ("" = fs root).
func LoadFS(fsys fs.FS, root string) (*RuleSet, error) {
	rs := &RuleSet{
		root:      root,
		fsys:      fsys,
		fpByID:    map[string]*Fingerprint{},
		vulnFiles: map[string][]string{},
		vulnCache: map[string][]*Vuln{},
	}
	files, err := fs.Glob(fsys, path.Join(root, "fingerprints", "*.y*ml"))
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	for _, p := range files {
		if strings.HasPrefix(path.Base(p), "_") {
			continue
		}
		fp, err := decodeFingerprint(fsys, p)
		if err != nil || fp == nil {
			continue
		}
		if _, dup := rs.fpByID[fp.ID]; dup {
			continue
		}
		rs.fpByID[fp.ID] = fp
		rs.fingerprints = append(rs.fingerprints, fp)
	}
	if len(rs.fingerprints) == 0 {
		return nil, fmt.Errorf("cve: no fingerprint rules under %q", path.Join(root, "fingerprints"))
	}

	vfiles, err := fs.Glob(fsys, path.Join(root, "vuln", "*.y*ml"))
	if err != nil {
		return nil, err
	}
	sort.Strings(vfiles)
	for _, p := range vfiles {
		if strings.HasPrefix(path.Base(p), "_") {
			continue
		}
		comp := componentFromFilename(p)
		if comp == "" {
			rs.unindexed = append(rs.unindexed, p)
			continue
		}
		rs.vulnFiles[comp] = append(rs.vulnFiles[comp], p)
	}
	return rs, nil
}

// componentFromFilename extracts "<component>" from
// "CVE-2024-1234__<component>.yaml". Empty when the convention is absent.
func componentFromFilename(p string) string {
	base := path.Base(p)
	base = strings.TrimSuffix(base, ".yaml")
	base = strings.TrimSuffix(base, ".yml")
	i := strings.LastIndex(base, "__")
	if i < 0 || i == len(base)-2 {
		return ""
	}
	return base[i+2:]
}

func decodeFingerprint(fsys fs.FS, p string) (*Fingerprint, error) {
	raw, err := fs.ReadFile(fsys, p)
	if err != nil {
		return nil, err
	}
	var fp Fingerprint
	if err := yaml.Unmarshal(raw, &fp); err != nil {
		return nil, err
	}
	if strings.TrimSpace(fp.ID) == "" {
		return nil, nil
	}
	fp.Source = p
	return &fp, nil
}

func decodeVuln(fsys fs.FS, p string) (*Vuln, error) {
	raw, err := fs.ReadFile(fsys, p)
	if err != nil {
		return nil, err
	}
	var v Vuln
	if err := yaml.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	if strings.TrimSpace(v.ID) == "" || strings.TrimSpace(v.Component) == "" {
		return nil, nil
	}
	v.Source = p
	return &v, nil
}

// Fingerprints returns the loaded component fingerprints in file order.
func (rs *RuleSet) Fingerprints() []*Fingerprint { return rs.fingerprints }

// Fingerprint looks a component up by id.
func (rs *RuleSet) Fingerprint(id string) *Fingerprint { return rs.fpByID[id] }

// HasComponent reports whether a fingerprint with this id exists.
func (rs *RuleSet) HasComponent(id string) bool { return rs.fpByID[id] != nil }

// Stats reports the pack size. VulnFiles is the number of on-disk CVE rules.
func (rs *RuleSet) Stats() RuleStats {
	n := len(rs.unindexed)
	for _, v := range rs.vulnFiles {
		n += len(v)
	}
	return RuleStats{Fingerprints: len(rs.fingerprints), VulnFiles: n}
}

// VulnsFor returns the CVE rules of one component, decoded lazily and cached.
// The result is sorted most-severe first, then by id.
func (rs *RuleSet) VulnsFor(component string) []*Vuln {
	component = strings.TrimSpace(component)
	if component == "" {
		return nil
	}
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if v, ok := rs.vulnCache[component]; ok {
		return v
	}
	paths := append([]string{}, rs.vulnFiles[component]...)
	paths = append(paths, rs.unindexed...)

	seen := map[string]bool{}
	var out []*Vuln
	for _, p := range paths {
		v, err := decodeVuln(rs.fsys, p)
		if err != nil || v == nil || v.Component != component {
			continue
		}
		key := v.ID + "\x00" + v.Component
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, v)
	}
	sortVulns(out)
	rs.vulnCache[component] = out
	return out
}

func sortVulns(vs []*Vuln) {
	sort.SliceStable(vs, func(i, j int) bool {
		ri, rj := SeverityRank(vs[i].Severity), SeverityRank(vs[j].Severity)
		if ri != rj {
			return ri < rj
		}
		return vs[i].ID < vs[j].ID
	})
}

// AllVulns decodes every CVE rule (used by cve_lookup). Cached after the first
// call; an API for humans/search, not on the hot scan path.
func (rs *RuleSet) AllVulns() ([]*Vuln, error) {
	rs.allOnce.Do(func() {
		comps := make([]string, 0, len(rs.vulnFiles))
		for c := range rs.vulnFiles {
			comps = append(comps, c)
		}
		sort.Strings(comps)
		seen := map[string]bool{}
		for _, c := range comps {
			for _, v := range rs.VulnsFor(c) {
				key := v.ID + "\x00" + v.Component
				if seen[key] {
					continue
				}
				seen[key] = true
				rs.all = append(rs.all, v)
			}
		}
		for _, p := range rs.unindexed {
			v, err := decodeVuln(rs.fsys, p)
			if err != nil {
				rs.allErr = err
				continue
			}
			if v == nil {
				continue
			}
			key := v.ID + "\x00" + v.Component
			if seen[key] {
				continue
			}
			seen[key] = true
			rs.all = append(rs.all, v)
		}
		sortVulns(rs.all)
	})
	return rs.all, rs.allErr
}
