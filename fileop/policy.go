//go:build amd64 && linux

package fileop

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/tensorchord/watchu/export"
)

//go:embed default-policy.json
var defaultPolicyBytes []byte

type MatchPolicy struct {
	Prefixes     []string `json:"prefixes"`
	HomePrefixes []string `json:"home_prefixes"`
	Suffixes     []string `json:"suffixes"`
}

type Policy struct {
	Read  MatchPolicy `json:"read"`
	Write MatchPolicy `json:"write"`
}

func LoadPolicy(path string) (*Policy, error) {
	if path == "" {
		return loadPolicyBytes(defaultPolicyBytes, "default-policy.json")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read fileop policy %s: %w", path, err)
	}

	policy, err := loadPolicyBytes(data, path)
	if err != nil {
		return nil, fmt.Errorf("parse fileop policy %s: %w", path, err)
	}
	return policy, nil
}

func loadPolicyBytes(data []byte, source string) (*Policy, error) {
	var policy Policy

	if source != "" {
		ext := strings.ToLower(filepath.Ext(source))
		if ext != ".json" {
			return nil, fmt.Errorf("unsupported fileop policy format %q", ext)
		}
	}
	if err := json.Unmarshal(data, &policy); err != nil {
		return nil, err
	}
	policy.normalize()
	return &policy, nil
}

func (p Policy) Matches(raw *export.RawFileOp) bool {
	switch raw.Op {
	case "open":
		return p.matchesOpen(raw)
	case "mmap_read":
		return p.matchesReadPath(raw.Path)
	case "write", "mmap_write":
		return p.matchesWritePath(raw.Path)
	case "delete":
		return p.matchesWritePath(raw.Path)
	case "rename":
		// raw.NewPath may be relative because the BPF probe only fully resolves
		// the source path. Keep matching it as best-effort auxiliary context.
		return p.matchesWritePath(raw.Path) || p.matchesWritePath(raw.NewPath)
	case "hardlink", "symlink":
		return p.matchesSensitivePath(raw.Path) || p.matchesWritePath(raw.NewPath)
	default:
		return false
	}
}

func (p Policy) matchesOpen(raw *export.RawFileOp) bool {
	switch raw.Access {
	case "read":
		return p.matchesReadPath(raw.Path)
	case "write":
		return p.matchesWritePath(raw.Path)
	case "read_write":
		return p.matchesReadPath(raw.Path) || p.matchesWritePath(raw.Path)
	default:
		return false
	}
}

func (p Policy) matchesReadPath(path string) bool {
	return matchPath(path, p.Read.Prefixes, p.Read.HomePrefixes, p.Read.Suffixes)
}

func (p Policy) matchesWritePath(path string) bool {
	return matchPath(path, p.Write.Prefixes, p.Write.HomePrefixes, p.Write.Suffixes)
}

func (p Policy) matchesSensitivePath(path string) bool {
	return p.matchesReadPath(path) || p.matchesWritePath(path)
}

func matchPath(path string, prefixes []string, homePrefixes []string, suffixes []string) bool {
	if matchesAnyPrefix(path, prefixes) || matchesAnySuffix(path, suffixes) {
		return true
	}

	homePath, ok := homeScopedPath(path)
	if !ok {
		return false
	}

	return matchesAnyPrefix(homePath, homePrefixes)
}

func homeScopedPath(path string) (string, bool) {
	if path == "/root" {
		return "", false
	}
	if rest, ok := strings.CutPrefix(path, "/root/"); ok {
		return normalizeHomeScopedPath(rest)
	}

	rest, ok := strings.CutPrefix(path, "/home/")
	if !ok {
		return "", false
	}
	_, suffix, ok := strings.Cut(rest, "/")
	if !ok {
		return "", false
	}
	return normalizeHomeScopedPath(suffix)
}

func normalizeHomeScopedPath(path string) (string, bool) {
	path = strings.TrimPrefix(path, "/")
	if path == "" {
		return "", false
	}
	return path, true
}

func (p *Policy) normalize() {
	p.Read.HomePrefixes = normalizeHomePrefixes(p.Read.HomePrefixes)
	p.Write.HomePrefixes = normalizeHomePrefixes(p.Write.HomePrefixes)
}

func normalizeHomePrefixes(prefixes []string) []string {
	for i, prefix := range prefixes {
		prefixes[i] = strings.TrimPrefix(prefix, "/")
	}
	return prefixes
}

func matchesAnyPrefix(path string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

func matchesAnySuffix(path string, suffixes []string) bool {
	for _, suffix := range suffixes {
		if strings.HasSuffix(path, suffix) {
			return true
		}
	}
	return false
}
