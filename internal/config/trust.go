package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"

	"github.com/Flurit/applygate/internal/guard"
	"github.com/Flurit/applygate/internal/safefile"
)

// A repository config decides which directories are production, so any
// route that rewrites it (a git checkout, plumbing, an extraction, a clone,
// a program applygate does not know) can loosen protection. Recognizing
// each route does not converge, so a repository config takes effect only
// when its exact content was approved by a person with `applygate trust`,
// like direnv's allow. An untrusted config is not read, and every directory
// it would cover is judged as protected.

// TrustAll skips the check. Only tests and selftest set it.
var TrustAll bool

// TrustPath is the store of approved repository configs: canonical path to
// SHA-256 of the content. It lives in the user config directory, a guard
// path.
func TrustPath() string { return filepath.Join(UserDir(), "trusted.json") }

func loadTrust() map[string]string {
	m := map[string]string{}
	if b, err := safefile.ReadFile(TrustPath()); err == nil {
		_ = json.Unmarshal(b, &m)
	}
	return m
}

func sum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// Trusted reports whether the repository config at path, with content b,
// was approved.
func Trusted(path string, b []byte) bool {
	if TrustAll {
		return true
	}
	return loadTrust()[guard.Canonical(path)] == sum(b)
}

// Trust records the current content of each repository config as approved.
func Trust(paths []string) error {
	m := loadTrust()
	for _, p := range paths {
		b, err := safefile.ReadFile(p)
		if err != nil {
			return err
		}
		m[guard.Canonical(p)] = sum(b)
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	ordered := make(map[string]string, len(m))
	for _, k := range keys {
		ordered[k] = m[k]
	}
	out, err := json.MarshalIndent(ordered, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(TrustPath()), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(TrustPath()), ".trusted-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(out, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), TrustPath())
}
