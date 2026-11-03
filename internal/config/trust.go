package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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
// path, or under a managed install in the root-owned system directory, the
// only store that counts there.
func TrustPath() string {
	if Managed() {
		return SystemTrustPath()
	}
	return filepath.Join(UserDir(), "trusted.json")
}

// TrustCommand is what a person runs to trust a config.
func TrustCommand() string {
	if Managed() {
		// The managed binary by its path: the applygate first on the
		// agent's PATH may be one it planted (R6-4).
		// sudo by its path too: a sudo planted earlier on PATH would be
		// handed the person's password.
		if b := ManagedBinary(); b != "" {
			return "/usr/bin/sudo " + b + " trust"
		}
		return "/usr/bin/sudo /usr/local/libexec/applygate/applygate trust"
	}
	return "applygate trust"
}

func loadTrust() map[string]string {
	m := map[string]string{}
	p := TrustPath()
	if Managed() && CheckSystemFile(p) != nil {
		return m // a system store root does not own approves nothing
	}
	if b, err := safefile.ReadFile(p); err == nil {
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
	content := map[string][]byte{}
	for _, p := range paths {
		b, err := safefile.ReadFile(p)
		if err != nil {
			return err
		}
		content[p] = b
	}
	return TrustContent(content)
}

// TrustContent records the given content of each repository config as
// approved, whatever is on disk now.
func TrustContent(content map[string][]byte) error {
	m := loadTrust()
	for p, b := range content {
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
	path := TrustPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".trusted-*")
	if err != nil {
		if Managed() && errors.Is(err, os.ErrPermission) {
			return fmt.Errorf("%s is root's under a managed install: run %s", path, TrustCommand())
		}
		return err
	}
	// The hook runs as the user and reads the system store.
	mode := os.FileMode(0o600)
	if Managed() {
		mode = 0o644
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
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
	return os.Rename(tmp.Name(), path)
}
