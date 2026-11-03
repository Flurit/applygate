package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// A managed install (`sudo applygate install --managed`) puts applygate where
// the agent's user cannot change it: a root-owned binary, a root-owned
// system config read above the user config, a system trust store for
// repository configs, and the hooks in each host's managed settings. The
// paths are variables so tests can point them at a temporary directory.

var (
	// SystemDir holds the system config and trust store. Empty turns
	// managed mode off.
	SystemDir = defaultSystemDir()
	// ManagedBinDir holds the root-owned binary the managed hooks run.
	ManagedBinDir = defaultManagedBinDir()
	// ClaudeManagedDir is Claude Code's managed settings directory (from
	// the Claude Code docs, read 2026-11-03).
	ClaudeManagedDir = defaultClaudeManagedDir()
	// CodexManagedDir holds Codex's requirements.toml (from the Codex docs,
	// read 2026-11-03).
	CodexManagedDir = defaultCodexManagedDir()
	// RequireRootOwned makes a system config count only when root owns it
	// and nobody else can write it. Tests turn it off.
	RequireRootOwned = true
)

func defaultSystemDir() string {
	if runtime.GOOS == "windows" {
		return "" // not supported yet: ownership is not checked there
	}
	return "/etc/applygate"
}

func defaultManagedBinDir() string {
	if runtime.GOOS == "windows" {
		return ""
	}
	return "/usr/local/libexec/applygate"
}

func defaultClaudeManagedDir() string {
	switch runtime.GOOS {
	case "darwin":
		return "/Library/Application Support/ClaudeCode"
	case "windows":
		return ""
	}
	return "/etc/claude-code"
}

func defaultCodexManagedDir() string {
	if runtime.GOOS == "windows" {
		return ""
	}
	return "/etc/codex"
}

// SystemPath is the managed install's system config, or "" without one.
func SystemPath() string {
	if SystemDir == "" {
		return ""
	}
	return filepath.Join(SystemDir, "config.yaml")
}

// SystemTrustPath is the managed install's store of trusted repository
// configs.
func SystemTrustPath() string {
	if SystemDir == "" {
		return ""
	}
	return filepath.Join(SystemDir, "trusted.json")
}

// ManagedBinary is the path of the managed install's binary.
func ManagedBinary() string {
	if ManagedBinDir == "" {
		return ""
	}
	return filepath.Join(ManagedBinDir, "applygate")
}

// Managed reports whether a system config is present. Under managed mode
// only the system trust store counts.
func Managed() bool {
	p := SystemPath()
	if p == "" {
		return false
	}
	_, err := os.Lstat(p)
	return err == nil
}

// CheckSystemFile reports why a system file cannot be relied on: it must be
// a regular file that root owns and only root can write, in a directory that
// is the same.
func CheckSystemFile(p string) error {
	fi, err := os.Lstat(p)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", p)
	}
	if !RequireRootOwned {
		return nil
	}
	if err := rootOnly(p, fi); err != nil {
		return err
	}
	di, err := os.Lstat(filepath.Dir(p))
	if err != nil {
		return err
	}
	return rootOnly(filepath.Dir(p), di)
}

func rootOnly(p string, fi os.FileInfo) error {
	uid, ok := ownerUID(fi)
	if !ok {
		return errors.New("cannot read the owner of " + p)
	}
	if uid != 0 {
		return fmt.Errorf("%s is owned by uid %d, not root", p, uid)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s can be written by users other than root (mode %v)", p, fi.Mode().Perm())
	}
	return nil
}

// managedGuards are the managed install's files, guarded like the rest.
func managedGuards() []string {
	var out []string
	for _, d := range []string{SystemDir, ManagedBinDir} {
		if d != "" {
			out = append(out, d, filepath.Join(d, "**"))
		}
	}
	if CodexManagedDir != "" {
		out = append(out, filepath.Join(CodexManagedDir, "requirements.toml"))
	}
	return out
}
