package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Flurit/applygate/internal/config"
)

func TestManagedInstall(t *testing.T) {
	d := t.TempDir()
	old := []string{config.SystemDir, config.ManagedBinDir, config.ClaudeManagedDir, config.CodexManagedDir}
	oldRoot, oldEuid := config.RequireRootOwned, euid
	t.Cleanup(func() {
		config.SystemDir, config.ManagedBinDir, config.ClaudeManagedDir, config.CodexManagedDir = old[0], old[1], old[2], old[3]
		config.RequireRootOwned, euid = oldRoot, oldEuid
	})
	config.SystemDir, config.ManagedBinDir = filepath.Join(d, "etc", "applygate"), filepath.Join(d, "libexec", "applygate")
	config.ClaudeManagedDir, config.CodexManagedDir = filepath.Join(d, "ClaudeCode"), filepath.Join(d, "codex")
	config.RequireRootOwned = false

	var out, errb bytes.Buffer
	euid = func() int { return 501 }
	if rc := run([]string{"install", "--managed"}, nil, &out, &errb); rc != 2 || !strings.Contains(errb.String(), "sudo") {
		t.Fatalf("install without root: rc %d %s", rc, errb.String())
	}
	if rc := run([]string{"install"}, nil, &out, &errb); rc != 2 {
		t.Fatalf("install without --managed: rc %d", rc)
	}
	euid = func() int { return 0 }
	out.Reset()
	if rc := run([]string{"install", "--managed", "--exclusive"}, nil, &out, &errb); rc != 0 {
		t.Fatalf("install: rc %d %s", rc, errb.String())
	}
	self, _ := os.ReadFile(selfPath())
	bin, err := os.ReadFile(config.ManagedBinary())
	if err != nil || sha256.Sum256(bin) != sha256.Sum256(self) {
		t.Fatalf("binary not copied: %v", err)
	}
	if fi, _ := os.Stat(config.ManagedBinary()); fi.Mode().Perm() != 0o755 {
		t.Fatalf("binary mode %v", fi.Mode().Perm())
	}
	if !config.Managed() {
		t.Fatal("no system config")
	}
	cfg, err := config.Load("", "")
	if err != nil || cfg.Mode != "enforce" || cfg.Approvals == nil || *cfg.Approvals {
		t.Fatalf("system config: %v %+v", err, cfg)
	}
	b, err := os.ReadFile(filepath.Join(config.ClaudeManagedDir, "managed-settings.d", "applygate.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Hooks struct {
			PreToolUse []struct {
				Matcher string
				Hooks   []struct{ Command, OnFailure string }
			}
		}
		Permissions           struct{ DisableBypassPermissionsMode string }
		AllowManagedHooksOnly bool
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	h := doc.Hooks.PreToolUse
	if len(h) != 1 || h[0].Matcher != "*" || len(h[0].Hooks) != 1 || !strings.Contains(h[0].Hooks[0].Command, config.ManagedBinary()) ||
		h[0].Hooks[0].OnFailure != "block" || doc.Permissions.DisableBypassPermissionsMode != "disable" || !doc.AllowManagedHooksOnly {
		t.Fatalf("managed settings: %s", b)
	}
	if !strings.Contains(out.String(), "allow_managed_hooks_only = true") || !strings.Contains(out.String(), "not tested live") {
		t.Fatalf("Codex snippet missing:\n%s", out.String())
	}
	// A second install keeps the system config an organisation edited.
	os.WriteFile(config.SystemPath(), []byte("version: 1\nmode: enforce\nstrict: true\n"), 0o644)
	out.Reset()
	if rc := run([]string{"install", "--managed"}, nil, &out, &errb); rc != 0 || !strings.Contains(out.String(), "kept as it is") {
		t.Fatalf("reinstall: rc %d %s", rc, out.String())
	}
	if b, _ := os.ReadFile(config.SystemPath()); !strings.Contains(string(b), "strict: true") {
		t.Fatal("system config overwritten")
	}
	out.Reset()
	if rc := run([]string{"uninstall", "--managed", "--purge"}, nil, &out, &errb); rc != 0 {
		t.Fatalf("uninstall: rc %d %s", rc, errb.String())
	}
	for _, p := range []string{config.ManagedBinary(), config.SystemPath(), filepath.Join(config.ClaudeManagedDir, "managed-settings.d", "applygate.json")} {
		if fileExists(p) {
			t.Errorf("%s left after uninstall --purge", p)
		}
	}
}
