package config

import (
	"os"
	"path/filepath"
	"testing"
)

// A repository config is read only when its exact content was trusted.
func TestRepoConfigNeedsTrust(t *testing.T) {
	TrustAll = false
	defer func() { TrustAll = true }()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	repo := t.TempDir()
	p := filepath.Join(repo, FileName)
	os.WriteFile(p, []byte("version: 1\nstrict: true\nenvironments:\n  - name: dev\n    tier: disposable\n    match: {paths: [\"dev/**\"]}\n"), 0o644)
	dev := filepath.Join(repo, "dev")
	os.MkdirAll(dev, 0o755)

	cfg, err := Load("", dev)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Untrusted) != 1 || cfg.Resolve(Signals{Dir: dev}).Tier != Protected {
		t.Fatalf("untrusted config: untrusted %v tier %s", cfg.Untrusted, cfg.Resolve(Signals{Dir: dev}).Tier)
	}
	if err := Trust([]string{p}); err != nil {
		t.Fatal(err)
	}
	cfg, _ = Load("", dev)
	if len(cfg.Untrusted) != 0 || cfg.Resolve(Signals{Dir: dev}).Tier != Disposable {
		t.Fatalf("trusted config not read: %v", cfg.Untrusted)
	}
	// Any change, by any route, makes it untrusted again.
	os.WriteFile(p, []byte("version: 1\nstrict: true\nenvironments:\n  - name: dev\n    tier: disposable\n    match: {paths: [\"**\"]}\n"), 0o644)
	cfg, _ = Load("", dev)
	if len(cfg.Untrusted) != 1 || cfg.Resolve(Signals{Dir: filepath.Join(repo, "prod")}).Tier != Protected {
		t.Fatalf("changed config still read")
	}
}

// A directory reached through a symlink from outside the repository still
// finds the repository's config (4H15).
func TestRepoConfigsThroughSymlink(t *testing.T) {
	repo, out := t.TempDir(), t.TempDir()
	if err := os.MkdirAll(filepath.Join(repo, "envs", "prod"), 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(repo, FileName), []byte("environments: []\n"), 0o644)
	link := filepath.Join(out, "p")
	if err := os.Symlink(filepath.Join(repo, "envs", "prod"), link); err != nil {
		t.Fatal(err)
	}
	got := RepoConfigs(link)
	if len(got) != 1 || !sameEntry(got[0], filepath.Join(repo, FileName)) {
		t.Fatalf("got %v", got)
	}
}
