package config

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// A git repository without .applygate.yaml, and a session started in a
// subdirectory, have their hook files guarded; those targets are soft (a
// work-tree rewrite asks there), and the plant-only ones are not counted
// for a removal.
func TestGuardRootsWithoutAConfig(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	repo := t.TempDir()
	os.MkdirAll(filepath.Join(repo, ".git"), 0o755)
	sub := filepath.Join(repo, "svc", "api")
	os.MkdirAll(sub, 0o755)
	cfg, err := Load("", sub)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.GitRoot != repo || cfg.GuardRoot != "" || cfg.Root != "" {
		t.Fatalf("GitRoot %q GuardRoot %q Root %q; want the repository, none, none", cfg.GitRoot, cfg.GuardRoot, cfg.Root)
	}
	targets := cfg.GuardTargets(home, sub)
	for _, want := range []string{filepath.Join(repo, ".claude", "settings.json"), filepath.Join(sub, ".claude", "settings.json"), filepath.Join(home, ".claude", "settings.json")} {
		if !slices.Contains(targets, want) {
			t.Errorf("GuardTargets lacks %s", want)
		}
	}
	soft := cfg.SoftTargets(home, sub)
	if !slices.Contains(soft, filepath.Join(repo, ".claude", "settings.json")) || !slices.Contains(soft, filepath.Join(sub, ".codex", "hooks.json")) {
		t.Errorf("SoftTargets lacks the git root's or the session's hook files: %v", soft[:min(len(soft), 6)])
	}
	if slices.Contains(soft, filepath.Join(home, ".claude", "settings.json")) {
		t.Errorf("home's hook settings are soft")
	}
	plant := cfg.PlantOnlyTargets(home, sub)
	if !slices.Contains(plant, filepath.Join(repo, ".terraform", "providers")) || !slices.Contains(plant, filepath.Join(repo, ".git", "hooks")) {
		t.Errorf("PlantOnlyTargets lacks .terraform/providers or .git/hooks")
	}
	for _, p := range plant {
		if filepath.Base(p) == "settings.json" || filepath.Base(p) == "hooks.json" {
			t.Errorf("hook settings %s are plant-only", p)
		}
	}
	// A config root is soft too (a git rewrite there asks); home stays hard.
	os.WriteFile(filepath.Join(repo, ".applygate.yaml"), []byte("version: 1\n"), 0o644)
	TrustAll = true
	cfg, err = Load("", sub)
	if err != nil {
		t.Fatal(err)
	}
	soft = cfg.SoftTargets(home)
	if !slices.Contains(soft, filepath.Join(repo, ".claude", "settings.json")) || !slices.Contains(soft, filepath.Join(repo, ".applygate.yaml")) {
		t.Errorf("the config root's hook settings or config are not soft")
	}
	if slices.Contains(soft, filepath.Join(home, ".claude", "settings.json")) {
		t.Errorf("home's hook settings are soft under a config")
	}
}
