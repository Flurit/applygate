package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// managedDirs points the managed install's paths at a temporary directory.
func managedDirs(t *testing.T, rootOwned bool) string {
	t.Helper()
	d := t.TempDir()
	old := []string{SystemDir, ManagedBinDir, ClaudeManagedDir, CodexManagedDir}
	oldRoot := RequireRootOwned
	SystemDir, ManagedBinDir = filepath.Join(d, "etc", "applygate"), filepath.Join(d, "libexec", "applygate")
	ClaudeManagedDir, CodexManagedDir = filepath.Join(d, "claude"), filepath.Join(d, "codex")
	RequireRootOwned = rootOwned
	t.Cleanup(func() {
		SystemDir, ManagedBinDir, ClaudeManagedDir, CodexManagedDir = old[0], old[1], old[2], old[3]
		RequireRootOwned = oldRoot
	})
	os.MkdirAll(SystemDir, 0o755)
	return d
}

// What the system config sets wins over the user config.
func TestSystemConfigWins(t *testing.T) {
	managedDirs(t, false)
	user := filepath.Join(t.TempDir(), "config.yaml")
	os.WriteFile(user, []byte("version: 1\nmode: observe\napprovals: true\njudge:\n  enabled: true\n  backend: command\n  command: [\"true\"]\n"), 0o600)
	cfg, err := Load(user, "")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != "observe" {
		t.Fatalf("without a system config the user's mode holds, got %s", cfg.Mode)
	}
	os.WriteFile(SystemPath(), []byte("version: 1\nmode: enforce\napprovals: false\n"), 0o644)
	cfg, err = Load(user, "")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != "enforce" || cfg.Approvals == nil || *cfg.Approvals {
		t.Fatalf("system config did not win: mode %s approvals %v", cfg.Mode, cfg.Approvals)
	}
	// The judge sends calls off the machine with a command the user names:
	// under a managed install that is the system config's choice.
	if cfg.Judge.Enabled != nil && *cfg.Judge.Enabled {
		t.Fatalf("the user config turned the judge on under a managed install: %+v", cfg.Judge)
	}
}

// Under a managed install the user config may only tighten (finding 3S2).
func TestManagedUserConfigOnlyTightens(t *testing.T) {
	managedDirs(t, false)
	os.WriteFile(SystemPath(), []byte("version: 1\nmode: enforce\napprovals: false\n"), 0o644)
	dir := t.TempDir()
	for _, user := range []string{
		"version: 1\nstrict: false\ndefault_tier: disposable\n",
		"version: 1\nenvironments:\n  - {name: all, tier: disposable, match: {paths: [\"**\"]}}\n",
		"version: 1\naliases: {terraform: ls}\n",
		"version: 1\non_error: allow\nunknown_dir: session_root\n",
		"version: 1\nwrappers:\n  - {name: company-run, skip: 1}\n",
	} {
		p := filepath.Join(t.TempDir(), "config.yaml")
		os.WriteFile(p, []byte(user), 0o600)
		cfg, err := Load(p, "")
		if err != nil {
			t.Fatal(err)
		}
		if r := cfg.Resolve(Signals{Dir: dir}); r.Tier != Protected || cfg.Aliases["terraform"] != "" || cfg.OnError == "allow" || len(cfg.Wrappers) > 0 {
			t.Errorf("user config %q loosened: tier %s aliases %v on_error %s wrappers %v", user, r.Tier, cfg.Aliases, cfg.OnError, cfg.Wrappers)
		}
		if len(cfg.Deprecations) == 0 {
			t.Errorf("user config %q: no note says what was ignored", user)
		}
	}
	// Tightening still works: a protected environment.
	p := filepath.Join(t.TempDir(), "config.yaml")
	os.WriteFile(p, []byte("version: 1\nenvironments:\n  - {name: core, tier: protected, match: {paths: [\"**/core/**\"]}}\n"), 0o600)
	if cfg, _ := Load(p, ""); len(cfg.Environments) != 1 {
		t.Fatalf("a protected environment from the user config was dropped")
	}
}

// A system config that root does not own decides nothing, and every
// directory is protected.
func TestSystemConfigMustBeRootOwned(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root")
	}
	managedDirs(t, true)
	os.WriteFile(SystemPath(), []byte("version: 1\nmode: observe\n"), 0o644)
	cfg, err := Load("", "")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode == "observe" || len(cfg.Untrusted) != 1 {
		t.Fatalf("a user-owned system config was read: mode %s untrusted %v", cfg.Mode, cfg.Untrusted)
	}
	if r := cfg.Resolve(Signals{Dir: t.TempDir()}); r.Tier != Protected {
		t.Fatalf("tier %s", r.Tier)
	}
}

// Under a managed install only the system trust store counts.
func TestManagedTrustStore(t *testing.T) {
	TrustAll = false
	defer func() { TrustAll = true }()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	repo := t.TempDir()
	p := filepath.Join(repo, FileName)
	os.WriteFile(p, []byte("version: 1\n"), 0o644)
	// Trusted in the user store before the managed install.
	if err := Trust([]string{p}); err != nil {
		t.Fatal(err)
	}
	managedDirs(t, false)
	os.WriteFile(SystemPath(), []byte("version: 1\n"), 0o644)
	if cfg, _ := Load("", repo); len(cfg.Untrusted) != 1 {
		t.Fatalf("the user trust store counted under a managed install")
	}
	if TrustPath() != SystemTrustPath() || TrustCommand() != "sudo applygate trust" {
		t.Fatalf("trust path %s", TrustPath())
	}
	if err := Trust([]string{p}); err != nil {
		t.Fatal(err)
	}
	if cfg, _ := Load("", repo); len(cfg.Untrusted) != 0 {
		t.Fatalf("system trust not read: %v", cfg.Untrusted)
	}
	if fi, _ := os.Stat(SystemTrustPath()); fi.Mode().Perm() != 0o644 {
		t.Fatalf("system trust store mode %v", fi.Mode().Perm())
	}
}

// doctor names every repository setting that is ignored (finding 2D16).
func TestRepoUserOnlySettingsNoted(t *testing.T) {
	repo := t.TempDir()
	os.WriteFile(filepath.Join(repo, FileName), []byte("version: 1\nlog_path: /tmp/x.jsonl\napprovals: true\nunknown_dir: session_root\njudge:\n  enabled: true\npreflight:\n  live_state: true\n"), 0o644)
	cfg, err := Load("", repo)
	if err != nil {
		t.Fatal(err)
	}
	notes := strings.Join(cfg.Deprecations, "\n")
	for _, k := range []string{"log_path", "approvals: true", "unknown_dir: session_root", "judge", "preflight.live_state"} {
		if !strings.Contains(notes, k) {
			t.Errorf("no note for %s:\n%s", k, notes)
		}
	}
}
